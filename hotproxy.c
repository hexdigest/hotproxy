/* vim:ai ts=4 sw=4
 * tproxy.c:
 *
 * This is a transparent proxy server daemon. HTTP requests
 * are transparently accepted and passed to the destination HTTP-server for
 * handling. The destination site IP-address is extracted from
 * the TCP-headers to avoid extra DNS lookups.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
# include <syslog.h>
#endif
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#if defined(IPFILTER) && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__))
# include <sys/ioctl.h>
# include <netinet/in_systm.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <net/if.h>
# include <netinet/ip_compat.h>
# include <netinet/ip_fil.h>
# include <netinet/ip_nat.h>
#endif

#if defined(IPTABLES) && defined(__linux__)
# include <linux/netfilter_ipv4.h>
#endif

/* For Solaris */
#ifndef INADDR_NONE
# define INADDR_NONE		(in_addr_t)-1
#endif

/* For older Linux */
#if defined(SIGCLD) && !defined(SIGCHLD)
# define SIGCHLD			SIGCLD
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif
#ifndef _PATH_VARRUN
# define _PATH_VARRUN		"/var/run/"
#endif

#define CONNECTION_TIMEOUT	10			/* 10 seconds */
#define ACTIVITY_TIMEOUT	120			/* 120 seconds, 2 minutes */
#define BUFFER_SIZE			4096		/* Read/write buffer size */
#define REQUEST_SIZE		32768		/* Requests must fit in this size */
#define REFERRER_SIZE		4096		/* Holds the referrer URL */
#define HOSTNAME_SIZE		1024		/* Holds the requested hostname */

/*
 * Typedefs.
 */
typedef unsigned long	ip_address_t;
typedef unsigned char	byte_t;

typedef struct connection_
{
	int					client_fd;
	int					proxy_fd;
	struct sockaddr_in	client_addr;					// Addr of connected client.
	struct sockaddr_in	dest_addr;						// Addr of intended destination.
	char				request_buffer[BUFFER_SIZE];	// Requests are read into here.
	char				response_buffer[BUFFER_SIZE];	// Responses are read into here.
	char				request[REQUEST_SIZE];			// Buffer to hold the request.
	int					request_length;					// Length of request.
	char				*posted_content;				// Buffer to hold the posted content.
	int					posted_content_length;			// Length of the posted content.
	int					method_offset;					// Index of METHOD in 'request'.
	int					method_end_offset;				// Index to end of METHOD in 'request'.
	int					url_offset;						// Index of URL in 'request.
	int					url_end_offset;					// Index to end of URL in 'request'.
	int					version_offset;					// Index of VERSION in 'request'.
	int					version_end_offset;				// Index to end of VERSION in 'request'.
	char				host_header[HOSTNAME_SIZE];		// Extracted or looked up hostname header.
	int					host_header_length;				// Length of hostname.
	char				referer_header[REFERRER_SIZE];	// Extracted referrer header.
	int					referer_header_length;			// Length of referrer.
	int					content_length;					// Extracted content length header.
	int					request_number;					// Number of requests handled by connection.
}	connection_t;

/*
 * Macros.
 */
#define FD_MAX(a,b)		((a) > (b) ? (a) : (b))

/*
 * Function prototypes.
 */
static void usage(char *prog, char *opt);
static short getportnum(char *portnum);
static ip_address_t getipaddress(char *ipaddr);
static uid_t getuserid(char *user);
static uid_t getgroupid(uid_t uid);
static int bind_to_port(ip_address_t bind_ip, short bind_port);
static int connect_to_proxy(ip_address_t ip, short port);
static void lookup_hostname(struct sockaddr_in *addr, char *hostname, int hostlen, int needed);
static void server_main_loop(int sock, char *server_hostname, short server_port);
static void trans_proxy(int sock, struct sockaddr_in *addr,
						char *server_hostname, short server_port);
static int process_proxy_response(connection_t *conn, size_t last_read);
static int process_client_request(connection_t *conn, size_t last_read);
static int send_data(int fd, char *data, size_t length);
#if defined(DEBUG_INPUT_REQUESTS) || defined(DEBUG_OUTPUT_REQUESTS)
static void print_request(char *prefix, char *data, size_t length, int dump_mode);
#endif
static void write_pid(char *prog);
static void term_signal(int sig);
static void alarm_signal(int sig);
#ifdef LOG_TO_FILE
static void hup_signal(int sig);
static void log_it(char *fmt, ...);
#endif

/*
 * Command line switches.
 */
static char				*prog;
static int				daemonize = 0;
static int				proxy_only = 0;
static char				*force_url = NULL;
static int				force_url_length;
#ifdef LOG_TO_FILE
static char				*log_file_name = NULL;
static FILE				*log_file = NULL;
#endif
static int				ignore_alarm;

#ifdef IPFILTER
/*
 * The /dev/ipnat device node.
 */
static int				natdev = -1;
#endif

/*
 * Main loop.
 */
int main(int argc, char **argv)
{
	int					arg;
	ip_address_t		bind_ip = INADDR_ANY;
	short				bind_port = -1;
	char 				*server_hostname = NULL;
	short				server_port = -1;
	uid_t				run_uid = 0;
	gid_t				run_gid = 0;
#if !defined(DEBUG) && !defined(DEBUG_INPUT_REQUESTS) && !defined(DEBUG_OUTPUT_REQUESTS)
	int					fd;
#endif
	int					sock;
	struct sockaddr_in	addr;
	int					len;

	/*
	 * Get the name if the program.
	 */
	if ((prog = strrchr(argv[0], '/')) != NULL)
		++prog;
	else
		prog = argv[0];

	/*
	 * Parse the command line arguments.
	 */

	while ((arg = getopt(argc, argv, "dp:u:h:f:l:")) != EOF)
	{
		switch (arg)
		{
		case 'd':
			daemonize = 1;
			break;

 		case 'f':
 			force_url = optarg;
 			force_url_length = strlen(force_url);
 			break;

#ifdef LOG_TO_FILE
		case 'l':
			log_file_name = optarg;
			break;
#endif
		case 'p':
			bind_port = getportnum(optarg);
			break;

		case 'h':
			bind_ip = getipaddress(optarg);
			break;

		case 'u':
			run_uid = getuserid(optarg);
			run_gid = getgroupid(run_uid);
			break;

		default:
		case '?':
			usage(prog, NULL);
			break;
		}
	}

	/*
	 * Process the remaining command line arguments.
	 */
	for (; optind < argc; ++optind)
	{
		if (server_hostname == NULL)
		{
			server_hostname = argv[optind];
		}
		else if (server_port == -1)
		{
			server_port = getportnum(argv[optind]);
		}
		else
		{
			usage(prog, "Extra arguments were specified.");
		}
	}

	if (INADDR_NONE == bind_ip)
	{
		usage(prog, "The server ipaddr is invalid.");
	}

	if (-1 == bind_port)
	{
		usage(prog, "No server port was specified (or it was invalid).");
	}

	/*
	 * Set the current directory to the root filesystem.
	 */
	chdir("/");

#ifdef IPFILTER
	/*
	 * Now is a good time to open /dev/ipnat, before giving up our uid/gid.
	 */
	if ((natdev = open(IPL_NAT, O_RDONLY)) < 0)
	{
		perror("open(" IPL_NAT ")");
		exit(1);
	}
#endif

#ifdef LOG_TO_FILE
	/*
	 * Open the log file for the first time.
	 */
	if (log_file_name)
	{
		log_file = fopen(log_file_name, "a");
# ifdef LOG_TO_FILE_LINEBUFF
		if (log_file)
			setvbuf(log_file, NULL, _IOLBF, BUFSIZ);
# endif
	}
#endif

	/*
	 * Start by binding to the port, the child inherits this socket.
	 */
	sock = bind_to_port(bind_ip, bind_port);

	/*
	 * Start a server process.
	 */
	if (daemonize)
	{
		switch (fork())
		{
		case -1:
			/*
			 * We could not fork a daemon process.
			 */
			perror("fork()");
			exit(1);
		case 0:
			/*
			 * The child continues as the daemon process.
			 */
			break;
		default:
			/*
			 * Parent exits at this stage.
			 */
			_exit(0);
		}

		/*
		 * Start a new session and group.
		 */
		setsid();
	}

#if !defined(DEBUG) && !defined(DEBUG_INPUT_REQUESTS) && !defined(DEBUG_OUTPUT_REQUESTS)
	/*
	 * Point file descriptors to /dev/null, unless DEBUG is defined.
	 */
	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) >= 0)
	{
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
#endif

#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
	/*
	 * Open syslog for logging errors.
	 */
	openlog(prog, LOG_PID, LOG_DAEMON);
#endif

	/*
	 * Ignore some signals.
	 */
	if (daemonize)
		signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCONT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, alarm_signal);
#ifdef LOG_TO_FILE
	signal(SIGHUP, hup_signal);
#else
	signal(SIGHUP, SIG_IGN);
#endif
	signal(SIGTERM, term_signal);

	/*
	 * Create a .pid file in /var/run.
	 */
	write_pid(prog);

	/*
	 * Drop back to an untrusted user.
	 */
	if (run_gid != 0)
		setgid(run_gid);
	if (run_uid != 0)
		setuid(run_uid);

	/*
	 * Handle the server main loop.
	 */
	server_main_loop(sock, server_hostname, server_port);

	/*
	 * Should never exit.
	 */
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
	closelog();
#endif
	exit(1);

	return (0);
}

/*
 * Print some basic help information.
 */
static void usage(char *prog, char *opt)
{
	if (opt)
	{
		fprintf(stderr, "%s: %s\n", prog, opt);
	}
#ifdef LOG_TO_FILE
	fprintf(stderr, "usage: %s [-p port [-d] [-h ipaddr] [-u user]] [-l file]\n", prog);
#else
	fprintf(stderr, "usage: %s [-p port [-d] [-h ipaddr] [-u user]] [-l file]\n", prog);
#endif
	fprintf(stderr, "    -d          Do not background the daemon in server mode.\n");
	fprintf(stderr, "    -h ipaddr   Bind to the specified ipaddr in server mode.\n");
	fprintf(stderr, "    -p port     Run as a server bound to the specified port.\n");
	fprintf(stderr, "    -u user     Run as the specified user in server mode.\n");
	fprintf(stderr, "    -f url      URL to force.\n");
#ifdef LOG_TO_FILE
	fprintf(stderr, "    -l file     Log accesses to the specified file (relative to /).\n");
#endif
	exit(1);
}

/*
 * Return the port number, in network order, of the specified service.
 */
static short getportnum(char *portnum)
{
	char			*digits = portnum;
	struct servent	*serv;
	short			port;

	for (port = 0; isdigit((int)*digits); ++digits)
	{
		port = (port * 10) + (*digits - '0');
	}

	if ((*digits != '\0') || (port <= 0))
	{
		if ((serv = getservbyname(portnum, "tcp")) != NULL)
		{
			port = serv->s_port;
		}
		else
		{
			port = -1;
		}
		endservent();
	}
	else
		port = htons(port);

#ifdef DEBUG
	printf("Port lookup %s -> %hd\n", portnum, ntohs(port));
#endif

	return (port);
}

/*
 * Return the IP address of the specified host.
 */
static ip_address_t getipaddress(char *ipaddr)
{
	struct hostent	*host;
	ip_address_t	ip;

	if (((ip = inet_addr(ipaddr)) == INADDR_NONE)
	    &&
		(strcmp(ipaddr, "255.255.255.255") != 0))
	{
		if ((host = gethostbyname(ipaddr)) != NULL)
		{
			memcpy(&ip, host->h_addr, sizeof(ip));
		}
		endhostent();
	}

#ifdef DEBUG
	printf("IP lookup %s -> 0x%08lx\n", ipaddr, (unsigned long)ntohl(ip));
#endif

	return (ip);
}

/*
 * Find the userid of the specified user.
 */
static uid_t getuserid(char *user)
{
	struct passwd	*pw;
	uid_t			uid;

	if ((pw = getpwnam(user)) != NULL)
	{
		uid = pw->pw_uid;
	}
	else if (*user == '#')
	{
		uid = (uid_t)atoi(&user[1]);
	}
	else
	{
		uid = -1;
	}

#ifdef DEBUG
	printf("User lookup %s -> %lu\n", user, (unsigned long)uid);
#endif

	endpwent();

	return (uid);
}

/*
 * Find the groupid of the specified user.
 */
static uid_t getgroupid(uid_t uid)
{
	struct passwd	*pw;
	gid_t			gid;

	if ((pw = getpwuid(uid)) != NULL)
	{
		gid = pw->pw_gid;
	}
	else
	{
		gid = -1;
	}

#ifdef DEBUG
	printf("Group lookup %lu -> %lu\n", (unsigned long)uid, (unsigned long)gid);
#endif

	endpwent();

	return (gid);
}

/*
 * Bind to the specified ip and port.
 */
static int bind_to_port(ip_address_t bind_ip, short bind_port)
{
	struct sockaddr_in	addr;
	int					sock;

	/*
	 * Allocate a socket.
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket()");
		exit(1);
	}

	/*
	 * Set the SO_REUSEADDR option so we can start tproxy quickly if it dies.
	 */
	{
	 	int	on = 1;

		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
	}

	/*
	 * Set the address to listen to.
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = bind_port;
	addr.sin_addr.s_addr = bind_ip;

	/*
	 * Bind our socket to the above address.
	 */
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("bind()");
		close(sock);
		exit(1);
	}

	/*
	 * Establish a large listen backlog.
	 */
	if (listen(sock, SOMAXCONN) < 0)
	{
		perror("listen()");
		close(sock);
		exit(1);
	}

	return (sock);
}

/*
 * Connect to the proxy server.
 */
static int connect_to_proxy(ip_address_t ip, short port)
{
	struct sockaddr_in	addr;
	int					sock;

#ifdef DEBUG
	printf("Connect to proxy 0x%08lx %d\n", (unsigned long)ntohl(ip), ntohs(port));
#endif

	/*
	 * Allocate a socket.
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_ERR, "socket(): %m");
#endif
		return (-1);
	}

	/*
	 * Set the address to connect to.
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = port;
	addr.sin_addr.s_addr = ip;

	/*
	 * Connect our socket to the above address.
	 */
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		alarm(0);
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_WARNING, "connect(): %m");
#endif
		close(sock);
		return (-1);
	}

	/*
	 * Success, so disable the alarm.
	 */
	alarm(0);

	/*
	 * Set the keepalive socket option to on.
	 */
	{
		int		on = 1;
		setsockopt(STDIN_FILENO, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof(on));
	}

	return (sock);
}

/*
 * Translate a sockaddr_in structure into a usable ASCII hostname.
 */
static void lookup_hostname(struct sockaddr_in *addr, char *hostname, int hostlen, int needed)
{
#ifdef DNS_LOOKUPS
	struct hostent	*host;

	if (needed)
	{
		if ((host = gethostbyaddr((char *)&addr->sin_addr,
								  sizeof(addr->sin_addr), AF_INET)) != NULL)
		{
			strncpy(hostname, host->h_name, hostlen);
			hostname[hostlen - 1] = '\0';
		}
		else
		{
			strncpy(hostname, inet_ntoa(addr->sin_addr), hostlen);
			hostname[hostlen - 1] = '\0';
# ifdef LOG_TO_SYSLOG
			syslog(LOG_WARNING, "DNS lookup for %s failed: %m", hostname);
# endif
		}
	}
	else
	{
# ifdef USELESS_DNS_LOOKUPS
		if ((host = gethostbyaddr((char *)&addr->sin_addr,
								  sizeof(addr->sin_addr), AF_INET)) != NULL)
		{
			strncpy(hostname, host->h_name, hostlen);
			hostname[hostlen - 1] = '\0';
		}
		else
		{
			strncpy(hostname, inet_ntoa(addr->sin_addr), hostlen);
			hostname[hostlen - 1] = '\0';
#  ifdef LOG_TO_SYSLOG
			syslog(LOG_WARNING, "DNS lookup for %s failed: %m", hostname);
#  endif
		}
# else
		strncpy(hostname, inet_ntoa(addr->sin_addr), hostlen);
		hostname[hostlen - 1] = '\0';
# endif
	}
#else
	strncpy(hostname, inet_ntoa(addr->sin_addr), hostlen);
	hostname[hostlen - 1] = '\0';
#endif
}

/*
 * This is the main loop when running as a server.
 */
static void server_main_loop(int sock, char *server_hostname, short server_port)
{
	int					new_sock;
	struct sockaddr_in	addr;
	int					len;
	pid_t				pid;
#ifdef DO_DOUBLE_FORK
	int					status;
#endif

	/*
	 * Ignore dead children so no zombies should be left hanging. However some
	 * systems don't allow this, see the DO_DOUBLE_FORK option.
	 */
#ifdef SA_NOCLDWAIT
	/* Go BSD */
	{
		struct sigaction	sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sa.sa_flags = SA_NOCLDWAIT;
		sigaction(SIGCHLD, &sa, NULL);
	}
#else
	/* Go Linux & SVR4 */
 	signal(SIGCHLD, SIG_IGN);
#endif

	for (;;)
	{
		/*
		 * Accept an incoming connection.
		 */
		len = sizeof(addr);
		while ((new_sock = accept(sock, (struct sockaddr *)&addr, &len)) < 0)
		{
			/*
			 * Connection resets are common enough to log them as debug only.
			 */
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
			if (errno != ECONNRESET)
				syslog(LOG_ERR, "accept(): %m");
# ifdef LOG_TO_SYSLOG
			else
				syslog(LOG_INFO, "accept(): %m");
# endif
#endif
		}

		/*
		 * Create a new process to handle the connection.
		 */
		switch (pid = fork())
		{
		case -1:	/* Error */
			/*
			 * Under load conditions just ignore new connections.
			 */
			break;

		case 0:		/* Child */
#ifdef DO_DOUBLE_FORK
			/*
			 * Some systems like to fork again as the child. This makes the client
			 * run as a child of init so we don't have to handle reaping them.
			 * However all this forking slows us downm so it's optional.
			 */
			if (fork() > 0)	/* Parent */
				exit(0);
#endif

			/*
			 * Start the proxy work in the new socket.
			 */
			trans_proxy(new_sock, &addr, server_hostname, server_port);
			close(new_sock);
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
			closelog();
#endif
			exit(0);

#ifdef DO_DOUBLE_FORK
		default:	/* Parent */
			/*
			 * Wait for the child process to terminate. Since it forked another
			 * child to handle the request, it should terminate quickly.
			 */
			waitpid(pid, &status, 0);
			break;
#endif
		}
///
		/*
		 * Close the socket as the child handles the call.
		 */
		close(new_sock);
	}
}

/*
 * Perform the transparent proxy activity.
 */
static void trans_proxy(int sock, struct sockaddr_in *from_addr,
						char *server_hostname, short server_port)
{
	connection_t		conn;
	int					length;
	int					max_fd;
	fd_set				read_fd;
#ifdef IPFILTER
	natlookup_t			natlook;
#endif

	/*
	 * Initialise the connection structure.
	 */
	memset(&conn, 0, sizeof(connection_t));
	conn.client_fd = sock;
	conn.client_addr = *from_addr;

#if defined(IPTABLES) && defined(__linux__)
	/*
	 * The first thing we do is get the IP address that the client was
	 * trying to connected to. Here lies part of the magic. Linux-2.4
	 * introduces IPTABLES which uses getsockopt instead of getsockname
	 * for a more obvious interface.
	 */
	length = sizeof(conn.dest_addr);
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, (char *)&conn.dest_addr, &length) < 0)
	{
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_ERR, "getsockopt(SO_ORIGINAL_DST): %m");
#endif
		return;
	}
	
#else/*!IPTABLES*/

	/*
	 * The first thing we do is get the IP address that the client was
	 * trying to connected to. Here lies part of the magic. Normally
	 * getsockname returns our address, but not with transparent proxying.
	 */
	length = sizeof(conn.dest_addr);
	if (getsockname(sock, (struct sockaddr *)&conn.dest_addr, &length) < 0)
	{
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_ERR, "getsockname(): %m");
#endif
		return;
	}

#ifdef IPFILTER
	/*
	 * However, under IPFILTER, we have to do additional work. The "to_addr"
	 * has been changed by the IP filter to trick the IP stack into
	 * processing the packet locally. We need to lookup the real remote
	 * address ourselves using an ioctl().
	 */

	/*
	 * Build up the NAT natlookup structure.
	 */
	memset(&natlook, 0, sizeof(natlook));
	natlook.nl_inip = conn.dest_addr.sin_addr;
	natlook.nl_outip = conn.client_addr.sin_addr;
	natlook.nl_flags = IPN_TCP;
	natlook.nl_inport = conn.dest_addr.sin_port;
	natlook.nl_outport = conn.client_addr.sin_port;

	/*
	 * Use the NAT device to lookup the mapping pair.
	 */
	if (ioctl(natdev, SIOCGNATL, &natlook) == -1)
	{
# if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_ERR, "ioctl(SIOCGNATL): %m");
# endif
		return;
	}

	conn.dest_addr.sin_addr = natlook.nl_realip;
	conn.dest_addr.sin_port = natlook.nl_realport;
#endif

#endif/*!IPTABLES*/

	conn.proxy_fd = connect_to_proxy(conn.dest_addr.sin_addr.s_addr, conn.dest_addr.sin_port);
	if (conn.proxy_fd == -1)
	{
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
		syslog(LOG_ERR, "Could not connect to destination");
#endif
		return;
	}

	/*
	 * This loop acts a bit like the guy in the middle of a "bucket brigade".
	 * When the client passes some data, it gets handed off to the server,
	 * and vise-versa. However for data received from the client, it is
	 * buffered until a full request is received. Once a full request is
	 * received, the request is re-written before being sent to the server.
	 */
	for (;;)
	{
		/*
		 * Construct a select read mask from both file descriptors.
		 */
		FD_ZERO(&read_fd);
		FD_SET(conn.client_fd, &read_fd);
		FD_SET(conn.proxy_fd, &read_fd);
		max_fd = FD_MAX(conn.client_fd, conn.proxy_fd);

		/*
		 * Disconnect after some period of in-activity.
		 */
		ignore_alarm = 0;
		alarm(ACTIVITY_TIMEOUT);

		/*
		 * Wait for some data to be read. If we get a signal then
		 * ignore the -1 return and try again.
		 */
		if (select(max_fd + 1, &read_fd, NULL, NULL, NULL) < 0)
		{
			if (errno != EINTR)
			{
				alarm(0);
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
				syslog(LOG_ERR, "select(): %m");
#endif
				close(conn.proxy_fd);
				return;
			}
		}

		/*
		 * We have something so disable the alarm.
		 */
		alarm(0);

		/*
		 * See if any data can be read from the client.
		 */
		if (FD_ISSET(conn.client_fd, &read_fd))
		{
			switch (length = read(conn.client_fd, conn.request_buffer, BUFFER_SIZE))
			{
			case -1:
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
				if (errno != ECONNRESET)
					syslog(LOG_WARNING, "read(client) failed: %m");
# ifdef LOG_TO_SYSLOG
				else
					syslog(LOG_INFO, "read(client) failed: %m");
# endif
#endif
				close(conn.proxy_fd);
				return;

			case 0:
				close(conn.proxy_fd);
				return;

			default:
				/*
				 * Process requests read from the client. Returns 0 if a
				 * processed request could not be written to the proxy.
				 */
				if (!process_client_request(&conn, length))
				{
#ifdef LOG_TO_SYSLOG
					syslog(LOG_WARNING, "write(proxy) failed: %m");
#endif
					close(conn.proxy_fd);
					return;
				}
				break;
			}
		}

		/*
		 * See if any data can be read from the proxy.
		 */
		if (FD_ISSET(conn.proxy_fd, &read_fd))
		{
			switch (length = read(conn.proxy_fd, conn.response_buffer, BUFFER_SIZE))
			{
			case -1:
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
				syslog(LOG_WARNING, "read(proxy) failed: %m");
#endif
				close(conn.proxy_fd);
				return;

			case 0:
				close(conn.proxy_fd);
				return;

			default:
				/*
				 * Process responses read from the proxy. Returns 0 if a
				 * processed request could not be written to the client.
				 */
				if (!process_proxy_response(&conn, length))
				{
#ifdef LOG_TO_SYSLOG
					syslog(LOG_WARNING, "write(client) failed: %m");
#endif
					close(conn.proxy_fd);
					return;
				}
				break;
			}
		}
	}
}

/*
 * Send data to a file descriptor (sock). Re-try if the write returns
 * after not sending all of the data.
 */
static int send_data(int fd, char *data, size_t length)
{
	size_t	written;
	size_t	write_len;

	/*
	 * Loop while there is data to process.
	 */
	for (written = 0; written < length; written += write_len)
	{
		write_len = write(fd, &data[written], length - written);

		if (write_len < 0)
			return (0);
	}

	return (1);
}

/*
 * Process responses read from the proxy. Returns 0 if a
 * processed request could not be written to the client.
 */
static int process_proxy_response(connection_t *conn, size_t last_read)
{
	/*
	 * Write the response to the client.
	 */
	return (send_data(conn->client_fd, conn->response_buffer, last_read));
}

/*
 * Process requests read from the client. Returns 0 if a
 * processed request could not be written to the proxy.
 *
 * Requests are parsed by way of a state machine. The
 * request is only written to the proxy when it has been
 * fully read and processed.
 */
static int process_client_request(connection_t *conn, size_t last_read)
{
	size_t	processed;
	size_t	index;
	int		c;
	int		request_mode;
	size_t	send_size;
	char	request_buffer[REQUEST_SIZE];
	char	request_port[16];
#if defined(LOG_TO_SYSLOG) || defined(LOG_TO_FILE)
	char	client_host[HOSTNAME_SIZE];
	char	*url_string;
#endif

	/*
	 * Loop over the data that has just been read into the request buffer.
	 */
	for (processed = 0; processed < last_read; )
	{
		
		if (!send_data(conn->proxy_fd, &conn->request_buffer[processed], last_read - processed))
			return (0);
		processed = last_read;
	}

	return (1);
}

#if defined(DEBUG_INPUT_REQUESTS) || defined(DEBUG_OUTPUT_REQUESTS)
/*
 * Print an HTTP request.
 */
static void print_request(char *prefix, char *data, size_t length, int dump_mode)
{
	size_t	index;
	int		c;
	int		print_prefix = 1;
	int		line_length = 0;

	for (index = 0; index < length; ++index)
	{
		if (print_prefix)
		{
			print_prefix = 0;
			printf("%s", prefix);
		}

		c = data[index];

		if (c >= ' ' && c <= '~')
		{
			printf("%c", c);
			line_length += 1;
		}
		else if ((c == '\r') && !dump_mode)
		{
			printf("\\r");
			line_length += 2;
		}
		else if ((c == '\n') && !dump_mode)
		{
			printf("\\n");
			line_length += 2;
		}
		else
		{
			printf(".");
			line_length += 1;
		}

		if (((c == '\n') && !dump_mode) || (line_length >= 70))
		{
			printf("\n");
			line_length = 0;
			print_prefix = 1;
		}
	}

	if (!print_prefix)
		printf("\n");
}
#endif

/*
 * Write out a pid file.
 */
static void write_pid(char *prog)
{
	char	filename[1024];
	FILE	*fp;

	sprintf(filename, "%s%s.pid", _PATH_VARRUN, prog);
	if ((fp = fopen(filename, "w")) != NULL)
	{
		fprintf(fp, "%lu\n", (unsigned long)getpid());
		fclose(fp);
	}
}

/*
 * Catch alarm signals and exit.
 */
static void alarm_signal(int sig)
{
#if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
	syslog(LOG_NOTICE, "Alarm signal caught - connection timeout");
#endif
	if (!ignore_alarm)
		exit(1);
}

/*
 * Catch termination signal and exit.
 */
static void term_signal(int sig)
{
	char	filename[1024];

	sprintf(filename, "%s%s.pid", _PATH_VARRUN, prog);
	unlink(filename);

#ifdef LOG_TO_SYSLOG
	syslog(LOG_NOTICE, "Termination signal caught - exiting");
#endif
	exit(1);
}

#ifdef LOG_TO_FILE
/*
 * Catch HUP signals and re-open the log file.
 */
static void hup_signal(int sig)
{
	signal(sig, hup_signal);

	/*
	 * Close the current log file.
	 */
	if (log_file)
	{
		fclose(log_file);
		log_file = NULL;
	}

	/*
	 * Re-open the log file if it is closed.
	 */
	if (log_file == NULL && log_file_name)
	{
		log_file = fopen(log_file_name, "a");
# ifdef LOG_TO_FILE_LINEBUFF
		if (log_file)
			setvbuf(log_file, NULL, _IOLBF, BUFSIZ);
# endif
	}

# if defined(LOG_TO_SYSLOG) || defined(LOG_FAULTS_TO_SYSLOG)
	if (log_file)
		syslog(LOG_NOTICE, "HUP signal caught - re-open log '%s'", log_file_name);
	else if (log_file_name)
		syslog(LOG_NOTICE, "HUP signal caught - re-open failed '%s'", log_file_name);
# endif
}

/*
 * Append an entry to the log file.
 */
static void log_it(char *fmt, ...)
{
	time_t	now;
	char	date[20];
	va_list	args;

	if (log_file)
	{
		time(&now);
		strftime(date, sizeof(date), "%Y/%m/%d %H:%M:%S", localtime(&now));
		fprintf(log_file, "%s  ", date);
		va_start(args, fmt);
		vfprintf(log_file, fmt, args);
		va_end(args);
		fprintf(log_file, "\n");
	}
}
#endif