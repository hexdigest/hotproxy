/* vim:ai ts=4 sw=4
 * hotproxy.c:
 *
 * This is a transparent proxy server daemon. HTTP requests
 * are transparently accepted and passed to the destination HTTP-server for
 * handling. The destination site IP-address is extracted from
 * the OS internals to avoid extra DNS lookups.
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
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
//#include <getopt.h>

# include <sys/ioctl.h>

//#include <arpa/inet.h> 
#include <net/if.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <time.h>
#include <sys/mman.h>

# include <linux/netfilter_ipv4.h>

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif
#ifndef _PATH_VARRUN
# define _PATH_VARRUN		"/var/run/"
#endif

#define ACTIVITY_TIMEOUT	120			/* 120 seconds, 2 minutes */
#define BUFFER_SIZE			4096		/* Read/write buffer size */

#define SESSIONS_SIZE		100			/* 100 devices */
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
}	connection_t;

typedef struct session_t session_t;
struct session_t
{
	time_t time; //start time of the last session initiated by
	unsigned char mac[6]; //this device
};

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
static void server_main_loop(int sock, char *server_hostname, short server_port);
static void trans_proxy(int sock, struct sockaddr_in *addr,
						char *server_hostname, short server_port,
						session_t * session);
static int process_proxy_response(connection_t *conn, size_t last_read);
static int process_client_request(connection_t *conn, size_t last_read);
static int send_data(int fd, char *data, size_t length);

static void write_pid(char *prog);
static void term_signal(int sig);
static void alarm_signal(int sig);

static char* get_interface_name(int sock, ip_address_t *bind_ip);
static session_t * session_find(int sock, struct sockaddr_in *from_addr);
static void	debug_message(char *message, ...);

/*
 * Command line switches.
 */
static char				*prog;
static int				daemonize = 0;
static int				debug_enabled = 0;
static char				*force_url = NULL;
static int				force_url_length;
static int				ignore_alarm;
static time_t			expiration = 3600;

static session_t 		*sessions = NULL;
static char				*interface = NULL;

static char				*redirect_template = "HTTP/1.1 302 Found\nLocation: %s\n\n";
static char				redirect_buffer[256];

static char				trigger_host[128];
static char				trigger_url[256];
static char				redirect_host[128];

static char				*domains_whitelist = NULL;
static char				temp_str[256];

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
	int					fd;
	int					sock;

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
	while ((arg = getopt(argc, argv, "dmp:u:h:f:t:e:w:")) != EOF)
	{
		switch (arg)
		{
		case 'd':
			daemonize = 1;
			break;

 		case 'm':
 			debug_enabled = 1;
 			break;

		case 'p':
			bind_port = getportnum(optarg);
			break;

		case 'h':
			bind_ip = getipaddress(optarg);
			break;

		case 'e':
 			expiration = atoi(optarg);
 			break;

 		case 'f':
 			force_url = optarg;
 			force_url_length = strlen(force_url);
 			memset(redirect_buffer, 0, sizeof(redirect_buffer));
 			sprintf(redirect_buffer, redirect_template, force_url);

 			sscanf(force_url, "http://%128[^/]", redirect_host);

 			break;
 		
 		case 't':
 			sscanf(optarg, "http://%128[^/]/%128[^\n]", trigger_host, temp_str);
			snprintf(trigger_url, sizeof(trigger_url), "%s%s", "/", temp_str);

 			break;

 		case 'w':
			domains_whitelist = optarg;
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

	debug_message("Expiration time: %ld sec.", expiration);
	if (NULL == force_url)
		debug_message("Hotspot URL to force: NONE");
	else
		debug_message("Hotspot URL to force: %s", force_url);

	if (NULL == domains_whitelist) {
		domains_whitelist = malloc(512);
		strcpy(domains_whitelist, trigger_url);
	}

	if (strlen(redirect_host)) {
		sprintf(temp_str, "%s,%s", domains_whitelist, redirect_host);
		strcpy(domains_whitelist, temp_str);
	}
	
	//trigger host already present in whitelisted domains
	if (NULL == strstr(domains_whitelist, trigger_host)) 
	{
		snprintf(temp_str, sizeof(temp_str), "%s,%s", domains_whitelist, trigger_host);
		strcpy(domains_whitelist, temp_str);
	}

	debug_message("Domains white list: %s", domains_whitelist);
	debug_message("Trigger host: %s", trigger_host);
	debug_message("Trigger URL: %s", trigger_url);

	/*
	 * Start by binding to the port, the child inherits this socket.
	 */
	sock = bind_to_port(bind_ip, bind_port);

	//Getting some shared memory for sessions
	sessions = mmap(NULL, sizeof(session_t) * SESSIONS_SIZE, 
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	memset(sessions, 0, sizeof(session_t) * SESSIONS_SIZE);

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

	/*
	 * Point file descriptors to /dev/null, unless debug mode is enabled.
	 */
	if (!debug_enabled && (fd = open(_PATH_DEVNULL, O_RDWR, 0)) >= 0)
	{
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}

	/*
	 * Open syslog for logging errors.
	 */
	openlog(prog, LOG_PID, LOG_DAEMON);

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
	signal(SIGHUP, SIG_IGN);
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
	closelog();
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

	fprintf(stderr, "usage: %s [-p port [-d] [-h ipaddr] [-u user] [-e expiration]] [-l file]\n", prog);
	fprintf(stderr, "    -d          	Do not background the daemon in server mode.\n");
	fprintf(stderr, "    -h ipaddr   	Bind to the specified ipaddr in server mode.\n");
	fprintf(stderr, "    -p port     	Run as a server bound to the specified port.\n");
	fprintf(stderr, "    -u user     	Run as the specified user in server mode.\n");
	fprintf(stderr, "    -f url      	URL to force.\n");
	fprintf(stderr, "    -t trigger  	URL that triggers session start\n");
	fprintf(stderr, "    -w whitelist 	Comma-separated white list of domains\n");
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

	debug_message("User lookup %s -> %lu\n", user, (unsigned long)uid);

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

	debug_message("Group lookup %lu -> %lu\n", (unsigned long)uid, (unsigned long)gid);

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

	interface = get_interface_name(sock, &bind_ip);
	debug_message("Bound to interface: %s", interface);

	return (sock);
}

/*
 * Connect to the proxy server.
 */
static int connect_to_proxy(ip_address_t ip, short port)
{
	struct sockaddr_in	addr;
	int					sock;

	debug_message("Connected to host 0x%08lx %d\n", (unsigned long)ntohl(ip), ntohs(port));

	/*
	 * Allocate a socket.
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
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
 * This is the main loop when running as a server.
 */
static void server_main_loop(int sock, char *server_hostname, short server_port)
{
	int					new_sock;
	struct sockaddr_in	addr;
	socklen_t			len;
	pid_t				pid;
	session_t			*session;

	/* Go Linux & SVR4 */
 	signal(SIGCHLD, SIG_IGN);

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
			if (errno != ECONNRESET)
				debug_message("Accept filed: %s", strerror(errno));
		}

		session = session_find(new_sock, &addr);
		if (NULL == session) {
			syslog(LOG_ERR, "ioctl error, check if you set up iptables correctly");
			debug_message("ioctl error, check if you set up iptables correctly");
		} 
		else
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
			/*
			 * Start the proxy work in the new socket.
			 */

			trans_proxy(new_sock, &addr, server_hostname, server_port, session);
			close(new_sock);
			closelog();
			exit(0);
		}

		/*
		 * Close the socket as the child handles the call.
		 */
		close(new_sock);
	}
}

/*
 * Finds or creates session for this MAC 
 * and returns pointer to this session
 */
static session_t * session_find(int sock, struct sockaddr_in *from_addr) {
	int i = 0;
	session_t 		*session;
	struct arpreq	arp;
	time_t	current_time;

	//Getting MAC of current client
	arp.arp_pa = * (struct sockaddr *)from_addr;
	strcpy(arp.arp_dev, interface);

	if (0 != ioctl(sock, SIOCGARP, &arp)) 
		return NULL;
	
	current_time = time(NULL);

	for (i = 0; i < SESSIONS_SIZE; i++) {
		session = &sessions[i];

		if (session->time && current_time - session->time > expiration)
			session->time = 0;

		if (!memcmp(session->mac, (char *)&arp.arp_ha.sa_data, 6)) 
			break;
		 
		//this is the end of sessions list - fill last session with
		//MAC address of current device and return it
		if (0 == session->mac[0] && 0 == session->mac[5]) {
			memcpy(session->mac, (char *)&arp.arp_ha.sa_data, 6);
			break;
		}
			
	}

	return session;
}

/*
 * Perform the transparent proxy activity.
 */
static void trans_proxy(int sock, struct sockaddr_in *from_addr,
						char *server_hostname, short server_port, 
						session_t * session)
{
	connection_t		conn;
	socklen_t			length;
	int					max_fd;
	fd_set				read_fd;

	/*
	 * Initialise the connection structure.
	 */
	memset(&conn, 0, sizeof(connection_t));
	conn.client_fd = sock;
	conn.client_addr = *from_addr;

	/*
	 * The first thing we do is get the IP address that the client was
	 * trying to connected to. Here lies part of the magic. Linux-2.4
	 * introduces IPTABLES which uses getsockopt instead of getsockname
	 * for a more obvious interface.
	 */
	length = sizeof(conn.dest_addr);
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, (char *)&conn.dest_addr, &length) < 0)
	{
		syslog(LOG_ERR, "ioctl error, check if you set up iptables correctly: %m");
		debug_message("ioctl error, check if you set up iptables correctly: %s", strerror(errno));

		return;
	}


	
	conn.proxy_fd = connect_to_proxy(conn.dest_addr.sin_addr.s_addr, conn.dest_addr.sin_port);
	if (conn.proxy_fd == -1)
	{
		debug_message("Could not connect to destination");
		return;
	}

	/*
	 * This loop acts a bit like the guy in the middle of a "bucket brigade".
	 * When the client passes some data, it gets handed off to the server,
	 * and vise-versa. However for data received from the client, it is
	 * buffered until a full request is received. 
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
				syslog(LOG_ERR, "select(): %m");
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
				if (errno != ECONNRESET)
					syslog(LOG_WARNING, "read(client) failed: %m");

				close(conn.proxy_fd);
				return;

			case 0:
				close(conn.proxy_fd);
				return;

			default:
				/*
				 * If new session just started
				 */
				if (!session->time) 
				{
					debug_message("Session is not active");

					char	*host = NULL;
					int		host_length = 0;
					char	*url = NULL;
					int		url_length = 0;

					char temp[256];

					int	is_whitelisted = 0;

					/*
					 * Analyzing only GET-requests
					 */
					if (conn.request_buffer == strstr(conn.request_buffer, "GET ")) {
						host = strstr(conn.request_buffer, "Host: ");
						if (host) {
							host += 6;
							host_length = strchr(host, '\r') - host;

							url = conn.request_buffer + 4;
							url_length = strstr(url, " HTTP/1.") - url;

							if (url_length >= 0) {
								/*
								 * Session trigger URL requested
								 */
								if ((strlen(trigger_host) == host_length && !memcmp(trigger_host, host, host_length)) &&
									(strlen(trigger_url) == url_length && !memcmp(trigger_url, url, url_length))) 
								{
									session->time = time(NULL);
									debug_message("Trigger URL requested: %.*s", url_length, url);
								}
								else 
								{
									/*
									 * check if some whitelisted domain was requested
									 */
									memset(temp, 0, sizeof(temp));

									char *comma;
									int l = strlen(domains_whitelist);
									char *first = domains_whitelist;
									do 
									{
										comma = strchr(first, ',');

										if (NULL == comma)
											comma = domains_whitelist + l;

										if (host_length == comma - first && !memcmp(host, first, host_length)) {
											debug_message("Target host is whitelisted: %.*s", host_length, host);
											is_whitelisted = 1;
											break;
										}

										first = comma + 1;
									} while (first < domains_whitelist + l);
								}
							}
						}
					}

					/*
					 * Forcing default hotspot URL
					 */
					if (!is_whitelisted) {
						debug_message("Forcing hotspot URL: http://%s/%s", trigger_host, trigger_url);
						close(conn.proxy_fd);
						send_data(conn.client_fd, redirect_buffer, strlen(redirect_buffer));
						return;
					}

				}

				/*
				 * Process requests read from the client. Returns 0 if a
				 * processed request could not be written to the proxy.
				 */
				if (!process_client_request(&conn, length))
				{
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
	syslog(LOG_NOTICE, "Alarm signal caught - connection timeout");
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

	syslog(LOG_NOTICE, "Termination signal caught - exiting");
	exit(1);
}

static char* get_interface_name(int sock, ip_address_t * bind_ip)
{
	struct ifaddrs *addrs, *iap;
	struct sockaddr_in *sa;
	char buf[32];
	char *result = NULL;

	getifaddrs(&addrs);
	for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) 
		{
			sa = (struct sockaddr_in *)(iap->ifa_addr);
			inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
			if (!strcmp(inet_ntoa(* (struct in_addr *) bind_ip), buf)) 
			{
				result = malloc(sizeof(iap->ifa_name));
				strcpy(result, iap->ifa_name);
			}
		}
	}
	freeifaddrs(addrs);
	return result;
}

void debug_message(char *message, ...)
{
	if (debug_enabled) {
		va_list args;
		va_start(args, message);

		vprintf(message, args);
		printf("\n");

		va_end(args);
	}
}
