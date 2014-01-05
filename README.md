Introduction
------------

The program is used in conjunction with the Linux iptables or FreeBSD (ipfw and
ipnat) to transparently proxy HTTP requests. It's based on a transproxy source
code (ftp://ftp.nlc.net.au/pub/unix/transproxy/).


How Is It Used?
---------------

If you want to make a WiFi hotspot that should redirect users to some
page before letting them to watch requested page this program is what you need.
It should nomally run on simple wifi routers with OpenWRT installed.
I plan to create special package for OpenWRT.


How Do I Build It?
------------------

Just type 'make' no configuration in the source is needed. It's
written in ANSI C using the portable Berkeley sockets interface so
it should compile on 99.9% of machine without change.

How Do I Install It?
--------------------

Just type 'make install' to install the binary and man page. Then
choose either one of 'Inetd Installation' or 'Standalone Server'.

Find a place to add the server startup to, /etc/rc.d/rc.local
or something similar. Add a line like the following to this
file.

	hotproxy -p 3128 -u nobody -h 127.0.0.1

This tells the transparent proxy server to accept requests on port
81 and to pass these on to the host 'proxy' at port 8080.

Linux Iptables Config
----------------------------------------

To make HTTP requests get proxied transparently, ipfwadm, ipchains, or
iptables filter rules must be put in place to pass HTTP requests to the
proxy that would normally pass through to the outside world. Also the Linux
kernel must be compiled with the TRANSPARENT_PROXY feature enabled. You
only get asked about this feature if you have requested to be prompted
about EXPERIMENTAL things.

	iptables -t nat -A PREROUTING -p tcp -d localhost --dport 80 -j ACCEPT
	iptables -t nat -A PREROUTING -p tcp -d <ip of local network>/<bits-in-net> --dport 80 -j ACCEPT
	iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128

If no httpd is running on the local network you may want to
reject connections quickly instead of accepting them.

	iptables -t nat -A PREROUTING -p tcp -d localhost --dport 80 -j REJECT
	iptables -t nat -A PREROUTING -p tcp -d <ip of local network>/<bits-in-net> --dport 80 -j ACCEPT
	iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128

These rules allow port 80 requests direct at the local network to pass (or
get rejected). Then any requests to the outside world get redirected to
port 81 and hence get handled by the transparent proxy.

FreeBSD ipfw and ipnat Config
-----------------------------

I suggest you use ipfw.

add 2 filter entries like below:

	ipfw add 1000 allow tcp from <this-host> to any 80
	ipfw add 1010 fwd <your-proxy-server>,3128 tcp from any to any 80

Who Am I?
---------

My name is Maxim Chechel <maximchick@gmail.com> I'm a WEB/NFC/Ruby developer.
Please feel free to contact me.
