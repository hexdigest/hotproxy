Introduction
------------

This program is used in conjunction with the Linux iptables or FreeBSD (ipfw and ipnat) to transparently proxy HTTP requests. It's based on a transproxy source code (ftp://ftp.nlc.net.au/pub/unix/transproxy/).


How Is It Used?
---------------

If you want to make a WiFi hotspot that is intended to redirect users to some web page before letting them go to the requested page this program is what you need. It should run nomally on simple WiFi routers with OpenWRT installed. I plan to create a special package for OpenWRT.


How Do I Build It?
------------------

Just type 'make'. No configuration in the source is needed. It's written in ANSI C.

How Do I Install It?
--------------------

Just type 'make install' to install the binary.

Find a place to add the server startup to, /etc/rc.d/rc.local
or something similar. Add a line like the following to this
file.

	hotproxy -p 3128 -u nobody -h 127.0.0.1

This tells the transparent proxy server to bind to port 3128.

Linux Iptables Config
----------------------------------------

To make HTTP requests get proxied transparently, iptables filter rules must be put in place to pass HTTP requests to the proxy that would normally pass through to the outside world. 

Make sure that client devices are in the same network otherwise hotproxy
won't be able to get client MAC addresses to start the session.

Also the Linux kernel must be compiled with the TRANSPARENT_PROXY feature enabled.

If you run hotproxy on your router then you can set your iptables like this:

	iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128

We assume that eth0 is the interface where client's requests are comming to.

Otherwise, if you have hotproxy and router running on different machines:

	iptables -t nat -A PREROUTING -i eth0 -s ! hotproxy-host -p tcp --dport 80 -j DNAT --to hotproxy-host:3128
	iptables -t nat -A POSTROUTING -o eth0 -s local-network -d hotproxy-host -j SNAT --to router-host
	iptables -A FORWARD -s local-network -d hotproxy-host -i eth0 -o eth0 -p tcp --dport 3128 -j ACCEPT	

where:
* hotproxy-host is the ip address of the host where hotproxy is running (your router)
* local-network - IP range of your local network
* router-host - your router IP address

Who Am I?
---------

My name is Maxim Chechel <maximchick@gmail.com> I'm a WEB/NFC/Ruby developer.
Please feel free to contact me.
