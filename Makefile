# vim:ai ts=8 sw=8
#
#	Makefile for hotproxy.
#

#LIBS    += -lwrap

# You may need to touch PREFIX, CC and CFLAGS.
PREFIX = /usr/local
INSTALL_PROGRAM = install -c -m 555 -o bin -g bin
INSTALL_MAN = install -c -m 444 -o bin -g bin

# Some make's don't define this.
RM      = rm -f

# Should be OK for GNU gcc.
CC      = gcc
CFLAGS  = -g -O2 -Wall
LDFLAGS = -s

# For using BIND resolver instead of system resolver.
#LIBS    += -lresolv	# Really old Linux has this.
#LIBS    += -lbind

# You shouldn't need to touch anything below this.
all:		hotproxy

hotproxy:		hotproxy.o
	$(CC) $(LDFLAGS) hotproxy.o -o $@ $(LIBS)

hotproxy.o:	hotproxy.c Makefile
	$(CC) $(CFLAGS) $(OPTIONS) -c hotproxy.c -o $@

clean:
	$(RM) hotproxy.o *core *~

clobber dist-clean:	clean
	$(RM) hotproxy

install:	hotproxy
	$(INSTALL_PROGRAM) hotproxy $(PREFIX)/sbin
	$(INSTALL_PROGRAM) hotproxyrun $(PREFIX)/sbin
	$(INSTALL_PROGRAM) hotproxywatch $(PREFIX)/sbin
