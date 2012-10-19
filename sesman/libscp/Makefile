# libscp makefile
LIBSCPOBJ = libscp_vX.o libscp_v0.o \
	    libscp_v1s.o libscp_v1c.o \
	    libscp_init.o libscp_lock.o libscp_tcp.o \
	    os_calls.o

DESTDIR = /usr/local/xrdp
CFGDIR = /etc/xrdp
PIDDIR = /var/run
MANDIR = /usr/local/man
DOCDIR = /usr/doc/xrdp

DESTDIRDEB = /tmp

LIBSCPLNAME = libscp.so

DEFINES = -DSESMAN_CFG_FILE=\"$(CFGDIR)/sesman.ini\" \
	  -DSESMAN_PID_FILE=\"$(PIDDIR)/sesman.pid\" \
	  -DSESMAN_SESSVC_FILE=\"sessvc\"

CFLAGS = -Wall -O2 -I../../common -I/usr/include/nptl -fPIC $(DEFINES)
LDFLAGS = -shared -L/usr/gnu/lib -L/usr/lib/nptl -lpthread
C_OS_FLAGS = $(CFLAGS) -c
CC = gcc

all: $(LIBSCPOBJ)
	$(CC) $(LDFLAGS) -o $(LIBSCPLNAME) $(LIBSCPOBJ)

clean:
	rm -f $(LIBSCPOBJ) $(LIBSCPLNAME)

install:
	install $(LIBSCPLNAME) $(DESTDIR)/$(LIBSCPLNAME)

installdeb:
	install $(LIBSCPLNAME) $(DESTDIRDEB)/usr/lib/xrdp/$(LIBSCPLNAME)

os_calls.o: ../../common/os_calls.c
	$(CC) $(C_OS_FLAGS) ../../common/os_calls.c
