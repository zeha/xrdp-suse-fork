# sesman tools makefile
SESTESTOBJ = sestest.o \
	     os_calls.o

SESRUNOBJ = sesrun.o config.o tcp.o \
	    os_calls.o d3des.o list.o file.o log.o

DESTDIR = /usr/local/xrdp
CFGDIR = /etc/xrdp
PIDDIR = /var/run
MANDIR = /usr/local/man
DOCDIR = /usr/doc/xrdp

DEFINES = -DLIBSCP_CLIENT

CFLAGS = -Wall -O2 -I../../common -I../ -I/usr/include/nptl -I../libscp $(DEFINES)
LDFLAGS = -L/usr/gnu/lib -L/usr/lib/nptl -L../libscp -Wl,-rpath,. -lpthread -ldl -lscp
C_OS_FLAGS = $(CFLAGS) -c
CC = gcc

all: stest srun

stest: $(SESTESTOBJ)
	$(CC) $(LDFLAGS) -o sestest $(SESTESTOBJ)

srun: $(SESRUNOBJ)
	$(CC) $(LDFLAGS) -o sesrun $(SESRUNOBJ)

os_calls.o: ../../common/os_calls.c
	$(CC) $(C_OS_FLAGS) ../../common/os_calls.c

list.o: ../../common/list.c
	$(CC) $(C_OS_FLAGS) ../../common/list.c

file.o: ../../common/file.c
	$(CC) $(C_OS_FLAGS) ../../common/file.c

log.o: ../../common/log.c
	$(CC) $(C_OS_FLAGS) ../../common/log.c

d3des.o: ../../common/d3des.c
	$(CC) $(C_OS_FLAGS) ../../common/d3des.c

config.o: ../config.c
	$(CC) $(C_OS_FLAGS) ../config.c

clean:
	rm -f *.o sestest sesrun

install:
	install sesrun $(DESTDIR)/sesrun
	install sestest $(DESTDIR)/sestest

installdeb:
	install sesrun $(DESTDIRDEB)/usr/lib/xrdp/sesrun
	install sestest $(DESTDIRDEB)/usr/lib/xrdp/sestest
