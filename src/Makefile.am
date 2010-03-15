AM_CFLAGS = -Wall -Wextra -std=c99  -fgnu89-inline -D_GNU_SOURCE 
bin_PROGRAMS = flowgrind flowgrind-stop
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = acl.h adt.h common.h debug.h fg_pcap.h fg_socket.h fg_time.h

flowgrind_SOURCES = common.c debug.c fg_socket.c fg_time.c flowgrind.h flowgrind.c adt.c
flowgrind_LDADD = $(XMLRPC_C_CLIENT_LDADD)

flowgrindd_SOURCES = acl.c acl.h common.c daemon.c daemon.h debug.c \
	destination.c destination.h fg_pcap.c fg_socket.c fg_time.c flowgrindd.c log.c log.h \
	source.h source.c

flowgrindd_LDADD = $(XMLRPC_C_SERVER_LDADD)
flowgrindd_LDADD += $(PCAP_LIBS)
flowgrindd_CFLAGS = $(AM_CFLAGS) $(XMLRPC_C_SERVER_CFLAGS)

flowgrind_stop_SOURCES = flowgrind_stop.c
flowgrind_stop_LDADD= $(XMLRPC_C_CLIENT_LDADD)
