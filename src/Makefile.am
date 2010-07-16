AM_CFLAGS = -Wall -Wextra -std=gnu99 -D_GNU_SOURCE -fgnu89-inline 
bin_PROGRAMS = flowgrind flowgrind-stop
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = adt.h common.h debug.h fg_pcap.h fg_socket.h fg_time.h fg_math.h trafgen.h

flowgrind_SOURCES = common.c debug.c fg_socket.c fg_time.c fg_math.h fg_math.c \
		    flowgrind.h flowgrind.c adt.c
flowgrind_LDADD = $(XMLRPC_C_CLIENT_LDADD)

flowgrindd_SOURCES = common.c daemon.h daemon.c debug.c \
	destination.h destination.c fg_pcap.c fg_socket.c fg_time.c flowgrindd.c log.h log.c \
	source.h source.c fg_math.h fg_math.c trafgen.h trafgen.c

flowgrindd_LDADD = $(XMLRPC_C_SERVER_LDADD)
flowgrindd_LDADD += $(PCAP_LIBS)
flowgrindd_CFLAGS = $(AM_CFLAGS) $(XMLRPC_C_SERVER_CFLAGS)

flowgrind_stop_SOURCES = flowgrind_stop.c
flowgrind_stop_LDADD= $(XMLRPC_C_CLIENT_LDADD)
