AM_CFLAGS = -Wall -Wextra -Werror=implicit -std=gnu99 -fgnu89-inline 
AM_LDFLAGS = -Wl,--as-needed

bin_PROGRAMS = flowgrind flowgrind-stop
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = common.h debug.h

flowgrind_SOURCES = common.c debug.c fg_socket.c fg_time.c fg_math.h fg_math.c \
		    flowgrind.h flowgrind.c adt.c adt.h
flowgrind_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD) $(GSL_LDADD)
flowgrind_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XMLRPC_C_CLIENT_CFLAGS) $(GSL_CFLAGS)

flowgrindd_SOURCES = common.c daemon.h daemon.c debug.c destination.h destination.c \
                     fg_pcap.c fg_pcap.h fg_socket.c fg_socket.h fg_time.c flowgrindd.c log.h log.c \
                     source.h source.c fg_math.h fg_math.c trafgen.h trafgen.c
flowgrindd_LDADD = $(LIBS) $(XMLRPC_C_SERVER_LDADD) $(PCAP_LDADD) $(GSL_LDADD)
flowgrindd_CFLAGS = $(AM_CFLAGS) $(PCAP_CFLAGS) $(XMLRPC_C_SERVER_CFLAGS) $(GSL_CFLAGS)

flowgrind_stop_SOURCES = flowgrind_stop.c
flowgrind_stop_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD)
flowgrind_stop_CFLAGS = $(AM_CFLAGS) $(CURL_FLAGS) $(XMLRPC_C_CLIENT_CFLAGS) 
