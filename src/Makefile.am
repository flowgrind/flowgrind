AM_CFLAGS = -Wall -Wextra -Werror=implicit -std=gnu99 -fgnu89-inline

bin_PROGRAMS = flowgrind flowgrind-stop
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = common.h debug.h

flowgrind_SOURCES = common.h debug.c fg_error.h fg_error.c fg_progname.h \
					fg_progname.c fg_socket.h fg_socket.c fg_string.h \
					fg_string.c fg_stdlib.h fg_time.h fg_time.c flowgrind.h \
					flowgrind.c fg_argparser.h fg_argparser.c
flowgrind_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD) $(GSL_LDADD)
flowgrind_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XMLRPC_C_CLIENT_CFLAGS) $(GSL_CFLAGS)

flowgrindd_SOURCES = common.h daemon.h daemon.c debug.c destination.h \
					 destination.c fg_error.h fg_error.c fg_math.h fg_math.c \
					 fg_progname.h fg_progname.c fg_socket.c fg_socket.h \
					 fg_string.h fg_string.c fg_time.c  flowgrindd.c log.h \
					 log.c source.h  source.c trafgen.h trafgen.c \
					 fg_argparser.h fg_argparser.c
flowgrindd_LDADD = $(LIBS) $(XMLRPC_C_SERVER_LDADD) $(GSL_LDADD)
flowgrindd_CFLAGS = $(AM_CFLAGS) $(XMLRPC_C_SERVER_CFLAGS) $(GSL_CFLAGS)

if USE_LIBPCAP
    flowgrindd_SOURCES += fg_pcap.h fg_pcap.c
    flowgrindd_LDADD += $(PCAP_LDADD)
    flowgrindd_CFLAGS += $(PCAP_CFLAGS)
endif

flowgrind_stop_SOURCES = fg_error.h fg_error.c fg_progname.h fg_progname.c \
						 flowgrind_stop.c fg_argparser.h fg_argparser.c
flowgrind_stop_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD)
flowgrind_stop_CFLAGS = $(AM_CFLAGS) $(CURL_FLAGS) $(XMLRPC_C_CLIENT_CFLAGS)
