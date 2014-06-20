CLEANFILES = gitversion.h doc/doxyfile.stamp
CLEAN_LOCAL_FILES = doc/html doc/latex doc/html.timestamp
MR_PROPER_FILES = Makefile.in aclocal.m4 build-aux config.h.in config.h.in~ \
				  configure

BUILT_SOURCES = gitversion.h

bin_PROGRAMS = flowgrind flowgrind-stop
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = src/common.h src/debug.h

dist_man1_MANS = man/flowgrind.1 \
				 man/flowgrindd.1 \
				 man/flowgrind-stop.1

AM_CFLAGS = -Wall -Wextra -Werror=implicit -std=gnu99 -fgnu89-inline

# flowgrind controller
flowgrind_SOURCES = src/common.h src/debug.c src/fg_error.h src/fg_error.c \
					src/fg_progname.h src/fg_progname.c src/fg_socket.h \
					src/fg_socket.c src/fg_string.h src/fg_string.c \
					src/fg_stdlib.h src/fg_time.h src/fg_time.c \
					src/flowgrind.h src/flowgrind.c src/fg_argparser.h \
					src/fg_argparser.c
flowgrind_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD) $(GSL_LDADD)
flowgrind_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XMLRPC_C_CLIENT_CFLAGS) $(GSL_CFLAGS)

# flowgrind daemon
flowgrindd_SOURCES = src/common.h src/daemon.h src/daemon.c src/debug.c \
					 src/destination.h src/destination.c src/fg_error.h \
					 src/fg_error.c src/fg_math.h src/fg_math.c \
					 src/fg_progname.h src/fg_progname.c src/fg_socket.c \
					 src/fg_socket.h src/fg_string.h src/fg_string.c \
					 src/fg_time.c src/flowgrindd.c src/log.h src/log.c \
					 src/source.h src/source.c src/trafgen.h src/trafgen.c \
                     src/fg_argparser.h src/fg_argparser.c
flowgrindd_LDADD = $(LIBS) $(XMLRPC_C_SERVER_LDADD) $(GSL_LDADD)
flowgrindd_CFLAGS = $(AM_CFLAGS) $(XMLRPC_C_SERVER_CFLAGS) $(GSL_CFLAGS)

# flowgrind-stop
flowgrind_stop_SOURCES = src/fg_error.h src/fg_error.c src/fg_progname.h \
						 src/fg_progname.c src/flowgrind_stop.c \
						 src/fg_argparser.h src/fg_argparser.c
flowgrind_stop_LDADD = $(LIBS) $(CURL_LDADD) $(XMLRPC_C_CLIENT_LDADD)
flowgrind_stop_CFLAGS = $(AM_CFLAGS) $(CURL_FLAGS) $(XMLRPC_C_CLIENT_CFLAGS)

# configured w/ pcap
if USE_LIBPCAP
flowgrindd_SOURCES += src/fg_pcap.h src/fg_pcap.c
flowgrindd_LDADD += $(PCAP_LDADD)
flowgrindd_CFLAGS += $(PCAP_CFLAGS)
endif

# system has no clock_gettime
if ! CLOCK_GETTIME
flowgrind_SOURCES += src/fg_gettime.h src/fg_gettime.c
flowgrindd_SOURCES += src/fg_gettime.h src/fg_gettime.c
endif

.PHONY: gitversion.h mrproper html.timestamp clean-local

gitversion.h:
	$(shellL) ./scripts/make-version.sh

mrproper: maintainer-clean
	-rm -rf $(MR_PROPER_FILES)

# configured w/ doxygen
if USE_DOXYGEN
html: html.timestamp

html.timestamp:
	$(DOXYGEN) doc/Doxyfile
	touch doc/$@

clean-local:
	-rm -rf $(CLEAN_LOCAL_FILES)
endif

