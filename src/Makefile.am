AM_CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE
dist_bin_SCRIPTS = flow_plotter
bin_PROGRAMS = flowgrind
sbin_PROGRAMS = flowgrindd
noinst_HEADERS = common.h debug.h fg_time.h fg_pcap.h fg_socket.h 
flowgrind_SOURCES = common.c debug.c fg_socket.c fg_time.c flowgrind.h flowgrind.c
flowgrindd_SOURCES = common.c debug.c fg_pcap.c fg_socket.c \
		     fg_time.c log.h log.c flowgrindd.c
flowgrindd_LDFLAGS = -lpcap
