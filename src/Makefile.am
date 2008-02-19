AM_CFLAGS = -Wall -D_GNU_SOURCE -DDEBUG -g
dist_bin_SCRIPTS = flow_plotter
bin_PROGRAMS = flowgrind
sbin_PROGRAMS = flowgrindd
flowgrind_SOURCES = common.h common.c flowgrind.h flowgrind.c
flowgrindd_SOURCES = common.h common.c fg_pcap.h fg_pcap.c log.h log.c flowgrindd.c
flowgrindd_LDFLAGS = -lpcap
