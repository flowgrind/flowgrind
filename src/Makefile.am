AM_CFLAGS = -Wall -D_GNU_SOURCE -DDEBUG -g -save-temps
dist_bin_SCRIPTS = flow_plotter
bin_PROGRAMS = flowgrind
sbin_PROGRAMS = flowgrindd
flowgrind_SOURCES = common.c debug.c fg_socket.c fg_time.c flowgrind.c
flowgrindd_SOURCES = common.c debug.c fg_pcap.c fg_socket.c \
		     fg_time.c log.c flowgrindd.c
flowgrindd_LDFLAGS = -lpcap
