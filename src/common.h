#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_FASTTIME_H
#include <fasttime.h>
#endif

#ifdef HAVE_TSCI2_H
#include <tsci2.h>
#endif

#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define UNUSED_ARGUMENT(x) (void)x

#include "svnversion.h"

#ifdef SVNVERSION
#define FLOWGRIND_VERSION SVNVERSION
#elif defined PACKAGE_VERSION
#define FLOWGRIND_VERSION PACKAGE_VERSION
#else
#define FLOWGRIND_VERSION "(n/a)"
#endif

#define DEFAULT_LISTEN_PORT	5999

#define ERR_FATAL	0
#define ERR_WARNING	1

#define ASSIGN_MIN(s, c) if ((s)>(c)) (s) = (c)
#define ASSIGN_MAX(s, c) if ((s)<(c)) (s) = (c)

void error(int errcode, const char *fmt, ...);

#define WRITE 0
#define READ 1

#define INTERVAL 0
#define TOTAL 1

#define MAX_EXTRA_SOCKET_OPTIONS 10
#define MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH 100

enum _extra_socket_option_level
{
	level_sol_socket,
	level_sol_tcp,
	level_ipproto_ip,
	level_ipproto_sctp,
	level_ipproto_tcp,
	level_ipproto_udp
};

enum _traffic_generation_types
{
	CONSTANT=0,
	POISSON,
	WEIBULL,
};

/* Common to both endpoints */
struct _flow_settings
{
	char bind_address[1000];

	double delay[2];
	double duration[2];

	double reporting_interval;
	double interleave_time;

	int requested_send_buffer_size;
	int requested_read_buffer_size;

	int default_request_block_size;
	int default_response_block_size;

	int advstats;
	int so_debug;
	int route_record;
	int pushy;
	int shutdown;

	int write_rate;
	enum _traffic_generation_types traffic_generation_type;
	double traffic_generation_parm_alpha;
	double traffic_generation_parm_beta;
	int random_seed;

	int flow_control;

	int byte_counting;

	int cork;
	char cc_alg[256];
	int elcn;
	int icmp;
	int dscp;
	int ipmtudiscover;

	struct _extra_socket_options {
		int level;
		int optname;
		int optlen;
		char optval[MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH];
	} extra_socket_options[MAX_EXTRA_SOCKET_OPTIONS];
	int num_extra_socket_options;
};


struct _report
{
	int id;
	int type; /* INTERVAL or TOTAL */
	struct timeval begin;
	struct timeval end;

	long long bytes_read;
	long long bytes_written;

	long request_blocks_read;
	long request_blocks_written;
	long response_blocks_read;
	long response_blocks_written;

	double rtt_min, rtt_max, rtt_sum;
	double iat_min, iat_max, iat_sum;

#ifdef __LINUX__
	struct tcp_info tcp_info;
#endif
	int mss;
	int mtu;

	/* Flow status.as displayed in comment column */
	int status;

	struct _report* next;
};

#endif
