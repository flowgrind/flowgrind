#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
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

#define DEFAULT_LISTEN_PORT     5999

#define ERR_FATAL       0
#define ERR_WARNING     1

#define ASSIGN_MIN(s, c) if ((s)>(c)) (s) = (c)
#define ASSIGN_MAX(s, c) if ((s)<(c)) (s) = (c)

void error(int errcode, const char *fmt, ...);

#define WRITE 0
#define READ 1

#define INTERVAL 0
#define TOTAL 1

#define MAX_EXTRA_SOCKET_OPTIONS 10
#define MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH 100

#define MAX_FLOWS              2048

enum _extra_socket_option_level
{
	level_sol_socket,
	level_sol_tcp,
	level_ipproto_ip,
	level_ipproto_sctp,
	level_ipproto_tcp,
	level_ipproto_udp
};

/*
 * our data block has the following layout:
 *
 * this_block_size (int32_t), request_block_size (int32_t), data (timeval), trail
 *
 * this_block_size:     the size of our request or response block (we generate
 *                      a request block here)
 *
 * request_block_size:  the size of the response block we request
 *                      0 if we dont request a response block
 *                     -1 indicates this is a response block (needed for parsing data)
 *
 * data                 RTT data if this is a response block
 *
 * trail:               trailing garbage to fill up the blocksize (not used)
 */

#define MIN_BLOCK_SIZE (signed) sizeof (struct _block)
struct _block
{
	int32_t this_block_size;
	int32_t request_block_size;
	struct timeval data;
	struct timeval data2; /* used to access 64bit timeval on 32bit arch */
};

enum _stochastic_distributions
{
	CONSTANT='0',
	NORMAL,
	WEIBULL,
	UNIFORM,
	EXPONENTIAL,
	PARETO,
	LOGNORMAL
};

struct _trafgen_options
{
	enum _stochastic_distributions distribution;
	double param_one;
	double param_two;

};

/* Common to both endpoints */
struct _flow_settings
{
	char bind_address[1000];

	double delay[2];
	double duration[2];

	double reporting_interval;

	int requested_send_buffer_size;
	int requested_read_buffer_size;

	int maximum_block_size;

	int traffic_dump;
	int so_debug;
	int route_record;
	int pushy;
	int shutdown;

	int write_rate;
	unsigned int random_seed;

	int flow_control;

	int byte_counting;

	int cork;
	int nonagle;
	char cc_alg[256];
	int elcn;
	int lcd;
	int mtcp;
	int dscp;
	int ipmtudiscover;

	struct _trafgen_options request_trafgen_options;
	struct _trafgen_options response_trafgen_options;
	struct _trafgen_options interpacket_gap_trafgen_options;

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
#ifdef HAVE_UNSIGNED_LONG_LONG_INT
	unsigned long long bytes_read;
	unsigned long long bytes_written;
#else
	long bytes_read;
	long bytes_written;
#endif
	unsigned int request_blocks_read;
	unsigned int request_blocks_written;
	unsigned int response_blocks_read;
	unsigned int response_blocks_written;

	double rtt_min, rtt_max, rtt_sum;
	double iat_min, iat_max, iat_sum;

#ifdef __LINUX__
	struct tcp_info tcp_info;
#endif
	int pmtu;
	int imtu;

	int status;

	struct _report* next;
};

#endif
