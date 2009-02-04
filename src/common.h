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

/* Common to both endpoints */
struct _flow_settings
{
	char bind_address[1000];

	double delay[2];
	double duration[2];

	double reporting_interval;

	int requested_send_buffer_size;
	int requested_read_buffer_size;

	int write_block_size;
	int read_block_size;

	int advstats;
	int so_debug;
	int route_record;
	int pushy;
	int shutdown;

	int write_rate;
	int poisson_distributed;
	int flow_control;

	int byte_counting;

	int cork;
	char cc_alg[256];
	int elcn;
	int icmp;
	int dscp;
	int ipmtudiscover;
};

struct _flow_source_settings
{
	char destination_host[256];
	char destination_host_reply[256];
	int destination_port;
	int destination_port_reply;

	int late_connect;

	pthread_cond_t* add_source_condition;
};

#define REQUEST_ADD_DESTINATION 0
#define REQUEST_ADD_SOURCE 1
#define REQUEST_START_FLOWS 2
#define REQUEST_STOP_FLOW 3
#define REQUEST_GET_STATUS 4
struct _request
{
	char type;

	/* We signal this condition once the daemon thread
	 * has processed the request */
	pthread_cond_t* condition;

	char* error;

	struct _request *next;
};
extern struct _request *requests, *requests_last;

struct _request_add_flow_destination
{
	struct _request r;

	struct _flow_settings settings;

	/* The request reply */
	int flow_id;
	int listen_data_port;
	int listen_reply_port;
	int real_listen_send_buffer_size;
	int real_listen_read_buffer_size;
};

struct _request_add_flow_source
{
	struct _request r;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	/* The request reply */
	char cc_alg[256];
	int flow_id;
};

struct _request_start_flows
{
	struct _request r;

	int start_timestamp;
};

struct _request_stop_flow
{
	struct _request r;

	int flow_id;
};

struct _request_get_status
{
	struct _request r;

	int started;
	int num_flows;
};

struct _report
{
	int id;
	int type; /* INTERVAL or TOTAL */
	struct timeval begin;
	struct timeval end;

	long long bytes_read;
	long long bytes_written;
	int reply_blocks_read;

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
