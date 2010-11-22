#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "common.h"
#include "fg_time.h"
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>


#define MAX_FLOWS               256
#define CONGESTION_LIMIT        10000
#define DEFAULT_SELECT_TIMEOUT  10000

struct _opt {
	unsigned short num_flows;
	double reporting_interval;
	char dont_log_stdout;
	char dont_log_logfile;
	char *log_filename;
	char *log_filename_prefix;
	char clobber;
	char mbyte;
	char symbolic;
	char doAnderson;
	unsigned short base_port;
};
extern struct _opt opt;

enum protocol {
	PROTO_TCP = 1,
	PROTO_UDP
};

enum endpoint {
	SOURCE = 0,
	DESTINATION
};

struct _flow_endpoint {
	/* Flow options only affecting source or destination
	 * SO_SNDBUF and SO_RCVBUF affect the size of the TCP window */

	/* SO_SNDBUF */
	int send_buffer_size_real;

	/* SO_RCVBUF */
	int receive_buffer_size_real;

	struct timeval flow_start_timestamp;
	struct timeval flow_stop_timestamp;

	char *rate_str;

	char server_url[1000];
	char server_address[1000];
	unsigned short server_port;
	char test_address[1000];
	char bind_address[1000];
};

struct _flow {

	enum protocol proto;

	char late_connect;
	char shutdown;
	char summarize_only;
	char byte_counting;

	unsigned int random_seed;

	int endpoint_id[2];

	struct timeval start_timestamp[2];

	// 0 for source
	// 1 for destination
	struct _flow_endpoint endpoint_options[2];
	struct _flow_settings settings[2];

	char finished[2];
	struct _report *final_report[2];
};

char *guess_topology (int mtu);

inline static double scale_thruput(double thruput)
{
	if (opt.mbyte)
		return thruput / (1<<20);
	return thruput / 1e6 *(1<<3);
}

#endif
