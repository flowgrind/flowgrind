#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fg_time.h"

#define	MAX_FLOWS		256
#define CONGESTION_LIMIT 	10000
#define DEFAULT_SELECT_TIMEOUT	10000

char sigint_caught = 0;

FILE *log_stream = NULL;
char *log_filename = NULL;
int active_flows = 0;
unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;

//Array for the dynamical output
//default show every parameter
//[0] := begin
//[1] := end
//[2] := throughput
//[3] := rtt
//[4] := iat
//[5] := linux kernel output
int visible_columns[6] = {1, 1, 1, 1, 1, 1};


//now we define the arrays to be used for anderson-darlington test
//naming convention: add _s or _r for sender and receiver respectively.
//use	t_ for throughput
//	r_ for average rtt
//	i_ for average IAT
// array_size will be the counter for the number of values inside the arrays
int array_size = 0;
#define MAXANDERSONSIZE 1000
double t_array_s[MAXANDERSONSIZE], r_array_s[MAXANDERSONSIZE], i_array_s[MAXANDERSONSIZE]
	, t_array_r[MAXANDERSONSIZE], r_array_r[MAXANDERSONSIZE], i_array_r[MAXANDERSONSIZE];

// these are the 2 parameters for the ADT test. If the user wants to test for
// Exponential only ADT1 will be used and will represent the mean if the user
// wants to test for the uniform then ADT1 is the lower bound and ADT2 the
// upper bound
double ADT1 = 0.05;
double ADT2 = 0.05;
int anderson_outbound = 0 ; // will become one if array_size> MAXANDERSONSIZE
int doAnderson = 0; // it will be 1 if we do the exponential test; it will be 2 if we do the uniform test

struct {
	unsigned short num_flows;
	double reporting_interval;
	char advstats;
	char dont_log_stdout;
	char dont_log_logfile;
	char *log_filename;
	char *log_filename_prefix;
	char clobber;
	char mbyte;
	unsigned short base_port;
} opt;

enum protocol {
	PROTO_TCP = 1,
	PROTO_UDP
};

enum endpoint {
	SOURCE = 0,
	DESTINATION
};

struct _flow_endpoint {
	/* Flow options only affecting source or destination*/

	/* SO_SNDBUF and SO_RCVBUF affect the size of the TCP window */

	/* SO_SNDBUF */
	unsigned send_buffer_size_real;

	/* SO_RCVBUF */
	unsigned receive_buffer_size_real;

	struct timeval flow_start_timestamp;
	struct timeval flow_stop_timestamp;
	char flow_finished;

	char *rate_str;

	char server_url[1000];
	char server_address[1000];
	unsigned server_port;
	char test_address[1000];
	char bind_address[1000];
};

struct _flow {

	enum protocol proto;

	char late_connect;
	char shutdown;
	char summarize_only;
	char byte_counting;

	int endpoint_id[2];

	struct timeval start_timestamp[2];

#ifdef __LINUX__
	int last_retrans[2];
#endif

	// 0 for source
	// 1 for destination
	struct _flow_endpoint endpoint_options[2];
	struct _flow_settings settings[2];

	char finished[2];
	struct _report *final_report[2];
};
struct _flow flow[MAX_FLOWS];

char *guess_topology (int mss, int mtu);
void close_flow(int id);

inline static double scale_thruput(double thruput)
{
	if (opt.mbyte)
		return thruput / (1<<20);
	return thruput / 1e6 *(1<<3);
}
#endif
