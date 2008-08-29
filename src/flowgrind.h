#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fg_time.h"

#define	MAX_FLOWS		256
#define CONGESTION_LIMIT 	10000
#define DEFAULT_SELECT_TIMEOUT	10000

struct timeval now;
char sigint_caught = 0;

fd_set rfds, wfds, efds, efds_orig;
FILE *log_stream = NULL;
char *log_filename = NULL;
int maxfd = 0;
int active_flows = 0;
unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;

unsigned int client_port, server_port;
unsigned int packet_size;
unsigned int protocol_rate;
int tcp_sock, udp_sock;
uint64_t npackets;
struct sockaddr *server = NULL;
socklen_t server_len;

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
	unsigned send_buffer_size;
	unsigned send_buffer_size_real;

	/* SO_RCVBUF */
	unsigned receive_buffer_size;
	unsigned receive_buffer_size_real;

	double flow_duration;
	double flow_delay;
	struct timeval flow_start_timestamp;
	struct timeval flow_stop_timestamp;
	char flow_finished;

	// For one endpoint this is the write block size.
	// The corresponding read block size is the other endpoint's
	// block size
	unsigned block_size;

	char *rate_str;
	unsigned rate;
	char poisson_distributed;

	char route_record;
};

struct _flow {
	char *server_name;
	char *server_name_control;
	unsigned server_control_port;
	unsigned server_data_port;

	int sock;
	int sock_control;
	struct sockaddr *saddr;
	socklen_t saddr_len;

	enum protocol proto;

	int mss;
	int mtu;

	/* here we use current_mss and current_mtu to store the most current
	   values of get_mss and get_mtu. The problem encountered was that at the
	   very end when guess_topology was called get_mss and get_mtu returned
	   some bogus value because the call to getsockopt failed.
	*/
	int current_mss;
	int current_mtu;

	char *cc_alg;
	int elcn;
	int icmp;
	int ipmtudiscover; //1 - set, 0 - option not set
	char cork;
	char so_debug;
	uint8_t dscp;
	char pushy;
	char late_connect;
	char connect_called;
	char shutdown;
	char summarize_only;
	char two_way;
	char flow_control;
	char byte_counting;

	unsigned write_errors;
	unsigned read_errors;

	char *read_block;
	unsigned read_block_bytes_read;
	uint64_t read_block_count;
	struct timeval last_block_read;

	char *write_block;
	unsigned write_block_bytes_written;
	uint64_t write_block_count;
	struct timeval last_block_written;
	struct timeval next_write_block_timestamp;
	unsigned congestion_counter;
	char reply_block[sizeof(struct timeval) + sizeof(double)];
	unsigned reply_block_bytes_read;

	char stopped;
	char closed;
	struct timeval stopped_timestamp;

	struct timeval initial_server_clock;

#ifdef __LINUX__
	char final_cc_alg[30];
	struct tcp_info last_tcp_info;
	struct tcp_info final_tcp_info;
#endif

	long bytes_read_since_first;
	long bytes_read_since_last;

	long bytes_written_since_first;
	long bytes_written_since_last;

	double min_rtt_since_first;
	double min_rtt_since_last;
	double max_rtt_since_first;
	double max_rtt_since_last;
	double tot_rtt_since_first;
	double tot_rtt_since_last;

	double min_iat_since_first;
	double min_iat_since_last;
	double max_iat_since_first;
	double max_iat_since_last;
	double tot_iat_since_first;
	double tot_iat_since_last;

	// 0 for source
	// 1 for destination
	struct _flow_endpoint endpoint_options[2];
};
struct _flow flow[MAX_FLOWS];

struct {
	struct timeval start;
	struct timeval next;
	struct timeval last;
} timer;

void report_flow(int id);
char *guess_topology (int mss, int mtu);
void close_flow(int id);
void stop_flow(int id);

static int server_flow_in_delay(int id)
{
	return time_is_after(&flow[id].endpoint_options[1].flow_start_timestamp, &now);
}

static int client_flow_in_delay(int id)
{
	return time_is_after(&flow[id].endpoint_options[0].flow_start_timestamp, &now);
}

static int server_flow_sending(int id)
{
	return !server_flow_in_delay(id) &&
		(flow[id].endpoint_options[1].flow_duration < 0 ||
		 time_diff(&flow[id].endpoint_options[1].flow_stop_timestamp, &now) < 0.0);

}

static int client_flow_sending(int id)
{
	return !client_flow_in_delay(id) && (flow[id].endpoint_options[0].flow_duration < 0
		 || time_diff(&flow[id].endpoint_options[0].flow_stop_timestamp, &now) < 0);
}

static int client_flow_block_scheduled(int id)
{
	return !flow[id].endpoint_options[0].rate ||
		time_is_after(&now, &flow[id].next_write_block_timestamp);
}


inline static double scale_thruput(double thruput)
{
	if (opt.mbyte)
		return thruput / (1<<20);
	return thruput / 1e6 *(1<<3);
}
#endif
