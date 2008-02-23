#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#ifdef __LINUX__
#include <linux/tcp.h>
#else
#include <netinet/tcp.h>
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

struct {
	char *server_name;		
	char *server_name_control;
	unsigned server_control_port;			
	unsigned server_data_port;

	int sock;		
	int sock_control;
	struct sockaddr *saddr;
	socklen_t saddr_len;

	enum protocol proto;

	unsigned mss;
	int mtu;
		
	unsigned client_window_size;
	unsigned client_window_size_real;
	unsigned server_window_size;
	unsigned server_window_size_real;
	char *cc_alg;			/* Congestion algorithm to use with TCP flows */	
	int elcn;			/* Flag to use TCP_ELCN */
	int icmp;			/* Flag to use TCP_ICMP */
	char cork;			/* Flag to use TCP_CORK */
	char so_debug;
	uint8_t dscp;			/* DSCP: 6 bit field */
	char pushy;			/* Do not iterate through next select to continue sending */
	char route_record;
	char late_connect;
	char connect_called;
	char shutdown;
	char summarize_only;
	char two_way;
	char *rate_str;
	unsigned rate;
	char poisson_distributed;
	char flow_control;
	char byte_counting;

	unsigned write_errors;		
	unsigned read_errors;	

	char *read_block;
	unsigned read_block_size;
	unsigned read_block_bytes_read;
	uint64_t read_block_count;
	struct timeval last_block_read;

	char *write_block;
	unsigned write_block_size;
	unsigned write_block_bytes_written;
	uint64_t write_block_count;
	struct timeval last_block_written;
	struct timeval next_write_block_timestamp;
	unsigned congestion_counter;
	char reply_block[sizeof(struct timeval) + sizeof(double)];
	unsigned reply_block_bytes_read;

	double client_flow_duration;
	double client_flow_delay;
	struct timeval client_flow_start_timestamp;
	struct timeval client_flow_stop_timestamp;
	char client_flow_finished;
	double server_flow_duration;
	double server_flow_delay;
	struct timeval server_flow_start_timestamp;
	struct timeval server_flow_stop_timestamp;
	char server_flow_finished;

	char stopped;
	char closed;
	struct timeval stopped_timestamp;

	struct timeval initial_server_clock;

#ifdef __LINUX__
	struct tcp_info last_tcp_info;
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
} flow[MAX_FLOWS];

struct {
	struct timeval start;
	struct timeval next;
	struct timeval last;
} timer;

void report_flow(int id);
char *guess_topology (unsigned mss, unsigned mtu);
void close_flow(int id);

inline static int server_flow_in_delay(int id)
{
	return time_is_after(&flow[id].server_flow_start_timestamp, &now);
}

inline static int client_flow_in_delay(int id)
{
	return time_is_after(&flow[id].client_flow_start_timestamp, &now);
}

inline static int server_flow_sending(int id)
{
	return !server_flow_in_delay(id) && 
		(flow[id].server_flow_duration < 0 || 
		 time_diff(&flow[id].server_flow_stop_timestamp, &now) 
		 + flow[id].max_rtt_since_first < 0);
	/* XXX: This relies on the RTT measurement from the _client_
	 * flow which does not necessarily exist. */
}

inline static int client_flow_sending(int id)
{
	return !client_flow_in_delay(id) && (flow[id].client_flow_duration < 0
		 || time_diff(&flow[id].client_flow_stop_timestamp, &now) < 0);
}
	
inline static int client_flow_block_scheduled(int id)
{
	return !flow[id].rate || 
		time_is_after(&now, &flow[id].next_write_block_timestamp);
}


inline static double scale_thruput(double thruput)
{
	if (opt.mbyte)
		return thruput /= 1<<20;

	return thruput /= 1e6/(1<<3) ;
}
#endif 
