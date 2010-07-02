#ifndef __DAEMON_H__
#define __DAEMON_H__

#include "common.h"

void *daemon_main(void* ptr);

pthread_t daemon_thread;

/* Through this pipe we wakeup the thread from select */
extern int daemon_pipe[2];

extern pthread_mutex_t mutex;

enum flow_endpoint
{
	SOURCE,
	DESTINATION,
};

enum flow_state
{
        /* SOURCE */
        GRIND_WAIT_CONNECT,

        /* DESTINATION */
        GRIND_WAIT_ACCEPT,

	/* RUN */
	GRIND
};

struct _flow_source_settings
{
	char destination_host[256];
	int destination_port;

	int late_connect;

	pthread_cond_t* add_source_condition;
};

struct _flow
{
	int id;

	enum flow_state state;
	enum flow_endpoint endpoint;

	int fd;
	int listenfd_data;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct timeval start_timestamp[2];
	struct timeval stop_timestamp[2];
	struct timeval last_block_read;
	struct timeval last_block_written;

	struct timeval first_report_time;
	struct timeval last_report_time;
	struct timeval next_report_time;

	struct timeval next_write_block_timestamp;

	char *read_block;
	char *write_block;

	unsigned int current_write_block_size;
	unsigned int current_read_block_size;

	unsigned int current_block_bytes_read;
	unsigned int current_block_bytes_written;

	unsigned short requested_server_test_port;

	unsigned real_listen_send_buffer_size;
	unsigned real_listen_receive_buffer_size;

	char connect_called;
	char finished[2];

	int mss;
	int mtu;

	unsigned congestion_counter;

	/* Used for late_connect */
	struct sockaddr *addr;
	socklen_t addr_len;

	struct _statistics {
		long long bytes_read;
		long long bytes_written;

		int request_blocks_read;
		int request_blocks_written;
		int response_blocks_read;
		int response_blocks_written;

		double iat_min, iat_max, iat_sum;
		double rtt_min, rtt_max, rtt_sum;

#ifdef __LINUX__
		int has_tcp_info;
		struct tcp_info tcp_info;
#endif

	} statistics[2];

	char* error;
};

#define	MAX_FLOWS	256

extern struct _flow flows[MAX_FLOWS];
extern unsigned int num_flows;

extern struct _report* reports;
extern struct _report* reports_last;
extern unsigned int pending_reports;

void add_report(struct _report* report);

/* Gets 50 reports. There may be more pending but there's a limit on how
 * large a reply can get */
struct _report* get_reports(int *has_more);

extern char started;

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
	int real_listen_send_buffer_size;
	int real_listen_read_buffer_size;
};

struct _request_add_flow_source
{
	struct _request r;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	/* The request reply */
	int flow_id;
	char cc_alg[256];
	int real_send_buffer_size;
	int real_read_buffer_size;
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
 * data:                IAT data if this is a request block
 *                      RTT data if this is a response block
 *                     
 * trail:               trailing garbage to fill up the blocksize (not used)
 */

#define MIN_BLOCK_SIZE 32
struct _block 
{
	int32_t this_block_size;
	int32_t	request_block_size;
	struct timeval data;
};

void flow_error(struct _flow *flow, const char *fmt, ...);
void request_error(struct _request *request, const char *fmt, ...);
int set_flow_tcp_options(struct _flow *flow);

#endif //__DAEMON_H__
