#ifndef __DAEMON_H__
#define __DAEMON_H__

#include <netinet/tcp.h>
#include <sys/socket.h>

void *daemon_main(void* ptr);

pthread_t daemon_thread;

/* Through this pipe we wakeup the thread from select */
extern int daemon_pipe[2];

extern pthread_mutex_t mutex;

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

struct _flow_destination_settings
{
};

enum flow_state
{
	/* SOURCE */
	WAIT_CONNECT_REPLY,
	GRIND_WAIT_CONNECT,

	/* DESTINATION */
	WAIT_ACCEPT_REPLY,
	GRIND_WAIT_ACCEPT,

	/* BOTH */
	GRIND
};

struct _flow
{
	int id;

	enum flow_state state;

	int fd_reply;
	int fd;

	int listenfd_reply;
	int listenfd_data;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct timeval start_timestamp[2];
	struct timeval stop_timestamp[2];
	struct timeval last_block_read;
	struct timeval last_block_written;

	struct timeval first_report_time;
	struct timeval last_report_time;

	struct timeval next_write_block_timestamp;

	char *read_block;
	unsigned read_block_bytes_read;
	uint64_t read_block_count;

	char *write_block;
	unsigned write_block_bytes_written;
	uint64_t write_block_count;

	char reply_block[sizeof(struct timeval) + sizeof(double) + 1];
	unsigned int reply_block_bytes_read;

	unsigned short requested_server_test_port;

	unsigned real_listen_send_buffer_size;
	unsigned real_listen_receive_buffer_size;

	char connect_called;
	char finished[2];

	int mss;
	int mtu;

	unsigned congestion_counter;

	/* here we use current_mss and current_mtu to store the most current
	   values of get_mss and get_mtu. The problem encountered was that at the
	   very end when guess_topology was called get_mss and get_mtu returned
	   some bogus value because the call to getsockopt failed.
	*/
	/*int current_mss;
	int current_mtu;*/

	/* Used for late_connect */
	struct sockaddr *addr;
	socklen_t addr_len;

	struct _statistics {
		long long bytes_read;
		long long bytes_written;
		long reply_blocks_read;

		double rtt_min, rtt_max, rtt_sum;
		double iat_min, iat_max, iat_sum;

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

#define REQUEST_ADD_DESTINATION 0
#define REQUEST_ADD_SOURCE 1
#define REQUEST_START_FLOWS 2
#define REQUEST_STOP_FLOW 3
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
	struct _flow_destination_settings destination_settings;

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

extern double reporting_interval;

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
extern struct _report* reports;
extern struct _report* reports_last;
extern int pending_reports;

void add_report(struct _report* report);
struct _report* get_reports();

extern char started;

void flow_error(struct _flow *flow, const char *fmt, ...);
void request_error(struct _request *request, const char *fmt, ...);
int set_flow_tcp_options(struct _flow *flow);

#endif //__DAEMON_H__
