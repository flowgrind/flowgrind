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
};

struct _flow_source_settings
{
	char destination_host[256];
	char destination_host_reply[256];
	int destination_port;
	int destination_port_reply;

	char cc_alg[256];
	int elcn;
	int icmp;
	int cork;
	int dscp;
	int ipmtudiscover;
	int late_connect;
	int byte_counting;

	pthread_cond_t* add_source_condition;
};

struct _flow_destination_settings
{
};

#define REQUEST_ADD_DESTINATION 0
#define REQUEST_ADD_SOURCE 1
#define REQUEST_START_FLOWS 2
struct _request
{
	char type;

	/* We signal this condition once the daemon thread
	 * has processed the request */
	pthread_cond_t* condition;

	const char* error;

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

extern double reporting_interval;

struct _report
{
	int id;
	int type; /* INTERVAL or TOTAL */
	struct timeval tv;

	int bytes_read;
	int bytes_written;
	int reply_blocks_read;

	double rtt_min, rtt_max, rtt_sum;
	double iat_min, iat_max, iat_sum;

#ifdef __LINUX__
	struct tcp_info tcp_info;
#endif
	int mss;
	int mtu;

	struct _report* next;
};
extern struct _report* reports;
extern struct _report* reports_last;
extern int pending_reports;

void add_report(struct _report* report);
struct _report* get_reports();

#endif //__DAEMON_H__
