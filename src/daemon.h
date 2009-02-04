#ifndef __DAEMON_H__
#define __DAEMON_H__

#include "common.h"

void *daemon_main(void* ptr);

pthread_t daemon_thread;

/* Through this pipe we wakeup the thread from select */
extern int daemon_pipe[2];

extern pthread_mutex_t mutex;

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
	struct timeval next_report_time;

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
