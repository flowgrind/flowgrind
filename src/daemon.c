#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef DEBUG
#include <assert.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <inttypes.h>

#include "common.h"
#include "debug.h"
#if HAVE_LIBPCAP
#include "fg_pcap.h"
#endif
#include "fg_socket.h"
#include "fg_time.h"
#include "fg_math.h"
#include "log.h"
#include "daemon.h"
#include "source.h"
#include "destination.h"
#include "trafgen.h"

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

#ifdef __SOLARIS__
#define RANDOM_MAX              4294967295UL    /* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX              LONG_MAX        /* Darwin */
#else
#define RANDOM_MAX              RAND_MAX        /* Linux, FreeBSD */
#endif

#define CONGESTION_LIMIT 10000

int daemon_pipe[2];

int next_flow_id = 0;

pthread_mutex_t mutex;
struct _request *requests = 0, *requests_last = 0;

fd_set rfds, wfds, efds;
int maxfd;

struct _report* reports = 0;
struct _report* reports_last = 0;
unsigned int pending_reports = 0;

struct _flow flows[MAX_FLOWS];
unsigned int num_flows = 0;

char started = 0;

static void process_rtt(struct _flow* flow);
static void process_iat(struct _flow* flow);
static void send_response(struct _flow* flow, int requested_response_block_size);

void flow_error(struct _flow *flow, const char *fmt, ...)
{
	char str[1000];

	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(str, 1000, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = 0;
	flow->error = malloc(strlen(str) + 1);
	strcpy(flow->error, str);
}

void request_error(struct _request *request, const char *fmt, ...)
{
	char str[1000];

	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(str, 1000, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = 0;
	request->error = malloc(strlen(str) + 1);
	strcpy(request->error, str);
}

static inline int flow_in_delay(struct timeval *now, struct _flow *flow, int direction)
{
	return time_is_after(&flow->start_timestamp[direction], now);
}


static inline int flow_sending(struct timeval *now, struct _flow *flow, int direction)
{
	return !flow_in_delay(now, flow, direction) && (flow->settings.duration[direction] < 0 ||
		 time_diff(&flow->stop_timestamp[direction], now) < 0.0);
}

static inline int flow_block_scheduled(struct timeval *now, struct _flow *flow)
{
	return time_is_after(now, &flow->next_write_block_timestamp);
}

void uninit_flow(struct _flow *flow)
{
	if (flow->fd != -1)
		close(flow->fd);
	if (flow->listenfd_data != -1)
		close(flow->listenfd_data);
	free(flow->read_block);
	free(flow->write_block);
	free(flow->addr);
	free(flow->error);
}

void remove_flow(unsigned int i)
{
	for (unsigned int j = i; j < num_flows - 1; j++)
		flows[j] = flows[j + 1];
	num_flows--;
	if (!num_flows)
		started = 0;
}

static void prepare_wfds(struct timeval *now, struct _flow *flow, fd_set *wfds)
{
	int rc = 0;

	if (flow_in_delay(now, flow, WRITE)) {
		DEBUG_MSG(LOG_WARNING, "flow %i not started yet (delayed)", flow->id);
		return;
	}

	if (flow_sending(now, flow, WRITE)) {
#ifdef DEBUG
		assert(!flow->finished[WRITE]);
#endif
		if (flow_block_scheduled(now, flow)) {
			DEBUG_MSG(LOG_DEBUG, "adding sock of flow %d to wfds", flow->id);
			FD_SET(flow->fd, wfds);
		} else {
			DEBUG_MSG(LOG_DEBUG, "no block for flow %d scheduled yet", flow->id);
		}
	} else if (!flow->finished[WRITE]) {
		flow->finished[WRITE] = 1;
		if (flow->settings.shutdown) {
			DEBUG_MSG(LOG_WARNING, "shutting down flow %d (WR)", flow->id);
			rc = shutdown(flow->fd, SHUT_WR);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown() SHUT_WR failed: %s",
						strerror(errno));
			}
		}
	}

	return;
}

static int prepare_rfds(struct timeval *now, struct _flow *flow, fd_set *rfds)
{
	int rc = 0;

	if (!flow_in_delay(now, flow, READ) && !flow_sending(now, flow, READ)) {
		if (!flow->finished[READ] && flow->settings.shutdown) {
			error(ERR_WARNING, "server flow %u missed to shutdown", flow->id);
			rc = shutdown(flow->fd, SHUT_RD);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown SHUT_RD "
						"failed: %s", strerror(errno));
			}
			flow->finished[READ] = 1;
		}
	}

	if (flow->source_settings.late_connect && !flow->connect_called ) {
		DEBUG_MSG(LOG_ERR, "late connecting test socket "
				"for flow %d after %.3fs delay",
				flow->id, flow->settings.delay[WRITE]);
		rc = connect(flow->fd, flow->addr,
				flow->addr_len);
		if (rc == -1 && errno != EINPROGRESS) {
			flow_error(flow, "Connect failed: %s", strerror(errno));
			return -1;
		}
		flow->connect_called = 1;
		flow->mtu = get_mtu(flow->fd);
		flow->mss = get_mss(flow->fd);
	}

	/* Altough the server flow might be finished we keep the socket in
	 * rfd in order to check for buggy servers */
	if (flow->connect_called && !flow->finished[READ]) {
		DEBUG_MSG(LOG_DEBUG, "adding sock of flow %d to rfds", flow->id);
		FD_SET(flow->fd, rfds);
	}

	return 0;
}

#ifdef __LINUX__
int get_tcp_info(struct _flow *flow, struct tcp_info *info);
#endif
static void report_flow(struct _flow* flow, int type);

static int prepare_fds() {

	unsigned int i = 0;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	FD_SET(daemon_pipe[0], &rfds);
	maxfd = daemon_pipe[0];

	struct timeval now;
	tsc_gettimeofday(&now);

	while (i < num_flows) {
		struct _flow *flow = &flows[i++];

		if (started &&
			(flow->finished[READ] || !flow->settings.duration[READ] || (!flow_in_delay(&now, flow, READ) && !flow_sending(&now, flow, READ))) &&
			(flow->finished[WRITE] || !flow->settings.duration[WRITE] || (!flow_in_delay(&now, flow, WRITE) && !flow_sending(&now, flow, WRITE)))) {

			/* Nothing left to read, nothing left to send */
			if (flow->fd != -1) {
#ifdef __LINUX__
				flow->statistics[TOTAL].has_tcp_info = get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info) ? 0 : 1;
#endif
				flow->mtu = get_mtu(flow->fd);
				flow->mss = get_mss(flow->fd);

				report_flow(flow, TOTAL);
			}

			uninit_flow(flow);
			remove_flow(--i);
			continue;
		}


		if (flow->state == GRIND_WAIT_ACCEPT && flow->listenfd_data != -1) {
			FD_SET(flow->listenfd_data, &rfds);
			maxfd = MAX(maxfd, flow->listenfd_data);
		}

		if (!started)
			continue;

		if (flow->fd != -1) {
			FD_SET(flow->fd, &efds);
			maxfd = MAX(maxfd, flow->fd);

			prepare_wfds(&now, flow, &wfds);
			prepare_rfds(&now, flow, &rfds);
		}
	}

	return num_flows;
}

static void start_flows(struct _request_start_flows *request)
{
	struct timeval start;
	tsc_gettimeofday(&start);

#if 0
	if (start.tv_sec < request->start_timestamp) {
		/* If the clock is synchronized between nodes, all nodes will start
		   at the same time regardless of any RPC delays */
		start.tv_sec = request->start_timestamp;
		start.tv_usec = 0;
	}
#else
	UNUSED_ARGUMENT(request);
#endif

	for (unsigned int i = 0; i < num_flows; i++) {
		struct _flow *flow = &flows[i];

		/* READ and WRITE */
		for (int j = 0; j < 2; j++) {
			flow->start_timestamp[j] = start;
			time_add(&flow->start_timestamp[j], flow->settings.delay[j]);
			if (flow->settings.duration[j] >= 0) {
				flow->stop_timestamp[j] = flow->start_timestamp[j];
				time_add(&flow->stop_timestamp[j], flow->settings.duration[j]);
			}
		}
		flow->next_write_block_timestamp = flow->start_timestamp[WRITE];

		tsc_gettimeofday(&flow->last_report_time);
		flow->first_report_time = flow->last_report_time;
		flow->next_report_time = flow->last_report_time;

		time_add(&flow->next_report_time, flow->settings.reporting_interval);
	}

	started = 1;
}

static void stop_flow(struct _request_stop_flow *request)
{
	if (request->flow_id == -1) {
		/* Stop all flows */

		for (unsigned int i = 0; i < num_flows; i++) {
			struct _flow *flow = &flows[i];

			uninit_flow(flow);
			remove_flow(i);
		}

		return;
	}

	for (unsigned int i = 0; i < num_flows; i++) {
		struct _flow *flow = &flows[i];

		if (flow->id != request->flow_id)
			continue;

		uninit_flow(flow);
		remove_flow(i);
		return;
	}

	request_error(&request->r, "Unknown flow id");
}

static void process_requests()
{
	int rc;
	pthread_mutex_lock(&mutex);

	char tmp[100];
	for (;;) {
		int rc = read(daemon_pipe[0], tmp, 100);
		if (rc != 100)
			break;
	}

	while (requests)
	{
		struct _request* request = requests;
		requests = requests->next;
		rc = 0;

		switch (request->type) {
		case REQUEST_ADD_DESTINATION:
			add_flow_destination((struct _request_add_flow_destination *)request);
			break;
		case REQUEST_ADD_SOURCE:
			rc = add_flow_source((struct _request_add_flow_source *)request);
			break;
		case REQUEST_START_FLOWS:
			start_flows((struct _request_start_flows *)request);
			break;
		case REQUEST_STOP_FLOW:
			stop_flow((struct _request_stop_flow *)request);
			break;
		case REQUEST_GET_STATUS:
			{
				struct _request_get_status *r = (struct _request_get_status *)request;
				r->started = started;
				r->num_flows = num_flows;
			}
			break;
		default:
			request_error(request, "Unknown request type");
			break;
		}
		if (rc != 1)
			pthread_cond_signal(request->condition);
	};

	pthread_mutex_unlock(&mutex);
}

/*
 * Prepare a report.
 * type is either INTERVAL or TOTAL
 */
static void report_flow(struct _flow* flow, int type)
{
	struct _report* report = (struct _report*)malloc(sizeof(struct _report));

	report->id = flow->id;
	report->type = type;

	if (type == INTERVAL)
		report->begin = flow->last_report_time;
	else
		report->begin = flow->first_report_time;

	tsc_gettimeofday(&report->end);
	flow->last_report_time = report->end;
	report->bytes_read = flow->statistics[type].bytes_read;
	report->bytes_written = flow->statistics[type].bytes_written;
	report->request_blocks_read = flow->statistics[type].request_blocks_read;
	report->response_blocks_read = flow->statistics[type].response_blocks_read;
	report->request_blocks_written = flow->statistics[type].request_blocks_written;
	report->response_blocks_written = flow->statistics[type].response_blocks_written;


	report->rtt_min = flow->statistics[type].rtt_min;
	report->rtt_max = flow->statistics[type].rtt_max;
	report->rtt_sum = flow->statistics[type].rtt_sum;
	report->iat_min = flow->statistics[type].iat_min;
	report->iat_max = flow->statistics[type].iat_max;
	report->iat_sum = flow->statistics[type].iat_sum;

#ifdef __LINUX__
	if (flow->statistics[type].has_tcp_info)
		report->tcp_info = flow->statistics[type].tcp_info;
	else
		memset(&report->tcp_info, 0, sizeof(struct tcp_info));
#endif
	if (flow->fd != -1) {
		/* Get latest MTU and MSS */
		int mtu, mss;
		mtu = get_mtu(flow->fd);
		mss = get_mss(flow->fd);
		if (mtu != -1)
			flow->mtu = mtu;
		if (mss != -1)
			flow->mss = mss;
	}
	report->mss = flow->mss;
	report->mtu = flow->mtu;

	/* Add status flags to report */
	report->status = 0;

	if (flow->statistics[type].bytes_read == 0) {
		if (flow_in_delay(&report->end, flow, READ))
			report->status |= 'd';
		else if (flow_sending(&report->end, flow, READ))
			report->status |= 'l';
		else if (flow->settings.duration[READ] == 0)
			report->status |= 'o';
		else
			report->status |= 'f';
	} else {
		if (!flow_sending(&report->end, flow, READ) && !flow->finished)
			report->status |= 'c';
		else
			report->status |= 'n';
	}
	report->status <<= 8;

	if (flow->statistics[type].bytes_written == 0) {
		if (flow_in_delay(&report->end, flow, WRITE))
			report->status |= 'd';
		else if (flow_sending(&report->end, flow, WRITE))
			report->status |= 'l';
		else if (flow->settings.duration[WRITE] == 0)
			report->status |= 'o';
		else
			report->status |= 'f';
	} else {
		if (!flow_sending(&report->end, flow, WRITE) && !flow->finished)
			report->status |= 'c';
		else
			report->status |= 'n';
	}


	/* New report interval, reset old data */
	if (type == INTERVAL) {
		flow->statistics[INTERVAL].bytes_read = 0;
		flow->statistics[INTERVAL].bytes_written = 0;

		flow->statistics[INTERVAL].request_blocks_read = 0;
		flow->statistics[INTERVAL].response_blocks_read = 0;

		flow->statistics[INTERVAL].request_blocks_written = 0;
		flow->statistics[INTERVAL].response_blocks_written = 0;

		flow->statistics[INTERVAL].rtt_min = +INFINITY;
		flow->statistics[INTERVAL].rtt_max = -INFINITY;
		flow->statistics[INTERVAL].rtt_sum = 0.0F;
		flow->statistics[INTERVAL].iat_min = +INFINITY;
		flow->statistics[INTERVAL].iat_max = -INFINITY;
		flow->statistics[INTERVAL].iat_sum = 0.0F;
	}

	add_report(report);
}

#ifdef __LINUX__
int get_tcp_info(struct _flow *flow, struct tcp_info *info)
{
	struct tcp_info tmp_info;
	socklen_t info_len = sizeof(tmp_info);
	int rc;

	rc = getsockopt(flow->fd, IPPROTO_TCP, TCP_INFO, &tmp_info, &info_len);
	if (rc == -1) {
		error(ERR_WARNING, "getsockopt() failed: %s",
				strerror(errno));
		return -1;
	}
	*info = tmp_info;

	return 0;
}
#endif

static void timer_check()
{
	struct timeval now;

	if (!started)
		return;

	tsc_gettimeofday(&now);
	for (unsigned int i = 0; i < num_flows; i++) {
		struct _flow *flow = &flows[i];

		if (!flow->settings.reporting_interval)
			continue;

		if (!time_is_after(&now, &flow->next_report_time))
			continue;

#ifdef __LINUX__
		if (flow->fd != -1)
			flow->statistics[INTERVAL].has_tcp_info = get_tcp_info(flow, &flow->statistics[INTERVAL].tcp_info) ? 0 : 1;
#endif
		report_flow(flow, INTERVAL);

		do {
			time_add(&flow->next_report_time, flow->settings.reporting_interval);
		} while (time_is_after(&now, &flow->next_report_time));
	}
}

static int write_data(struct _flow *flow);
static int read_data(struct _flow *flow);

static void process_select(fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	unsigned int i = 0;
	while (i < num_flows) {
		struct _flow *flow = &flows[i];

		if (flow->listenfd_data != -1 && FD_ISSET(flow->listenfd_data, rfds)) {
			if (flow->state == GRIND_WAIT_ACCEPT) {
				if (accept_data(flow) == -1)
					goto remove;
			}
		}

		if (flow->fd != -1) {

			if (FD_ISSET(flow->fd, efds)) {
				int error_number, rc;
				socklen_t error_number_size = sizeof(error_number);
				DEBUG_MSG(LOG_DEBUG, "sock of flow %d in efds", flow->id);
				rc = getsockopt(flow->fd, SOL_SOCKET,
						SO_ERROR,
						(void *)&error_number,
						&error_number_size);
				if (rc == -1) {
					error(ERR_WARNING, "failed to get "
							"errno for non-blocking "
							"connect: %s",
							strerror(errno));
					goto remove;
				}
				if (error_number != 0) {
					fprintf(stderr, "connect: %s\n",
							strerror(error_number));
					goto remove;
				}
			}
			if (FD_ISSET(flow->fd, wfds))
				if (write_data(flow) == -1)
					goto remove;
			if (FD_ISSET(flow->fd, rfds))
				if (read_data(flow) == -1)
					goto remove;
		}
#ifdef HAVE_LIBPCAP
		if (!flow->settings.traffic_dump)
			fg_pcap_dispatch();
#endif
		i++;
		continue;
remove:
#ifdef __LINUX__
		if (flow->fd != -1) {
			flow->statistics[TOTAL].has_tcp_info = get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info) ? 0 : 1;
			flow->mtu = get_mtu(flow->fd);
			flow->mss = get_mss(flow->fd);

			report_flow(flow, TOTAL);
		}
#endif

		uninit_flow(flow);
		remove_flow(i);
		DEBUG_MSG(LOG_ERR, "removed flow %d", flow->id);
	}
}

void* daemon_main(void* ptr __attribute__((unused)))
{
	struct timeval timeout;
	for (;;) {
		int need_timeout = prepare_fds();

		timeout.tv_sec = 2;
		timeout.tv_usec = 0;

		int rc = select(maxfd + 1, &rfds, &wfds, &efds, need_timeout ? &timeout : 0);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			error(ERR_FATAL, "select() failed: %s",
					strerror(errno));
			exit(1);
		}

		if (FD_ISSET(daemon_pipe[0], &rfds))
			process_requests();

		timer_check();

		process_select(&rfds, &wfds, &efds);
	}
}

void add_report(struct _report* report)
{
	pthread_mutex_lock(&mutex);

	/* Do not keep too much data */
	if (pending_reports >= 100 && report->type != TOTAL) {
		free(report);
		pthread_mutex_unlock(&mutex);
		return;
	}

	report->next = 0;

	if (reports_last)
		reports_last->next = report;
	else
		reports = report;
	reports_last = report;

	pending_reports++;

	pthread_mutex_unlock(&mutex);
}

struct _report* get_reports(int *has_more)
{
	const unsigned int max_reports = 50;

	struct _report* ret;

	pthread_mutex_lock(&mutex);

	ret = reports;

	if (pending_reports <= max_reports) {
		*has_more = 0;
		pending_reports = 0;
		reports = NULL;
		reports_last = 0;
	}
	else {
		/* Split off first 50 items */
		struct _report* tmp;
		for (unsigned int i = 0; i < max_reports - 1; i++)
			reports = reports->next;
		tmp = reports->next;
		reports->next = 0;
		reports = tmp;

		pending_reports -= max_reports;
		*has_more = 1;
	}

	pthread_mutex_unlock(&mutex);

	return ret;
}

void init_flow(struct _flow* flow, int is_source)
{
	flow->id = next_flow_id++;
	flow->endpoint = is_source ? SOURCE : DESTINATION;
	flow->state = is_source ? GRIND_WAIT_CONNECT : GRIND_WAIT_ACCEPT;
	flow->fd = -1;
	flow->listenfd_data = -1;

	flow->read_block = 0;
	flow->write_block = 0;

	flow->current_block_bytes_read = 0;
	flow->current_block_bytes_written = 0;

	flow->current_read_block_size = MIN_BLOCK_SIZE;
	flow->current_write_block_size = MIN_BLOCK_SIZE;

	flow->last_block_read.tv_sec = 0;
	flow->last_block_read.tv_usec = 0;

	flow->connect_called = 0;
	flow->finished[READ] = flow->finished[WRITE] = 0;

	flow->addr = 0;

	/* INTERVAL and TOTAL */
	for (int i = 0; i < 2; i++) {
		flow->statistics[i].bytes_read = 0;
		flow->statistics[i].bytes_written = 0;

		flow->statistics[i].request_blocks_read = 0;
		flow->statistics[i].request_blocks_written = 0;
		flow->statistics[i].response_blocks_read = 0;
		flow->statistics[i].response_blocks_written = 0;

		flow->statistics[i].rtt_min = +INFINITY;
		flow->statistics[i].rtt_max = -INFINITY;
		flow->statistics[i].rtt_sum = 0.0;

		flow->statistics[i].iat_min = +INFINITY;
		flow->statistics[i].iat_max = -INFINITY;
		flow->statistics[i].iat_sum = 0.0;
	}

	flow->congestion_counter = 0;

	flow->error = 0;
	DEBUG_MSG(LOG_NOTICE, "called init flow %d", flow->id);
}

static int write_data(struct _flow *flow)
{
	int rc = 0;
	int response_block_size = 0;
	double interpacket_gap = .0;
	for (;;) {

		/* fill buffer with new data */
		if (flow->current_block_bytes_written == 0) {
			flow->current_write_block_size = next_request_block_size(flow);
			response_block_size = next_response_block_size(flow);
			/* serialize data:
			 * this_block_size */
			((struct _block *)flow->write_block)->this_block_size = htonl(flow->current_write_block_size);
			/* requested_block_size */
			((struct _block *)flow->write_block)->request_block_size = htonl(response_block_size);
			/* write rtt data (will be echoed back by the receiver in the response packet) */
			tsc_gettimeofday((struct timeval *)( flow->write_block + 2 * (sizeof (int32_t)) ));

			DEBUG_MSG(LOG_DEBUG, "wrote new request data to out buffer bs = %d, rqs = %d, on flow %d",
					ntohl(((struct _block *)flow->write_block)->this_block_size),
					ntohl(((struct _block *)flow->write_block)->request_block_size),
					flow->id);
		}

		rc = write(flow->fd,
			   flow->write_block +
			   flow->current_block_bytes_written,
			   flow->current_write_block_size -
			   flow->current_block_bytes_written);

		if (rc == -1) {
			if (errno == EAGAIN) {
				logging_log(LOG_WARNING, "write queue limit hit "
						"for flow %d", flow->id);
				break;
			}
			flow_error(flow, "Premature end of test: %s",
					strerror(errno));
			return -1;
		}

		if (rc == 0) {
			DEBUG_MSG(LOG_CRIT, "flow %d sent zero bytes. what does that mean?", flow->id);
			return -1;
			break;
		}

		DEBUG_MSG(LOG_DEBUG, "flow %d sent %d request bytes of %u (before = %u)", flow->id, rc,
				flow->current_write_block_size,
				flow->current_block_bytes_written);

		for (int i = 0; i < 2; i++) {
			flow->statistics[i].bytes_written += rc;
		}
		flow->current_block_bytes_written += rc;

		if (flow->current_block_bytes_written >= flow->current_write_block_size) {
#ifdef DEBUG
			assert(flow->current_block_bytes_written == flow->current_write_block_size);
#endif
			/* we just finished writing a block */
			flow->current_block_bytes_written = 0;
			tsc_gettimeofday(&flow->last_block_written);
			for (int i = 0; i < 2; i++) {
				flow->statistics[i].request_blocks_written++;
			}

			interpacket_gap = next_interpacket_gap(flow);

			/* if we calculated a non-zero packet add relative time to the next write stamp
			 * which is then checked in the select call */
			if (interpacket_gap) {
				time_add(&flow->next_write_block_timestamp,
						interpacket_gap);
				if (time_is_after(&flow->last_block_written, &flow->next_write_block_timestamp)) {
					DEBUG_MSG(LOG_WARNING, "incipient congestion on "
							"flow %u new block scheduled "
							"for %s, %.6lfs before now.",
							flow->id,
							ctime_us(&flow->next_write_block_timestamp),
							time_diff(&flow->next_write_block_timestamp, &flow->last_block_written));
					flow->congestion_counter++;
					if (flow->congestion_counter >
							CONGESTION_LIMIT &&
							flow->settings.flow_control) {
						return -1;
					}

				}
			}
			if (flow->settings.cork && toggle_tcp_cork(flow->fd) == -1)
				DEBUG_MSG(LOG_NOTICE, "failed to recork test socket "
						"for flow %d: %s",
						flow->id, strerror(errno));
		}

		if (!flow->settings.pushy)
			break;
	}
	return 0;
}

static inline int try_read_n_bytes(struct _flow *flow, int bytes)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;
/* we only read out of band data for debugging purpose */
#ifdef DEBUG
	char cbuf[512];
	struct cmsghdr *cmsg;
#else
	char cbuf[16];
#endif
	iov.iov_base = flow->read_block +
		       flow->current_block_bytes_read;
	iov.iov_len = bytes;
	/* no name required */
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	rc = recvmsg(flow->fd, &msg, 0);

	if (rc == -1) {
		if (errno == EAGAIN)
			flow_error(flow, "Premature end of test: %s", strerror(errno));
			return -1;
	}

	if (rc == 0) {
		DEBUG_MSG(LOG_ERR, "server shut down test socket of flow %d", flow->id);
		if (!flow->finished[READ] || !flow->settings.shutdown)
			error(ERR_WARNING, "Premature shutdown of server flow");
			flow->finished[READ] = 1;
			if (flow->finished[WRITE]) {
				DEBUG_MSG(LOG_WARNING, "flow %u finished", flow->id);
				return -1;
			}
			return 0;
	}


	DEBUG_MSG(LOG_DEBUG, "flow %d received %u bytes", flow->id, rc);

	flow->current_block_bytes_read += rc;
	for (int i = 0; i < 2; i++) {
		flow->statistics[i].bytes_read += rc;
	}

#ifdef DEBUG
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		DEBUG_MSG(LOG_NOTICE, "flow %d received cmsg: type = %u, len = %zu",
		flow->id, cmsg->cmsg_type, cmsg->cmsg_len);
	}
#endif

	return rc;
}

static int read_data(struct _flow *flow)
{
	int rc = 0;
	int optint = 0;
	int requested_response_block_size = 0;

	for (;;) {
		/* make sure to read block header for new block */
		if (flow->current_block_bytes_read < MIN_BLOCK_SIZE)
			rc = try_read_n_bytes(flow,MIN_BLOCK_SIZE-flow->current_block_bytes_read);
			if (rc == -1)
				break;
			if (flow->current_block_bytes_read < MIN_BLOCK_SIZE)
				continue;

		/* parse data and update status */

		/* parse and check current block size for validity */
		optint = ntohl( ((struct _block *)flow->read_block)->this_block_size );
		if (optint >= MIN_BLOCK_SIZE && optint <= flow->settings.maximum_block_size )
			flow->current_read_block_size = optint;
		else
			logging_log(LOG_WARNING, "flow %d parsed illegal cbs %d, ignoring", flow->id, optint);

		/* parse and check current request size for validity */
		optint = ntohl( ((struct _block *)flow->read_block)->request_block_size );
		if (optint == -1 || optint == 0  || (optint >= MIN_BLOCK_SIZE && optint <= flow->settings.maximum_block_size ) )
			requested_response_block_size = optint;
		else
			logging_log(LOG_WARNING, "flow %d parsed illegal qbs %d, ignoring", flow->id, optint);
#ifdef DEBUG
		if (requested_response_block_size == -1) {
			DEBUG_MSG(LOG_NOTICE, "processing response block on flow %d size: %d",
					flow->id,
					flow->current_read_block_size);
		} else {
			DEBUG_MSG(LOG_NOTICE, "processing request block on flow %d size: %d, request: %d",
					flow->id,
					flow->current_read_block_size,
					requested_response_block_size);
		}
#endif
		/* read rest of block, if we have more to read */
		if (flow->current_block_bytes_read < flow->current_read_block_size)
			if (try_read_n_bytes(flow,flow->current_read_block_size -
				      flow->current_block_bytes_read) == -1)
				break;

		if (flow->current_block_bytes_read >= flow->current_read_block_size ) {
#ifdef DEBUG
			assert(flow->current_block_bytes_read == flow->current_read_block_size);
#endif
			flow->current_block_bytes_read = 0;

			if (requested_response_block_size == -1) {
				/* This is a response block, consider DATA as RTT  */
				for (int i = 0; i < 2; i++) {
					flow->statistics[i].response_blocks_read++;
				}
				process_rtt(flow);

			} else {
				/* this is a request block, calculate IAT */
				for (int i = 0; i < 2; i++) {
					flow->statistics[i].request_blocks_read++;
				}
				process_iat(flow);

				/* send response if requested */
				if ( requested_response_block_size >= (signed)MIN_BLOCK_SIZE && !flow->finished[READ])
					send_response(flow, requested_response_block_size);

			}
		}
		if (!flow->settings.pushy)
			break;
	}
	return 0;
}

static void process_rtt(struct _flow* flow)
{
	double current_rtt = .0;
	struct timeval now;
	struct timeval *data = (struct timeval *)(flow->read_block + 2*(sizeof (int32_t)) );

	tsc_gettimeofday(&now);
	current_rtt = time_diff(data, &now);

	if (current_rtt < 0) {
		logging_log(LOG_CRIT, "received malformed rtt block of flow %d (rtt = %.3lfms), ignoring",
				     flow->id,
				     current_rtt * 1e3);
		current_rtt = NAN;
	}

	flow->last_block_read = now;

	if (!isnan(current_rtt)) {
		for (int i = 0; i < 2; i++) {
			ASSIGN_MIN(flow->statistics[i].rtt_min, current_rtt);
			ASSIGN_MAX(flow->statistics[i].rtt_max, current_rtt);
			flow->statistics[i].rtt_sum += current_rtt;
		}
	}

	DEBUG_MSG(LOG_NOTICE, "processed RTT of flow %d (%.3lfms)", flow->id, current_rtt * 1e3);
}


static void process_iat(struct _flow* flow)
{
	double current_iat = .0;
	struct timeval now;

	tsc_gettimeofday(&now);

	if (flow->last_block_read.tv_sec ||
	    flow->last_block_read.tv_usec) {
		current_iat = time_diff(&flow->last_block_read, &now);
	} else {
		current_iat = NAN;
	}

	if (current_iat < 0) {
		logging_log(LOG_CRIT, "calculated malformed iat of flow %d (iat = %.3lfms) (clock skew?), ignoring",
				     flow->id,
				     current_iat * 1e3);
		current_iat = NAN;
	}

	flow->last_block_read = now;

	if (!isnan(current_iat)) {
		for (int i = 0; i < 2; i++) {
			ASSIGN_MIN(flow->statistics[i].iat_min, current_iat);
			ASSIGN_MAX(flow->statistics[i].iat_max, current_iat);
			flow->statistics[i].iat_sum += current_iat;
		}
	}
	DEBUG_MSG(LOG_NOTICE, "processed IAT flow %d (%.3lfms)", flow->id, current_iat * 1e3);
}

static void send_response(struct _flow* flow, int requested_response_block_size)
{
		int rc;
		int try = 0;
#ifdef DEBUG
		assert(!flow->current_block_bytes_written);
#endif
		 /* write requested block size as current size */
		((struct _block *)flow->write_block)->this_block_size = htonl(requested_response_block_size);
		/* rqs = -1 indicates response block */
		((struct _block *)flow->write_block)->request_block_size = htonl(-1);
		/* copy rtt data from received block to response block (echo back) */
		((struct _block *)flow->write_block)->data = ((struct _block *)flow->read_block)->data;
		/* workaround for 64bit sender and 32bit receiver:
		 * we check if the timeeval is 64bit and then echo the missing 32bit back, too */
		if (( ((struct _block *)flow->write_block)->data.tv_sec) || ((struct _block *)flow->write_block)->data.tv_usec)
			((struct _block *)flow->write_block)->data2 = ((struct _block *)flow->read_block)->data2;

		DEBUG_MSG(LOG_DEBUG, "wrote new response data to out buffer bs = %d, rqs = %d on flow %d",
			ntohl(((struct _block *)flow->write_block)->this_block_size),
			ntohl(((struct _block *)flow->write_block)->request_block_size),
			flow->id);

		/* send data out until block is finished (or abort if 0 zero bytes are send CONGESTION_LIMIT times) */
		for (;;) {
			rc = write(flow->fd,
				   flow->write_block + flow->current_block_bytes_written,
				   requested_response_block_size - flow->current_block_bytes_written);

			DEBUG_MSG(LOG_NOTICE, "send %d bytes response (rqs %d) on flow %d",
					      rc,
					      requested_response_block_size,flow->id);

			if (rc == -1) {
				if (errno == EAGAIN) {
					DEBUG_MSG(LOG_DEBUG,
						"%s, still trying to send response block (write queue hit limit)",
						strerror(errno));
					try++;
					if (try >= CONGESTION_LIMIT && !flow->current_block_bytes_written) {
						logging_log(LOG_WARNING,
							    "tried to send response block %d times without success, dropping (%s)",
							    try,
							    strerror(errno));

						break;
					}
				}
				else {
					logging_log(LOG_WARNING,
						"Premature end of test: %s, abort flow",
						strerror(errno));
					flow->finished[READ] = 1;
					break;
				}
			}
			else {
				flow->current_block_bytes_written += rc;
				for (int i = 0; i < 2; i++) {
					flow->statistics[i].bytes_written += rc;
				}
				if (flow->current_block_bytes_written >=
				    (unsigned int)requested_response_block_size) {
#ifdef DEBUG
					assert(flow->current_block_bytes_written == (unsigned int)requested_response_block_size);
#endif
					/* just finish sending response block */
					flow->current_block_bytes_written = 0;
					tsc_gettimeofday(&flow->last_block_written);
					for (int i = 0; i < 2; i++) {
						flow->statistics[i].response_blocks_written++;
					}
					break;
				}
			}
		}

}


int apply_extra_socket_options(struct _flow *flow)
{
	int i;

	for (i = 0; i < flow->settings.num_extra_socket_options; i++) {

		int level, res;
		const struct _extra_socket_options *option = &flow->settings.extra_socket_options[i];

		switch (option->level) {
			case level_sol_socket:
				level = SOL_SOCKET;
				break;
			case level_sol_tcp:
				level = SOL_TCP;
				break;
			case level_ipproto_ip:
				level = IPPROTO_IP;
				break;
			case level_ipproto_sctp:
				level = IPPROTO_SCTP;
				break;
			case level_ipproto_tcp:
				level = IPPROTO_TCP;
				break;
			case level_ipproto_udp:
				level = IPPROTO_UDP;
				break;
			default:
				flow_error(flow, "Unknown socket option level: %d", option->level);
				return -1;
		}

		res = setsockopt(flow->fd, level, option->optname, option->optval, option->optlen);

		if (res == -1) {
			flow_error(flow, "Unable to set socket option %d: %s", option->optname, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/* Set the TCP options on the data socket */
int set_flow_tcp_options(struct _flow *flow)
{
	set_non_blocking(flow->fd);

	if (*flow->settings.cc_alg && set_congestion_control(
				flow->fd, flow->settings.cc_alg) == -1) {
		flow_error(flow, "Unable to set congestion control algorithm: %s",
				strerror(errno));
		return -1;
	}

	if (flow->settings.elcn && set_so_elcn(flow->fd, flow->settings.elcn) == -1) {
		flow_error(flow, "Unable to set TCP_ELCN: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.icmp && set_so_icmp(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_ICMP: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.cork && set_tcp_cork(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_CORK: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.so_debug && set_so_debug(flow->fd) == -1) {
		flow_error(flow, "Unable to set SO_DEBUG: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.mtcp && set_tcp_mtcp(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_MTCP: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.route_record && set_route_record(flow->fd) == -1) {
		flow_error(flow, "Unable to set route record option: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.dscp && set_dscp(flow->fd, flow->settings.dscp) == -1) {
		flow_error(flow, "Unable to set DSCP value: %s", strerror(errno));
		return -1;
	}

	if (flow->settings.ipmtudiscover && set_ip_mtu_discover(flow->fd) == -1) {
		flow_error(flow, "Unable to set IP_MTU_DISCOVER value: %s", strerror(errno));
		return -1;
	}

	if (apply_extra_socket_options(flow) == -1)
		return -1;

	return 0;
}
