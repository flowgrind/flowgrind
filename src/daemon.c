/**
 * @file daemon.c
 * @brief Routines used by the Flowgrind daemon
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
 *
 * This file is part of Flowgrind.
 *
 * Flowgrind is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Flowgrind is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Flowgrind.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
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
#include <float.h>

#include "common.h"
#include "debug.h"
#include "fg_error.h"
#include "fg_math.h"
#include "fg_definitions.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"
#include "daemon.h"
#include "source.h"
#include "destination.h"
#include "trafgen.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif /* SOL_TCP */

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif /* SOL_IP */

#define CONGESTION_LIMIT 10000

int daemon_pipe[2];

int next_flow_id = 0;

pthread_mutex_t mutex;
struct request *requests = 0, *requests_last = 0;

fd_set rfds, wfds, efds;
int maxfd;

struct report* reports = 0;
struct report* reports_last = 0;
unsigned int pending_reports = 0;

struct linked_list flows;

char started = 0;

#ifdef HAVE_LIBPCAP
char dumping = 0;
#endif /* HAVE_LIBPCAP */

/* Forward declarations */
static int write_data(struct flow *flow);
static int read_data(struct flow *flow);
static void process_rtt(struct flow* flow);
static void process_iat(struct flow* flow);
static void process_delay(struct flow* flow);
static void report_flow(struct flow* flow, int type);
static void send_response(struct flow* flow,
			  int requested_response_block_size);
int get_tcp_info(struct flow *flow, struct fg_tcp_info *info);


void flow_error(struct flow *flow, const char *fmt, ...)
{
	char str[1000];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(str, 1000, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = 0;
	flow->error = malloc(strlen(str) + 1);
	strcpy(flow->error, str);
}

void request_error(struct request *request, const char *fmt, ...)
{
	char str[1000];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(str, 1000, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = 0;
	request->error = malloc(strlen(str) + 1);
	strcpy(request->error, str);
}

static inline int flow_in_delay(struct timespec *now, struct flow *flow,
				int direction)
{
	return time_is_after(&flow->start_timestamp[direction], now);
}


static inline int flow_sending(struct timespec *now, struct flow *flow,
			       int direction)
{
	return !flow_in_delay(now, flow, direction) &&
		(flow->settings.duration[direction] < 0 ||
		 time_diff_now(&flow->stop_timestamp[direction]) < 0.0);
}

static inline int flow_block_scheduled(struct timespec *now, struct flow *flow)
{
	return time_is_after(now, &flow->next_write_block_timestamp);
}

void uninit_flow(struct flow *flow)
{
	DEBUG_MSG(LOG_DEBUG,"uninit_flow() called for flow %d",flow->id);
	if (flow->fd != -1)
		close(flow->fd);
	if (flow->listenfd_data != -1)
		close(flow->listenfd_data);
#ifdef HAVE_LIBPCAP
	int rc;
	if (flow->settings.traffic_dump && flow->pcap_thread) {
		rc = pthread_cancel(flow->pcap_thread);
		if (rc)
			logging_log(LOG_WARNING, "failed to cancel dump "
				    "thread: %s", strerror(rc));

		/* wait for the dump thread to react to the cancellation request */
		rc = pthread_join(flow->pcap_thread, NULL);
		if (rc)
			logging_log(LOG_WARNING, "failed to join dump "
					"thread: %s", strerror(rc));
	}
#endif /* HAVE_LIBPCAP */
	free_all(flow->read_block, flow->write_block, flow->addr, flow->error);
	free_math_functions(flow);
}

void remove_flow(struct flow * const flow)
{
	fg_list_remove(&flows, flow);
	free(flow);
	if (!fg_list_size(&flows))
		started = 0;
}

static void prepare_wfds(struct timespec *now, struct flow *flow, fd_set *wfds)
{
	int rc = 0;

	if (flow_in_delay(now, flow, WRITE)) {
		DEBUG_MSG(LOG_WARNING, "flow %i not started yet (delayed)",
			  flow->id);
		return;
	}

	if (flow_sending(now, flow, WRITE)) {
		assert(!flow->finished[WRITE]);
		if (flow_block_scheduled(now, flow)) {
			DEBUG_MSG(LOG_DEBUG, "adding sock of flow %d to wfds",
				  flow->id);
			FD_SET(flow->fd, wfds);
		} else {
			DEBUG_MSG(LOG_DEBUG, "no block for flow %d scheduled "
				  "yet", flow->id);
		}
	} else if (!flow->finished[WRITE]) {
		flow->finished[WRITE] = 1;
		if (flow->settings.shutdown) {
			DEBUG_MSG(LOG_WARNING, "shutting down flow %d (WR)",
				  flow->id);
			rc = shutdown(flow->fd,SHUT_WR);
			if (rc == -1)
				warn("shutdown() SHUT_WR failed");
		}
	}

	return;
}

static int prepare_rfds(struct timespec *now, struct flow *flow, fd_set *rfds)
{
	int rc = 0;

	if (!flow_in_delay(now, flow, READ) && !flow_sending(now, flow, READ)) {
		if (!flow->finished[READ] && flow->settings.shutdown) {
			warnx("server flow %u missed to shutdown", flow->id);
			rc = shutdown(flow->fd, SHUT_RD);
			if (rc == -1)
				warn("shutdown SHUT_RD failed");
			flow->finished[READ] = 1;
		}
	}

	if (flow->source_settings.late_connect && !flow->connect_called ) {
		DEBUG_MSG(LOG_ERR, "late connecting test socket for flow %d "
			  "after %.3fs delay",
			  flow->id, flow->settings.delay[WRITE]);
		rc = connect(flow->fd, flow->addr, flow->addr_len);
		if (rc == -1 && errno != EINPROGRESS) {
			flow_error(flow, "Connect failed: %s", strerror(errno));
			return -1;
		}
		flow->connect_called = 1;
		flow->pmtu = get_pmtu(flow->fd);
	}

	/* Altough the server flow might be finished we keep the socket in
	 * rfd in order to check for buggy servers */
	if (flow->connect_called && !flow->finished[READ]) {
		DEBUG_MSG(LOG_DEBUG, "adding sock of flow %d to rfds",
			  flow->id);
		FD_SET(flow->fd, rfds);
	}

	return 0;
}

static int prepare_fds() {

	DEBUG_MSG(LOG_DEBUG, "prepare_fds() called, number of flows: %zu",
		  fg_list_size(&flows));

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	FD_SET(daemon_pipe[0], &rfds);
	maxfd = daemon_pipe[0];

	struct timespec now;
	gettime(&now);

	const struct list_node *node = fg_list_front(&flows);
	while (node) {
		struct flow *flow = node->data;
		node = node->next;

		if (started &&
		    (flow->finished[READ] ||
		     !flow->settings.duration[READ] ||
		     (!flow_in_delay(&now, flow, READ) &&
		      !flow_sending(&now, flow, READ))) &&
		    (flow->finished[WRITE] ||
		     !flow->settings.duration[WRITE] ||
		     (!flow_in_delay(&now, flow, WRITE) &&
		      !flow_sending(&now, flow, WRITE)))) {

			/* On Other OSes than Linux or FreeBSD, tcp_info will contain all zeroes */
			flow->statistics[FINAL].has_tcp_info =
				get_tcp_info(flow,
					     &flow->statistics[FINAL].tcp_info)
					? 0 : 1;

			flow->pmtu = get_pmtu(flow->fd);

			if (flow->settings.reporting_interval)
				report_flow(flow, INTERVAL);
			report_flow(flow, FINAL);
			uninit_flow(flow);
			remove_flow(flow);
			continue;
		}

		if (flow->state == GRIND_WAIT_ACCEPT &&
		    flow->listenfd_data != -1) {
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

	return fg_list_size(&flows);
}

static void start_flows(struct request_start_flows *request)
{
	struct timespec start;
	gettime(&start);

#if 0
	if (start.tv_sec < request->start_timestamp) {
		/* If the clock is synchronized between nodes, all nodes will
		 * start at the same time regardless of any RPC delays */
		start.tv_sec = request->start_timestamp;
		start.tv_nsec = 0;
	}
#else /* 0 */
	UNUSED_ARGUMENT(request);
#endif /* 0 */

	const struct list_node *node = fg_list_front(&flows);
	while (node) {
		struct flow *flow = node->data;
		node = node->next;
		/* initalize random number generator etc */
		init_math_functions(flow, flow->settings.random_seed);

		/* READ and WRITE */
		for (int j = 0; j < 2; j++) {
			flow->start_timestamp[j] = start;
			time_add(&flow->start_timestamp[j],
				 flow->settings.delay[j]);
			if (flow->settings.duration[j] >= 0) {
				flow->stop_timestamp[j] =
					flow->start_timestamp[j];
				time_add(&flow->stop_timestamp[j],
					 flow->settings.duration[j]);
			}
		}
		flow->next_write_block_timestamp =
			flow->start_timestamp[WRITE];

		gettime(&flow->last_report_time);
		flow->first_report_time = flow->last_report_time;
		flow->next_report_time = flow->last_report_time;

		time_add(&flow->next_report_time,
			 flow->settings.reporting_interval);
	}

	started = 1;
}

static void stop_flow(struct request_stop_flow *request)
{
	DEBUG_MSG(LOG_DEBUG, "stop_flow forcefully unlocked mutex");
	pthread_mutex_unlock(&mutex);

	if (request->flow_id == -1) {
		/* Stop all flows */

		const struct list_node *node = fg_list_front(&flows);
		while (node) {
			struct flow *flow = node->data;
			node = node->next;

			flow->statistics[FINAL].has_tcp_info =
				get_tcp_info(flow,
					     &flow->statistics[FINAL].tcp_info)
					? 0 : 1;
			flow->pmtu = get_pmtu(flow->fd);

			if (flow->settings.reporting_interval)
				report_flow(flow, INTERVAL);
			report_flow(flow, FINAL);

			uninit_flow(flow);
			remove_flow(flow);
		}

		return;
	}

	const struct list_node *node = fg_list_front(&flows);
	while (node) {
		struct flow *flow = node->data;
		node = node->next;

		if (flow->id != request->flow_id)
			continue;

		/* On Other OSes than Linux or FreeBSD, tcp_info will contain all zeroes */
		flow->statistics[FINAL].has_tcp_info =
			get_tcp_info(flow,
				     &flow->statistics[FINAL].tcp_info)
				? 0 : 1;
		flow->pmtu = get_pmtu(flow->fd);

		if (flow->settings.reporting_interval)
			report_flow(flow, INTERVAL);
		report_flow(flow, FINAL);

		uninit_flow(flow);
		remove_flow(flow);
		return;
	}

	request_error(&request->r, "Unknown flow id");
}

static void process_requests()
{
	int rc;
	DEBUG_MSG(LOG_DEBUG, "process_requests trying to lock mutex");
	pthread_mutex_lock(&mutex);
	DEBUG_MSG(LOG_DEBUG, "process_requests locked mutex");

	char tmp[100];
	for (;;) {
		int rc = read(daemon_pipe[0], tmp, 100);
		if (rc != 100)
			break;
	}

	while (requests) {
		struct request* request = requests;
		requests = requests->next;
		rc = 0;

		switch (request->type) {
		case REQUEST_ADD_DESTINATION:
			add_flow_destination((struct
						request_add_flow_destination
						*)request);
			break;
		case REQUEST_ADD_SOURCE:
			rc = add_flow_source((struct
						request_add_flow_source
						*)request);
			break;
		case REQUEST_START_FLOWS:
			start_flows((struct request_start_flows *)request);
			break;
		case REQUEST_STOP_FLOW:
			stop_flow((struct request_stop_flow *)request);
			break;
		case REQUEST_GET_STATUS:
			{
				struct request_get_status *r =
					(struct request_get_status *)request;
				r->started = started;
				r->num_flows = fg_list_size(&flows);
			}
			break;
		default:
			request_error(request, "Unknown request type");
			break;
		}
		if (rc != 1)
			pthread_cond_signal(request->condition);
	}

	pthread_mutex_unlock(&mutex);
	DEBUG_MSG(LOG_DEBUG, "process_requests unlocked mutex");
}

/*
 * Prepare a report. type is either INTERVAL or FINAL
 */
static void report_flow(struct flow* flow, int type)
{
	DEBUG_MSG(LOG_DEBUG, "report_flow called for flow %d (type %d)",
		  flow->id, type);
	struct report* report =
		(struct report*)malloc(sizeof(struct report));

	report->id = flow->id;
	report->type = type;

	if (type == INTERVAL)
		report->begin = flow->last_report_time;
	else
		report->begin = flow->first_report_time;

	gettime(&report->end);
	flow->last_report_time = report->end;

	/* abort if we were scheduled way to early for a interval report */
	if (time_diff(&report->begin,&report->end) < 0.2 *
			flow->settings.reporting_interval && type == INTERVAL){
		free(report);
		return;
	}

	report->bytes_read = flow->statistics[type].bytes_read;
	report->bytes_written = flow->statistics[type].bytes_written;
	report->request_blocks_read =
		flow->statistics[type].request_blocks_read;
	report->response_blocks_read =
		flow->statistics[type].response_blocks_read;
	report->request_blocks_written =
		flow->statistics[type].request_blocks_written;
	report->response_blocks_written =
		flow->statistics[type].response_blocks_written;

	report->rtt_min = flow->statistics[type].rtt_min;
	report->rtt_max = flow->statistics[type].rtt_max;
	report->rtt_sum = flow->statistics[type].rtt_sum;
	report->iat_min = flow->statistics[type].iat_min;
	report->iat_max = flow->statistics[type].iat_max;
	report->iat_sum = flow->statistics[type].iat_sum;
	report->delay_min = flow->statistics[type].delay_min;
	report->delay_max = flow->statistics[type].delay_max;
	report->delay_sum = flow->statistics[type].delay_sum;

	/* Currently this will only contain useful information on Linux
	 * and FreeBSD */
	report->tcp_info = flow->statistics[type].tcp_info;

	if (flow->fd != -1) {
		/* Get latest MTU */
		flow->pmtu = get_pmtu(flow->fd);
		report->pmtu = flow->pmtu;
		if (type == FINAL)
			report->imtu = get_imtu(flow->fd);
		else
			report->imtu = 0;
	} else {
		report->imtu = 0;
		report->pmtu = 0;
	}
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

		flow->statistics[INTERVAL].rtt_min = FLT_MAX;
		flow->statistics[INTERVAL].rtt_max = FLT_MIN;
		flow->statistics[INTERVAL].rtt_sum = 0.0F;
		flow->statistics[INTERVAL].iat_min = FLT_MAX;
		flow->statistics[INTERVAL].iat_max = FLT_MIN;
		flow->statistics[INTERVAL].iat_sum = 0.0F;
		flow->statistics[INTERVAL].delay_min = FLT_MAX;
		flow->statistics[INTERVAL].delay_max = FLT_MIN;
		flow->statistics[INTERVAL].delay_sum = 0.0F;
	}

	add_report(report);
	DEBUG_MSG(LOG_DEBUG, "report_flow finished for flow %d (type %d)",
		  flow->id, type);
}

/* Fills the given _fg_tcp_info with the values of the OS specific tcp_info,
 * returns 0 on success */
int get_tcp_info(struct flow *flow, struct fg_tcp_info *info)
{
#ifdef HAVE_TCP_INFO
	struct tcp_info tmp_info;
	socklen_t info_len = sizeof(tmp_info);
	int rc;
	memset(info, 0, sizeof(struct fg_tcp_info));

	rc = getsockopt(flow->fd, IPPROTO_TCP, TCP_INFO, &tmp_info, &info_len);
	if (rc == -1) {
		warn("getsockopt() failed");
		return -1;
	}
	#define CPY_INFO_MEMBER(a) info->a = (int) tmp_info.a;
	CPY_INFO_MEMBER(tcpi_snd_cwnd);
	CPY_INFO_MEMBER(tcpi_snd_ssthresh);
	CPY_INFO_MEMBER(tcpi_rtt);
	CPY_INFO_MEMBER(tcpi_rttvar);
	CPY_INFO_MEMBER(tcpi_rto);
	CPY_INFO_MEMBER(tcpi_snd_mss);

	/* TODO FreeBSD 9.1 doesn't fill these members, but maybe FreeBSD 10.0
	 * will fill it, so get rid of this ifdef */
#ifdef __LINUX__
	CPY_INFO_MEMBER(tcpi_backoff);
	CPY_INFO_MEMBER(tcpi_unacked);
	CPY_INFO_MEMBER(tcpi_sacked);
	CPY_INFO_MEMBER(tcpi_lost);
	CPY_INFO_MEMBER(tcpi_retrans);
	CPY_INFO_MEMBER(tcpi_retransmits);
	CPY_INFO_MEMBER(tcpi_fackets);
	CPY_INFO_MEMBER(tcpi_reordering);
	CPY_INFO_MEMBER(tcpi_ca_state);
#endif /* __LINUX__ */
#else /* HAVE_TCP_INFO */
	UNUSED_ARGUMENT(flow);
	memset(info, 0, sizeof(struct fg_tcp_info));
#endif /* HAVE_TCP_INFO */
	return 0;
}

static void timer_check()
{
	struct timespec now;

	if (!started)
		return;

	gettime(&now);
	const struct list_node *node = fg_list_front(&flows);
	while (node) {
		struct flow *flow = node->data;
		node = node->next;

		DEBUG_MSG(LOG_DEBUG, "processing timer_check() for flow %d",
			  flow->id);

		if (!flow->settings.reporting_interval)
			continue;

		if (!time_is_after(&now, &flow->next_report_time))
			continue;

		/* On Other OSes than Linux or FreeBSD, tcp_info will contain all zeroes */
		if (flow->fd != -1)
			flow->statistics[INTERVAL].has_tcp_info =
				get_tcp_info(flow,
					     &flow->statistics[INTERVAL].tcp_info)
					? 0 : 1;
		report_flow(flow, INTERVAL);

		do {
			time_add(&flow->next_report_time,
				 flow->settings.reporting_interval);
		} while (time_is_after(&now, &flow->next_report_time));
	}
	DEBUG_MSG(LOG_DEBUG, "finished timer_check()");
}

static void process_select(fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	const struct list_node *node = fg_list_front(&flows);
	while (node) {
		struct flow *flow = node->data;
		node = node->next;

		DEBUG_MSG(LOG_DEBUG, "processing pselect() for flow %d",
			  flow->id);

		if (flow->listenfd_data != -1 &&
		    FD_ISSET(flow->listenfd_data, rfds)) {
			DEBUG_MSG(LOG_DEBUG, "ready for accept");
			if (flow->state == GRIND_WAIT_ACCEPT) {
				if (accept_data(flow) == -1) {
					DEBUG_MSG(LOG_ERR, "accept_data() "
						  "failed");
					goto remove;
				}
			}
		}

		if (flow->fd != -1) {
			if (FD_ISSET(flow->fd, efds)) {
				int error_number, rc;
				socklen_t error_number_size =
					sizeof(error_number);
				DEBUG_MSG(LOG_DEBUG, "sock of flow %d in efds",
					  flow->id);
				rc = getsockopt(flow->fd, SOL_SOCKET,
						SO_ERROR,
						(void *)&error_number,
						&error_number_size);
				if (rc == -1) {
					warn("failed to get errno for"
					     "non-blocking connect");
					goto remove;
				}
				if (error_number != 0) {
					warnc(error_number, "connect");
					goto remove;
				}
			}
			if (FD_ISSET(flow->fd, wfds))
				if (write_data(flow) == -1) {
					DEBUG_MSG(LOG_ERR, "write_data() failed");
					goto remove;
				}

			if (FD_ISSET(flow->fd, rfds))
				if (read_data(flow) == -1) {
					DEBUG_MSG(LOG_ERR, "read_data() failed");
					goto remove;
				}
		}
		continue;
remove:
		if (flow->fd != -1) {
			flow->statistics[FINAL].has_tcp_info =
				get_tcp_info(flow,
					     &flow->statistics[FINAL].tcp_info)
					? 0 : 1;
		}
		flow->pmtu = get_pmtu(flow->fd);
		report_flow(flow, FINAL);
		uninit_flow(flow);
		remove_flow(flow);
		DEBUG_MSG(LOG_ERR, "removed flow %d", flow->id);
	}
}

void* daemon_main(void* ptr __attribute__((unused)))
{
	struct timespec timeout;
	for (;;) {
		int need_timeout = prepare_fds();

		timeout.tv_sec = 0;
		timeout.tv_nsec = DEFAULT_SELECT_TIMEOUT;
		DEBUG_MSG(LOG_DEBUG, "calling pselect() need_timeout: %i",
			  need_timeout);
		int rc = pselect(maxfd + 1, &rfds, &wfds, &efds,
				 need_timeout ? &timeout : 0, NULL);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			crit("pselect() failed");
		}
		DEBUG_MSG(LOG_DEBUG, "pselect() finished");

		if (FD_ISSET(daemon_pipe[0], &rfds))
			process_requests();

		timer_check();
		process_select(&rfds, &wfds, &efds);
	}
}

void add_report(struct report* report)
{
	DEBUG_MSG(LOG_DEBUG, "add_report trying to lock mutex");
	pthread_mutex_lock(&mutex);
	DEBUG_MSG(LOG_DEBUG, "add_report aquired mutex");
	/* Do not keep too much data */
	if (pending_reports >= 250 && report->type != FINAL) {
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
	DEBUG_MSG(LOG_DEBUG, "add_report unlocked mutex");
}

struct report* get_reports(int *has_more)
{
	const unsigned int max_reports = 50;

	struct report* ret;
	DEBUG_MSG(LOG_DEBUG, "get_reports trying to lock mutex");
	pthread_mutex_lock(&mutex);
	DEBUG_MSG(LOG_DEBUG, "get_reports aquired mutex");
	ret = reports;

	if (pending_reports <= max_reports) {
		*has_more = 0;
		pending_reports = 0;
		reports = NULL;
		reports_last = 0;
	} else {
		/* Split off first 50 items */
		struct report* tmp;
		for (unsigned int i = 0; i < max_reports - 1; i++)
			reports = reports->next;
		tmp = reports->next;
		reports->next = 0;
		reports = tmp;

		pending_reports -= max_reports;
		*has_more = 1;
	}

	pthread_mutex_unlock(&mutex);
	DEBUG_MSG(LOG_DEBUG, "get_reports unlocked mutex");
	return ret;
}

void init_flow(struct flow* flow, int is_source)
{
	memset(flow, 0, sizeof(struct flow));

	flow->id = next_flow_id++;
	flow->endpoint = is_source ? SOURCE : DESTINATION;
	flow->state = is_source ? GRIND_WAIT_CONNECT : GRIND_WAIT_ACCEPT;
	flow->fd = -1;
	flow->listenfd_data = -1;

	flow->current_read_block_size = MIN_BLOCK_SIZE;
	flow->current_write_block_size = MIN_BLOCK_SIZE;

	flow->finished[READ] = flow->finished[WRITE] = 0;

	flow->addr = 0;
	/* INTERVAL and FINAL */
	for (int i = 0; i < 2; i++) {
		flow->statistics[i].bytes_read = 0;
		flow->statistics[i].bytes_written = 0;

		flow->statistics[i].request_blocks_read = 0;
		flow->statistics[i].request_blocks_written = 0;
		flow->statistics[i].response_blocks_read = 0;
		flow->statistics[i].response_blocks_written = 0;

		flow->statistics[i].rtt_min = FLT_MAX;
		flow->statistics[i].rtt_max = FLT_MIN;
		flow->statistics[i].rtt_sum = 0.0F;
		flow->statistics[i].iat_min = FLT_MAX;
		flow->statistics[i].iat_max = FLT_MIN;
		flow->statistics[i].iat_sum = 0.0F;
		flow->statistics[i].delay_min = FLT_MAX;
		flow->statistics[i].delay_max = FLT_MIN;
		flow->statistics[i].delay_sum = 0.0F;
	}

	DEBUG_MSG(LOG_NOTICE, "called init flow %d", flow->id);
}

static int write_data(struct flow *flow)
{
	int rc = 0;
	int response_block_size = 0;
	double interpacket_gap = .0;
	for (;;) {

		/* fill buffer with new data */
		if (flow->current_block_bytes_written == 0) {
			flow->current_write_block_size =
				next_request_block_size(flow);
			response_block_size = next_response_block_size(flow);
			/* serialize data:
			 * this_block_size */
			((struct block *)flow->write_block)->this_block_size =
				htonl(flow->current_write_block_size);
			/* requested_block_size */
			((struct block *)flow->write_block)->request_block_size =
				htonl(response_block_size);
			/* write rtt data (will be echoed back by the receiver
			 * in the response packet) */
			gettime((struct timespec *)
				(flow->write_block + 2 * (sizeof (int32_t))));

			DEBUG_MSG(LOG_DEBUG, "wrote new request data to out "
				  "buffer bs = %d, rqs = %d, on flow %d",
				  ntohl(((struct block *)flow->write_block)->this_block_size),
				  ntohl(((struct block *)flow->write_block)->request_block_size),
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
			DEBUG_MSG(LOG_WARNING, "write() returned %d on flow %d, "
				   "fd %d: %s", rc, flow->id, flow->fd,
				   strerror(errno));
			flow_error(flow, "premature end of test: %s",
				   strerror(errno));
			return rc;
		}

		if (rc == 0) {
			DEBUG_MSG(LOG_CRIT, "flow %d sent zero bytes. what "
				  "does that mean?", flow->id);
			return rc;
		}

		DEBUG_MSG(LOG_DEBUG, "flow %d sent %d request bytes of %u "
			  "(before = %u)", flow->id, rc,
			  flow->current_write_block_size,
			  flow->current_block_bytes_written);

		for (int i = 0; i < 2; i++)
			flow->statistics[i].bytes_written += rc;

		flow->current_block_bytes_written += rc;

		if (flow->current_block_bytes_written >=
		    flow->current_write_block_size) {
			assert(flow->current_block_bytes_written ==
			       flow->current_write_block_size);
			/* we just finished writing a block */
			flow->current_block_bytes_written = 0;
			gettime(&flow->last_block_written);
			for (int i = 0; i < 2; i++)
				flow->statistics[i].request_blocks_written++;

			interpacket_gap = next_interpacket_gap(flow);

			/* if we calculated a non-zero packet add relative time
			 * to the next write stamp which is then checked in the
			 * select call */
			if (interpacket_gap) {
				time_add(&flow->next_write_block_timestamp,
					 interpacket_gap);
				if (time_is_after(&flow->last_block_written,
						  &flow->next_write_block_timestamp)) {
					DEBUG_MSG(LOG_WARNING, "incipient "
						  "congestion on flow %u new "
						  "block scheduled for %s, "
						  "%.6lfs before now.",
						   flow->id,
						   ctimespec(&flow->next_write_block_timestamp),
						   time_diff(&flow->next_write_block_timestamp,
							     &flow->last_block_written));
					flow->congestion_counter++;
					if (flow->congestion_counter >
					    CONGESTION_LIMIT &&
					    flow->settings.flow_control)
						return -1;
				}
			}
			if (flow->settings.cork && toggle_tcp_cork(flow->fd) == -1)
				DEBUG_MSG(LOG_NOTICE, "failed to recork test "
					  "socket for flow %d: %s",
					  flow->id, strerror(errno));
		}

		if (!flow->settings.pushy)
			break;
	}
	return 0;
}

static inline int try_read_n_bytes(struct flow *flow, int bytes)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;
/* we only read out of band data for debugging purpose */
#ifdef DEBUG
	char cbuf[512];
	struct cmsghdr *cmsg;
#else /* DEBUG */
	char cbuf[16];
#endif /* DEBUG */
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

	DEBUG_MSG(LOG_DEBUG, "tried reading %d bytes, got %d", bytes, rc);

	if (rc == -1) {
		if (errno == EAGAIN)
			flow_error(flow, "Premature end of test: %s",
				   strerror(errno));
		return -1;
	}

	if (rc == 0) {
		DEBUG_MSG(LOG_ERR, "server shut down test socket of "
			  "flow %d", flow->id);
		if (!flow->finished[READ] || !flow->settings.shutdown)
			warnx("premature shutdown of server flow");
		flow->finished[READ] = 1;
		return -1;
	}

	DEBUG_MSG(LOG_DEBUG, "flow %d received %u bytes", flow->id, rc);

	flow->current_block_bytes_read += rc;
	for (int i = 0; i < 2; i++)
		flow->statistics[i].bytes_read += rc;

#ifdef DEBUG
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		DEBUG_MSG(LOG_NOTICE, "flow %d received cmsg: type = %u, "
			  "len = %zu",
		flow->id, cmsg->cmsg_type, cmsg->cmsg_len);
#endif /* DEBUG */

	return rc;
}

static int read_data(struct flow *flow)
{
	int rc = 0;
	int optint = 0;
	int requested_response_block_size = 0;

	for (;;) {
		/* make sure to read block header for new block */
		if (flow->current_block_bytes_read < MIN_BLOCK_SIZE) {
			rc = try_read_n_bytes(flow,
					      MIN_BLOCK_SIZE-flow->current_block_bytes_read);
			if (flow->current_block_bytes_read < MIN_BLOCK_SIZE)
				break;
		}
		/* parse data and update status */

		/* parse and check current block size for validity */
		optint = ntohl( ((struct block *)flow->read_block)->this_block_size );
		if (optint >= MIN_BLOCK_SIZE &&
		    optint <= flow->settings.maximum_block_size )
			flow->current_read_block_size = optint;
		else
			logging_log(LOG_WARNING, "flow %d parsed illegal cbs %d, "
				    "ignoring (max: %d)", flow->id, optint,
				    flow->settings.maximum_block_size);

		/* parse and check current request size for validity */
		optint = ntohl( ((struct block *)flow->read_block)->request_block_size );
		if (optint == -1 || optint == 0  ||
		    (optint >= MIN_BLOCK_SIZE &&
		     optint <= flow->settings.maximum_block_size))
			requested_response_block_size = optint;
		else
			logging_log(LOG_WARNING, "flow %d parsed illegal qbs "
				    "%d, ignoring (max: %d)",
				    flow->id,
				    optint,
				    flow->settings.maximum_block_size);
#ifdef DEBUG
		if (requested_response_block_size == -1) {
			DEBUG_MSG(LOG_NOTICE, "processing response block on "
				  "flow %d size: %d", flow->id,
				  flow->current_read_block_size);
		} else {
			DEBUG_MSG(LOG_NOTICE, "processing request block on "
				  "flow %d size: %d, request: %d",
				  flow->id,
				  flow->current_read_block_size,
				  requested_response_block_size);
		}
#endif /* DEBUG */
		/* read rest of block, if we have more to read */
		if (flow->current_block_bytes_read <
		    flow->current_read_block_size)
			rc += try_read_n_bytes(flow,
					       flow->current_read_block_size -
					       flow->current_block_bytes_read);

		if (flow->current_block_bytes_read >=
		    flow->current_read_block_size ) {
			assert(flow->current_block_bytes_read ==
					flow->current_read_block_size);
			flow->current_block_bytes_read = 0;

			/* TODO process_rtt(), process_iat(), and
			 * process_delay () call all gettime().
			 * Quite inefficient... */

			if (requested_response_block_size == -1) {
				/* this is a response block, consider DATA as
				 * RTT  */
				for (int i = 0; i < 2; i++)
					flow->statistics[i].response_blocks_read++;
				process_rtt(flow);
			} else {
				/* this is a request block, calculate IAT */
				for (int i = 0; i < 2; i++)
					flow->statistics[i].request_blocks_read++;
				process_iat(flow);
				process_delay(flow);

				/* send response if requested */
				if (requested_response_block_size >=
				    (signed)MIN_BLOCK_SIZE && !flow->finished[READ])
					send_response(flow,
						      requested_response_block_size);
			}
		}
		if (!flow->settings.pushy)
			break;
	}
	return rc;
}

static void process_rtt(struct flow* flow)
{
	double current_rtt = .0;
	struct timespec now;
	struct timespec *data = (struct timespec *)
		(flow->read_block + 2*(sizeof (int32_t)));

	gettime(&now);
	current_rtt = time_diff(data, &now);

	if (current_rtt < 0) {
		logging_log(LOG_CRIT, "received malformed rtt block of flow %d "
			    "(rtt = %.3lfms), ignoring",
			    flow->id, current_rtt * 1e3);
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

	DEBUG_MSG(LOG_NOTICE, "processed RTT of flow %d (%.3lfms)",
		  flow->id, current_rtt * 1e3);
}

static void process_iat(struct flow* flow)
{
	double current_iat = .0;
	struct timespec now;

	gettime(&now);

	if (flow->last_block_read.tv_sec ||
	    flow->last_block_read.tv_nsec)
		current_iat = time_diff(&flow->last_block_read, &now);
	else
		current_iat = NAN;

	if (current_iat < 0) {
		logging_log(LOG_CRIT, "calculated malformed iat of flow %d "
			    "(iat = %.3lfms) (clock skew?), ignoring",
			    flow->id, current_iat * 1e3);
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
	DEBUG_MSG(LOG_NOTICE, "processed IAT of flow %d (%.3lfms)",
		  flow->id, current_iat * 1e3);
}

static void process_delay(struct flow* flow)
{
	double current_delay = .0;
	struct timespec now;
	struct timespec *data = (struct timespec *)
		(flow->read_block + 2*(sizeof (int32_t)));

	gettime(&now);
	current_delay = time_diff(data, &now);

	if (current_delay < 0) {
		logging_log(LOG_CRIT, "calculated malformed delay of flow "
			    "%d (rtt = %.3lfms) (clocks out-of-sync?), "
			    "ignoring", flow->id, current_delay * 1e3);
		current_delay = NAN;
	}

	if (!isnan(current_delay)) {
		for (int i = 0; i < 2; i++) {
			ASSIGN_MIN(flow->statistics[i].delay_min,
				   current_delay);
			ASSIGN_MAX(flow->statistics[i].delay_max,
				   current_delay);
			flow->statistics[i].delay_sum += current_delay;
		}
	}

	DEBUG_MSG(LOG_NOTICE, "processed delay of flow %d (%.3lfms)",
		  flow->id, current_delay * 1e3);
}

static void send_response(struct flow* flow, int requested_response_block_size)
{
	int rc;
	int try = 0;

	assert(!flow->current_block_bytes_written);

	/* write requested block size as current size */
	((struct block *)flow->write_block)->this_block_size =
		htonl(requested_response_block_size);
	/* rqs = -1 indicates response block */
	((struct block *)flow->write_block)->request_block_size = htonl(-1);
	/* copy rtt data from received block to response block (echo back) */
	((struct block *)flow->write_block)->data =
		((struct block *)flow->read_block)->data;
	/* workaround for 64bit sender and 32bit receiver: we check if the
	 * timespec is 64bit and then echo the missing 32bit back, too */
	if ((((struct block *)flow->write_block)->data.tv_sec) ||
	    ((struct block *)flow->write_block)->data.tv_nsec)
		((struct block *)flow->write_block)->data2 =
			((struct block *)flow->read_block)->data2;

	DEBUG_MSG(LOG_DEBUG, "wrote new response data to out buffer bs = %d, "
		  "rqs = %d on flow %d",
		  ntohl(((struct block *)flow->write_block)->this_block_size),
		  ntohl(((struct block *)flow->write_block)->request_block_size),
		  flow->id);

	/* send data out until block is finished (or abort if 0 zero bytes are
	 * send CONGESTION_LIMIT times) */
	for (;;) {
		rc = write(flow->fd,
			   flow->write_block + flow->current_block_bytes_written,
			   requested_response_block_size -
				flow->current_block_bytes_written);

		DEBUG_MSG(LOG_NOTICE, "send %d bytes response (rqs %d) on flow "
			  "%d", rc, requested_response_block_size,flow->id);

		if (rc == -1) {
			if (errno == EAGAIN) {
				DEBUG_MSG(LOG_DEBUG,
					  "%s, still trying to send response "
					  "block (write queue hit limit)",
					  strerror(errno));
				try++;
				if (try >= CONGESTION_LIMIT &&
				    !flow->current_block_bytes_written) {
					logging_log(LOG_WARNING,
						    "tried to send response "
						    "block %d times without "
						    "success, dropping (%s)",
						    try, strerror(errno));
						break;
				}
			} else {
				logging_log(LOG_WARNING,
					    "Premature end of test: %s, abort "
					    "flow", strerror(errno));
				flow->finished[READ] = 1;
				break;
			}
		} else {
			flow->current_block_bytes_written += rc;
			for (int i = 0; i < 2; i++)
				flow->statistics[i].bytes_written += rc;

			if (flow->current_block_bytes_written >=
			    (unsigned int)requested_response_block_size) {
				assert(flow->current_block_bytes_written ==
					(unsigned int)requested_response_block_size);
				/* just finish sending response block */
				flow->current_block_bytes_written = 0;
				gettime(&flow->last_block_written);
				for (int i = 0; i < 2; i++)
					flow->statistics[i].response_blocks_written++;
				break;
			}
		}
	}
}


int apply_extra_socket_options(struct flow *flow)
{
	for (int i = 0; i < flow->settings.num_extra_socket_options; i++) {
		int level, res;
		const struct extra_socket_options *option =
			&flow->settings.extra_socket_options[i];

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
			flow_error(flow, "Unknown socket option level: %d",
				   option->level);
			return -1;
		}

		res = setsockopt(flow->fd, level, option->optname,
				 option->optval, option->optlen);

		if (res == -1) {
			flow_error(flow, "Unable to set socket option %d: %s",
				   option->optname, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/* Set the TCP options on the data socket */
int set_flow_tcp_options(struct flow *flow)
{
	set_non_blocking(flow->fd);

	if (*flow->settings.cc_alg &&
	    set_congestion_control(flow->fd, flow->settings.cc_alg) == -1) {
		flow_error(flow, "Unable to set congestion control "
			   "algorithm: %s", strerror(errno));
		return -1;
	}
	if (flow->settings.elcn &&
	    set_so_elcn(flow->fd, flow->settings.elcn) == -1) {
		flow_error(flow, "Unable to set TCP_ELCN: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.lcd && set_so_lcd(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_LCD: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.cork && set_tcp_cork(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_CORK: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.so_debug && set_so_debug(flow->fd) == -1) {
		flow_error(flow, "Unable to set SO_DEBUG: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.mtcp && set_tcp_mtcp(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_MTCP: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.nonagle && set_tcp_nodelay(flow->fd) == -1) {
		flow_error(flow, "Unable to set TCP_NODELAY: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.route_record && set_route_record(flow->fd) == -1) {
		flow_error(flow, "Unable to set route record option: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.dscp &&
	    set_dscp(flow->fd, flow->settings.dscp) == -1) {
		flow_error(flow, "Unable to set DSCP value: %s",
			   strerror(errno));
		return -1;
	}
	if (flow->settings.ipmtudiscover &&
	    set_ip_mtu_discover(flow->fd) == -1) {
		flow_error(flow, "Unable to set IP_MTU_DISCOVER value: %s",
			   strerror(errno));
		return -1;
	}
	if (apply_extra_socket_options(flow) == -1)
		return -1;

	return 0;
}

