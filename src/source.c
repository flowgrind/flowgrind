/**
 * @file source.c
 * @brief Routines used by Flowgrind to setup the source for a test flow
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
#include <float.h>

#include "debug.h"
#include "fg_error.h"
#include "fg_math.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

void remove_flow(unsigned int i);

#ifdef HAVE_TCP_INFO
int get_tcp_info(struct flow *flow, struct tcp_info *info);
#endif /* HAVE_TCP_INFO */

void init_flow(struct flow* flow, int is_source);
void uninit_flow(struct flow *flow);

static int name2socket(struct flow *flow, char *server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp, char do_connect,
		const int read_buffer_size_req, int *read_buffer_size,
		const int send_buffer_size_req, int *send_buffer_size)
{
	int fd, n;
	struct addrinfo hints, *res, *ressave;
	struct sockaddr_in *tempv4;
	struct sockaddr_in6 *tempv6;
	char service[7];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(service, sizeof(service), "%u", port);

	if ((n = getaddrinfo(server_name, service, &hints, &res)) != 0) {
		flow_error(flow, "getaddrinfo() failed: %s",
				gai_strerror(n));
		return -1;
	}
	ressave = res;

	do {
		int rc;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		if (send_buffer_size)
			*send_buffer_size = set_window_size_directed(fd, send_buffer_size_req, SO_SNDBUF);
		if (read_buffer_size)
		*read_buffer_size = set_window_size_directed(fd, read_buffer_size_req, SO_RCVBUF);

		if (!do_connect)
			break;

		rc = connect(fd, res->ai_addr, res->ai_addrlen);
		if (rc == 0) {
			if (res->ai_family == PF_INET) {
				tempv4 = (struct sockaddr_in *) res->ai_addr;
				strncpy(server_name, inet_ntoa(tempv4->sin_addr), 256);
				server_name[255] = 0;
			}
			else if (res->ai_family == PF_INET6){
				tempv6 = (struct sockaddr_in6 *) res->ai_addr;
				inet_ntop(AF_INET6, &tempv6->sin6_addr, server_name, 256);
			}
			break;
		}

		warn("failed to connect to '%s:%d' ", server_name, port);
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		flow_error(flow, "Could not establish connection to "
				"\"%s:%d\": %s", server_name, port, strerror(errno));
		freeaddrinfo(ressave);
		return -1;
	}

	if (saptr && lenp) {
		*saptr = malloc(res->ai_addrlen);
		if (*saptr == NULL)
			crit("malloc(): failed");
		memcpy(*saptr, res->ai_addr, res->ai_addrlen);
		*lenp = res->ai_addrlen;
	}

	freeaddrinfo(ressave);

	return fd;
}

int add_flow_source(struct request_add_flow_source *request)
{
#ifdef HAVE_SO_TCP_CONGESTION
	socklen_t opt_len = 0;
#endif /* HAVE_SO_TCP_CONGESTION */
	struct flow *flow;

	if (fg_list_size(&flows) >= MAX_FLOWS) {
		logging_log(LOG_WARNING, "Can not accept another flow, already handling MAX_FLOW flows.");
		request_error(&request->r, "Can not accept another flow, already handling MAX_FLOW flows.");
		return -1;
	}

	flow = malloc(sizeof(struct flow));
	if (!flow) {
		logging_log(LOG_ALERT, "could not allocate memory for flow");
		return -1;
	}

	init_flow(flow, 1);

	flow->settings = request->settings;
	flow->source_settings = request->source_settings;
	/* be greedy with buffer sizes */
	flow->write_block = calloc(1, flow->settings.maximum_block_size);
	flow->read_block = calloc(1, flow->settings.maximum_block_size);

	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging_log(LOG_ALERT, "could not allocate memory for read/write blocks");
		request_error(&request->r, "could not allocate memory for read/write blocks");
		uninit_flow(flow);
		return -1;
	}
	if (flow->settings.byte_counting) {
		int byte_idx;
		for (byte_idx = 0; byte_idx < flow->settings.maximum_block_size; byte_idx++)
			*(flow->write_block + byte_idx) = (unsigned char)(byte_idx & 0xff);
	}

	flow->state = GRIND_WAIT_CONNECT;
	flow->fd = name2socket(flow, flow->source_settings.destination_host,
			flow->source_settings.destination_port,
			&flow->addr, &flow->addr_len, 0,
			flow->settings.requested_read_buffer_size, &request->real_read_buffer_size,
			flow->settings.requested_send_buffer_size, &request->real_send_buffer_size);
	if (flow->fd == -1) {
		logging_log(LOG_ALERT, "Could not create data socket: %s", flow->error);
		request_error(&request->r, "Could not create data socket: %s", flow->error);
		uninit_flow(flow);
		return -1;
	}

	if (set_flow_tcp_options(flow) == -1) {
		request->r.error = flow->error;
		flow->error = NULL;
		uninit_flow(flow);
		return -1;
	}

#ifdef HAVE_SO_TCP_CONGESTION
	opt_len = sizeof(request->cc_alg);
	if (getsockopt(flow->fd, IPPROTO_TCP, TCP_CONGESTION,
				request->cc_alg, &opt_len) == -1) {
		request_error(&request->r, "failed to determine actual congestion control algorithm: %s",
			strerror(errno));
		uninit_flow(flow);
		return -1;
	}
#endif /* HAVE_SO_TCP_CONGESTION */

#ifdef HAVE_LIBPCAP
	fg_pcap_go(flow);
#endif /* HAVE_LIBPCAP */
	if (!flow->source_settings.late_connect) {
		DEBUG_MSG(4, "(early) connecting test socket");
		connect(flow->fd, flow->addr, flow->addr_len);
		flow->connect_called = 1;
		flow->pmtu = get_pmtu(flow->fd);
	}

	request->flow_id = flow->id;

	fg_list_push_back(&flows, flow);

	return 0;
}
