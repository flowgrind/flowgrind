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
#include "fg_log.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

void remove_flow(unsigned i);

#ifdef HAVE_TCP_INFO
int get_tcp_info(struct flow *flow, struct tcp_info *info);
#endif /* HAVE_TCP_INFO */

void init_flow(struct flow* flow, int is_source);
void uninit_flow(struct flow *flow);

static int name2socket(struct flow *flow, char *server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp,
		const int read_buffer_size_req, int *read_buffer_size,
		const int send_buffer_size_req, int *send_buffer_size)
{
	int fd, n;
	struct addrinfo hints, *res, *ressave;
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

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

		if (fd < 0)
			continue;
		/* FIXME: currently we use portable select() API, which
		 * is limited by the number of bits in an fd_set */
		if (fd >= FD_SETSIZE) {
		        logging(LOG_ALERT, "too many file descriptors are"
				"already in use by this daemon");
		        flow_error(flow, "failed to create listen socket: too many"
		                "file descriptors in use by this daemon");
		        close(fd);
		        freeaddrinfo(ressave);
			return -1;
		}

		if (send_buffer_size)
			*send_buffer_size = set_window_size_directed(fd, send_buffer_size_req, SO_SNDBUF);
		if (read_buffer_size)
			*read_buffer_size = set_window_size_directed(fd, read_buffer_size_req, SO_RCVBUF);

		break;

	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		flow_error(flow, "Could not create socket for "
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

/**
 * Establishes a connection of a flow.
 *
 * Establishes a connection to the destination daemon listening port, and
 * marks the flow as connected.
 *
 * @param[in,out] flow Flow to connect.
 */
int do_connect(struct flow *flow) {
	int rc;

	rc = connect(flow->fd, flow->addr, flow->addr_len);
	if (rc == -1 && errno != EINPROGRESS) {
		flow_error(flow, "connect() failed: %s",
				strerror(errno));
		err("failed to connect flow %u", flow->id);
		return rc;
	}
	flow->connect_called = 1;
	flow->pmtu = get_pmtu(flow->fd);
	return 0;
}

/**
 * To set daemon flow as source endpoint
 *
 * To set the flow options and settings as source endpoint. Depending upon the 
 * late connection option the data connection is established to connect the 
 * destination daemon listening port address with source daemon. 
 *
 * @param[in,out] request Contain the test option and parameter for daemon source endpoint 
 */
int add_flow_source(struct request_add_flow_source *request)
{
#ifdef HAVE_SO_TCP_CONGESTION
	socklen_t opt_len = 0;
#endif /* HAVE_SO_TCP_CONGESTION */
	struct flow *flow;

	if (fg_list_size(&flows) >= MAX_FLOWS_DAEMON) {
		logging(LOG_WARNING, "can not accept another flow, already "
			"handling %zu flows", fg_list_size(&flows));
		request_error(&request->r,
			"Can not accept another flow, already "
			"handling %zu flows.", fg_list_size(&flows));
		return -1;
	}

	flow = malloc(sizeof(struct flow));
	if (!flow) {
		logging(LOG_ALERT, "could not allocate memory for flow");
		return -1;
	}

	init_flow(flow, 1);

	flow->settings = request->settings;
	flow->source_settings = request->source_settings;
	/* be greedy with buffer sizes */
	flow->write_block = calloc(1, flow->settings.maximum_block_size);
	flow->read_block = calloc(1, flow->settings.maximum_block_size);
	/* Controller flow ID is set in the daemon */
	flow->id = flow->settings.flow_id;
	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging(LOG_ALERT, "could not allocate memory for read/write "
			"blocks");
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
			&flow->addr, &flow->addr_len,
			flow->settings.requested_read_buffer_size, &request->real_read_buffer_size,
			flow->settings.requested_send_buffer_size, &request->real_send_buffer_size);
	if (flow->fd == -1) {
		logging(LOG_ALERT, "could not create data socket: %s",
			flow->error);
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
		DEBUG_MSG(4, "(early) connecting test socket (fd=%u)", flow->fd);
		if (do_connect(flow) == -1) {
			request->r.error = flow->error;
			flow->error = NULL;
			uninit_flow(flow);
			return -1;
		}
	}

	request->flow_id = flow->id;

	fg_list_push_back(&flows, flow);

	return 0;
}
