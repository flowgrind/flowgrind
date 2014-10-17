/**
 * @file destination.c
 * @brief Routines used to setup a Flowgrind destination for a test
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

#include "common.h"
#include "debug.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "fg_math.h"
#include "log.h"
#include "daemon.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

void remove_flow(unsigned int i);

#ifdef HAVE_TCP_INFO
int get_tcp_info(struct flow *flow, struct tcp_info *info);
#endif /* HAVE_TCP_INFO */

void init_flow(struct flow* flow, int is_source);
void uninit_flow(struct flow *flow);

/* listen_port will receive the port of the created socket */
static int create_listen_socket(struct flow *flow, char *bind_addr,
				unsigned short *listen_port)
{
	int port;
	int rc;
	int fd;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = bind_addr ? 0 : AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* Any port will be fine */
	if ((rc = getaddrinfo(bind_addr, "0", &hints, &res)) != 0) {
		logging_log(LOG_ALERT, "Error: getaddrinfo() failed: %s\n",
			    gai_strerror(rc));
		flow_error(flow, "getaddrinfo() failed: %s",
			   gai_strerror(rc));
		return -1;
	}

	ressave = res;

	do {
		fd = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
		if (fd < 0)
			continue;
		if (bind(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		logging_log(LOG_ALERT, "failed to create listen socket");
		flow_error(flow, "Failed to create listen socket: %s",
			   strerror(errno));
		freeaddrinfo(ressave);
		return -1;
	}

	freeaddrinfo(ressave);

	/* we need to set sockopt mtcp before we start listen() */
	if (flow->settings.mtcp)
		set_tcp_mtcp(fd);

	if (flow->settings.cc_alg)
		set_congestion_control(fd, flow->settings.cc_alg);

	if (listen(fd, 0) < 0) {
		logging_log(LOG_ALERT, "listen failed: %s",
			    strerror(errno));
		flow_error(flow, "Listen failed: %s", strerror(errno));
		return -1;
	}

	set_non_blocking(fd);

	port = get_port(fd);
	if (port < 0) {
		flow_error(flow, "Could not get port: %s", strerror(errno));
		close(fd);
		return -1;
	}
	DEBUG_MSG(LOG_DEBUG, "listening on port %d", port);
	*listen_port = (unsigned short)port;

	return fd;
}

void add_flow_destination(struct request_add_flow_destination *request)
{
	struct flow *flow;
	unsigned short server_data_port;

	if (fg_list_size(&flows) >= MAX_FLOWS) {
		logging_log(LOG_WARNING, "Can not accept another flow, already "
			    "handling MAX_FLOW flows.");
		request_error(&request->r, "Can not accept another flow, "
			     "already handling MAX_FLOW flows.");
		return;
	}

	flow = malloc(sizeof(struct flow));
	if (!flow) {
		logging_log(LOG_ALERT, "could not allocate memory for flow");
		return;
	}

	init_flow(flow, 0);

	flow->settings = request->settings;
	flow->write_block = calloc(1, flow->settings.maximum_block_size );
	flow->read_block = calloc(1, flow->settings.maximum_block_size );
	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging_log(LOG_ALERT, "could not allocate memory for "
			    "read/write blocks");
		request_error(&request->r, "could not allocate memory "
			      "for read/write blocks");
		uninit_flow(flow);
		return;
	}

	if (flow->settings.byte_counting) {
		int byte_idx;
		for (byte_idx = 0; byte_idx < flow->settings.maximum_block_size;
		     byte_idx++)
			*(flow->write_block + byte_idx) =
				(unsigned char)(byte_idx & 0xff);
	}

	/* Create listen socket for data connection */
	if ((flow->listenfd_data =
			create_listen_socket(flow,
					     flow->settings.bind_address[0]
						? flow->settings.bind_address : 0,
					     &server_data_port)) == -1) {
		logging_log(LOG_ALERT, "could not create listen socket for "
			    "data connection: %s", flow->error);
		request_error(&request->r, "could not create listen socket "
			      "for data connection: %s", flow->error);
		uninit_flow(flow);
		return;
	} else {
		DEBUG_MSG(LOG_WARNING, "listening on %s port %u for data "
			  "connection", flow->settings.bind_address,
			  server_data_port);
	}

	flow->real_listen_send_buffer_size =
		set_window_size_directed(flow->listenfd_data,
					 flow->settings.requested_send_buffer_size,
					 SO_SNDBUF);
	flow->real_listen_receive_buffer_size =
		set_window_size_directed(flow->listenfd_data,
					 flow->settings.requested_read_buffer_size,
					 SO_RCVBUF);

	request->listen_data_port = (int)server_data_port;
	request->real_listen_send_buffer_size =
		flow->real_listen_send_buffer_size;
	request->real_listen_read_buffer_size =
		flow->real_listen_receive_buffer_size;
	request->flow_id = flow->id;

	fg_list_push_back(&flows, flow);

	return;
}

int accept_data(struct flow *flow)
{
	struct sockaddr_storage caddr;
	socklen_t addrlen = sizeof(caddr);
	unsigned real_send_buffer_size;
	unsigned real_receive_buffer_size;

	flow->fd = accept(flow->listenfd_data, (struct sockaddr *)&caddr,
			  &addrlen);
	if (flow->fd == -1) {
		/* try again later .... */
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		logging_log(LOG_ALERT, "accept() failed: %s", strerror(errno));
		return -1;
	}
	if (close(flow->listenfd_data) == -1)
		logging_log(LOG_WARNING, "close(): failed");
	flow->listenfd_data = -1;

	logging_log(LOG_NOTICE, "client %s connected for testing.",
		    fg_nameinfo((struct sockaddr *)&caddr, addrlen));

#ifdef HAVE_LIBPCAP
	fg_pcap_go(flow);
#endif /* HAVE_LIBPCAP */

	real_send_buffer_size =
		set_window_size_directed(flow->fd,
					 flow->settings.requested_send_buffer_size,
					 SO_SNDBUF);
	if (flow->requested_server_test_port &&
	    flow->real_listen_send_buffer_size != real_send_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set send buffer size of test "
				"socket to send buffer size size of listen socket "
				"(listen = %u, test = %u).",
				flow->real_listen_send_buffer_size,
				real_send_buffer_size);
		return -1;
	}
	real_receive_buffer_size =
		set_window_size_directed(flow->fd,
					 flow->settings.requested_read_buffer_size,
					 SO_RCVBUF);
	if (flow->requested_server_test_port &&
	    flow->real_listen_receive_buffer_size != real_receive_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set receive buffer size "
			    "(advertised window) of test socket to receive "
			    "buffer size of listen socket (listen = %u, "
			    "test = %u).",
			    flow->real_listen_receive_buffer_size,
			    real_receive_buffer_size);
		return -1;
	}
	if (set_flow_tcp_options(flow) == -1)
		return -1;
	DEBUG_MSG(LOG_NOTICE, "data socket accepted");
	flow->state = GRIND;
	flow->connect_called = 1;

	return 0;
}
