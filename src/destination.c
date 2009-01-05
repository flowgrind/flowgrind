#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

#include "common.h"
#include "debug.h"
#include "fg_pcap.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"
#include "svnversion.h"
#include "acl.h"
#include "daemon.h"

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

static struct timeval now;

static int flow_in_delay(struct _flow *flow, int direction)
{
	return time_is_after(&flow->start_timestamp[direction], &now);
}

static int flow_sending(struct _flow *flow, int direction)
{
	return !flow_in_delay(flow, direction) &&
		(flow->settings.duration[direction] < 0 ||
		 time_diff(&flow->stop_timestamp[direction], &now) < 0.0);
}

/*
static int flow_block_scheduled(struct _flow *flow)
{
	return !flow->settings.write_rate ||
		time_is_after(&now, &flow->next_write_block_timestamp);
}*/

void remove_flow(unsigned int i);

#ifdef __LINUX__
int get_tcp_info(struct _flow *flow, struct tcp_info *info);
#endif

void init_flow(struct _flow* flow, int is_source);
void uninit_flow(struct _flow *flow);

int destination_prepare_fds(fd_set *rfds, fd_set *wfds, fd_set *efds, int *maxfd)
{
	unsigned int i = 0;

	while (i < num_flows) {
		struct _flow *flow = &flows[i++];

		if (started) {
			if ((flow->finished[READ] || !flow->settings.duration[READ] || (!flow_in_delay(flow, READ) && !flow_sending(flow, READ))) &&
				(flow->finished[WRITE] || !flow->settings.duration[WRITE] || (!flow_in_delay(flow, WRITE) && !flow_sending(flow, WRITE)))) {

				/* Nothing left to read, nothing left to send */
				/*get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info);*/
				uninit_flow(flow);
				remove_flow(--i);
				continue;
			}
		}

		if (flow->fd_reply != -1) {
			FD_SET(flow->fd_reply, rfds);
			FD_SET(flow->fd_reply, efds);
			*maxfd = MAX(*maxfd, flow->fd_reply);
		}
		if (flow->state == WAIT_ACCEPT_REPLY && flow->listenfd_reply != -1) {
			FD_SET(flow->listenfd_reply, rfds);
			*maxfd = MAX(*maxfd, flow->listenfd_reply);
		}
		if (flow->state == GRIND_WAIT_ACCEPT && flow->listenfd_data != -1) {
			FD_SET(flow->listenfd_data, rfds);
			*maxfd = MAX(*maxfd, flow->listenfd_data);
		}
		if (flow->fd != -1) {
			if (!flow->finished[READ])
				FD_SET(flow->fd, rfds);
			if (flow->settings.duration[WRITE] != 0)
				FD_SET(flow->fd, wfds);
			else
				flow->finished[WRITE] = 1;
			FD_SET(flow->fd, efds);
			*maxfd = MAX(*maxfd, flow->fd);
		}
	}

	return num_flows;
}

static void log_client_address(const struct sockaddr *sa, socklen_t salen)
{
	logging_log(LOG_NOTICE, "connection from %s", fg_nameinfo(sa, salen));
}

static int accept_reply(struct _flow *flow)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	flow->fd_reply = accept(flow->listenfd_reply, (struct sockaddr *)&addr, &addrlen);
	if (flow->fd_reply == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		
		logging_log(LOG_WARNING, "accept() failed: %s, continuing", strerror(errno));
		return 0;
	}
	if (close(flow->listenfd_reply) == -1)
		logging_log(LOG_WARNING, "close(): failed");
	flow->listenfd_reply = -1;

	set_non_blocking(flow->fd_reply);
	set_nodelay(flow->fd_reply);

	if (acl_check((struct sockaddr *)&addr) == ACL_DENY) {
		logging_log(LOG_WARNING, "Access denied for host %s",
				fg_nameinfo((struct sockaddr *)&addr, addrlen));
		close(flow->fd_reply);
		flow->fd_reply = -1;
		return 0;
	}

	log_client_address((struct sockaddr *)&addr, addrlen);

	flow->state = GRIND_WAIT_ACCEPT;

	return 0;
}

/* listen_port will receive the port of the created socket */
static int create_listen_socket(char *bind_addr, unsigned short *listen_port)
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
	if ((rc = getaddrinfo(bind_addr, "0",
			&hints, &res)) != 0) {
		logging_log(LOG_ALERT, "Error: getaddrinfo() failed: %s\n",
			gai_strerror(rc));
		/* XXX: Be nice and tell client. */
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

	freeaddrinfo(ressave);

	if (res == NULL) {
		logging_log(LOG_ALERT, "failed to create listen socket");
		return -1;
	}

	if (listen(fd, 0) < 0) {
		logging_log(LOG_ALERT, "listen failed: %s",
				strerror(errno));
		return -1;
	}

	set_non_blocking(fd);

	port = get_port(fd);
	if (port < 0) {
		close(fd);
		return -1;
	}
	*listen_port = (unsigned short)port;

	return fd;
}

void add_flow_destination(struct _request_add_flow_destination *request)
{
	struct _flow *flow;

	unsigned short server_reply_port;
	unsigned short server_data_port;

	if (num_flows >= MAX_FLOWS) {
		logging_log(LOG_WARNING, "Can not accept another flow, already handling MAX_FLOW flows.");
		request->r.error = "Can not accept another flow, already handling MAX_FLOW flows.";
		return;
	}

	flow = &flows[num_flows++];
	init_flow(flow, 0);

	flow->settings = request->settings;

	flow->write_block = calloc(1, flow->settings.write_block_size);
	flow->read_block = calloc(1, flow->settings.read_block_size);
	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging_log(LOG_ALERT, "could not allocate memory");
		request->r.error = "could not allocate memory";
		uninit_flow(flow);
		num_flows--;
		return;
	}

	/* Create listen socket for reply connection */
	if ((flow->listenfd_reply = create_listen_socket(0, &server_reply_port)) == -1) {
		logging_log(LOG_ALERT, "could not create listen socket");
		request->r.error = "could not create listen socket";
		uninit_flow(flow);
		num_flows--;
		return;
	}

	/* Create listen socket for data connection */
	if ((flow->listenfd_data = create_listen_socket(flow->settings.bind_address[0] ? flow->settings.bind_address : 0, &server_data_port)) == -1) {
		logging_log(LOG_ALERT, "could not create listen socket");
		request->r.error = "could not create listen socket";
		uninit_flow(flow);
		num_flows--;
		return;
	}

	flow->real_listen_send_buffer_size = set_window_size_directed(flow->listenfd_data, flow->settings.requested_send_buffer_size, SO_SNDBUF);
	flow->real_listen_receive_buffer_size = set_window_size_directed(flow->listenfd_data, flow->settings.requested_read_buffer_size, SO_RCVBUF);
	/* XXX: It might be too brave to report the window size of the listen
	 * socket to the client as the window size of test socket might differ
	 * from the reported one. Close the socket in that case. */

	request->listen_reply_port = (int)server_reply_port;
	request->listen_data_port = (int)server_data_port;
	request->real_listen_send_buffer_size = flow->real_listen_send_buffer_size;
	request->real_listen_read_buffer_size = flow->real_listen_receive_buffer_size;

	request->flow_id = flow->id;

	return;
}

static int accept_data(struct _flow *flow)
{
	struct sockaddr_storage caddr;
	socklen_t addrlen = sizeof(caddr);

	unsigned real_send_buffer_size;
	unsigned real_receive_buffer_size;

	flow->fd = accept(flow->listenfd_data, (struct sockaddr *)&caddr, &addrlen);
	if (flow->fd == -1) {
		if (errno == EINTR || errno == EAGAIN)
		{
			// TODO: Accept timeout
			// logging_log(LOG_ALERT, "client did not connect().");
			return 0;
		}
		
		logging_log(LOG_ALERT, "accept() failed: %s", strerror(errno));
		return -1;
	}
	/* XXX: Check if this is the same client. */
	if (close(flow->listenfd_data) == -1)
		logging_log(LOG_WARNING, "close(): failed");
	flow->listenfd_data = -1;

	logging_log(LOG_NOTICE, "client %s connected for testing.",
			fg_nameinfo((struct sockaddr *)&caddr, addrlen));
	real_send_buffer_size = set_window_size_directed(flow->fd, flow->settings.requested_send_buffer_size, SO_SNDBUF);
	if (flow->requested_server_test_port &&
			flow->real_listen_send_buffer_size != real_send_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set send buffer size of test "
				"socket to send buffer size size of listen socket "
				"(listen = %u, test = %u).",
				flow->real_listen_send_buffer_size, real_send_buffer_size);
		return -1;
	}
	real_receive_buffer_size = set_window_size_directed(flow->fd, flow->settings.requested_read_buffer_size, SO_RCVBUF);
	if (flow->requested_server_test_port &&
			flow->real_listen_receive_buffer_size != real_receive_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set receive buffer size (advertised window) of test "
				"socket to receive buffer size of listen socket "
				"(listen = %u, test = %u).",
				flow->real_listen_receive_buffer_size, real_receive_buffer_size);
		return -1;
	}
	if (flow->settings.route_record)
		set_route_record(flow->fd);
	if (flow->settings.advstats)
		fg_pcap_go(flow->fd);
	if (flow->settings.so_debug && set_so_debug(flow->fd)) {
		logging_log(LOG_WARNING, "Unable to set SO_DEBUG on test socket: %s",
				  strerror(errno));
	}
	if (flow->settings.cork && set_tcp_cork(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set TCP_CORK "
				"for flow id = %i: %s",
				flow->id, strerror(errno));

	set_non_blocking(flow->fd);

	DEBUG_MSG(2, "data socket accepted");
	flow->state = GRIND;

	return 0;
}

int write_data(struct _flow *flow);
int read_data(struct _flow *flow);
int read_reply(struct _flow *flow);

void destination_process_select(fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	unsigned int i = 0;
	while (i < num_flows) {
		struct timeval now;
		struct _flow *flow = &flows[i];

		/* If any function fails, the flow has ended. */
		if (flow->listenfd_reply != -1 && FD_ISSET(flow->listenfd_reply, rfds)) {
			if (flow->state == WAIT_ACCEPT_REPLY) {
				if (accept_reply(flow) == -1)
					goto remove;
			}
		}
		if (flow->listenfd_data != -1 && FD_ISSET(flow->listenfd_data, rfds)) {
			if (flow->state == GRIND_WAIT_ACCEPT) {
				if (accept_data(flow) == -1)
					goto remove;
			}
		}

		if (flow->fd_reply != -1 && FD_ISSET(flow->fd_reply, rfds))
			if (read_reply(flow) == -1)
				goto remove;

		if (flow->fd != -1) {
			if (FD_ISSET(flow->fd, efds)) {
				int error_number, rc;
				socklen_t error_number_size = sizeof(error_number);
				DEBUG_MSG(5, "sock of flow %d in efds", flow->id);
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

		tsc_gettimeofday(&now);

		if (flow->settings.shutdown &&
			time_is_after(&now, &flow->stop_timestamp[WRITE])) {
			DEBUG_MSG(4, "shutting down data connection.");
			if (shutdown(flow->fd, SHUT_WR) == -1) {
				logging_log(LOG_WARNING, "shutdown "
					"failed: %s", strerror(errno));
			}
			fg_pcap_dispatch();
		}

		i++;
		continue;
remove:
		// Flow has ended
#ifdef __LINUX__
		get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info);
#endif
		uninit_flow(flow);
		remove_flow(i);
	}
}
