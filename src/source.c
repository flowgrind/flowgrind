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

void remove_flow(unsigned int i);

#ifdef __LINUX__
int get_tcp_info(struct _flow *flow, struct tcp_info *info);
#endif

void init_flow(struct _flow* flow, int is_source);
void uninit_flow(struct _flow *flow);

static int name2socket(char *server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp, char do_connect)
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
		error(ERR_FATAL, "getaddrinfo() failed: %s",
				gai_strerror(n));
		return -1;
	}
	ressave = res;

	do {
		int rc;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

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

		error(ERR_WARNING, "Failed to connect to \"%s:%d\": %s",
				server_name, port, strerror(errno));
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		error(ERR_FATAL, "Could not establish connection to "
				"\"%s:%d\": %s", server_name, port, strerror(errno));
		return -1;
	}

	if (saptr && lenp) {
		*saptr = malloc(res->ai_addrlen);
		if (*saptr == NULL) {
			error(ERR_FATAL, "malloc(): failed: %s",
					strerror(errno));
		}
		memcpy(*saptr, res->ai_addr, res->ai_addrlen);
		*lenp = res->ai_addrlen;
	}

	freeaddrinfo(ressave);

	return fd;
}

int add_flow_source(struct _request_add_flow_source *request)
{
#ifdef __LINUX__
	socklen_t opt_len = 0;
#endif
	struct _flow *flow;

	if (num_flows >= MAX_FLOWS) {
		logging_log(LOG_WARNING, "Can not accept another flow, already handling MAX_FLOW flows.");
		request->r.error = "Can not accept another flow, already handling MAX_FLOW flows.";
		return -1;
	}

	flow = &flows[num_flows++];
	init_flow(flow, 1);

	flow->settings = request->settings;
	flow->source_settings = request->source_settings;

	flow->write_block = calloc(1, flow->settings.write_block_size);
	flow->read_block = calloc(1, flow->settings.read_block_size);
	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging_log(LOG_ALERT, "could not allocate memory");
		request->r.error = "could not allocate memory";
		uninit_flow(flow);
		num_flows--;
		return -1;
	}
	if (flow->source_settings.byte_counting) {
		int byte_idx;
		for (byte_idx = 0; byte_idx < flow->settings.write_block_size; byte_idx++)
			*(flow->write_block + byte_idx) = (unsigned char)(byte_idx & 0xff);
	}

	flow->fd_reply = name2socket(flow->source_settings.destination_host_reply,
				flow->source_settings.destination_port_reply, NULL, NULL, 1);
	if (flow->fd_reply == -1) {
		logging_log(LOG_ALERT, "could not connect reply socket");
		request->r.error = "could not connect reply socket";
		uninit_flow(flow);
		num_flows--;
		return -1;
	}
	flow->state = GRIND_WAIT_CONNECT;
	flow->fd = name2socket(flow->source_settings.destination_host,
			flow->source_settings.destination_port,
			&flow->addr, &flow->addr_len, 0);
	if (flow->fd == -1) {
		logging_log(LOG_ALERT, "could not create data socket");
		request->r.error = "could not create data socket";
		uninit_flow(flow);
		num_flows--;
		return -1;
	}

	set_non_blocking(flow->fd);
	set_non_blocking(flow->fd_reply);

	if (*flow->source_settings.cc_alg && set_congestion_control(
				flow->fd, flow->source_settings.cc_alg) == -1)
		error(ERR_FATAL, "Unable to set congestion control "
				"algorithm for flow id = %i: %s",
				flow->id, strerror(errno));

#ifdef __LINUX__
	opt_len = sizeof(request->cc_alg);
	if (getsockopt(flow->fd, IPPROTO_TCP, TCP_CONG_MODULE,
				request->cc_alg, &opt_len) == -1) {
		error(ERR_WARNING, "failed to determine actual congestion control "
				"algorithm for flow %d: %s: ", flow->id,
				strerror(errno));
		request->cc_alg[0] = '\0';
	}
#endif

	if (flow->source_settings.elcn && set_so_elcn(flow->fd, flow->source_settings.elcn) == -1)
		error(ERR_FATAL, "Unable to set TCP_ELCN "
				"for flow id = %i: %s",
				flow->id, strerror(errno));

	if (flow->source_settings.icmp && set_so_icmp(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set TCP_ICMP "
				"for flow id = %i: %s",
				flow->id, strerror(errno));

	if (flow->settings.cork && set_tcp_cork(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set TCP_CORK "
				"for flow id = %i: %s",
				flow->id, strerror(errno));

	if (flow->settings.so_debug && set_so_debug(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set SO_DEBUG "
				"for flow id = %i: %s",
				flow->id, strerror(errno));

	if (flow->settings.route_record && set_route_record(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set route record "
				"option for flow id = %i: %s",
				flow->id, strerror(errno));

	if (flow->source_settings.dscp && set_dscp(flow->fd, flow->source_settings.dscp) == -1)
		error(ERR_FATAL, "Unable to set DSCP value"
				"for flow %d: %s", flow->id, strerror(errno));

	if (flow->source_settings.ipmtudiscover && set_ip_mtu_discover(flow->fd) == -1)
		error(ERR_FATAL, "Unable to set IP_MTU_DISCOVER value"
				"for flow %d: %s", flow->id, strerror(errno));


	if (!flow->source_settings.late_connect) {
		DEBUG_MSG(4, "(early) connecting test socket");
		connect(flow->fd, flow->addr, flow->addr_len);
		flow->connect_called = 1;
		flow->mtu = get_mtu(flow->fd);
		flow->mss = get_mss(flow->fd);
	}

	request->flow_id = flow->id;

	return 0;
}
