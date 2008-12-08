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

#define	MAX_FLOWS	256
#define CONGESTION_LIMIT 	10000

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

enum flow_state
{
	WAIT_CONNECT_REPLY,
	GRIND_WAIT_CONNECT,
	GRIND
};

#define INTERVAL 0
#define TOTAL 1
struct _flow
{
	int id;

	enum flow_state state;

	int fd_reply;
	int fd;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct timeval start_timestamp[2];
	struct timeval stop_timestamp[2];
	struct timeval last_block_read;
	struct timeval last_block_written;

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
		long bytes_read;
		long bytes_written;
		long reply_blocks_read;

		double rtt_min, rtt_max, rtt_sum;
		double iat_min, iat_max, iat_sum;

#ifdef __LINUX__
		struct tcp_info tcp_info;
#endif

	} statistics[2];
};

static struct _flow flows[MAX_FLOWS];

static unsigned int num_flows = 0;

struct _timer {
	struct timeval start;
	struct timeval next;
	struct timeval last;
};
static struct _timer timer;
static struct timeval now;

static char started = 0;

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

static int flow_block_scheduled(struct _flow *flow)
{
	return !flow->settings.write_rate ||
		time_is_after(&now, &flow->next_write_block_timestamp);
}

static void remove_flow(unsigned int i)
{
	for (unsigned int j = i; j < num_flows - 1; j++)
		flows[j] = flows[j + 1];
	num_flows--;
	if (!num_flows)
		started = 0;
}

#ifdef __LINUX__
static int get_tcp_info(struct _flow *flow, struct tcp_info *info) {
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

static void prepare_wfds(struct _flow *flow, fd_set *wfds)
{
	int rc = 0;

	if (flow_in_delay(flow, WRITE)) {
		DEBUG_MSG(4, "flow %i not started yet (delayed)", flow->id);
		return;
	}

	if (flow_sending(flow, WRITE)) {
		assert(!flow->finished[WRITE]);
		if (flow_block_scheduled(flow)) {
			DEBUG_MSG(4, "adding sock of flow %d to wfds", flow->id);
			FD_SET(flow->fd, wfds);
		} else {
			DEBUG_MSG(4, "no block for flow %d scheduled yet", flow->id);
		}
	} else if (!flow->finished[WRITE]) {
		flow->finished[WRITE] = 1;
		if (flow->settings.shutdown) {
			DEBUG_MSG(4, "shutting down flow %d (WR)", flow->id);
			rc = shutdown(flow->fd, SHUT_WR);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown() SHUT_WR failed: %s",
						strerror(errno));
			}
		}
	}

	return;
}

static int prepare_rfds(struct _flow *flow, fd_set *rfds)
{
	int rc = 0;

	if (!flow_in_delay(flow, READ) && !flow_sending(flow, READ)) {
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
		DEBUG_MSG(1, "late connecting test socket "
				"for flow %d after %.3fs delay",
				flow->id, flow->settings.delay[WRITE]);
		rc = connect(flow->fd, flow->addr,
				flow->addr_len);
		if (rc == -1 && errno != EINPROGRESS) {
			error(ERR_WARNING, "Connect failed: %s",
					strerror(errno));
//xx_stop
			return -1;
		}
		flow->connect_called = 1;
		flow->mtu = get_mtu(flow->fd);
		flow->mss = get_mss(flow->fd);
	}

	/* Altough the server flow might be finished we keep the socket in
	 * rfd in order to check for buggy servers */
	if (flow->connect_called && !flow->finished[READ]) {
		DEBUG_MSG(4, "adding sock of flow %d to rfds", flow->id);
		FD_SET(flow->fd, rfds);
	}

	return 0;
}

static void uninit_flow(struct _flow *flow)
{
	if (flow->fd_reply != -1)
		close(flow->fd_reply);
	if (flow->fd != -1)
		close(flow->fd);
	if (flow->read_block)
		free(flow->read_block);
	if (flow->write_block)
		free(flow->write_block);
	if (flow->addr)
		free(flow->addr);
}

int source_prepare_fds(fd_set *rfds, fd_set *wfds, fd_set *efds, int *maxfd)
{
	unsigned int i = 0;
	if (!started)
		return num_flows;

	while (i < num_flows) {
		struct _flow *flow = &flows[i++];

		if ((flow->finished[READ] || !flow->settings.duration[READ] || (!flow_in_delay(flow, READ) && !flow_sending(flow, READ))) &&
			(flow->finished[WRITE] || !flow->settings.duration[WRITE] || (!flow_in_delay(flow, WRITE) && !flow_sending(flow, WRITE)))) {

			/* Nothing left to read, nothing left to send */
			get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info);
			uninit_flow(flow);
			remove_flow(--i);
			continue;
		}

		if (flow->fd != -1) {
			FD_SET(flow->fd, efds);
			*maxfd = MAX(*maxfd, flow->fd);
		}

		if (flow->fd_reply != -1) {
			FD_SET(flow->fd_reply, rfds);
			*maxfd = MAX(*maxfd, flow->fd_reply);
		}

		prepare_wfds(flow, wfds);
		prepare_rfds(flow, rfds);
	}

	return num_flows;
}

static void init_flow(struct _flow *flow)
{
	flow->state = WAIT_CONNECT_REPLY;
	flow->fd_reply = -1;
	flow->fd = -1;

	flow->read_block = 0;
	flow->read_block_bytes_read = 0;
	flow->read_block_count = 0;
	flow->write_block = 0;
	flow->write_block_bytes_written = 0;
	flow->write_block_count = 0;

	flow->reply_block_bytes_read = 0;

	flow->last_block_read.tv_sec = 0;
	flow->last_block_read.tv_usec = 0;

	flow->connect_called = 0;
	flow->finished[WRITE] = flow->finished[READ] = 0;

	flow->addr = 0;

	/* INTERVAL and TOTAL */
	for (int i = 0; i< 2; i++) {
		flow->statistics[i].bytes_read = 0;
		flow->statistics[i].bytes_written = 0;
		flow->statistics[i].reply_blocks_read = 0;

		flow->statistics[i].rtt_min = +INFINITY;
		flow->statistics[i].rtt_max = -INFINITY;
		flow->statistics[i].rtt_sum = 0;

		flow->statistics[i].iat_min = +INFINITY;
		flow->statistics[i].iat_max = -INFINITY;
		flow->statistics[i].iat_sum = 0;
	}

	flow->congestion_counter = 0;	
}

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

		error(ERR_WARNING, "Failed to connect to \"%s\": %s",
				server_name, strerror(errno));
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		error(ERR_FATAL, "Could not establish connection to "
				"\"%s\": %s", server_name, strerror(errno));
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
	init_flow(flow);

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

	if (flow->source_settings.cork && set_tcp_cork(flow->fd) == -1)
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

	return 0;
}

static double flow_interpacket_delay(struct _flow *flow)
{
	double delay = 0;

	DEBUG_MSG(5, "flow %d has rate %u", flow->id, flow->settings.write_rate);
	if (flow->settings.poisson_distributed) {
		double urand = (double)((random()+1.0)/(RANDOM_MAX+1.0));
		double erand = -log(urand) * 1/(double)flow->settings.write_rate;
		delay = erand;
	} else {
		delay = (double)1/flow->settings.write_rate;
	}

	DEBUG_MSG(5, "new interpacket delay %.6f for flow %d.", delay, flow->id);
	return delay;
}

static int write_data(struct _flow *flow)
{
	int rc = 0;

	/* Please note: you could argue that the following loop
	   is not necessary as not filling the socket send queue completely
	   would make the next select call return this very socket in wfds
	   and thus sending more blocks would immediately happen. However,
	   calling select with a non-full send queue might make the kernel
	   think we don't have more data to send. As a result, the kernel
	   might trigger some scheduling or whatever heuristics which would
	   not take place if we had written immediately. On the other hand,
	   in case the network is not a bottleneck the loop may take forever. */
	/* XXX: Detect this! */
	for (;;) {
		if (flow->write_block_bytes_written == 0) {
			DEBUG_MSG(5, "new write block %llu on flow %d",
					(long long unsigned int)flow->write_block_count, flow->id);
			flow->write_block[0] = sizeof(struct timeval) + 1;
			tsc_gettimeofday((struct timeval *)(flow->write_block + 1));
		}

		rc = write(flow->fd,
				flow->write_block +
				flow->write_block_bytes_written,
				flow->settings.write_block_size -
				flow->write_block_bytes_written);

		if (rc == -1) {
			if (errno == EAGAIN) {
				DEBUG_MSG(5, "write queue limit hit "
						"for flow %d", flow->id);
				break;
			}
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
//xx_stop
			return -1;
		}

		if (rc == 0) {
			DEBUG_MSG(5, "flow %d sent zero bytes. what does that mean?", flow->id);
			break;
		}

		DEBUG_MSG(4, "flow %d sent %d bytes of %u (already = %u)", flow->id, rc,
				flow->settings.write_block_size,
				flow->write_block_bytes_written);

		flow->statistics[INTERVAL].bytes_written += rc;
		flow->statistics[TOTAL].bytes_written += rc;
		flow->write_block_bytes_written += rc;
		if (flow->write_block_bytes_written >=
				flow->settings.write_block_size) {
			flow->write_block_bytes_written = 0;
			tsc_gettimeofday(&flow->last_block_written);
			flow->write_block_count++;

			if (flow->settings.write_rate) {
				time_add(&flow->next_write_block_timestamp,
						flow_interpacket_delay(flow));
				if (time_is_after(&now, &flow->next_write_block_timestamp)) {
					/* TODO: log time_diff and check if
					 * it's growing (queue build up) */
					DEBUG_MSG(3, "incipient congestion on "
							"flow %u (block %llu): "
							"new block scheduled "
							"for %s, %.6lfs before now.",
							flow->id,
							flow->write_block_count,
							ctime_us(&flow->next_write_block_timestamp),
							time_diff(&flow->next_write_block_timestamp, &now));
					flow->congestion_counter++;
					if (flow->congestion_counter >
							CONGESTION_LIMIT &&
							flow->settings.flow_control) {
//xx_stop
						return -1;
					}
					
				}
			}
			if (flow->source_settings.cork && toggle_tcp_cork(flow->fd) == -1)
				DEBUG_MSG(4, "failed to recork test socket "
						"for flow %d: %s",
						flow->id, strerror(errno));
		}

		if (!flow->settings.pushy)
			break;
	}
	return 0;
}

static int read_data(struct _flow *flow)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;
	char cbuf[512];
	struct cmsghdr *cmsg;

	for (;;) {
		if (flow->read_block_bytes_read == 0)
			DEBUG_MSG(5, "new read block %llu on flow %d",
					(long long unsigned int)flow->read_block_count, flow->id);

		iov.iov_base = flow->read_block +
			flow->read_block_bytes_read;
		iov.iov_len = flow->settings.read_block_size -
			flow->read_block_bytes_read;
		// no name required
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		rc = recvmsg(flow->fd, &msg, 0);

		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
//xx_stop
			return -1;
		}

		if (rc == 0) {
			DEBUG_MSG(1, "server shut down test socket "
					"of flow %d", flow->id);
			if (!flow->finished[READ] ||
					!flow->settings.shutdown)
				error(ERR_WARNING, "Premature shutdown of "
						"server flow");
			flow->finished[READ] = 1;
			if (flow->finished[WRITE]) {
				DEBUG_MSG(4, "flow %u finished", flow->id);
//xx_stop
				return -1;
			}
			return 0;
		}

		DEBUG_MSG(4, "flow %d received %u bytes", flow->id, rc);

#if 0
		if (flow->settings[DESTINATION].duration[WRITE] == 0)
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (no two-way)", id);
		else if (server_flow_in_delay(id))
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (too early)", id);
		else if (!server_flow_sending(id))
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (too late)", id);
#endif

		flow->statistics[INTERVAL].bytes_read += rc;
		flow->statistics[TOTAL].bytes_read += rc;
		flow->read_block_bytes_read += rc;
		if (flow->read_block_bytes_read >= flow->settings.read_block_size) {
			assert(flow->read_block_bytes_read == flow->settings.read_block_size);
			flow->read_block_bytes_read = 0;
			tsc_gettimeofday(&flow->last_block_read);
			flow->read_block_count++;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			DEBUG_MSG(2, "flow %d received cmsg: type = %u, len = %u",
					flow->id, cmsg->cmsg_type, cmsg->cmsg_len);
		}

		if (!flow->settings.pushy)
			break;
	}
	return 0;
}

static void process_reply(struct _flow* flow)
{
	/* XXX: There is actually a conversion from
		network to host byte order needed here!! */
	struct timeval *sent = (struct timeval *)(flow->reply_block + 1);
	double current_rtt;
	double *current_iat_ptr = (double *)(flow->reply_block + sizeof(struct timeval) + 1);

	tsc_gettimeofday(&now);
	current_rtt = time_diff(sent, &now);

	if ((!isnan(*current_iat_ptr) && *current_iat_ptr <= 0) || current_rtt <= 0) {
		DEBUG_MSG(5, "illegal reply_block: isnan = %d, iat = %e, rtt = %e", isnan(*current_iat_ptr), *current_iat_ptr, current_rtt);
		error(ERR_WARNING, "Found block with illegal round trip time or illegal inter arrival time, ignoring block.");
		return ;
	}

	/* Update statistics for flow, both INTERVAL and TOTAL. */
	for (int i = 0; i < 2; i++) {
		flow->statistics[i].reply_blocks_read++;

		/* Round trip times */
		ASSIGN_MIN(flow->statistics[i].rtt_min, current_rtt);
		ASSIGN_MAX(flow->statistics[i].rtt_max, current_rtt);
		flow->statistics[i].rtt_sum += current_rtt;
	
		/* Inter arrival times */
		if (!isnan(*current_iat_ptr)) {
			ASSIGN_MIN(flow->statistics[i].iat_min, *current_iat_ptr);
			ASSIGN_MAX(flow->statistics[i].iat_max, *current_iat_ptr);
			flow->statistics[i].iat_sum += *current_iat_ptr;
		}

	}
	// XXX: else: check that this only happens once!
	DEBUG_MSG(4, "processed reply_block of flow %d, (RTT = %.3lfms, IAT = %.3lfms)", flow->id, current_rtt * 1e3, isnan(*current_iat_ptr) ? NAN : *current_iat_ptr * 1e3);
}

static int read_reply(struct _flow *flow)
{
	int rc = 0;

	for (;;) {
		rc = recv(flow->fd_reply,
				flow->reply_block + flow->reply_block_bytes_read,
				sizeof(flow->reply_block) -
				flow->reply_block_bytes_read, 0);
		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
//xx_stop
			return -1;
		}

		if (rc == 0) {
			error(ERR_WARNING, "Premature end of test: server "
					"shut down control of flow %d.", flow->id);
//xx_stop
			return -1;
		}

		flow->reply_block_bytes_read += rc;
		if (flow->reply_block_bytes_read >=
				sizeof(flow->reply_block)) {
			process_reply(flow);
			flow->reply_block_bytes_read = 0;
		} else {
			DEBUG_MSG(4, "got partial reply_block for flow %d", flow->id);
		}

	}
	return 0;
}

void source_process_select(fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	unsigned int i = 0;
	tsc_gettimeofday(&now);
	while (i < num_flows) {
		struct _flow *flow = &flows[i];

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

/*		tsc_gettimeofday(&now);

		if (flow->fd != -1 && flow->settings.shutdown &&
			time_is_after(&now, &flow->stop_timestamp[WRITE])) {
			DEBUG_MSG(4, "shutting down data connection.");
			if (shutdown(flow->fd, SHUT_WR) == -1) {
				logging_log(LOG_WARNING, "shutdown "
					"failed: %s", strerror(errno));
			}
			fg_pcap_dispatch();
		}*/

		i++;
		continue;
remove:
		// Flow has ended
		get_tcp_info(flow, &flow->statistics[TOTAL].tcp_info);
		uninit_flow(flow);
		remove_flow(i);
	}
}

void source_start_flows(int start_timestamp)
{
	tsc_gettimeofday(&timer.start);
	if (timer.start.tv_sec < start_timestamp) {
		/* If the clock is syncrhonized between nodes, all nodes will start 
		   at the same time regardless of any RPC delays */
		timer.start.tv_sec = start_timestamp;
		timer.start.tv_usec = 0;
	}
	timer.last = timer.next = timer.start;
	time_add(&timer.next, reporting_interval);

	for (unsigned int i = 0; i < num_flows; i++) {
		struct _flow *flow = &flows[i];

		/* READ and WRITE */
		for (int j = 0; j < 2; j++) {
			flow->start_timestamp[j] = timer.start;
			time_add(&flow->start_timestamp[j], flow->settings.delay[j]);
			if (flow->settings.duration[j] >= 0) {
				flow->stop_timestamp[j] = flow->start_timestamp[j];
				time_add(&flow->stop_timestamp[j], flow->settings.duration[j]);
			}
		}
		if (flow->settings.write_rate)
			flow->next_write_block_timestamp = flow->start_timestamp[WRITE];

	}

	started = 1;
}

static void report_flow(struct _flow* flow)
{
	printf("TODO: report_flow\n");
}

void source_timer_check()
{
	if (!started)
		return;

	tsc_gettimeofday(&now);
	if (time_is_after(&now, &timer.next)) {
		for (unsigned int i = 0; i < num_flows; i++) {
			struct _flow *flow = &flows[i];

#ifdef __LINUX__
			get_tcp_info(flow, &flow->statistics[INTERVAL].tcp_info);
#endif
			report_flow(flow);
		}
		timer.last = now;
		while (time_is_after(&now, &timer.next))
			time_add(&timer.next, reporting_interval);
	}
}
