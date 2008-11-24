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

#include "common.h"
#include "debug.h"
#include "fg_pcap.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"
#include "svnversion.h"

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

#define	MAX_FLOWS	256

enum flow_state
{
	WRITE_GREETING,
	READ_PROPOSAL,
	WRITE_REPLY,
	GRIND_WAIT_ACCEPT,
	GRIND
};

struct _flow
{
	enum flow_state state;

	int fd_control;
	int listenfd;
	int fd;

	struct timeval start;
	struct timeval end;
	struct timeval start_timestamp;
	struct timeval stop_timestamp;
	struct timeval last_block_read;

	double delay;
	double duration;

	void* control_send_buffer;
	unsigned int control_send_buffer_len;
	unsigned int control_send_buffer_pos;

	char control_read_buffer[1024];
	unsigned int control_read_buffer_pos;

	char *read_block;
	unsigned read_block_size;
	unsigned read_block_bytes_read;

	char *write_block;
	unsigned write_block_size;
	unsigned write_block_bytes_written;

	unsigned short requested_server_test_port;

	unsigned requested_send_buffer_size;
	unsigned requested_receive_buffer_size;
	unsigned real_listen_send_buffer_size;
	unsigned real_listen_receive_buffer_size;

	char advstats;
	char so_debug;
	char route_record;
	char pushy;
	char server_shutdown;

	char reply_block_length;

	char got_eof;

	socklen_t addrlen;
} flows[MAX_FLOWS];

unsigned int num_flows = 0;

fd_set rfds, wfds, efds;

int listenfd, maxfd;

#define ACL_ALLOW	1
#define ACL_DENY	0

typedef struct acl {
	struct acl *next;
	struct sockaddr_storage sa;
	int mask;
} acl_t;

acl_t *acl_head = NULL;

int acl_allow_add (char *);
acl_t *acl_allow_add_list (acl_t *, struct sockaddr *, int);
int acl_check (struct sockaddr *);

int
acl_allow_add (char *str)
{
	struct addrinfo hints, *res;
	char *pmask = NULL;
	int mask = -1;
	int rc;

	pmask = strchr(str, '/');
	if (pmask != NULL) {
		*pmask++ = '\0';
		mask = atoi(pmask);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(str, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo(): failed, %s\n",
				gai_strerror(rc));
		exit(1);
	}

	acl_head = acl_allow_add_list(acl_head, res->ai_addr, mask);

	freeaddrinfo(res);

	return 0;
}

acl_t *
acl_allow_add_list (acl_t *acl, struct sockaddr *ss, int mask)
{
	if (acl == NULL) {
		acl = malloc(sizeof(acl_t));
		if (acl == NULL) {
			logging_log(LOG_WARNING, "malloc: %s", strerror(errno));
			exit(1);
		}
		acl->next = NULL;
		memcpy(&acl->sa, ss, sizeof(struct sockaddr_storage));
		acl->mask = mask;
	} else {
		acl->next = acl_allow_add_list(acl->next, ss, mask);
	}

	return acl;
}

int
acl_check (struct sockaddr *sa)
{
	struct sockaddr *acl_sa = NULL;
	struct sockaddr_in *sin = NULL, *acl_sin = NULL;
	struct sockaddr_in6 *sin6 = NULL, *acl_sin6 = NULL;
	acl_t *acl = NULL;
	int allow, i;

	if (acl_head == NULL) {
		return ACL_ALLOW;
	}

	for (acl = acl_head; acl != NULL; acl = acl->next) {

		acl_sa = (struct sockaddr *)&acl->sa;

		if (sa->sa_family != acl_sa->sa_family) {
			continue;
		}

		switch (sa->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)sa;
			acl_sin = (struct sockaddr_in *)acl_sa;

			if (acl->mask == -1) {
				acl->mask = 32;
			}

			if (acl->mask < 1 || acl->mask > 32) {
				fprintf(stderr, "Error: Bad netmask.\n");
				break;
			}

			if ((ntohl(sin->sin_addr.s_addr) >>
						(32 - acl->mask)) ==
					(ntohl(acl_sin->sin_addr.s_addr) >>
					 (32 - acl->mask))) {
				return ACL_ALLOW;
			}

			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			acl_sin6 = (struct sockaddr_in6 *)acl_sa;

			if (acl->mask == -1) {
				acl->mask = 128;
			}

			if (acl->mask < 1 || acl->mask > 128) {
				fprintf(stderr, "Error: Bad netmask.\n");
				break;
			}

			allow = 1;

			for (i = 0; i < (acl->mask / 8); i++) {
				if (sin6->sin6_addr.s6_addr[i]
					!= acl_sin6->sin6_addr.s6_addr[i]) {
					allow = 0;
					break;
				}
			}

			if ((sin6->sin6_addr.s6_addr[i] >>
			    (8 - (acl->mask % 8))) !=
					(acl_sin6->sin6_addr.s6_addr[i] >>
					 (8 - (acl->mask % 8)))) {
				allow = 0;
			}

			if (allow) {
				return ACL_ALLOW;
			}

			break;

		default:
			logging_log(LOG_WARNING, "Unknown address family.");
			break;
		}
	}

	return ACL_DENY;
}

void __attribute__((noreturn))
usage(void)
{
	fprintf(stderr, "Usage: flowgrindd [-a address ] [-w#] [-p#] [-d]\n");
	fprintf(stderr, "\t-a address\tadd address to list of allowed hosts "
			"(CIDR syntax)\n");
	fprintf(stderr, "\t-p#\t\tserver port\n");
	fprintf(stderr, "\t-D \t\tincrease debug verbosity (no daemon, log to "
					"stderr)\n");
	fprintf(stderr, "\t-V\t\tPrint version information and exit\n");
	exit(1);
}

void
sighandler(int sig)
{
	int status;

	switch (sig) {
	case SIGCHLD:
		while (waitpid(-1, &status, WNOHANG) > 0)
			logging_log(LOG_NOTICE, "child returned (status = %d)",
					status);
		break;

	case SIGHUP:
		logging_log(LOG_NOTICE, "got SIGHUP, don't know what do do.");
		break;

	case SIGALRM:
		DEBUG_MSG(1, "Caught SIGALRM.");
		break;

	case SIGPIPE:
		break;

	default:
		logging_log(LOG_ALERT, "got signal %d, but don't remember "
				"intercepting it, aborting...", sig);
		abort();
	}
}

void prepare_fds() {
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(listenfd, &rfds);
	maxfd = listenfd;

	for (unsigned int i = 0; i < num_flows; i++) {
		struct _flow *flow = &flows[i];

		FD_SET(flow->fd_control, &rfds);
		FD_SET(flow->fd_control, &efds);
		if (flow->state == WRITE_GREETING || flow->state == WRITE_REPLY || (flow->state == GRIND && flow->control_send_buffer))
			FD_SET(flow->fd_control, &wfds);
		if (flow->state == GRIND_WAIT_ACCEPT && flow->listenfd != -1) {
			FD_SET(flow->listenfd, &rfds);
			maxfd = MAX(maxfd, flow->listenfd);
		}
		if (flow->fd != -1) {
			if (!flow->got_eof)
				FD_SET(flow->fd, &rfds);
			if (flow->duration != 0)
				FD_SET(flow->fd, &wfds);
			FD_SET(flow->fd, &efds);
			maxfd = MAX(maxfd, flow->fd);
		}
		maxfd = MAX(maxfd, flow->fd_control);
	}
}

void log_client_address(const struct sockaddr *sa, socklen_t salen)
{
	logging_log(LOG_NOTICE, "connection from %s", fg_nameinfo(sa, salen));
}

void init_flow(unsigned int i, int fd_control)
{
	flows[i].state = WRITE_GREETING;
	flows[i].fd_control = fd_control;
	flows[i].listenfd = -1;
	flows[i].control_send_buffer = malloc(sizeof(FLOWGRIND_PROT_GREETING) - 1);
	memcpy(flows[i].control_send_buffer, FLOWGRIND_PROT_GREETING, sizeof(FLOWGRIND_PROT_GREETING) - 1);
	flows[i].control_send_buffer_pos = 0;
	flows[i].control_send_buffer_len = sizeof(FLOWGRIND_PROT_GREETING) - 1;
	flows[i].fd = -1;

	flows[i].read_block = 0;
	flows[i].read_block_bytes_read = 0;
	flows[i].write_block = 0;
	flows[i].write_block_bytes_written = 0;

	flows[i].last_block_read.tv_sec = 0;
	flows[i].last_block_read.tv_usec = 0;

	flows[i].got_eof = 0;
}

void uninit_flow(struct _flow *flow)
{
	if (flow->fd_control != -1)
		close(flow->fd_control);
	if (flow->listenfd != -1)
		close(flow->listenfd);
	if (flow->fd != -1)
		close(flow->fd);
	if (flow->control_send_buffer)
		free(flow->control_send_buffer);
	if (flow->read_block)
		free(flow->read_block);
	if (flow->write_block)
		free(flow->write_block);
}

void accept_control()
{
	int fd_control;

	struct sockaddr_storage caddr;
	socklen_t addrlen = sizeof(caddr);

	fd_control = accept(listenfd, (struct sockaddr *)&caddr, &addrlen);
	if (fd_control == -1) {
		if (errno != EINTR) {
			logging_log(LOG_WARNING, "accept(): failed, "
				"continuing");
		}
		return;
	}

	set_non_blocking(fd_control);
	set_nodelay(fd_control);

	if (num_flows >= MAX_FLOWS) {
		logging_log(LOG_WARNING, "Can not accept another flow, already handling MAX_FLOW flows.");
		close(fd_control);
		return;
	}

	if (acl_check((struct sockaddr *)&caddr) == ACL_DENY) {
		logging_log(LOG_WARNING, "Access denied for host %s",
				fg_nameinfo((struct sockaddr *)&caddr, addrlen));
		close(fd_control);
		return;
	}

	log_client_address((struct sockaddr *)&caddr, addrlen);

	init_flow(num_flows++, fd_control);
}

int write_control_data(struct _flow *flow)
{
	if (!flow->control_send_buffer || flow->control_send_buffer_len <= flow->control_send_buffer_pos) {
		logging_log(LOG_WARNING, "write_control_data called with nothing to send");
		return -1;
	}

	int rc = write(flow->fd_control, flow->control_send_buffer + flow->control_send_buffer_pos,
			flow->control_send_buffer_len - flow->control_send_buffer_pos);

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		logging_log(LOG_WARNING, "sending control data failed: %s", strerror(errno));
		return -1;
	}
	else if (!rc) {
		logging_log(LOG_WARNING, "control connection closed");
		return -1;
	}

	flow->control_send_buffer_pos += rc;
	if (flow->control_send_buffer_len == flow->control_send_buffer_pos) {
		free(flow->control_send_buffer);
		flow->control_send_buffer = 0;
		if (flow->state == WRITE_GREETING)
			flow->state = READ_PROPOSAL;
		else if (flow->state == WRITE_REPLY)
			flow->state = GRIND_WAIT_ACCEPT;
	}
	return 0;
}

int process_proposal(struct _flow *flow) {

	DEBUG_MSG(1, "proposal: %s", flow->control_read_buffer);

	int rc;
	char *buf_ptr;
	char *server_name;
	char server_service[7];

	unsigned short server_test_port;

	struct addrinfo hints, *res, *ressave;
	int on = 1;

	buf_ptr = flow->control_read_buffer;
	rc = memcmp(buf_ptr, FLOWGRIND_PROT_CALLSIGN, sizeof(FLOWGRIND_PROT_CALLSIGN) - 1);
	if (rc != 0) {
		logging_log(LOG_WARNING, "malformed callsign, not "
				"flowgrind connecting?");
		return -1;
	}
	buf_ptr += sizeof(FLOWGRIND_PROT_CALLSIGN) - 1;
	if (*buf_ptr != ',') {
		logging_log(LOG_WARNING, "callsign not followed by "
				"seperator");
		return -1;
	}
	buf_ptr++;
	rc = memcmp(buf_ptr, FLOWGRIND_PROT_VERSION, sizeof(FLOWGRIND_PROT_VERSION) - 1);
	if (rc != 0) {
		logging_log(LOG_WARNING, "malformed protocol version");
		return -1;
	}
	buf_ptr += sizeof(FLOWGRIND_PROT_VERSION) - 1;
	if (*buf_ptr != ',') {
		logging_log(LOG_WARNING, "protocol version not followed by "
				"','");
		return -1;
	}
	buf_ptr++;
	if ((buf_ptr[0] != 't') || (buf_ptr[1] != ',')) {
		logging_log(LOG_WARNING, "unknown test proposal type");
		return -1;
	}
	buf_ptr += 2;

	server_name = buf_ptr;
	if ((buf_ptr = strchr(buf_ptr, ',')) == NULL) {
		logging_log(LOG_WARNING, "malformed server name in proposal");
		return -1;
	}
	*buf_ptr++ = '\0';

	rc = sscanf(buf_ptr, "%hu,%hhd,%hhd,%u,%u,%lf,%lf,%u,%u,%hhd,%hhd,%hhd, %hhdz+",
			&flow->requested_server_test_port, &flow->advstats, &flow->so_debug,
			&flow->requested_send_buffer_size, &flow->requested_receive_buffer_size,
			&flow->delay, &flow->duration,
			&flow->read_block_size, &flow->write_block_size, &flow->pushy,
			&flow->server_shutdown, &flow->route_record, &flow->reply_block_length);
	if (rc != 13) {
		logging_log(LOG_WARNING, "malformed TCP session "
			"proposal from client");
		return -1;
	}
	snprintf(server_service, sizeof(server_service), "%hu",
			flow->requested_server_test_port);

	flow->write_block = calloc(1, flow->write_block_size);
	flow->read_block = calloc(1, flow->read_block_size);
	if (flow->write_block == NULL || flow->read_block == NULL) {
		logging_log(LOG_ALERT, "could not allocate memory");
		return -1;
	}

	/* Create socket for client to send test data to. */
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(server_name, server_service,
			&hints, &res)) != 0) {
		logging_log(LOG_ALERT, "Error: getaddrinfo() failed: %s\n",
			gai_strerror(rc));
		/* XXX: Be nice and tell client. */
		return -1;
	}

	ressave = res;

	do {
		flow->listenfd = socket(res->ai_family, res->ai_socktype,
			res->ai_protocol);
		if (flow->listenfd < 0)
			continue;

		/* XXX: Do we need this? */
		if (setsockopt(flow->listenfd, SOL_SOCKET, SO_REUSEADDR,
					(char *)&on, sizeof(on)) == -1) {
			logging_log(LOG_ALERT, "setsockopt(SO_REUSEADDR): "
					"failed, continuing: %s",
					strerror(errno));
		}

		if (bind(flow->listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		close(flow->listenfd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		freeaddrinfo(ressave);
		logging_log(LOG_ALERT, "failed to create listen socket");
		return -1;
	}

	if (listen(flow->listenfd, 0) < 0) {
		freeaddrinfo(ressave);
		logging_log(LOG_ALERT, "listen failed: %s",
				strerror(errno));
		return -1;
	}

	rc = getsockname(flow->listenfd, res->ai_addr, &(res->ai_addrlen));
	if (rc == -1) {
		freeaddrinfo(ressave);
		logging_log(LOG_ALERT, "getsockname() failed: %s",
				strerror(errno));
		return -1;
	}
	switch (res->ai_addr->sa_family) {
	case AF_INET:
		server_test_port = ntohs((
			(struct sockaddr_in *)(res->ai_addr))->sin_port);
		break;

	case AF_INET6:
		server_test_port = ntohs((
			(struct sockaddr_in6 *)(res->ai_addr))->sin6_port);
		break;

	default:
		freeaddrinfo(ressave);
		logging_log(LOG_ALERT, "Unknown address family.");
		return -1;

	}

	flow->addrlen = res->ai_addrlen;
	freeaddrinfo(ressave);

	flow->real_listen_send_buffer_size = set_window_size_directed(flow->listenfd, flow->requested_send_buffer_size, SO_SNDBUF);
	flow->real_listen_receive_buffer_size = set_window_size_directed(flow->listenfd, flow->requested_receive_buffer_size, SO_RCVBUF);
	/* XXX: It might be too brave to report the window size of the listen
	 * socket to the client as the window size of test socket might differ
	 * from the reported one. Close the socket in that case. */

	flow->control_send_buffer = malloc(1024);
	flow->control_send_buffer_len = snprintf(flow->control_send_buffer, 1024, "%u,%u,%u+", server_test_port,
			flow->real_listen_send_buffer_size, flow->real_listen_receive_buffer_size);
	DEBUG_MSG(1, "proposal reply: %s", (char*)flow->control_send_buffer);
	flow->control_send_buffer_pos = 0;

	flow->state = WRITE_REPLY;

	return 0;
}

int read_control_data(struct _flow *flow)
{
	int rc = recv(flow->fd_control, flow->control_read_buffer + flow->control_read_buffer_pos,
			sizeof(flow->control_read_buffer) - flow->control_read_buffer_pos, 0);

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		logging_log(LOG_WARNING, "sending control data failed: %s", strerror(errno));
		return -1;
	}
	else if (!rc) {
		logging_log(LOG_WARNING, "control connection closed");
		return -1;
	}

	switch (flow->state) {
	case READ_PROPOSAL:
		flow->control_read_buffer_pos += rc;
		if (flow->control_read_buffer[flow->control_read_buffer_pos - 1] == '+') {
			// We've got the proposal
			rc = process_proposal(flow);

			flow->control_read_buffer_pos = 0;
			return rc;
		}
		else if (flow->control_read_buffer_pos == sizeof(flow->control_read_buffer)) {
			logging_log(LOG_WARNING, "too much incoming data on control connection");
			return -1;
		}
	default:
		logging_log(LOG_WARNING, "client sent unexpected data on control connection, discarding");
		break;
	}

	return 0;
}

int accept_data(struct _flow *flow)
{
	struct sockaddr_storage caddr;

	unsigned real_send_buffer_size;
	unsigned real_receive_buffer_size;

	flow->fd = accept(flow->listenfd, (struct sockaddr *)&caddr, &flow->addrlen);
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
	if (close(flow->listenfd) == -1)
		logging_log(LOG_WARNING, "close(): failed");
	flow->listenfd = -1;

	logging_log(LOG_NOTICE, "client %s connected for testing.",
			fg_nameinfo((struct sockaddr *)&caddr, flow->addrlen));
	real_send_buffer_size = set_window_size_directed(flow->fd, flow->requested_send_buffer_size, SO_SNDBUF);
	if (flow->requested_server_test_port &&
			flow->real_listen_send_buffer_size != real_send_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set send buffer size of test "
				"socket to send buffer size size of listen socket "
				"(listen = %u, test = %u).",
				flow->real_listen_send_buffer_size, real_send_buffer_size);
		return -1;
	}
	real_receive_buffer_size = set_window_size_directed(flow->fd, flow->requested_receive_buffer_size, SO_RCVBUF);
	if (flow->requested_server_test_port &&
			flow->real_listen_receive_buffer_size != real_receive_buffer_size) {
		logging_log(LOG_WARNING, "Failed to set receive buffer size (advertised window) of test "
				"socket to receive buffer size of listen socket "
				"(listen = %u, test = %u).",
				flow->real_listen_receive_buffer_size, real_receive_buffer_size);
		return -1;
	}
	if (flow->route_record)
		set_route_record(flow->fd);
	if (flow->advstats)
		fg_pcap_go(flow->fd);
	if (flow->so_debug && set_so_debug(flow->fd)) {
		logging_log(LOG_WARNING, "Unable to set SO_DEBUG on test socket: %s",
				  strerror(errno));
	}

	set_non_blocking(flow->fd);

	tsc_gettimeofday(&flow->start);
	flow->start_timestamp = flow->start;
	time_add(&flow->start_timestamp, flow->delay);
	if (flow->duration >= 0) {
		flow->stop_timestamp = flow->start_timestamp;
		time_add(&flow->stop_timestamp, flow->duration);
	}

	DEBUG_MSG(1, "The grind can begin");
	flow->state = GRIND;

	return 0;
}

int write_data(struct _flow *flow)
{
	struct timeval now;
	int rc;

	DEBUG_MSG(5, "test sock in wfds");

	tsc_gettimeofday(&now);

	if (!time_is_after(&now, &flow->start_timestamp) ||
			(flow->duration >= 0 && !time_is_after(&flow->stop_timestamp, &now)))
		return 0;

	/* Read comment in write_test_data in flowgrind.c why this loop is needed */
	for (;;) {
		if (flow->write_block_bytes_written == 0)
			tsc_gettimeofday((struct timeval *)flow->write_block);
		rc = send(flow->fd, flow->write_block +
				flow->write_block_bytes_written,
				flow->write_block_size -
				flow->write_block_bytes_written, 0);
		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			logging_log(LOG_WARNING, "Premature end of test: %s",
				strerror(errno));
			return -1;
		} else if (rc == 0)
			break;
		DEBUG_MSG(4, "sent %u bytes", rc);
		flow->write_block_bytes_written += rc;
		if (flow->write_block_bytes_written >=
				flow->write_block_size) {
			assert(flow->write_block_bytes_written =
					flow->write_block_size);
			flow->write_block_bytes_written = 0;
		}
		if (!flow->pushy)
			break;
	}

	return 0;
}

int read_data(struct _flow *flow)
{
	struct timeval now;
	int rc;

	tsc_gettimeofday(&now);

	DEBUG_MSG(5, "test sock in rfds");
	for (;;) {
		rc = recv(flow->fd, flow->read_block+flow->read_block_bytes_read,
			flow->read_block_size -
				flow->read_block_bytes_read, 0);
		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			logging_log(LOG_WARNING, "Premature "
				"end of test: %s",
				strerror(errno));
			return -1;
		} else if (rc == 0) {
			DEBUG_MSG(1, "client shut down flow");
			flow->got_eof = 1;
			return 0;
		}
		DEBUG_MSG(4, "received %d bytes "
			"(in flow->read_block already = %u)",
			rc, flow->read_block_bytes_read);
		flow->read_block_bytes_read += rc;
		if (flow->read_block_bytes_read >= flow->read_block_size) {
			double *iat_ptr = (double *)(flow->read_block
				+ flow->reply_block_length - sizeof(double));
			assert(flow->read_block_bytes_read ==
				flow->read_block_size);
			flow->read_block_bytes_read = 0;
			if (flow->read_block_size <
					flow->reply_block_length)
				continue;
			if (flow->last_block_read.tv_sec == 0 &&
				flow->last_block_read.tv_usec == 0) {
				*iat_ptr = NAN;
				DEBUG_MSG(5, "isnan = %d",
					isnan(*iat_ptr));
			} else
				*iat_ptr = time_diff_now(
					&flow->last_block_read);
			tsc_gettimeofday(&flow->last_block_read);
			rc = write(flow->fd_control, flow->read_block,
					flow->reply_block_length);
			if (rc == -1) {
				if (errno == EAGAIN) {
					logging_log(LOG_WARNING,
						"congestion on "
						"control connection, "
						"dropping reply block");
					continue;
				}
				logging_log(LOG_WARNING,
					"Premature end of test: %s",
					strerror(errno));
				return -1;
			}
			DEBUG_MSG(4, "sent reply block (IAT = "
				"%.3lf)", (isnan(*iat_ptr) ?
					NAN : (*iat_ptr) * 1e3));
			}
		if (!flow->pushy)
			break;
	}

	return 0;
}

void grind_flows()
{
	struct timeval timeout;
	for (;;) {
		prepare_fds();

		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		int rc = select(maxfd + 1, &rfds, &wfds, &efds, &timeout);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			error(ERR_FATAL, "select() failed: %s",
					strerror(errno));
			exit(1);
		}
		if (FD_ISSET(listenfd, &rfds))
			accept_control();

		unsigned int i = 0;
		while (i < num_flows) {
			struct _flow *flow = &flows[i];

			if (FD_ISSET(flow->fd_control, &wfds))
				rc = write_control_data(flow);
			if (rc >= 0 && FD_ISSET(flow->fd_control, &rfds))
				rc = read_control_data(flow);
			if (rc >= 0 && flow->listenfd != -1 && FD_ISSET(flow->listenfd, &rfds))
				rc = accept_data(flow);
			if (rc >= 0 && flow->fd != -1 && FD_ISSET(flow->fd, &wfds))
				rc = write_data(flow);
			if (rc >= 0 && flow->fd != -1 && FD_ISSET(flow->fd, &rfds))
				rc = read_data(flow);

			if (rc >= 0) {
				struct timeval now;
				tsc_gettimeofday(&now);

				if (flow->server_shutdown &&
					time_is_after(&now, &flow->stop_timestamp)) {
					DEBUG_MSG(4, "shutting down data connection.");
					if (shutdown(flow->fd, SHUT_WR) == -1) {
						logging_log(LOG_WARNING, "shutdown "
						"failed: %s", strerror(errno));
					}
				fg_pcap_dispatch();
			}

			}
			if (rc < 0) {
				// Flow has ended
				uninit_flow(flow);
				for (unsigned int j = i; j < num_flows - 1; j++)
					flows[j] = flows[j + 1];
				num_flows--;
			}
			else
				i++;
		}
	}
}

int
main(int argc, char *argv[])
{
	unsigned port = DEFAULT_LISTEN_PORT;
	char service[7];
	int on = 1;
	int rc;
	struct addrinfo hints, *res, *ressave;
	socklen_t addrlen;
	int ch;
	int argcorig = argc;
	struct sigaction sa;


	while ((ch = getopt(argc, argv, "a:Dp:V")) != -1) {
		switch (ch) {
		case 'a':
			if (acl_allow_add(optarg) == -1) {
				fprintf(stderr, "unable to add host to ACL "
						"list\n");
				usage();
			}
			break;

		case 'D':
			log_type = LOGTYPE_STDERR;
			increase_debuglevel();
			break;

		case 'p':
			rc = sscanf(optarg, "%u", &port);
			if (rc != 1) {
				fprintf(stderr, "failed to "
					"parse port number.\n");
				usage();
			}
			break;

		case 'V':
			fprintf(stderr, "flowgrindd version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		default:
			usage();
		}
	}
	argc = argcorig;

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		error(ERR_FATAL, "Could not ignore SIGPIPE: %s",
				strerror(errno));
		/* NOTREACHED */
	}

	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGHUP, &sa, NULL);
	sigaction (SIGALRM, &sa, NULL);
	sigaction (SIGCHLD, &sa, NULL);

	logging_init();
	fg_pcap_init();
	tsc_init();

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* Convert integer port number to string for getaddrinfo(). */
	snprintf(service, sizeof(service), "%u", port);

	if ((rc = getaddrinfo(NULL, service, &hints, &res)) != 0) {
		fprintf(stderr, "Error: getaddrinfo() failed: %s\n",
				gai_strerror(rc));
		exit(1);
	}

	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (listenfd < 0)
			continue;

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
					(char *)&on, sizeof(on)) == -1) {
			error(ERR_WARNING, "setsockopt(SO_REUSEADDR): failed,"
					" continuing: %s",
					strerror(errno));
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_KEEPALIVE,
				(char *)&on, sizeof(on)) == -1) {
			error(ERR_WARNING, "setsockopt(SO_KEEPALIVE): failed,"
					" continuing: %s",
					strerror(errno));
		}

		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;		/* success */

		close(listenfd);	/* bind error, close and try next one */
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		error(ERR_FATAL, "Unable to start server. Already running?");
		/* NOTREACHED */
	}

	if (listen(listenfd, 64) < 0) {
		error(ERR_FATAL, "listen() failed: %s", strerror(errno));
	}

	addrlen = res->ai_addrlen;
	freeaddrinfo(ressave);

	if (log_type == LOGTYPE_SYSLOG) {
		if (daemon(0, 0) == -1) {
			error(ERR_FATAL, "daemon() failed: %s", strerror(errno));
		}
	}

	logging_log(LOG_NOTICE, "flowgrind daemonized, listening on port %u",
			port);

	// Enter the main select loop
	grind_flows();
}
