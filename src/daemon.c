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
#include "source.h"
#include "destination.h"

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

double reporting_interval = 0.05;

pthread_mutex_t mutex;
struct _request *requests = 0, *requests_last = 0;

fd_set rfds, wfds, efds;
int maxfd;

void prepare_fds() {
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	maxfd = 0;

	source_prepare_fds(&rfds, &wfds, &efds, &maxfd);
	destination_prepare_fds(&rfds, &wfds, &efds, &maxfd);
}

static void start_flows(struct _request_start_flows *request)
{
	destination_start_flows(request->start_timestamp);
	source_start_flows(request->start_timestamp);
}

static void process_requests()
{
	int rc;
	pthread_mutex_lock(&mutex);

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
		default:
			request->error = "Unknown request type";
			break;
		}
		if (rc != 1)
			pthread_cond_signal(request->condition);
	};

	pthread_mutex_unlock(&mutex);
}

void timer_check()
{
	source_timer_check();
	destination_timer_check();
}

void* daemon_main(void* ptr __attribute__((unused)))
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

		timer_check();

		process_requests();
		source_process_select(&rfds, &wfds, &efds);
		destination_process_select(&rfds, &wfds, &efds);
	}
}
