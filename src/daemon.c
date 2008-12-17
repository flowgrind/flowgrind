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

int daemon_pipe[2];

double reporting_interval = 0.05;

pthread_mutex_t mutex;
struct _request *requests = 0, *requests_last = 0;

fd_set rfds, wfds, efds;
int maxfd;

struct _report* reports = 0;
struct _report* reports_last = 0;
int pending_reports = 0;

int prepare_fds() {

	int need_timeout = 0;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	FD_SET(daemon_pipe[0], &rfds);
	maxfd = daemon_pipe[0];

	need_timeout += source_prepare_fds(&rfds, &wfds, &efds, &maxfd);
	need_timeout += destination_prepare_fds(&rfds, &wfds, &efds, &maxfd);

	return need_timeout;
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
		int need_timeout = prepare_fds();

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

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

		source_process_select(&rfds, &wfds, &efds);
		destination_process_select(&rfds, &wfds, &efds);
	}
}

void add_report(struct _report* report)
{
	pthread_mutex_lock(&mutex);

	// Do not keep too much data
	if (pending_reports >= 100) {
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

struct _report* get_reports()
{
	struct _report* ret;

	pthread_mutex_lock(&mutex);

	ret = reports;
	pending_reports = 0;
	reports = NULL;
	reports_last = 0;

	pthread_mutex_unlock(&mutex);

	return ret;
}
