/*
 * fg_pcap.c - Package capture support for the Flowgrind Daemon
 *
 * Copyright (C) Christian Samsel <christian.samsel@rwth-aachen.de>, 2010-2013
 * Copyright (C) Tim Kosse <tim.kosse@gmx.de>, 2009
 * Copyright (C) Daniel Schaffrath <daniel.schaffrath@mac.com>, 2007-2008
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _FG_PCAP_H_
#define _FG_PCAP_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "common.h"
#include "debug.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"
#include "daemon.h"
#include "fg_pcap.h"

#ifdef HAVE_LIBPCAP

#include <pcap.h>

#define PCAP_SNAPLEN 130
#define PCAP_FILTER "tcp"
#define PCAP_PROMISC 0

static char errbuf[PCAP_ERRBUF_SIZE];

void fg_pcap_init()
{
/* initalize *alldevs for later use */
#ifdef DEBUG
	pcap_if_t *d;
	char devdes[200];
#endif /* DEBUG */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		logging_log(LOG_WARNING,"Error in pcap_findalldevs: %s\n",
			    errbuf);
		return;
	}
#ifdef DEBUG
	for (d = alldevs; d; d = d->next) {
		pcap_addr_t *a;
		snprintf(devdes, sizeof(devdes), "%s: ", d->name);
		for (a = d->addresses; a; a = a->next) {
			char addr[100];
			if (!a->addr)
				continue;
			snprintf(addr, sizeof(addr), "a=%s",
				 fg_nameinfo(a->addr, sizeof(struct sockaddr)));
			strncat(devdes, addr, sizeof(devdes)-1);
			if (a->next)
				strncat(devdes, ", ", sizeof(devdes));
		}
		DEBUG_MSG(LOG_ERR, "pcap: found pcapable device (%s)", devdes);
	}
#endif /* DEBUG*/
	pthread_mutex_init(&pcap_mutex, NULL);
#ifndef __DARWIN__
	pthread_barrier_init(&pcap_barrier, NULL, 2);
#endif /* __DARWIN__ */
	return;
}

void fg_pcap_cleanup(void* arg)
{
	struct _flow * flow;
	flow = (struct _flow *) arg;
	if (!dumping)
		return;
	DEBUG_MSG(LOG_DEBUG, "fg_pcap_cleanup() called for flow %d", flow->id);
	pthread_mutex_lock(&pcap_mutex);
	if (flow->pcap_dumper)
		pcap_dump_close((pcap_dumper_t *)flow->pcap_dumper);
	flow->pcap_dumper = NULL;

	if (flow->pcap_handle)
		pcap_close((pcap_t *)flow->pcap_handle);
	flow->pcap_handle = NULL;
	pthread_mutex_unlock(&pcap_mutex);
	dumping = 0;
}

static void* fg_pcap_work(void* arg)
{
	/* note: all the wierd casts in this function are completely useless,
	 * execpt they cirumvent strange compiler warnings because of libpcap
	 * typedef woo's */

#ifdef DEBUG
	struct pcap_stat p_stats;
#endif /* DEBUG */
	int rc;
	struct _flow * flow;
	flow = (struct _flow *) arg;
	pcap_if_t *d;
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	char found = 0;
	uint32_t net = 0;
	uint32_t mask = 0;

	char dump_filename[500];
	char hostname[100];

	struct bpf_program pcap_program;
	struct timeval now;
	char buf[60];

	DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() called for flow %d", flow->id);

	/* make sure all resources are released when finished */
	pthread_detach(pthread_self());
	pthread_cleanup_push(fg_pcap_cleanup, (void*) flow);

	if (getsockname(flow->fd, (struct sockaddr *)&sa, &sl) == -1) {
		logging_log(LOG_WARNING, "getsockname() failed. Eliding "
			    "packet capture for flow.");
		goto remove;
	}

	/* find appropriate (used for test) interface to dump */
	for (d = alldevs; d; d = d->next) {
		pcap_addr_t *a;
		for (a = d->addresses; a; a = a->next) {
			if (!a->addr)
				continue;
			if (sockaddr_compare(a->addr, (struct sockaddr *)&sa)) {
				DEBUG_MSG(LOG_NOTICE, "pcap: data connection "
					  "inbound from %s (%s)", d->name,
					  fg_nameinfo(a->addr,
						      sizeof(struct sockaddr)));
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found) {
		logging_log(LOG_WARNING, "Failed to determine interface "
			    "for data connection. No pcap support.");
		goto remove;
	}

	/* Make sure errbuf contains zero-length string in order to enable
	 * pcap_open_live to report warnings. */
	errbuf[0] = '\0';
	flow->pcap_handle =
		(struct pcap_t *)pcap_open_live(d->name, PCAP_SNAPLEN,
						PCAP_PROMISC,
						0, /* no read timeout */
						errbuf);

	if (!flow->pcap_handle) {
		logging_log(LOG_WARNING, "Failed to init pcap on device %s:"
			    " %s", d->name, errbuf);
		goto remove;
	}


	if (pcap_lookupnet(d->name, &net, &mask, errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: netmask lookup failed: %s",
			    errbuf);
		goto remove;
	}

	/* We rely on a non-blocking dispatch loop */
	if (pcap_setnonblock((pcap_t *)flow->pcap_handle,
			     1 /* non-blocking */,
			     errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set non-blocking: "
			    "%s", errbuf);
		goto remove;
	}

	/* compile filter */
	if (pcap_compile((pcap_t *)flow->pcap_handle,
			 &pcap_program, PCAP_FILTER, 1, mask) < 0) {
		logging_log(LOG_WARNING, "pcap: failed compiling filter "
			    "'%s': %s", PCAP_FILTER,
			    pcap_geterr((pcap_t *)flow->pcap_handle));
		goto remove;
	}

	/* attach filter to interface */
	if (pcap_setfilter((pcap_t *)flow->pcap_handle,
			   &pcap_program) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set filter: "
			    "%s", pcap_geterr((pcap_t *)flow->pcap_handle));
		goto remove;
	}

	/* generate a nice filename */
	dump_filename[0] = '\0';

	/* prefix */
	if (dump_filename_prefix_server)
		strcat(dump_filename, dump_filename_prefix_server);
	if (dump_filename_prefix_client)
		strcat(dump_filename, dump_filename_prefix_client);

	/* timestamp */
	tsc_gettimeofday(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S",
		 localtime(&now.tv_sec));
	strcat(dump_filename, buf);

	/* hostname */
	hostname[0]= '\0';
	if (!gethostname(hostname, 59)) {
		strcat(dump_filename, "-");
		strcat(dump_filename, hostname);
	}

	/* interface */
	strcat(dump_filename, "-");
	strcat(dump_filename, d->name);

	/* suffix */
	strcat(dump_filename, ".pcap");

	DEBUG_MSG(LOG_NOTICE, "dumping to \"%s\"", dump_filename);

	flow->pcap_dumper = (struct pcap_dumper_t *)pcap_dump_open(
			(pcap_t *)flow->pcap_handle, dump_filename);

	if (!flow->pcap_dumper) {
		logging_log(LOG_WARNING, "pcap: failed to open dump file "
			    "writing: %s",
			    pcap_geterr((pcap_t *)flow->pcap_handle));
		goto remove;
	}

	/* barrier: dump is ready */
#ifndef __DARWIN__
	pthread_barrier_wait(&pcap_barrier);
#endif /* __DARWIN__ */
	for (;;) {
		rc = pcap_dispatch((pcap_t *)flow->pcap_handle, -1,
				   &pcap_dump, (u_char *)flow->pcap_dumper);

		if (rc < 0) {
			logging_log(LOG_WARNING, "pcap_dispatch() failed. "
				    "Packet dumping stopped for flow %d.",
				    flow->id);
			/* cleanup automatically called */
			pthread_exit(0);
		}
#ifdef DEBUG
		pcap_stats((pcap_t *)flow->pcap_handle, &p_stats);
#endif /* DEBUG */
		DEBUG_MSG(LOG_NOTICE, "pcap: finished dumping %u packets for "
			  "flow %d", rc, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets received by filter for "
			  "flow %d", p_stats.ps_recv, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets dropped by kernel for "
			  "flow %d", p_stats.ps_drop, flow->id);
		if (rc == 0)
			/* if no packets are received try
			 * if we should cancel */
			pthread_testcancel();
	}
	pthread_cleanup_pop(1);

remove:
#ifndef __DARWIN__
	pthread_barrier_wait(&pcap_barrier);
#endif /* __DARWIN__ */
	return 0;

}

void fg_pcap_go(struct _flow *flow)
{
	int rc;
	if (!flow->settings.traffic_dump)
		return;

	if (dumping) {
		logging_log(LOG_WARNING, "pcap: dumping already in progress "
			    "on this host");
		return;
	}

	DEBUG_MSG(LOG_DEBUG, "called fg_pcap_go() for flow %d", flow->id);
	dumping = 1;
	rc = pthread_create(&flow->pcap_thread, NULL, fg_pcap_work,
			    (void*)flow);
	/* barrier: dump thread is ready (or aborted) */
#ifndef __DARWIN__
	pthread_barrier_wait(&pcap_barrier);
#endif /* __DARWIN__ */
	if (rc)
		logging_log(LOG_WARNING, "Could not start pcap thread: %s",
			    strerror(errno) );
	return;
}

#endif /* HAVE_LIBPCAP */

#endif /* _FG_PCAP_H_ */
