/**
 * @file fg_pcap.c
 * @brief Packet capture support for the Flowgrind daemon
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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <pcap.h>
#include <netdb.h>

#include "debug.h"
#include "fg_socket.h"
#include "fg_time.h"
#include "log.h"
#include "daemon.h"
#include "fg_pcap.h"

/* OS X hasn't defined pthread_barrier */
#ifndef HAVE_PTHREAD_BARRIER
#include "fg_barrier.h"
#endif

/* PCAP snapshot length */
#define PCAP_SNAPLEN 130

/* PCAP filter string */
#define PCAP_FILTER "tcp"

/* Flag whether to use promiscuous mode */
#define PCAP_PROMISC 0

/* Error message buffer filled by the pcap library in case of an error */
static char errbuf[PCAP_ERRBUF_SIZE] = "";

/* Barrier to block fg_pcap_go() until worker thread reaches its main loop */
static pthread_barrier_t pcap_barrier;

/* Pointer to the first element in a list containing all 'pcapable' devices */
static pcap_if_t *alldevs;

/* Flag if traffic is currently dumped */
static bool dumping;

void fg_pcap_init(void)
{
	/* initalize *alldevs for later use */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		logging_log(LOG_WARNING,"Error in pcap_findalldevs: %s\n",
			    errbuf);
		return;
	}

#ifdef DEBUG
	char devdes[200];
	for (pcap_if_t *d = alldevs; d; d = d->next) {
		snprintf(devdes, sizeof(devdes), "%s: ", d->name);
		for (pcap_addr_t *a = d->addresses; a; a = a->next) {
			char addr[100];
			if (!a->addr)
				continue;
			snprintf(addr, sizeof(addr), "a=%s",
				 fg_nameinfo(a->addr, sizeof(struct sockaddr)));
			strncat(devdes, addr,
				sizeof(devdes) - strlen(devdes) - 1);
			if (a->next)
				strncat(devdes, ", ",
					sizeof(devdes) - strlen(devdes) - 1);
		}
		DEBUG_MSG(LOG_ERR, "pcap: found pcapable device (%s)", devdes);
	}
#endif /* DEBUG*/

	pthread_barrier_init(&pcap_barrier, NULL, 2);
}

/**
 * Cleanup method to be called after dumping of the specified flow has finished.
 *
 * It closes the handle to the savefile and the handle to the device whose
 * traffic was captured.
 *
 * @param[in] arg pointer to the flow whose dumping finished
 */
void fg_pcap_cleanup(void *arg)
{
	/* signature of pthread_create() requires that all arguments must be
	 * passed by reference and cast to (void *) */
	struct flow *flow = (struct flow *) arg;

	if (!dumping)
		return;

	DEBUG_MSG(LOG_DEBUG, "fg_pcap_cleanup() called for flow %d", flow->id);
	if (flow->pcap_dumper)
		pcap_dump_close((pcap_dumper_t *)flow->pcap_dumper);
	flow->pcap_dumper = NULL;

	if (flow->pcap_handle)
		pcap_close((pcap_t *)flow->pcap_handle);
	flow->pcap_handle = NULL;
	dumping = false;
}

/**
 * Worker method performing actual packet capturing for the provided flow.
 *
 * It prepares the flow for packet capturing by figuring out the correct
 * device, constructing the pcap filter, etc. and finally starts capturing.
 * Synchronizes with fg_pcap_go() after initialization before starting
 * capturing.
 *
 * @param[in] arg pointer to the flow whose traffic should be captured
 */
static void* fg_pcap_work(void *arg)
{
	/* note: all the wierd casts in this function are completely useless,
	 * execpt they cirumvent strange compiler warnings because of libpcap
	 * typedef woo's */

	/* signature of pthread_create() requires that all arguments must be
	 * passed by reference and cast to (void *) */
	struct flow *flow = (struct flow *) arg;

	DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() called for flow %d", flow->id);

	/* make sure all resources are released when finished */
	pthread_cleanup_push(fg_pcap_cleanup, (void*) flow);

	struct addrinfo *ainf = NULL;
	int rc = getaddrinfo(flow->settings.bind_address, NULL, NULL, &ainf);
	if (rc) {
		logging_log(LOG_WARNING, "getaddrinfo() failed (%s). Eliding "
			    "packet capture for flow.", gai_strerror(rc));
		goto remove;
	}

	/* find appropriate (used for test) interface to dump */
	bool found = false;
	pcap_if_t *d = NULL;
	for (d = alldevs; d; d = d->next) {
		for (pcap_addr_t *a = d->addresses; a; a = a->next) {
			if (!a->addr)
				continue;
			if (sockaddr_compare(a->addr, ainf->ai_addr)) {
				DEBUG_MSG(LOG_NOTICE, "pcap: data connection "
					  "inbound from %s (%s)", d->name,
					  fg_nameinfo(a->addr,
						      sizeof(struct sockaddr)));
				found = true;
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

	flow->pcap_handle = (struct pcap_t *)pcap_open_live(
				d->name, PCAP_SNAPLEN, PCAP_PROMISC,
				0, errbuf); /* 0 = no read timeout */

	if (!flow->pcap_handle) {
		logging_log(LOG_WARNING, "Failed to init pcap on device %s: "
			    "%s", d->name, errbuf);
		goto remove;
	}

	uint32_t net = 0, mask = 0;
	if (pcap_lookupnet(d->name, &net, &mask, errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: netmask lookup failed: %s",
			    errbuf);
		goto remove;
	}

	/* we rely on a non-blocking dispatch loop */
	if (pcap_setnonblock((pcap_t *)flow->pcap_handle, 1, errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set non-blocking: "
			    "%s", errbuf);
		goto remove;
	}

	/* compile filter */
	struct bpf_program pcap_program;
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
	char dump_filename[500];
	dump_filename[0] = '\0';

	/* dir and prefix */
	if (dump_dir)
		strcat(dump_filename, dump_dir);
	if (dump_prefix)
		strcat(dump_filename, dump_prefix);

	/* timestamp */
	struct timespec now;
	char buf[60];
	gettime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S",
		 localtime(&now.tv_sec));
	strcat(dump_filename, buf);

	/* hostname */
	char hostname[100];
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
	pthread_barrier_wait(&pcap_barrier);

	for (;;) {
		int rc = pcap_dispatch((pcap_t *)flow->pcap_handle, -1,
				       &pcap_dump, (u_char *)flow->pcap_dumper);

		if (rc < 0) {
			logging_log(LOG_WARNING, "pcap_dispatch() failed. "
				    "Packet dumping stopped for flow %d.",
				    flow->id);
			/* cleanup automatically called */
			pthread_exit(0);
		}
#ifdef DEBUG
		struct pcap_stat p_stats;
		pcap_stats((pcap_t *)flow->pcap_handle, &p_stats);
#endif /* DEBUG */
		DEBUG_MSG(LOG_NOTICE, "pcap: finished dumping %d packets for "
			  "flow %d", rc, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets received by filter for "
			  "flow %d", p_stats.ps_recv, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets dropped by kernel for "
			  "flow %d", p_stats.ps_drop, flow->id);
		if (rc == 0)
			/* if no packets are received try if we should cancel */
			pthread_testcancel();
	}

remove: ;

	pthread_cleanup_pop(1);

	pthread_barrier_wait(&pcap_barrier);
	return 0;

}

void fg_pcap_go(struct flow *flow)
{
	if (!flow->settings.traffic_dump)
		return;

	if (dumping) {
		logging_log(LOG_WARNING, "pcap: dumping already in progress "
			    "on this host");
		return;
	}

	DEBUG_MSG(LOG_DEBUG, "called fg_pcap_go() for flow %d", flow->id);
	dumping = true;

	int rc = pthread_create(&flow->pcap_thread, NULL, fg_pcap_work,
				(void*)flow);

	/* barrier: dump thread is ready (or aborted) */
	pthread_barrier_wait(&pcap_barrier);

	if (rc)
		logging_log(LOG_WARNING, "Could not start pcap thread: %s",
			    strerror(rc) );
}

