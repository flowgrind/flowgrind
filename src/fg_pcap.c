#ifndef _FG_PCAP_H_
#define _FG_PCAP_H_

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
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

#include "pcap.h"

#define PCAP_SNAPLEN 90 
#define PCAP_FILTER "tcp"
#define PCAP_PROMISC 0

static pcap_if_t 	*alldevs;

static char errbuf[PCAP_ERRBUF_SIZE];

void fg_pcap_init()
{
/* initalize *alldevs for later use */
#ifdef DEBUG
	pcap_if_t *d;
	char devdes[200];
#endif
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		logging_log(LOG_WARNING,"Error in pcap_findalldevs: %s\n", errbuf);
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
			snprintf(addr, sizeof(addr), "a=%s", fg_nameinfo(a->addr, sizeof(struct sockaddr)));
			strncat(devdes, addr, sizeof(devdes)-1);
			if (a->next)
				strncat(devdes, ", ", sizeof(devdes));
		}
		DEBUG_MSG(LOG_ERR, "pcap: found pcapabple device (%s)", devdes);
	}
#endif
	return;
}

void fg_pcap_go(struct _flow *flow, int is_source)
{
	/* note: all the wierd casts in this function are completely useless, execpt they
	 * cirumvent strange compiler warnings because of libpcap typedef woo's */
	pcap_if_t *d;
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	char found = 0;
	int rc;
	uint32_t net = 0;
	uint32_t mask = 0;

	char dump_filename[500];
	char hostname[100];

	struct bpf_program pcap_program;
	struct timeval now;
	char buf[60];

	if (!flow->settings.traffic_dump)
		return;

	if (getsockname(flow->fd, (struct sockaddr *)&sa, &sl) == -1) {
		logging_log(LOG_WARNING, "getsockname() failed. Eliding packet "
				"capture for flow.");
		goto error;
	}
	/* find approciate (used for test) interface to dump */
	for (d = alldevs; d; d = d->next) {
		pcap_addr_t *a;
		for (a = d->addresses; a; a = a->next) {
			if (!a->addr)
				continue;
			if (sockaddr_compare(a->addr, (struct sockaddr *)&sa)) {
				DEBUG_MSG(LOG_NOTICE, "pcap: data connection inbound "
						"from %s (%s)", d->name,
						fg_nameinfo(a->addr, sizeof(struct sockaddr)));
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
		goto error;
	}

	/* Make sure errbuf contains zero-length string in order to enable
	 * pcap_open_live to report warnings. */
	errbuf[0] = '\0';
	flow->pcap_handle = (struct pcap_t *)pcap_open_live(d->name, 
				     PCAP_SNAPLEN,
				     PCAP_PROMISC,
				     0, /* no read timeout */ 
				     errbuf);

	if (!flow->pcap_handle) {
		logging_log(LOG_WARNING, "Failed to init pcap on device %s:"
				" %s", d->name, errbuf);
		goto error;
	}


	if (pcap_lookupnet(d->name, &net, &mask, errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: netmask lookup failed: %s", errbuf);
		goto error;
	}

	/* We rely on a non-blocking dispatch loop */
	if (pcap_setnonblock((pcap_t *)flow->pcap_handle, 1 /* non-blocking */ , errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set non-blocking: %s",
				 errbuf );
		goto error;
	}

	/* compile filter */
	if (pcap_compile((pcap_t *)flow->pcap_handle, &pcap_program, PCAP_FILTER, 1, mask) < 0) { 
		logging_log(LOG_WARNING, "pcap: failed compiling filter '%s': %s", PCAP_FILTER, pcap_geterr((pcap_t *)flow->pcap_handle)); 
		goto error;
	}
	
	/* attach filter to interface */
	if (pcap_setfilter((pcap_t *)flow->pcap_handle, &pcap_program) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set filter: %s", pcap_geterr((pcap_t *)flow->pcap_handle));
		goto error;
	}

	/* generate a nice filename */
	dump_filename[0] = '\0';
	
	/* timestamp */

	/* prefix */
	if (dump_filename_prefix)
		strcat(dump_filename, dump_filename_prefix); 
	else	
		strcat(dump_filename, "/tmp/");
	strcat(dump_filename, "flowgrind-");

	/* timestamp */
	tsc_gettimeofday(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S", localtime(&now.tv_sec));
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
	/* -source or -destination */
	if (is_source)
		strcat(dump_filename, "-source");
	else
		strcat(dump_filename, "-destination");

	/* suffix */
	strcat(dump_filename, ".pcap");

	DEBUG_MSG(LOG_NOTICE, "dumping to \"%s\"", dump_filename);

	flow->pcap_dumper = (struct pcap_dumper_t *)pcap_dump_open((pcap_t *)flow->pcap_handle, dump_filename);
	if (flow->pcap_dumper == NULL) {
		logging_log(LOG_WARNING, "pcap: failed to open dump file writing: %s", pcap_geterr((pcap_t *)flow->pcap_handle));
		goto error;
	}

	DEBUG_MSG(LOG_ERR, "pcap init done.");

	rc = pthread_create(&flow->pcap_thread, NULL, fg_pcap_thread, (void*) flow);
	
	if (rc) {
		logging_log(LOG_WARNING, "Could not start pcap thread: %s", strerror(errno) );
	}
	return;

error:
	logging_log(LOG_ERR, "pcap init abort.");
	DEBUG_MSG(LOG_ERR, "pcap dump close.");
	if (flow->pcap_dumper)
		pcap_dump_close((pcap_dumper_t *)flow->pcap_dumper);
	DEBUG_MSG(LOG_ERR, "pcap handle close.");
	if (flow->pcap_handle)
		pcap_close((pcap_t *)flow->pcap_handle);
	DEBUG_MSG(LOG_ERR, "pcap unlock mutex.");
	return;
}

void* fg_pcap_thread(void* arg)
{
#ifdef DEBUG
	struct pcap_stat p_stats;
#endif
	int rc;
	struct _flow * flow; 
	flow = (struct _flow *) arg;
	DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() called for flow %d", flow->id);
	pthread_mutex_init(&flow->pcap_mutex, NULL);	
	for (;;) {
		DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() waiting for lock on flow %d", flow->id);
		pthread_mutex_lock(&flow->pcap_mutex);
		DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() locked flow %d", flow->id);
		rc = pcap_dispatch((pcap_t *)flow->pcap_handle, -1, &pcap_dump, (u_char *)flow->pcap_dumper);
		pthread_mutex_unlock(&flow->pcap_mutex);
		DEBUG_MSG(LOG_DEBUG, "fg_pcap_thread() unlocked on flow %d", flow->id);
		if (rc < 0) {
			logging_log(LOG_WARNING, "pcap_dispatch() failed. Packet "
				"dumping stopped for flow %d.", flow->id);
			pcap_dump_close((pcap_dumper_t *)flow->pcap_dumper);
			pcap_close((pcap_t *)flow->pcap_handle);
			pthread_exit(0);
		}
		/* if we did only received a few packets, we wait some time */
		if (rc < 20)
			usleep( 50000 );
#ifdef DEBUG
		pcap_stats((pcap_t *)flow->pcap_handle, &p_stats); 
#endif
		DEBUG_MSG(LOG_NOTICE, "pcap: finished dumping %u packets for flow %d", rc, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets received by filter for flow %d", p_stats.ps_recv, flow->id);
		DEBUG_MSG(LOG_NOTICE, "pcap: %d packets dropped by kernel for flow %d", p_stats.ps_drop, flow->id);
	}

}

#endif


#endif
