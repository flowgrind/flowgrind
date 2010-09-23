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

static pcap_if_t 	*alldevs;
static pcap_t 		*pcap_handle;
static pcap_dumper_t 	*pcap_dumper;
struct pcap_stat 	pcap_statistics;

static char errbuf[PCAP_ERRBUF_SIZE];
static char pcap_init_done = 0;

void fg_pcap_init()
{
#ifdef DEBUG
	pcap_if_t *d;
	char devdes[160];
#endif
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
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

void fg_pcap_go(struct _flow *flow)
{
	int pcap_ll_type = 0;
	pcap_if_t *d;
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	char found = 0;
	int len;
	uint32_t net = 0;
	uint32_t mask = 0;

	char pcap_expression[200];
	char dump_filename[20];
	struct bpf_program pcap_program;
	struct timeval now;
	char buf[60];

	if (!flow->settings.traffic_dump)
			return;

	if (getsockname(flow->fd, (struct sockaddr *)&sa, &sl) == -1) {
		logging_log(LOG_WARNING, "getsockname() failed. Eliding packet "
				"capture for flow.");
		return;
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
		return;
	}

	/* Make sure errbuf contains zero-length string in order to enable
	 * pcap_open_live to report warnings. */
	errbuf[0] = '\0';
	pcap_handle = pcap_open_live(d->name, PCAP_SNAPLEN,
			0 /* non-promisc */,
			0 /* no read timeout */, errbuf);

	if (!pcap_handle) {
		logging_log(LOG_WARNING, "Failed to init pcap on device %s:"
				" %s", d->name, errbuf);
		return;
	}

	/* Check link-layer type */
	pcap_ll_type = pcap_datalink(pcap_handle);
	if (pcap_ll_type == -1) {
		logging_log(LOG_WARNING, "pcap: failed to determine link "
				"layer type: %s", pcap_geterr(pcap_handle));
		return;
	}

	DEBUG_MSG(LOG_NOTICE, "pcap: device %s has link layer type "
			"\"%s\" (%u).", 
			d->name,
			pcap_datalink_val_to_name(pcap_ll_type),
			pcap_ll_type);


	if (pcap_lookupnet(d->name, &net, &mask, errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: netmask lookup failed: %s", errbuf);
		return;
	}

	/* We rely on a non-blocking dispatch loop */
	if (pcap_setnonblock(pcap_handle, 1 /* non-blocking */ , errbuf) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set non-blocking: %s",
				 errbuf );
		return;
	}

	/* strong pcap expression: tcp and on if and host a and b and port c and d */
	/* weaker pcap expression: on if and host a and b */
	sprintf(pcap_expression, "on %s and tcp and port %u", d->name, get_port(flow->fd));
	if (pcap_compile(pcap_handle, &pcap_program, pcap_expression, 1, mask) < 0) { 
		logging_log(LOG_WARNING, "pcap: failed compiling filter '%s': %s", pcap_expression, pcap_geterr(pcap_handle)); 
	/*return;*/
	}
	
	/* attach filter to interface */
	if (pcap_setfilter(pcap_handle, &pcap_program) < 0) {
		logging_log(LOG_WARNING, "pcap: failed to set filter: %s", pcap_geterr(pcap_handle));
		return;
	}

	tsc_gettimeofday(&now);
	len = strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S", localtime(&now.tv_sec));

	strcat(dump_filename, "flowgrind-");

	strcat(dump_filename, buf);
	strcat(dump_filename, ".pcap");

	DEBUG_MSG(LOG_NOTICE, "dumping to \"%s\"", dump_filename);

	pcap_dumper = pcap_dump_open(pcap_handle, dump_filename);
	if (pcap_dumper == NULL)
		logging_log(LOG_WARNING, "pcap: failed to open file writeing: %s", pcap_geterr(pcap_handle));


	DEBUG_MSG(LOG_ERR, "pcap init done.");

	pcap_init_done = 1;
	return;
}

void fg_pcap_dispatch(void)
{
	int rc;
	if (!pcap_init_done)
		return;

	rc = pcap_dispatch(pcap_handle, -1, &pcap_dump, (u_char *)pcap_dumper);

	if (rc == -1) {
		logging_log(LOG_WARNING, "pcap_dispatch() failed. Packet "
				"dumping stopped.");
		pcap_init_done = 0;
		return;
	}
	DEBUG_MSG(LOG_NOTICE, "pcap: finished dumping %u packets.", rc);

	return;
}


void fg_pcap_shutdown()
{
	pcap_dump_close(pcap_dumper);
	pcap_close(pcap_handle);
	pcap_freealldevs(alldevs);
}

#endif


#endif
