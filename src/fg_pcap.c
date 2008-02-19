#ifndef _FG_PCAP_H_
#define _FG_PCAP_H_

#include <sys/socket.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 

#include "log.h"
#include "common.h"

#ifdef HAVE_LIBPCAP

#include "pcap.h"

#define PCAP_SNAPLEN 120

static pcap_if_t *alldevs;
static pcap_t *pcap_handle;
static char errbuf[PCAP_ERRBUF_SIZE];
static char pcap_init_done = 0;
static int pcap_ll_type = 0;

void fg_pcap_init()
{
	pcap_if_t *d;
	char devdes[160];

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}

	for (d = alldevs; d; d = d->next) {
		pcap_addr_t *a;
		snprintf(devdes, sizeof(devdes), "%s: ", d->name);
		for (a = d->addresses; a; a = a->next) {
			char addr[100];
			if (!a->addr)
				continue;
			snprintf(addr, sizeof(addr), "a=%s", fg_nameinfo(a->addr));
			strncat(devdes, addr, sizeof(devdes));
			if (a->next)
				strncat(devdes, ", ", sizeof(devdes));
		}
		DEBUG_MSG(3, "found pcapabple device (%s)", devdes);
	}

	return;
}

void fg_pcap_go(int fd)
{
	pcap_if_t *d;
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	char found = 0;

	if (getsockname(fd, (struct sockaddr *)&sa, &sl) == -1) {
		logging_log(LOG_WARNING, "getsockname() failed. Eliding packet "
				"capture for flow.");
		return;
	}
	for (d = alldevs; d; d = d->next) {
		pcap_addr_t *a;
		for (a = d->addresses; a; a = a->next) {
			if (!a->addr)
				continue;
			if (sockaddr_compare(a->addr, (struct sockaddr *)&sa)) {
				DEBUG_MSG(2, "pcap: data connection inbound "
						"from %s (%s)", d->name, 
						fg_nameinfo(a->addr));
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
	if (*errbuf)
		logging_log(LOG_WARNING, "pcap warning: %s", errbuf);
	
	/* Check link-layer type */
	pcap_ll_type = pcap_datalink(pcap_handle);
	if (pcap_ll_type == -1) {
		logging_log(LOG_WARNING, "pcap: failed to determine link "
				"layer type. Eliding packet caputure.");
		return;
	}

	DEBUG_MSG(3, "pcap: inbound device %s has link layer type "
			"\"%s\" (%u).", d->name, 
			pcap_datalink_val_to_name(pcap_ll_type), 
			pcap_ll_type);

	switch (pcap_ll_type) {
	case DLT_NULL:
	case DLT_LOOP:
		break;

	default:
		logging_log(LOG_WARNING, "pcap: link layer type not supported. " 
				"Eliding packet caputure.");
		return;
	}
	
	/* We rely on a non-blocking dispatch loop */
	if (pcap_setnonblock(pcap_handle, 1 /* non-blocking */ , errbuf) == -1) {
		logging_log(LOG_WARNING, "pcap: failed to set non-blocking: %s",
				 errbuf);
		return;
	}

	/* XXX: compile a pcap expression to match the inbound port. */
	DEBUG_MSG(1, "pcap init done.");
	pcap_init_done = 1;
	return;
}

void 
fg_pcap_handler(u_char *users, const struct pcap_pkthdr *h, const u_char *packet)
{
	DEBUG_MSG(5, "pcap: processing packet, ts = %lu.%lu"
			", %hhu bytes.", h->ts.tv_sec, h->ts.tv_usec, h->caplen);

	/* XXX: do something about it! */
	return;
}

void fg_pcap_dispatch(void)
{
	int rc;
	if (!pcap_init_done)
		return;

	rc = pcap_dispatch(pcap_handle, -1 /* all packets */, 
			fg_pcap_handler, NULL);
	if (rc == -1) {
		logging_log(LOG_WARNING, "pcap_dispatch() failed. Packet "
				"dispatching stopped.");
		pcap_init_done = 0;
	} else
		DEBUG_MSG(4, "pcap: finished processing %u packets.", rc);

	return;
}


void fg_pcap_shutdown()
{
	pcap_freealldevs(alldevs);
}

#else

void fg_pcap_init(struct sockaddr *addr) {DEBUG_MSG(1, "(no pcap support compiled)");}
void fg_pcap_go(struct sockaddr *addr) {}
void fg_pcap_dispatch(void) {}
void fg_pcap_shutdown() {}

#endif

#endif
