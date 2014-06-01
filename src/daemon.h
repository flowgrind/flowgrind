/**
 * @file daemon.h
 * @brief Routines used by the Flowgrind daemon
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
 *
 * This file is part of Flowgrind. Flowgrind is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2 as published by the Free Software Foundation.
 *
 * Flowgrind distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _DAEMON_H_
#define _DAEMON_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_LIBGSL
#include <gsl/gsl_rng.h>
#endif /* HAVE_LIBGSL */

#include "common.h"
#include "fg_list.h"

/** time select() will block waiting for a file descriptor to become ready */
#define DEFAULT_SELECT_TIMEOUT  10000000

enum flow_state
{
	/* SOURCE */
	GRIND_WAIT_CONNECT = 0,
	/* DESTINATION */
	GRIND_WAIT_ACCEPT,
	/* RUN */
	GRIND
};

struct _flow_source_settings
{
	char destination_host[256];
	int destination_port;

	int late_connect;

	pthread_cond_t* add_source_condition;
};

struct _flow
{
	int id;

	enum flow_state state;
	enum flow_endpoint endpoint;

	int fd;
	int listenfd_data;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct timespec start_timestamp[2];
	struct timespec stop_timestamp[2];
	struct timespec last_block_read;
	struct timespec last_block_written;

	struct timespec first_report_time;
	struct timespec last_report_time;
	struct timespec next_report_time;

	struct timespec next_write_block_timestamp;

	char *read_block;
	char *write_block;

	unsigned int current_write_block_size;
	unsigned int current_read_block_size;

	unsigned int current_block_bytes_read;
	unsigned int current_block_bytes_written;

	unsigned short requested_server_test_port;

	unsigned real_listen_send_buffer_size;
	unsigned real_listen_receive_buffer_size;

	char connect_called;
	char finished[2];

	int pmtu;

	unsigned int congestion_counter;

	/* Used for late_connect */
	struct sockaddr *addr;
	socklen_t addr_len;

	struct _statistics {
#ifdef HAVE_UNSIGNED_LONG_LONG_INT
		unsigned long long bytes_read;
		unsigned long long bytes_written;
#else
		long bytes_read;
		long bytes_written;
#endif /* HAVE_UNSIGNED_LONG_LONG_INT */
		unsigned int request_blocks_read;
		unsigned int request_blocks_written;
		unsigned int response_blocks_read;
		unsigned int response_blocks_written;

		/* TODO Create an array for IAT / RTT and delay */

		/** Minimum interarrival time */
		double iat_min;
		/** Maximum interarrival time */
		double iat_max;
		/** Accumulated interarrival time */
		double iat_sum;
		/** Minimum one-way delay */
		double delay_min;
		/** Maximum one-way delay */
		double delay_max;
		/** Accumulated one-way delay */
		double delay_sum;
		/** Minimum round-trip time */
		double rtt_min;
		/** Maximum round-trip time */
		double rtt_max;
		/** Accumulated round-trip time */
		double rtt_sum;

#if (defined __LINUX__ || defined __FreeBSD__)
		int has_tcp_info;
		struct _fg_tcp_info tcp_info;
#endif /* (defined __LINUX__ || defined __FreeBSD__) */

	} statistics[2];

#ifdef HAVE_LIBPCAP
	pthread_t pcap_thread;
	struct pcap_t *pcap_handle;
	struct pcap_dumper_t *pcap_dumper;
#endif /* HAVE_LIBPCAP */

#ifdef HAVE_LIBGSL
	gsl_rng * r;
#endif /* HAVE_LIBGSL */

	char* error;
};

#define REQUEST_ADD_DESTINATION 0
#define REQUEST_ADD_SOURCE 1
#define REQUEST_START_FLOWS 2
#define REQUEST_STOP_FLOW 3
#define REQUEST_GET_STATUS 4
struct _request
{
	char type;

	/* We signal this condition once the daemon thread
	 * has processed the request */
	pthread_cond_t* condition;

	char* error;

	struct _request *next;
};
extern struct _request *requests, *requests_last;

struct _request_add_flow_destination
{
	struct _request r;

	struct _flow_settings settings;

	/* The request reply */
	int flow_id;
	int listen_data_port;
	int real_listen_send_buffer_size;
	int real_listen_read_buffer_size;
};

struct _request_add_flow_source
{
	struct _request r;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	/* The request reply */
	int flow_id;
	char cc_alg[TCP_CA_NAME_MAX];
	int real_send_buffer_size;
	int real_read_buffer_size;
};

struct _request_start_flows
{
	struct _request r;

	int start_timestamp;
};

struct _request_stop_flow
{
	struct _request r;

	int flow_id;
};

struct _request_get_status
{
	struct _request r;

	int started;
	int num_flows;
};

pthread_t daemon_thread;

/* Through this pipe we wakeup the thread from select */
extern int daemon_pipe[2];

extern char started;
extern char dumping;
extern pthread_mutex_t mutex;
extern struct _linked_list flows;
extern struct _report* reports;
extern struct _report* reports_last;
extern unsigned int pending_reports;

/* Gets 50 reports. There may be more pending but there's a limit on how
 * large a reply can get */
struct _report* get_reports(int *has_more);

#ifdef HAVE_LIBPCAP
char *dump_prefix;
char *dump_dir;
#endif /* HAVE_LIBPCAP */

void *daemon_main(void* ptr);
void add_report(struct _report* report);
void flow_error(struct _flow *flow, const char *fmt, ...);
void request_error(struct _request *request, const char *fmt, ...);
int set_flow_tcp_options(struct _flow *flow);

#endif /* _DAEMON_H_ */
