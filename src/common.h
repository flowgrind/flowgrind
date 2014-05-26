/**
 * @file common.h
 * @brief Data structures used by the Flowgrind daemon and controller
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "gitversion.h"

#ifdef GITVERSION
/** Flowgrind version number */
#define FLOWGRIND_VERSION GITVERSION
#elif defined PACKAGE_VERSION
#define FLOWGRIND_VERSION PACKAGE_VERSION
#else
#define FLOWGRIND_VERSION "(n/a)"
#endif /* GITVERSION */

/** XML-RPC API version in integer representation */
#define FLOWGRIND_API_VERSION 3

/** Daemon's default listen port */
#define DEFAULT_LISTEN_PORT 5999

/** Maximal number of parallel flows */
#define MAX_FLOWS 2048

/* XXX add a brief description doxygen */
#define MAX_EXTRA_SOCKET_OPTIONS 10

/* XXX add a brief description doxygen */
#define MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH 100

#ifndef TCP_CA_NAME_MAX
/* XXX add a brief description doxygen */
#define TCP_CA_NAME_MAX 16
#endif /* TCP_CA_NAME_MAX */

/** Minium block (message) size we can send */
#define MIN_BLOCK_SIZE (signed) sizeof (struct _block)

/** Flow endpoint */
enum flow_endpoint {
	/** Endpoint that opens the connection */
	SOURCE = 0,
	/** Endpoint that accepts the connection */
	DESTINATION,
};

/** I/O operation */
enum io_ops {
	/** Write operation */
	WRITE = 0,
	/** Read operation */
	READ
};

/** Report types */
enum interval_type {
	/** Intermediated interval report */
	INTERVAL = 0,
	/** Final report */
	FINAL
};

/* XXX add a brief description doxygen (no underscore for enum) */
enum _extra_socket_option_level {
	level_sol_socket,
	level_sol_tcp,
	level_ipproto_ip,
	level_ipproto_sctp,
	level_ipproto_tcp,
	level_ipproto_udp
};

/** Stochastic distributions for traffic generation */
enum distributions {
	/** No stochastic distribution */
	CONSTANT = 0,
	/** Normal distribution */
	NORMAL,
	/** Weibull distribution */
	WEIBULL,
	/** Uniform distribution */
	UNIFORM,
	/** Exponential distribution */
	EXPONENTIAL,
	/** Pareto distribution */
	PARETO,
	/** Log Normal distribution */
	LOGNORMAL
};

/** Flowgrind's data block layout */
struct _block {
	/** Size of our request or response block */
	int32_t this_block_size;

	/**
	 *  Size of the response block we request
	 *
	 *  0 indicates that we don't request a response block <BR>
	 * -1 indicates this is a response block (needed for parsing data) */
	int32_t request_block_size;

	/** Sending timestap for calculating delay and RTT */
	struct timespec data;
	/** Used to access 64bit timespec on 32bit arch */
	struct timespec data2;
};

/* XXX add a brief description doxygen */
struct _trafgen_options {
	enum distributions distribution;
	double param_one;
	double param_two;

};

/* Common to both endpoints */
struct _flow_settings {
	char bind_address[1000];

	double delay[2];
	double duration[2];

	double reporting_interval;

	int requested_send_buffer_size;
	int requested_read_buffer_size;

	int maximum_block_size;

	int traffic_dump;
	int so_debug;
	int route_record;
	int pushy;
	int shutdown;

	/** Send at specified rate per second (option -R) */
	char *write_rate_str;
	/** The actual rate we should send */
	int write_rate;

	unsigned int random_seed;

	int flow_control;

	int byte_counting;

	int cork;
	int nonagle;
	char cc_alg[TCP_CA_NAME_MAX];
	int elcn;
	int lcd;
	int mtcp;
	int dscp;
	int ipmtudiscover;

	struct _trafgen_options request_trafgen_options;
	struct _trafgen_options response_trafgen_options;
	struct _trafgen_options interpacket_gap_trafgen_options;

	struct _extra_socket_options {
		int level;
		int optname;
		int optlen;
		char optval[MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH];
	} extra_socket_options[MAX_EXTRA_SOCKET_OPTIONS];
	int num_extra_socket_options;
};

/* Flowgrinds view on the tcp_info struct for
 * serialization / deserialization */
struct _fg_tcp_info {
	int tcpi_snd_cwnd;
	int tcpi_snd_ssthresh;
	int tcpi_unacked;
	int tcpi_sacked;
	int tcpi_lost;
	int tcpi_retrans;
	int tcpi_retransmits;
	int tcpi_fackets;
	int tcpi_reordering;
	int tcpi_rtt;
	int tcpi_rttvar;
	int tcpi_rto;
	int tcpi_backoff;
	int tcpi_snd_mss;
	int tcpi_ca_state;
};

/* Report (measurement sample) of a flow */
struct _report {
	int id;
	/* Is this an INTERVAL or FINAL report? */
	int type;
	struct timespec begin;
	struct timespec end;
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

	/** Minimum inter-arrival time */
	double iat_min;
	/** Maximum inter-arrival time */
	double iat_max;
	/** Accumulated inter-arrival time */
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

	/* on the Daemon this is filled from the os specific
	 * tcp_info struct */
	struct _fg_tcp_info tcp_info;

	int pmtu;
	int imtu;

	int status;

	struct _report* next;
};

#endif /* _COMMON_H_*/
