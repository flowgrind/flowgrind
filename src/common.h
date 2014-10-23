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
#else /* GITVERSION */
#define FLOWGRIND_VERSION "(n/a)"
#endif /* GITVERSION */

/** XML-RPC API version in integer representation */
#define FLOWGRIND_API_VERSION 3

/** Daemon's default listen port */
#define DEFAULT_LISTEN_PORT 5999

/** Maximal number of parallel flows */
#define MAX_FLOWS 2048

/** Max number of arbitrary extra socket options which may be sent to the deamon */
#define MAX_EXTRA_SOCKET_OPTIONS 10

/** Ensures extra options are limited in length on both controller and deamon side */
#define MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH 100

#ifndef TCP_CA_NAME_MAX
/** Max size of the congestion control algorithm specifier string */
#define TCP_CA_NAME_MAX 16
#endif /* TCP_CA_NAME_MAX */

/** Minium block (message) size we can send */
#define MIN_BLOCK_SIZE (signed) sizeof (struct block)

/** Flowgrind's copyright year */
#define FLOWGRIND_COPYRIGHT "Copyright (C) 2007 - 2014 Flowgrind authors."

/** Standard GPL3 no warranty message */
#define FLOWGRIND_COPYING								    \
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"  \
	"This is free software: you are free to change and redistribute it.\n"		    \
	"There is NO WARRANTY, to the extent permitted by law."

/** Flowgrind's authors in a printable string */
#define FLOWGRIND_AUTHORS								    \
	"Written by Arnd Hannemann, Tim Kosse, Christian Samsel, Daniel Schaffrath\n"	    \
	"and Alexander Zimmermann."

/** Flow endpoint types */
enum flow_endpoint_type {
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

/* XXX add a brief description doxygen */
enum extra_socket_option_level {
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
struct block {
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

/** Options for stochastic traffic generation */
struct trafgen_options {
	/** The stochastic distribution to draw values from */
	enum distributions distribution;
	/** First mathemathical parameter of the distribution */
	double param_one;
	/** Second mathematical parameter of the distribution, if required */
	double param_two;

};

/**
 * Settings that describe a flow between two endpoints. These options can be
 * specified for each of the two endpoints
 */
struct flow_settings {
	/** The interface address for the flow (used by daemon) */
	char bind_address[1000];

	/** Delay of flow in seconds (option -Y) */
	double delay[2];
	/** Duration of flow in seconds (option -T) */
	double duration[2];

	/** Interval to report flow on screen (option -i) */
	double reporting_interval;

	/** Request sender buffer in bytes (option -B) */
	int requested_send_buffer_size;
	/** Request receiver buffer, advertised window in bytes (option -W) */
	int requested_read_buffer_size;

	/** Application buffer size in bytes (option -U) */
	int maximum_block_size;

	/** Dump traffic using libpcap (option -M) */
	int traffic_dump;
	/** Sets SO_DEBUG on test socket (option -O) */
	int so_debug;
	/** Sets ROUTE_RECORD on test socket (option -O) */
	int route_record;
	/**
	 * Do not iterate through select() to continue sending in case
	 * block size did not suffice to fill sending queue (pushy) (option -P)
	 */
	int pushy;
	/** Shutdown socket after test flow (option -N) */
	int shutdown;

	/** Send at specified rate per second (option -R) */
	const char *write_rate_str;
	/** The actual rate we should send */
	int write_rate;

	/** Random seed to use (default: read /dev/urandom) (option -J) */
	unsigned int random_seed;

	/** Stop flow if it is experiencing local congestion (option -C) */
	int flow_control;

	/** Enumerate bytes in payload instead of sending zeros (option -E) */
	int byte_counting;

	/** Sets SO_DEBUG on test socket (option -O) */
	int cork;
	/** Disable nagle algorithm on test socket (option -O) */
	int nonagle;
	/** Set congestion control algorithm ALG on test socket (option -O) */
	char cc_alg[TCP_CA_NAME_MAX];
	/** Set TCP_ELCN (20) on test socket (option -O) */
	int elcn;
	/** Set TCP_LCD (21) on test socket (option -O) */
	int lcd;
	/** Set TCP_MTCP (15) on test socket (option -O) */
	int mtcp;
	/** DSCP value for TOS byte (option -D) */
	int dscp;
	/** Set IP_MTU_DISCOVER on test socket (option -O) */
	int ipmtudiscover;

	/** Stochastic traffic generation settings for the request size */
	struct trafgen_options request_trafgen_options;
	/** Stochastic traffic generation settings for the response size */
	struct trafgen_options response_trafgen_options;
	/** Stochastic traffic generation settings for the interpacket gap */
	struct trafgen_options interpacket_gap_trafgen_options;

	/* XXX add a brief description doxygen + is this obsolete? */
	struct extra_socket_options {
		int level;
		int optname;
		int optlen;
		char optval[MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH];
	} extra_socket_options[MAX_EXTRA_SOCKET_OPTIONS];
	int num_extra_socket_options;
};

/* Flowgrinds view on the tcp_info struct for
 * serialization / deserialization */
struct fg_tcp_info {
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
struct report {
	int id;
	/* Is this an INTERVAL or FINAL report? */
	int type;
	struct timespec begin;
	struct timespec end;
#ifdef HAVE_UNSIGNED_LONG_LONG_INT
	unsigned long long bytes_read;
	unsigned long long bytes_written;
#else /* HAVE_UNSIGNED_LONG_LONG_INT */
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
	struct fg_tcp_info tcp_info;

	int pmtu;
	int imtu;

	int status;

	struct report* next;
};

#endif /* _COMMON_H_*/
