/**
 * @file flowgrind.h
 * @brief Flowgrind Controller
 */

/*
 * Copyright (C) 2013 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Arnd Hannemann <arnd@arndnet.de>
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

#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#include "common.h"
#include "fg_time.h"

#ifdef __LINUX__
/** Sysctl for quering available congestion control algorithms */
#define SYSCTL_CC_AVAILABLE  "net.ipv4.tcp_available_congestion_control"
#elif __FreeBSD__
#define SYSCTL_CC_AVAILABLE "net.inet.tcp.cc.available"
#endif /* __LINUX__ */

/** Shortcut for show_columns() */
#define SHOW_COLUMNS(...)						    \
	(set_column_visibility(true, NARGS(__VA_ARGS__), __VA_ARGS__))

/** Shortcut for hide_columns() */
#define HIDE_COLUMNS(...)						    \
	(set_column_visibility(false, NARGS(__VA_ARGS__), __VA_ARGS__))

/** Shortcut for set_column_header_unit() */
#define SET_COLUMN_UNIT(unit, ...)					    \
	(set_column_unit(unit, NARGS(__VA_ARGS__), __VA_ARGS__))

/** Transport protocols */
enum protocol {
	/** Transmission Control Protocol */
	PROTO_TCP = 1,
	/** User Datagram Protocol */
	PROTO_UDP
};

/** Unit of the TCP Stack */
enum tcp_stack {
	/** Linux is a segment-based stack */
	SEGMENT_BASED = 0,
	/** BSD stacks are bytes-based stacks */
	BYTE_BASED
};

#ifndef __LINUX__
/** Values for Linux tcpi_state, if not compiled on Linux */
enum tcp_ca_state
{
	/** TCP sender follows fast path execution (normal state) */
        TCP_CA_Open = 0,
	/** TCP sender receives duplicate ACKs or SACKs */
        TCP_CA_Disorder = 1,
	/** TCP sender receives ECN congestion notifications */
        TCP_CA_CWR = 2,
	/** TCP sender performs Fast Recovery */
        TCP_CA_Recovery = 3,
	/** Retransmission timeout occurred */
        TCP_CA_Loss = 4
};
#endif /* __LINUX__ */

/** IDs to explicit address an intermediated interval report column */
enum column_id
{
        /** Flow ID */
        COL_FLOW_ID = 0,
        /** Report interval @{ */
        COL_BEGIN,
        COL_END,                                            /** @} */
        /** Throughput per seconds */
        COL_THROUGH,
        /** Transactions per second */
        COL_TRANSAC,
        /** Blocks per second @{ */
        COL_BLOCK_REQU,
        COL_BLOCK_RESP,                                     /** @} */
        /** Application level round-trip time @{ */
        COL_RTT_MIN,
        COL_RTT_AVG,
        COL_RTT_MAX,                                        /** @} */
        /** Application level inter-arrival time @{ */
        COL_IAT_MIN,
        COL_IAT_AVG,
        COL_IAT_MAX,                                        /** @} */
        /** Application level one-way delay @{ */
        COL_DLY_MIN,
        COL_DLY_AVG,
        COL_DLY_MAX,                                        /** @} */
        /** Metric from the Linux / BSD TCP stack @{ */
        COL_TCP_CWND,
        COL_TCP_SSTH,
        COL_TCP_UACK,
        COL_TCP_SACK,
        COL_TCP_LOST,
        COL_TCP_RETR,
        COL_TCP_TRET,
        COL_TCP_FACK,
        COL_TCP_REOR,
        COL_TCP_BKOF,
        COL_TCP_RTT,
        COL_TCP_RTTVAR,
        COL_TCP_RTO,
        COL_TCP_CA_STATE,
        COL_SMSS,
        COL_PMTU,                                           /** @} */
#ifdef DEBUG
        /** Read / write status */
        COL_STATUS
#endif /* DEBUG */
};

/** General controller options */
struct _opt {
	/** Number of test flows (option -n) */
	unsigned short num_flows;
	/** Length of reporting interval, in seconds (option -i) */
	double reporting_interval;
	/** Write output to screen (option -q) */
	bool dont_log_stdout;
	/** Write output to logfile (option -w) */
	bool dont_log_logfile;
	/** Name of logfile (option -l) */
	char *log_filename;
	/** Prefix for log- and dumpfile (option -e) */
	char *log_filename_prefix;
	/** Overwrite existing log files (option -o) */
	bool clobber;
	/** Report in MByte/s instead of MBit/s (option -m) */
	bool mbyte;
	/** Don't use symbolic values instead of number (option -p) */
	bool symbolic;
	/** Force kernel output to specific unit  (option -u) */
	enum tcp_stack force_unit;
};

/** Infos about a flowgrind daemon */
struct _daemon {
/* Note: a daemon can potentially managing multiple flows */
	/** XMLRPC URL for this daemon */
	char server_url[1000];
	/** Name of the XMLRPC server */
	char server_name[257];
	/** Port of the XMLRPC server */
	unsigned short server_port;
	/** Flowgrind API version supported by this daemon */
	int api_version;
	/** OS on which this daemon runs */
	char os_name[257];
	/** Release number of the OS */
	char os_release[257];
};

/** Infos about the flow endpoint */
struct _flow_endpoint {
	/** Sending buffer (SO_SNDBUF) */
	int send_buffer_size_real;
	/** Receiver buffer (SO_RCVBUF) */
	int receive_buffer_size_real;

	/** Pointer to the daemon managing this endpoint */
	struct _daemon* daemon;
	/* XXX add a brief description doxygen */
	char test_address[1000];
};

/** Infos about the flow including flow options */
struct _cflow {
	/** Used transport protocol */
	enum protocol proto;

	/* TODO Some of this flow option members are duplicates from the
	 * _flow_settings struct (see common.h). Flowgrind contoller
	 * should use this one */

	/** Call connect() immediately before sending data (option -L) */
	char late_connect;
	/** shutdown() each socket direction after test flow (option (-N) */
	char shutdown;
	/** Summarize only, no intermediated interval reports (option -Q) */
	char summarize_only;
	/** Enumerate bytes in payload instead of sending zeros (option -E) */
	char byte_counting;
	/** Random seed for stochastic traffic generation (option -J) */
	unsigned int random_seed;

	/* For the following arrays: 0 stands for source; 1 for destination */

	/* XXX add a brief description doxygen */
	int endpoint_id[2];
	/* XXX add a brief description doxygen */
	struct timespec start_timestamp[2];
	/** Infos about flow endpoint */
	struct _flow_endpoint endpoint[2];
	/** Flow specific options */
	struct _flow_settings settings[2];
	/** Flag if final report for the flow is received  */
	char finished[2];
	/** Final report from the daemon */
	struct _report *final_report[2];
};

/** Header of an intermediated interval report column */
struct _column_header
{
        /** First header row: name of the column */
        const char* name;
        /** Second header row: unit of the column */
        const char* unit;
};

/** State of an intermediated interval report column */
struct _column_state
{
        /** Dynamically turn an column on/off */
        bool visible;
        /** How often the current column width was too high */
        unsigned int oversized;
        /** Last width of the column */
        unsigned int last_width;
};

/** Intermediated interval report column */
struct _column
{
        /** Unique column identifier */
        enum column_id type;
        /** Column header (name and unit) */
        struct _column_header header;
        /** State of the column */
        struct _column_state state;
};

/**
 * Print flowgrind usage and exit
 */
static void usage(void) __attribute__((noreturn));

/**
 * Print help on socket options and exit
 */
static void usage_sockopt(void) __attribute__((noreturn));

/**
 * Print help on traffic generation and exit
 */
static void usage_trafgenopt(void) __attribute__((noreturn));

/**
 * Print hint upon an error while parsing the command line
 */
inline static void usage_hint(void) __attribute__((noreturn));

/**
 * Initialization of general controller options
 */
static void init_general_options(void);

/**
 * To show/hide intermediated interval report columns
 *
 * @param[in] bool column visibility
 * @param[in] nargs length of variable argument list
 * @param[in] ... column IDs
 * @see enum column_id
 */
static void set_column_visibility(bool visibility, unsigned int nvargs, ...);

/**
 * To set the unit the in header of intermediated interval report columns
 *
 * @param[in] unit unit of column header as string
 * @param[in] nargs length of variable argument list
 * @param[in] ... column IDs
 * @see enum column_id
 */
static void set_column_unit(const char *unit, unsigned int nargs, ...);

/**
 * Parse argument for option -c to hide/show intermediated interval report
 * columns
 *
 * @param[in] optarg argument for option -c
 */
static void parse_visible_option(char *optarg);

#endif /* _FLOWGRIND_H_ */
