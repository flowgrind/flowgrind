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
	SEGMENT_BASED = 1,
	/** BSD stacks are bytes-based stacks */
	BYTE_BASED
};

/** General controller options */
struct _opt {
	/** Number of test flows (option -n) */
	unsigned short num_flows;
	/** Length of reporting interval, in seconds (option -i) */
	double reporting_interval;
	/** Write output to screen (option -q) */
	char dont_log_stdout;
	/** Write output to logfile (option -w) */
	char dont_log_logfile;
	/** Name of logfile (option -l) */
	char *log_filename;
	/** Prefix for log- and dumpfile (option -e) */
	char *log_filename_prefix;
	/** Overwrite existing log files (option -o) */
	char clobber;
	/** Report in MByte/s instead of MBit/s (option -m) */
	char mbyte;
	/** Don't use symbolic values instead of number (option -p) */
	char symbolic;
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

extern struct _opt opt;

/* XXX add a brief description doxygen */
inline static double scale_thruput(double thruput)
{
	if (opt.mbyte)
		return thruput / (1<<20);
	return thruput / 1e6 * (1<<3);
}
#endif /* _FLOWGRIND_H_ */
