/**
 * @file flowgrind.c
 * @brief Flowgrind controller
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Arnd Hannemann <arnd@arndnet.de>
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <sys/types.h>
/* for AF_INET6 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
/* for CA states (on Linux only) */
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
/* xmlrpc-c */
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#include "flowgrind.h"
#include "common.h"
#include "fg_error.h"
#include "fg_progname.h"
#include "fg_time.h"
#include "fg_definitions.h"
#include "fg_string.h"
#include "debug.h"
#include "fg_rpc_client.h"
#include "fg_argparser.h"
#include "fg_log.h"

/** To show intermediated interval report columns. */
#define SHOW_COLUMNS(...)                                                   \
        (set_column_visibility(true, NARGS(__VA_ARGS__), __VA_ARGS__))

/** To hide intermediated interval report columns. */
#define HIDE_COLUMNS(...)                                                   \
        (set_column_visibility(false, NARGS(__VA_ARGS__), __VA_ARGS__))

/** To set the unit of intermediated interval report columns. */
#define SET_COLUMN_UNIT(unit, ...)                                          \
        (set_column_unit(unit, NARGS(__VA_ARGS__), __VA_ARGS__))

/** Print error message, usage string and exit. Used for cmdline parsing errors. */
#define PARSE_ERR(err_msg, ...) do {	\
	errx(err_msg, ##__VA_ARGS__);	\
	usage(EXIT_FAILURE);		\
} while (0)

/* External global variables */
extern const char *progname;

/** Logfile for measurement output. */
static FILE *log_stream = NULL;

/** Name of logfile. */
static char *log_filename = NULL;

/** SIGINT (CTRL-C) received? */
static bool sigint_caught = false;

/* XML-RPC environment object that contains any error that has occurred. */
static xmlrpc_env rpc_env;

/** Global linked list to the flow endpoints XML RPC connection information. */
static struct linked_list flows_rpc_info;

/** Global linked list to the daemons containing UUID and daemons flowgrind version. */
static struct linked_list unique_daemons;

/** Command line option parser. */
static struct arg_parser parser;

/** Controller options. */
static struct controller_options copt;

/** Infos about all flows including flow options. */
static struct cflow cflow[MAX_FLOWS];

/** Command line option parser. */
static struct arg_parser parser;

/** Number of currently active flows. */
static unsigned short active_flows = 0;

/* To cover a gcc bug (http://gcc.gnu.org/bugzilla/show_bug.cgi?id=36446) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
/** Infos about the intermediated interval report columns. */
static struct column column_info[] = {
	{.type = COL_FLOW_ID, .header.name = "# ID",
	 .header.unit = "#   ", .state.visible = true},
	{.type = COL_BEGIN, .header.name = "begin",
	 .header.unit = "[s]", .state.visible = true},
	{.type = COL_END, .header.name = "end",
	 .header.unit = "[s]", .state.visible = true},
	{.type = COL_THROUGH, .header.name = "through",
	 .header.unit = "[Mbit/s]", .state.visible = true},
	{.type = COL_TRANSAC, .header.name = "transac",
	 .header.unit = "[#/s]", .state.visible = true},
	{.type = COL_BLOCK_REQU, .header.name = "requ",
	 .header.unit = "[#]", .state.visible = false},
	{.type = COL_BLOCK_RESP, .header.name = "resp",
	 .header.unit = "[#]", .state.visible = false},
	{.type = COL_RTT_MIN, .header.name = "min RTT",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_RTT_AVG, .header.name = "avg RTT",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_RTT_MAX, .header.name = "max RTT",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_IAT_MIN, .header.name = "min IAT",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_IAT_AVG, .header.name = "avg IAT",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_IAT_MAX, .header.name = "max IAT",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_DLY_MIN, .header.name = "min DLY",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_DLY_AVG, .header.name = "avg DLY",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_DLY_MAX, .header.name = "max DLY",
	 .header.unit = "[ms]", .state.visible = false},
	{.type = COL_TCP_CWND, .header.name = "cwnd",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_SSTH, .header.name = "ssth",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_UACK, .header.name = "uack",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_SACK, .header.name = "sack",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_LOST, .header.name = "lost",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_RETR, .header.name = "retr",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_TRET, .header.name = "tret",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_FACK, .header.name = "fack",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_REOR, .header.name = "reor",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_BKOF, .header.name = "bkof",
	 .header.unit = "[#]", .state.visible = true},
	{.type = COL_TCP_RTT, .header.name = "rtt",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_TCP_RTTVAR, .header.name = "rttvar",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_TCP_RTO, .header.name = "rto",
	 .header.unit = "[ms]", .state.visible = true},
	{.type = COL_TCP_CA_STATE, .header.name = "ca state",
	 .header.unit = "", .state.visible = true},
	{.type = COL_SMSS, .header.name = "smss",
	 .header.unit = "[B]", .state.visible = true},
	{.type = COL_PMTU, .header.name = "pmtu",
	 .header.unit = "[B]", .state.visible = true},
#ifdef DEBUG
	{.type = COL_STATUS, .header.name = "status",
	 .header.unit = "", .state.visible = false}
#endif /* DEBUG */
};
#pragma GCC diagnostic pop

/* Forward declarations */
static void usage(short status)
	__attribute__((noreturn));
static void usage_sockopt(void)
	__attribute__((noreturn));
static void usage_trafgenopt(void)
	__attribute__((noreturn));
inline static void print_output(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
static void fetch_reports(xmlrpc_client *);
static void report_flow(struct report* report);
static void print_interval_report(unsigned short flow_id, enum endpoint_t e,
		                  struct report *report);

/**
 * Print usage or error message and exit.
 *
 * Depending on exit status @p status print either the usage or an error
 * message. In all cases it call exit() with the given exit status @p status.
 *
 * @param[in] status exit status
 */
static void usage(short status)
{
	/* Syntax error. Emit 'try help' to stderr and exit */
	if (status != EXIT_SUCCESS) {
		fprintf(stderr, "Try '%s -h' for more information\n", progname);
		exit(status);
	}

	fprintf(stdout,
		"Usage: %1$s [OPTION]...\n"
		"Advanced TCP traffic generator for Linux, FreeBSD, and Mac OS X.\n\n"

		"Mandatory arguments to long options are mandatory for short options too.\n\n"

		"General options:\n"
		"  -h, --help[=WHAT]\n"
		"                 display help and exit. Optional WHAT can either be 'socket' for\n"
		"                 help on socket options or 'traffic' traffic generation help\n"
		"  -v, --version  print version information and exit\n\n"

		"Controller options:\n"
		"  -c, --show-colon=TYPE[,TYPE]...\n"
		"                 display intermediated interval report column TYPE in output.\n"
		"                 Allowed values for TYPE are: 'interval', 'through', 'transac',\n"
		"                 'iat', 'kernel' (all show per default), and 'blocks', 'rtt',\n"
#ifdef DEBUG
		"                 'delay', 'status' (optional)\n"
#else /* DEBUG */
		"                 'delay' (optional)\n"
#endif /* DEBUG */
#ifdef DEBUG
		"  -d, --debug    increase debugging verbosity. Add option multiple times to\n"
		"                 increase the verbosity\n"
#endif /* DEBUG */
		"  -e, --dump-prefix=PRE\n"
		"                 prepend prefix PRE to pcap dump filename (default: \"%3$s\")\n"
		"  -i, --report-interval=#.#\n"
		"                 reporting interval, in seconds (default: 0.05s)\n"
		"      --log-file[=FILE]\n"
		"                 write output to logfile FILE (default: %1$s-'timestamp'.log)\n"
		"  -m             report throughput in 2**20 bytes/s (default: 10**6 bit/s)\n"
		"  -n, --flows=#  number of test flows (default: 1)\n"
		"  -o             overwrite existing log files (default: don't)\n"
		"  -p             don't print symbolic values (like INT_MAX) instead of numbers\n"
		"  -q, --quiet    be quiet, do not log to screen (default: off)\n"
		"  -s, --tcp-stack=TYPE\n"
		"                 don't determine unit of source TCP stacks automatically. Force\n"
		"                 unit to TYPE, where TYPE is 'segment' or 'byte'\n"
		"  -w             write output to logfile (same as --log-file)\n\n"

		"Flow options:\n"
		"  Some of these options take the flow endpoint as argument, denoted by 'x' in\n"
		"  the option syntax. 'x' needs to be replaced with either 's' for the source\n"
		"  endpoint, 'd' for the destination endpoint or 'b' for both endpoints. To\n"
		"  specify different values for each endpoints, separate them by comma. For\n"
		"  instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"  and 4096 at the destination.\n\n"
		"  -A x           use minimal response size needed for RTT calculation\n"
		"                 (same as -G s=p,C,%2$d)\n"
		"  -B x=#         set requested sending buffer, in bytes\n"
		"  -C x           stop flow if it is experiencing local congestion\n"
		"  -D x=DSCP      DSCP value for TOS byte\n"
		"  -E             enumerate bytes in payload instead of sending zeros\n"
		"  -F #[,#]...    flow options following this option apply only to the given flow \n"
		"                 IDs. Useful in combination with -n to set specific options\n"
		"                 for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"                 to the second flow. With -1 all flow are refered\n"
#ifdef HAVE_LIBGSL
		"  -G x=(q|p|g):(C|U|E|N|L|P|W):#1:[#2]\n"
#else /* HAVE_LIBGSL */
		"  -G x=(q|p|g):(C|U):#1:[#2]\n"
#endif /* HAVE_LIBGSL */
		"                 activate stochastic traffic generation and set parameters\n"
		"                 according to the used distribution. For additional information \n"
		"                 see 'flowgrind --help=traffic'\n"
		"  -H x=HOST[/CONTROL[:PORT]]\n"
		"                 test from/to HOST. Optional argument is the address and port\n"
		"                 for the CONTROL connection to the same host.\n"
		"                 An endpoint that isn't specified is assumed to be localhost\n"
		"  -J #           use random seed # (default: read /dev/urandom)\n"
		"  -I             enable one-way delay calculation (no clock synchronization)\n"
		"  -L             call connect() on test socket immediately before starting to\n"
		"                 send data (late connect). If not specified the test connection\n"
		"                 is established in the preparation phase before the test starts\n"
		"  -M x           dump traffic using libpcap. flowgrindd must be run as root\n"
		"  -N             shutdown() each socket direction after test flow\n"
		"  -O x=OPT       set socket option OPT on test socket. For additional information\n"
		"                 see 'flowgrind --help=socket'\n"
		"  -P x           do not iterate through select() to continue sending in case\n"
		"                 block size did not suffice to fill sending queue (pushy)\n"
		"  -Q             summarize only, no intermediated interval reports are\n"
		"                 computed (quiet)\n"
		"  -R x=#.#(z|k|M|G)(b|B)\n"
		"                 send at specified rate per second, where: z = 2**0, k = 2**10,\n"
		"                 M = 2**20, G = 2**30, and b = bits/s (default), B = bytes/s\n"
		"  -S x=#         set block (message) size, in bytes (same as -G s=q,C,#)\n"
		"  -T x=#.#       set flow duration, in seconds (default: s=10,d=0)\n"
		"  -U x=#         set application buffer size, in bytes (default: 8192)\n"
		"                 truncates values if used with stochastic traffic generation\n"
		"  -W x=#         set requested receiver buffer (advertised window), in bytes\n"
		"  -Y x=#.#       set initial delay before the host starts to send, in seconds\n"
/*		"  -Z x=#.#       set amount of data to be send, in bytes (instead of -t)\n"*/,
		progname,
		MIN_BLOCK_SIZE
		, copt.dump_prefix
		);
	exit(EXIT_SUCCESS);
}

/**
 * Print help on flowgrind's socket options and exit with EXIT_SUCCESS.
 */
static void usage_sockopt(void)
{
	fprintf(stdout,
		"%s allows to set the following standard and non-standard socket options. \n\n"

		"All socket options take the flow endpoint as argument, denoted by 'x' in the\n"
		"option syntax. 'x' needs to be replaced with either 's' for the source endpoint,\n"
		"'d' for the destination endpoint or 'b' for both endpoints. To specify different\n"
		"values for each endpoints, separate them by comma. Moreover, it is possible to\n"
		"repeatedly pass the same endpoint in order to specify multiple socket options\n\n"

		"Standard socket options:\n"
		"  -O x=TCP_CONGESTION=ALG\n"
		"               set congestion control algorithm ALG on test socket\n"
		"  -O x=TCP_CORK\n"
		"               set TCP_CORK on test socket\n"
		"  -O x=TCP_NODELAY\n"
		"               disable nagle algorithm on test socket\n"
		"  -O x=SO_DEBUG\n"
		"               set SO_DEBUG on test socket\n"
		"  -O x=IP_MTU_DISCOVER\n"
		"               set IP_MTU_DISCOVER on test socket if not already enabled by\n"
		"               system default\n"
		"  -O x=ROUTE_RECORD\n"
		"               set ROUTE_RECORD on test socket\n\n"

		"Non-standard socket options:\n"
		"  -O x=TCP_MTCP\n"
		"               set TCP_MTCP (15) on test socket\n"
		"  -O x=TCP_ELCN\n"
		"               set TCP_ELCN (20) on test socket\n"
		"  -O x=TCP_LCD set TCP_LCD (21) on test socket\n\n"

		"Examples:\n"
		"  -O s=TCP_CONGESTION=reno,d=SO_DEBUG\n"
		"               sets Reno TCP as congestion control algorithm at the source and\n"
		"               SO_DEBUG as socket option at the destinatio\n"
		"  -O s=SO_DEBUG,s=TCP_CORK\n"
		"               set SO_DEBUG and TCP_CORK as socket option at the source\n",
		progname);
	exit(EXIT_SUCCESS);
}

/**
 * Print help on flowgrind's traffic generation facilities and exit with EXIT_SUCCESS.
 */
static void usage_trafgenopt(void)
{
	fprintf(stdout,
		"%s supports stochastic traffic generation, which allows to conduct\n"
		"besides normal bulk also advanced rate-limited and request-response data\n"
		"transfers.\n\n"

		"The stochastic traffic generation option '-G' takes the flow endpoint as\n"
		"argument, denoted by 'x' in the option syntax. 'x' needs to be replaced with\n"
		"either 's' for the source endpoint, 'd' for the destination endpoint or 'b' for\n"
		"both endpoints. However, please note that bidirectional traffic generation can\n"
		"lead to unexpected results. To specify different values for each endpoints,\n"
		"separate them by comma.\n\n"

		"Stochastic traffic generation:\n"
#ifdef HAVE_LIBGSL
		"  -G x=(q|p|g):(C|U|E|N|L|P|W):#1:[#2]\n"
#else /* HAVE_LIBGSL */
		"  -G x=(q|p|g):(C|U):#1:[#2]\n"
#endif /* HAVE_LIBGSL */
		"               Flow parameter:\n"
		"                 q = request size (in bytes)\n"
		"                 p = response size (in bytes)\n"
		"                 g = request interpacket gap (in seconds)\n\n"

		"               Distributions:\n"
		"                 C = constant (#1: value, #2: not used)\n"
		"                 U = uniform (#1: min, #2: max)\n"
#ifdef HAVE_LIBGSL
		"                 E = exponential (#1: lamba - lifetime, #2: not used)\n"
		"                 N = normal (#1: mu - mean value, #2: sigma_square - variance)\n"
		"                 L = lognormal (#1: zeta - mean, #2: sigma - std dev)\n"
		"                 P = pareto (#1: k - shape, #2 x_min - scale)\n"
		"                 W = weibull (#1: lambda - scale, #2: k - shape)\n"
#else /* HAVE_LIBGSL */
		"               advanced distributions are only available if compiled with libgsl\n"
#endif /* HAVE_LIBGSL */
		"  -U x=#       specify a cap for the calculated values for request and response\n"
		"               size (not needed for constant values or uniform distribution),\n"
		"               values over this cap are recalculated\n\n"

		"Examples:\n"
		"  -G s=q:C:40\n"
		"               use contant request size of 40 bytes\n"
		"  -G s=p:N:2000:50\n"
		"               use normal distributed response size with mean 2000 bytes and\n"
		"               variance 50\n"
		"  -G s=g:U:0.005:0.01\n"
		"               use uniform distributed interpacket gap with minimum 0.005s and\n"
		"               maximum 0.01s\n\n"

		"Notes: \n"
		"  - The man page contains more explained examples\n"
		"  - Using bidirectional traffic generation can lead to unexpected results\n"
		"  - Usage of -G in conjunction with -A, -R, -S is not recommended, as they\n"
		"    overwrite each other. -A, -R and -S exist as shortcut only\n",
		progname);
	exit(EXIT_SUCCESS);
}

/**
 * Signal handler to catching signals.
 *
 * @param[in] sig signal to catch
 */
static void sighandler(int sig)
{
	UNUSED_ARGUMENT(sig);

	DEBUG_MSG(LOG_ERR, "caught %s", strsignal(sig));

	if (!sigint_caught) {
		warnx("caught SIGINT, trying to gracefully close flows. "
		      "Press CTRL+C again to force termination \n");
		sigint_caught = true;
	} else {
		exit(EXIT_FAILURE);
	}
}

/**
 * Initialization of general controller options.
 */
static void init_controller_options(void)
{
	copt.num_flows = 1;
	copt.reporting_interval = 0.05;
	copt.log_to_stdout = true;
	copt.log_to_file = false;
	copt.dump_prefix = "flowgrind-";
	copt.clobber = false;
	copt.mbyte = false;
	copt.symbolic = true;
	copt.force_unit = INT_MAX;
}

/**
 * Initilization the flow option to default values.
 *
 * Initializes the controller flow option settings, 
 * final report for both source and destination daemon 
 * in the flow.
 */
static void init_flow_options(void)
{
	for (int id = 0; id < MAX_FLOWS; id++) {

		cflow[id].proto = PROTO_TCP;

		foreach(int *i, SOURCE, DESTINATION) {
			cflow[id].settings[*i].requested_send_buffer_size = 0;
			cflow[id].settings[*i].requested_read_buffer_size = 0;
			cflow[id].settings[*i].delay[WRITE] = 0;
			cflow[id].settings[*i].maximum_block_size = 8192;
			cflow[id].settings[*i].request_trafgen_options.param_one = 8192;
			cflow[id].settings[*i].response_trafgen_options.param_one = 0;
			cflow[id].settings[*i].route_record = 0;
			strcpy(cflow[id].endpoint[*i].test_address, "localhost");

			/* Default daemon is localhost, set in parse_cmdline */
			cflow[id].endpoint[*i].rpc_info = 0;
			cflow[id].endpoint[*i].daemon = 0;

			cflow[id].settings[*i].pushy = 0;
			cflow[id].settings[*i].cork = 0;
			cflow[id].settings[*i].cc_alg[0] = 0;
			cflow[id].settings[*i].elcn = 0;
			cflow[id].settings[*i].lcd = 0;
			cflow[id].settings[*i].mtcp = 0;
			cflow[id].settings[*i].nonagle = 0;
			cflow[id].settings[*i].traffic_dump = 0;
			cflow[id].settings[*i].so_debug = 0;
			cflow[id].settings[*i].dscp = 0;
			cflow[id].settings[*i].ipmtudiscover = 0;

			cflow[id].settings[*i].num_extra_socket_options = 0;
		}
		cflow[id].settings[SOURCE].duration[WRITE] = 10.0;
		cflow[id].settings[DESTINATION].duration[WRITE] = 0.0;

		cflow[id].endpoint_id[0] = cflow[id].endpoint_id[1] = -1;
		cflow[id].start_timestamp[0].tv_sec = 0;
		cflow[id].start_timestamp[0].tv_nsec = 0;
		cflow[id].start_timestamp[1].tv_sec = 0;
		cflow[id].start_timestamp[1].tv_nsec = 0;

		cflow[id].finished[0] = 0;
		cflow[id].finished[1] = 0;
		cflow[id].final_report[0] = NULL;
		cflow[id].final_report[1] = NULL;

		cflow[id].summarize_only = 0;
		cflow[id].late_connect = 0;
		cflow[id].shutdown = 0;
		cflow[id].byte_counting = 0;
		cflow[id].random_seed = 0;

		int data = open("/dev/urandom", O_RDONLY);
		int rc = read(data, &cflow[id].random_seed, sizeof (int) );
		close(data);
		if(rc == -1)
			crit("read /dev/urandom failed");
	}
}

/**
 * Create a logfile for measurement output.
 */
static void open_logfile(void)
{
	if (!copt.log_to_file)
		return;

	/* Log filename is not given by cmdline */
	if (!log_filename) {
		if (asprintf(&log_filename, "%s-%s.log", progname,
			     ctimenow(false)) == -1)
			critx("could not allocate memory for log filename");
	}

	if (!copt.clobber && access(log_filename, R_OK) == 0)
		critx("log file exists");

	log_stream = fopen(log_filename, "w");
	if (!log_stream)
		critx("could not open logfile '%s'", log_filename);

	DEBUG_MSG(LOG_NOTICE, "logging to '%s'", log_filename);
}

/**
 * Close measurement output file.
 */
static void close_logfile(void)
{
	if (!copt.log_to_file)
		return;
	if (fclose(log_stream) == -1)
		critx("could not close logfile '%s'", log_filename);

	free(log_filename);
}

/**
 * Print measurement output to logfile and / or to stdout.
 *
 * @param[in] fmt format string
 * @param[in] ... parameters used to fill fmt
 */
inline static void print_output(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (copt.log_to_stdout) {
		vprintf(fmt, ap);
		fflush(stdout);
	}
	if (copt.log_to_file) {
		vfprintf(log_stream, fmt, ap);
		fflush(log_stream);
	}
	va_end(ap);
}

inline static void die_if_fault_occurred(xmlrpc_env *env)
{
    if (env->fault_occurred)
	critx("XML-RPC Fault: %s (%d)", env->fault_string, env->fault_code);
}

/* creates an xmlrpc_client for connect to server, uses global env rpc_env */
static void prepare_xmlrpc_client(xmlrpc_client **rpc_client)
{
	struct xmlrpc_clientparms clientParms;
	size_t clientParms_cpsize = XMLRPC_CPSIZE(transport);

	/* Since version 1.21 xmlrpclib will automatically generate a
	 * rather long user_agent, we will do a lot of RPC calls so let's
	 * spare some bytes and omit this header */
#ifdef HAVE_STRUCT_XMLRPC_CURL_XPORTPARMS_DONT_ADVERTISE
	struct xmlrpc_curl_xportparms curlParms;
	memset(&curlParms, 0, sizeof(curlParms));

	curlParms.dont_advertise = 1;
	clientParms.transportparmsP = &curlParms;
	clientParms.transportparm_size = XMLRPC_CXPSIZE(dont_advertise);
	clientParms_cpsize = XMLRPC_CPSIZE(transportparm_size);
#endif /* HAVE_STRUCT_XMLRPC_CURL_XPORTPARMS_DONT_ADVERTISE */

	/* Force usage of curl transport, we require it in configure script
	 * anyway and at least FreeBSD 9.1 will use libwww otherwise */
	clientParms.transport = "curl";

	DEBUG_MSG(LOG_WARNING, "prepare xmlrpc client");
	xmlrpc_client_create(&rpc_env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind",
			     FLOWGRIND_VERSION, &clientParms,
			     clientParms_cpsize, rpc_client);
}

/**
 * Checks all the daemons flowgrind version.
 *
 * Collect the daemons flowgrind version, XML-RPC API version, 
 * OS name and release details. Store these information in the 
 * daemons linked list for the result display
 *
 * @param[in,out] rpc_client to connect controller to daemon
 */
static void check_version(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;
	char mismatch = 0;

	const struct list_node *node = fg_list_front(&unique_daemons);

	while (node) {
		if (sigint_caught)
			return;

		struct daemon *daemon = node->data;
		node = node->next;

		xmlrpc_client_call2f(&rpc_env, rpc_client, daemon->url,
					"get_version", &resultP, "()");
		if ((rpc_env.fault_occurred) && (strcasestr(rpc_env.fault_string,"response code is 400")))
			critx("node %s could not parse request.You are "
			      "probably trying to use a numeric IPv6 address "
			      "and the node's libxmlrpc is too old, please "
			      "upgrade!", daemon->url);

		die_if_fault_occurred(&rpc_env);

		/* Decomposes the xmlrpc value and extract the daemons data in
		 * it into controller local variable */
		if (resultP) {
			char* version;
			int api_version;
			char* os_name;
			char* os_release;
			xmlrpc_decompose_value(&rpc_env, resultP, "{s:s,s:i,s:s,s:s,*}",
						"version", &version,
						"api_version", &api_version,
						"os_name", &os_name,
						"os_release", &os_release);
			die_if_fault_occurred(&rpc_env);

			if (strcmp(version, FLOWGRIND_VERSION)) {
				mismatch = 1;
				warnx("node %s uses version %s",
				      daemon->url, version);
			}
			/* Store the daemons XML RPC API version, 
			 * OS name and release in daemons linked list */
			daemon->api_version = api_version;
			strncpy(daemon->os_name, os_name, 256);
			strncpy(daemon->os_release, os_release, 256);
			free_all(version, os_name, os_release);
			xmlrpc_DECREF(resultP);
		}
	}

	if (mismatch) {
		warnx("our version is %s\n\nContinuing in 5 seconds", FLOWGRIND_VERSION);
		sleep(5);
	}
}

/**
 * Add daemon for controller flow by UUID.
 *
 * Stores the daemons data and push the data in linked list
 * which contains daemons UUID and daemons XML RPC url
 *
 * @param[in,out] server_uuid UUID from daemons
 * @param[in,out] daemon_url URL from daemons
 */
static struct daemon * add_daemon_by_uuid(const char* server_uuid, 
		char* daemon_url)
{
	struct daemon *daemon;
	daemon = malloc((sizeof(struct daemon)));
	
	if (!daemon) {
		logging(LOG_ALERT, "could not allocate memory for daemon");
		return 0;
	}

	memset(daemon, 0, sizeof(struct daemon));
	strcpy(daemon->uuid, server_uuid);
	daemon->url = daemon_url;
	fg_list_push_back(&unique_daemons, daemon);
	return daemon;
}

/**
 * Determine the daemons for controller flow by UUID.
 *
 * Determine the daemons memory block size by number of server in
 * the controller flow option.
 *
 * @param[in,out] server_uuid UUID from daemons
 * @param[in,out] daemon_url URL from daemons
 */
static struct daemon * set_unique_daemon_by_uuid(const char* server_uuid, 
		char* daemon_url)
{
	/* Store the first daemon UUID and XML RPC url connection string.
	 * First daemon is used as reference to avoid the daemon duplication 
	 * by their UUID */	
	if (fg_list_size(&unique_daemons) == 0)
		return add_daemon_by_uuid(server_uuid, daemon_url);
	
	/* Compare the incoming daemons UUID with all daemons UUID in 
	 * memory in order to prevent dupliclity in storing the daemons. 
	 * If the incoming daemon UUID is already present in the daemons list, 
	 * then return existing daemon pointer to controller connection. 
	 * This is because a single daemons can run and maintain mutliple 
	 * data connection */
	const struct list_node *node = fg_list_front(&unique_daemons);
	while (node) {
		struct daemon *daemon = node->data;
		node = node->next;
		if (!strcmp(daemon->uuid, server_uuid))
			return daemon;
	}
	
	return add_daemon_by_uuid(server_uuid, daemon_url);
}

/**
 * Set the daemon for controller flow endpoint.
 *
 * @param[in,out] server_uuid UUID from daemons
 * @param[in,out] daemon_url URL from daemons
 */
static void set_flow_endpoint_daemon(const char* server_uuid, char* server_url)
{
	/* Determine the daemon in controller flow data by UUID 
	 * This prevent the daemons duplication */
	for (unsigned id = 0; id < copt.num_flows; id++) {
		foreach(int *i, SOURCE, DESTINATION) {
			struct flow_endpoint* e = &cflow[id].endpoint[*i];
			if(!strcmp(e->rpc_info->server_url, server_url) && !e->daemon) {
				e->daemon = set_unique_daemon_by_uuid(server_uuid,
								      server_url);
			}
		}
	}
}

/**
* Checks all daemons in flow option.
*
* Daemon UUID is retreived and this information is used
* to determine daemon in the controller flow information.
*
* @param[in,out] rpc_client to connect controller to daemon
*/
static void find_daemon(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;
	const struct list_node *node = fg_list_front(&flows_rpc_info);
	
	while (node) {
		if (sigint_caught)
			return;
		
		struct rpc_info *flow_rpc_info= node->data;
		node = node->next;
		/* call daemons by flow option XML-RPC URL connection string */
		xmlrpc_client_call2f(&rpc_env, rpc_client,
				     flow_rpc_info->server_url,
				     "get_uuid", &resultP, "()");
		die_if_fault_occurred(&rpc_env);
		
		/* Decomposes the xmlrpc_value and extract the daemon UUID
		 * in it into controller local variable */	
		if (resultP) {
			char* server_uuid = 0;
			
			xmlrpc_decompose_value(&rpc_env, resultP, "{s:s,*}", 
					"server_uuid", &server_uuid);
			set_flow_endpoint_daemon(server_uuid, flow_rpc_info->server_url);
			die_if_fault_occurred(&rpc_env);
			xmlrpc_DECREF(resultP);
		}
	}
}

/**
* Checks that all nodes are currently idle.
*
* Get the daemon's flow start status and number of flows running in 
* a daemon. This piece of information is used to determine, whether the
* daemon in a node is busy or idle.
*
* @param[in,out] rpc_client to connect controller to daemon
*/
static void check_idle(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;
	const struct list_node *node = fg_list_front(&unique_daemons);
	
	while (node) {
		if (sigint_caught)
			return;
		
		struct daemon *daemon = node->data;
		node = node->next;
		
		xmlrpc_client_call2f(&rpc_env, rpc_client,
				     daemon->url,
				     "get_status", &resultP, "()");
		die_if_fault_occurred(&rpc_env);
		
		/* Decomposes the xmlrpc_value and extract the daemons data 
		 * in it into controller local variable */
		if (resultP) {
			int started;
			int num_flows;

			xmlrpc_decompose_value(&rpc_env, resultP,
					       "{s:i,s:i,*}", "started",
					       &started, "num_flows",
					       &num_flows);
			die_if_fault_occurred(&rpc_env);

			/* Daemon start status and number of flows is used to
			 * determine node idle status */
			if (started || num_flows)
				critx("node %s is busy. %d flows, started=%d",
				       daemon->url, num_flows,
				       started);
			xmlrpc_DECREF(resultP);
		}
	}
}

/**
 * To show/hide intermediated interval report columns.
 *
 * @param[in] visibility show/hide column
 * @param[in] nargs length of variable argument list
 * @param[in] ... column IDs
 * @see enum column_id
 */
static void set_column_visibility(bool visibility, unsigned nargs, ...)
{
        va_list ap;
        enum column_id col_id;

        va_start(ap, nargs);
        while (nargs--) {
                col_id = va_arg(ap, enum column_id);
                column_info[col_id].state.visible = visibility;
        }
        va_end(ap);
}

/**
 * To set the unit the in header of intermediated interval report columns.
 *
 * @param[in] unit unit of column header as string
 * @param[in] nargs length of variable argument list
 * @param[in] ... column IDs
 * @see enum column_id
 */
static void set_column_unit(const char *unit, unsigned nargs, ...)
{
        va_list ap;
        enum column_id col_id;

        va_start(ap, nargs);
        while (nargs--) {
                col_id = va_arg(ap, enum column_id);
                column_info[col_id].header.unit = unit;
        }
        va_end(ap);
}

/**
 * Print headline with various informations before the actual measurement will
 * be begin.
 */
static void print_headline(void)
{
	/* Print headline */
	struct utsname me;
	int rc = uname(&me);
	print_output("# Date: %s, controlling host = %s, number of flows = %d, "
		     "reporting interval = %.2fs, [through] = %s (%s)\n",
		     ctimenow(false), (rc == -1 ? "(unknown)" : me.nodename),
		     copt.num_flows, copt.reporting_interval,
		     (copt.mbyte ? "2**20 bytes/second": "10**6 bit/second"),
		     FLOWGRIND_VERSION);

	/* Prepare column visibility based on involved OSes */
	bool involved_os[] = {[0 ... NUM_OSes-1] = false};
	const struct list_node *node = fg_list_front(&unique_daemons);
	while (node) {
		struct daemon *daemon = node->data;
		node = node->next;
		if (!strcmp(daemon->os_name, "Linux"))
			involved_os[LINUX] = true;
		else if (!strcmp(daemon->os_name, "FreeBSD"))
			involved_os[FREEBSD] = true;
		else if (!strcmp(daemon->os_name, "Darwin"))
			involved_os[DARWIN] = true;
	}

	/* No Linux OS is involved in the test */
	if (!involved_os[LINUX])
		HIDE_COLUMNS(COL_TCP_UACK, COL_TCP_SACK, COL_TCP_LOST,
			     COL_TCP_RETR, COL_TCP_TRET, COL_TCP_FACK,
			     COL_TCP_REOR, COL_TCP_BKOF, COL_TCP_CA_STATE,
			     COL_PMTU);

	/* No Linux and FreeBSD OS is involved in the test */
	if (!involved_os[FREEBSD] && !involved_os[LINUX])
		HIDE_COLUMNS(COL_TCP_CWND, COL_TCP_SSTH, COL_TCP_RTT,
			     COL_TCP_RTTVAR, COL_TCP_RTO, COL_SMSS);

	const struct list_node *firstnode = fg_list_front(&unique_daemons);
	struct daemon *daemon_firstnode = firstnode->data;
	
	/* Set unit for kernel TCP metrics to bytes */
	if (copt.force_unit == BYTE_BASED || (copt.force_unit != SEGMENT_BASED &&
	    strcmp(daemon_firstnode->os_name, "Linux")))
		SET_COLUMN_UNIT(" [B]", COL_TCP_CWND, COL_TCP_SSTH,
				COL_TCP_UACK, COL_TCP_SACK, COL_TCP_LOST,
				COL_TCP_RETR, COL_TCP_TRET, COL_TCP_FACK,
				COL_TCP_REOR, COL_TCP_BKOF);
}

/**
 * Prepare test connection for a flow between source and destination daemons.
 * 
 * Controller sends the flow option to source and destination daemons
 * separately through XML RPC connection and get backs the flow id and
 * snd/rcx buffer size from the daemons.
 *
 * @param[in] id flow id to prepare the test connection in daemons
 * @param[in,out] rpc_client to connect controller to daemon
 */
static void prepare_flow(int id, xmlrpc_client *rpc_client)
{
	xmlrpc_value *resultP, *extra_options;

	int listen_data_port;
	DEBUG_MSG(LOG_WARNING, "prepare flow %d destination", id);

	/* Contruct extra socket options array */
	extra_options = xmlrpc_array_new(&rpc_env);
	for (int i = 0; i < cflow[id].settings[DESTINATION].num_extra_socket_options; i++) {
		xmlrpc_value *value;
		xmlrpc_value *option = xmlrpc_build_value(&rpc_env, "{s:i,s:i}",
			 "level", cflow[id].settings[DESTINATION].extra_socket_options[i].level,
			 "optname", cflow[id].settings[DESTINATION].extra_socket_options[i].optname);

		value = xmlrpc_base64_new(&rpc_env, cflow[id].settings[DESTINATION].extra_socket_options[i].optlen, (unsigned char*)cflow[id].settings[DESTINATION].extra_socket_options[i].optval);

		xmlrpc_struct_set_value(&rpc_env, option, "value", value);

		xmlrpc_array_append_item(&rpc_env, extra_options, option);
		xmlrpc_DECREF(value);
		xmlrpc_DECREF(option);
	}
	xmlrpc_client_call2f(&rpc_env, rpc_client,
		cflow[id].endpoint[DESTINATION].rpc_info->server_url,
		"add_flow_destination", &resultP,
		"("
		"{s:s}"
		"{s:i}"
		"{s:d,s:d,s:d,s:d,s:d}"
		"{s:i,s:i}"
		"{s:i}"
		"{s:b,s:b,s:b,s:b,s:b}"
		"{s:i,s:i}"
		"{s:i,s:d,s:d}" /* request */
		"{s:i,s:d,s:d}" /* response */
		"{s:i,s:d,s:d}" /* interpacket_gap */
		"{s:b,s:b,s:i,s:i}"
		"{s:s}"
		"{s:i,s:i,s:i,s:i,s:i}"
		"{s:s}"
		"{s:i,s:A}"
		")",

		/* general flow settings */
		"bind_address", cflow[id].endpoint[DESTINATION].test_address,

		"flow_id",id,

		"write_delay", cflow[id].settings[DESTINATION].delay[WRITE],
		"write_duration", cflow[id].settings[DESTINATION].duration[WRITE],
		"read_delay", cflow[id].settings[SOURCE].delay[WRITE],
		"read_duration", cflow[id].settings[SOURCE].duration[WRITE],
		"reporting_interval", cflow[id].summarize_only ? 0 : copt.reporting_interval,

		"requested_send_buffer_size", cflow[id].settings[DESTINATION].requested_send_buffer_size,
		"requested_read_buffer_size", cflow[id].settings[DESTINATION].requested_read_buffer_size,

		"maximum_block_size", cflow[id].settings[DESTINATION].maximum_block_size,

		"traffic_dump", cflow[id].settings[DESTINATION].traffic_dump,
		"so_debug", cflow[id].settings[DESTINATION].so_debug,
		"route_record", (int)cflow[id].settings[DESTINATION].route_record,
		"pushy", cflow[id].settings[DESTINATION].pushy,
		"shutdown", (int)cflow[id].shutdown,

		"write_rate", cflow[id].settings[DESTINATION].write_rate,
		"random_seed",cflow[id].random_seed,

		"traffic_generation_request_distribution", cflow[id].settings[DESTINATION].request_trafgen_options.distribution,
		"traffic_generation_request_param_one", cflow[id].settings[DESTINATION].request_trafgen_options.param_one,
		"traffic_generation_request_param_two", cflow[id].settings[DESTINATION].request_trafgen_options.param_two,

		"traffic_generation_response_distribution", cflow[id].settings[DESTINATION].response_trafgen_options.distribution,
		"traffic_generation_response_param_one", cflow[id].settings[DESTINATION].response_trafgen_options.param_one,
		"traffic_generation_response_param_two", cflow[id].settings[DESTINATION].response_trafgen_options.param_two,

		"traffic_generation_gap_distribution", cflow[id].settings[DESTINATION].interpacket_gap_trafgen_options.distribution,
		"traffic_generation_gap_param_one", cflow[id].settings[DESTINATION].interpacket_gap_trafgen_options.param_one,
		"traffic_generation_gap_param_two", cflow[id].settings[DESTINATION].interpacket_gap_trafgen_options.param_two,

	"flow_control", cflow[id].settings[DESTINATION].flow_control,
		"byte_counting", cflow[id].byte_counting,
		"cork", (int)cflow[id].settings[DESTINATION].cork,
		"nonagle", cflow[id].settings[DESTINATION].nonagle,

		"cc_alg", cflow[id].settings[DESTINATION].cc_alg,

		"elcn", cflow[id].settings[DESTINATION].elcn,
		"lcd", cflow[id].settings[DESTINATION].lcd,
		"mtcp", cflow[id].settings[DESTINATION].mtcp,
		"dscp", (int)cflow[id].settings[DESTINATION].dscp,
		"ipmtudiscover", cflow[id].settings[DESTINATION].ipmtudiscover,
		"dump_prefix", copt.dump_prefix,
		"num_extra_socket_options", cflow[id].settings[DESTINATION].num_extra_socket_options,
		"extra_socket_options", extra_options);

	die_if_fault_occurred(&rpc_env);

	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,s:i,s:i,s:i,*}",
		"flow_id", &cflow[id].endpoint_id[DESTINATION],
		"listen_data_port", &listen_data_port,
		"real_listen_send_buffer_size", &cflow[id].endpoint[DESTINATION].send_buffer_size_real,
		"real_listen_read_buffer_size", &cflow[id].endpoint[DESTINATION].receive_buffer_size_real);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);

	/* Contruct extra socket options array */
	extra_options = xmlrpc_array_new(&rpc_env);
	for (int i = 0; i < cflow[id].settings[SOURCE].num_extra_socket_options; i++) {

		xmlrpc_value *value;
		xmlrpc_value *option = xmlrpc_build_value(&rpc_env, "{s:i,s:i}",
			 "level", cflow[id].settings[SOURCE].extra_socket_options[i].level,
			 "optname", cflow[id].settings[SOURCE].extra_socket_options[i].optname);

		value = xmlrpc_base64_new(&rpc_env, cflow[id].settings[SOURCE].extra_socket_options[i].optlen, (unsigned char*)cflow[id].settings[SOURCE].extra_socket_options[i].optval);

		xmlrpc_struct_set_value(&rpc_env, option, "value", value);

		xmlrpc_array_append_item(&rpc_env, extra_options, option);
		xmlrpc_DECREF(value);
		xmlrpc_DECREF(option);
	}
	DEBUG_MSG(LOG_WARNING, "prepare flow %d source", id);

	xmlrpc_client_call2f(&rpc_env, rpc_client,
		cflow[id].endpoint[SOURCE].rpc_info->server_url,
		"add_flow_source", &resultP,
		"("
		"{s:s}"
		"{s:i}"
		"{s:d,s:d,s:d,s:d,s:d}"
		"{s:i,s:i}"
		"{s:i}"
		"{s:b,s:b,s:b,s:b,s:b}"
		"{s:i,s:i}"
		"{s:i,s:d,s:d}" /* request */
		"{s:i,s:d,s:d}" /* response */
		"{s:i,s:d,s:d}" /* interpacket_gap */
		"{s:b,s:b,s:i,s:i}"
		"{s:s}"
		"{s:i,s:i,s:i,s:i,s:i}"
		"{s:s}"
		"{s:i,s:A}"
		"{s:s,s:i,s:i}"
		")",

		/* general flow settings */
		"bind_address", cflow[id].endpoint[SOURCE].test_address,

		"flow_id",id,

		"write_delay", cflow[id].settings[SOURCE].delay[WRITE],
		"write_duration", cflow[id].settings[SOURCE].duration[WRITE],
		"read_delay", cflow[id].settings[DESTINATION].delay[WRITE],
		"read_duration", cflow[id].settings[DESTINATION].duration[WRITE],
		"reporting_interval", cflow[id].summarize_only ? 0 : copt.reporting_interval,

		"requested_send_buffer_size", cflow[id].settings[SOURCE].requested_send_buffer_size,
		"requested_read_buffer_size", cflow[id].settings[SOURCE].requested_read_buffer_size,

		"maximum_block_size", cflow[id].settings[SOURCE].maximum_block_size,

		"traffic_dump", cflow[id].settings[SOURCE].traffic_dump,
		"so_debug", cflow[id].settings[SOURCE].so_debug,
		"route_record", (int)cflow[id].settings[SOURCE].route_record,
		"pushy", cflow[id].settings[SOURCE].pushy,
		"shutdown", (int)cflow[id].shutdown,

		"write_rate", cflow[id].settings[SOURCE].write_rate,
		"random_seed",cflow[id].random_seed,

		"traffic_generation_request_distribution", cflow[id].settings[SOURCE].request_trafgen_options.distribution,
		"traffic_generation_request_param_one", cflow[id].settings[SOURCE].request_trafgen_options.param_one,
		"traffic_generation_request_param_two", cflow[id].settings[SOURCE].request_trafgen_options.param_two,

		"traffic_generation_response_distribution", cflow[id].settings[SOURCE].response_trafgen_options.distribution,
		"traffic_generation_response_param_one", cflow[id].settings[SOURCE].response_trafgen_options.param_one,
		"traffic_generation_response_param_two", cflow[id].settings[SOURCE].response_trafgen_options.param_two,

		"traffic_generation_gap_distribution", cflow[id].settings[SOURCE].interpacket_gap_trafgen_options.distribution,
		"traffic_generation_gap_param_one", cflow[id].settings[SOURCE].interpacket_gap_trafgen_options.param_one,
		"traffic_generation_gap_param_two", cflow[id].settings[SOURCE].interpacket_gap_trafgen_options.param_two,


		"flow_control", cflow[id].settings[SOURCE].flow_control,
		"byte_counting", cflow[id].byte_counting,
		"cork", (int)cflow[id].settings[SOURCE].cork,
		"nonagle", (int)cflow[id].settings[SOURCE].nonagle,

		"cc_alg", cflow[id].settings[SOURCE].cc_alg,

		"elcn", cflow[id].settings[SOURCE].elcn,
		"lcd", cflow[id].settings[SOURCE].lcd,
		"mtcp", cflow[id].settings[SOURCE].mtcp,
		"dscp", (int)cflow[id].settings[SOURCE].dscp,
		"ipmtudiscover", cflow[id].settings[SOURCE].ipmtudiscover,
		"dump_prefix", copt.dump_prefix,
		"num_extra_socket_options", cflow[id].settings[SOURCE].num_extra_socket_options,
		"extra_socket_options", extra_options,

		/* source settings */
		"destination_address", cflow[id].endpoint[DESTINATION].test_address,
		"destination_port", listen_data_port,
		"late_connect", (int)cflow[id].late_connect);
	die_if_fault_occurred(&rpc_env);

	xmlrpc_DECREF(extra_options);

	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,s:i,s:i,*}",
		"flow_id", &cflow[id].endpoint_id[SOURCE],
		"real_send_buffer_size", &cflow[id].endpoint[SOURCE].send_buffer_size_real,
		"real_read_buffer_size", &cflow[id].endpoint[SOURCE].receive_buffer_size_real);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);
	DEBUG_MSG(LOG_WARNING, "prepare flow %d completed", id);
}

/**
 * Prepare test connection for all flows in a test
 *
 * @param[in,out] rpc_client to connect controller to daemon
 */
static void prepare_all_flows(xmlrpc_client *rpc_client)
{
	/* prepare flows */
	for (unsigned short id = 0; id < copt.num_flows; id++) {
		if (sigint_caught)
			return;
		prepare_flow(id, rpc_client);
	}
}

/**
 * Start test connections for all flows in a test
 *
 * All the test connection are started, but test connection flow in the 
 * controller and in daemon are different. In the controller, test connection
 * are respective to number of flows in a test,but in daemons test connection
 * are respective to flow endpoints. Single daemons can maintain multiple flows
 * endpoints, So controller should start a daemon only once.
 *
 * @param[in,out] rpc_client to connect controller to daemon
 */
static void start_all_flows(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;

	struct timespec lastreport_end;
	struct timespec lastreport_begin;
	struct timespec now;

	gettime(&lastreport_end);
	gettime(&lastreport_begin);
	gettime(&now);

	const struct list_node *node = fg_list_front(&unique_daemons);
	while (node) {
		if (sigint_caught)
			return;
		struct daemon *daemon = node->data;
		node = node->next;

		DEBUG_MSG(LOG_ERR, "starting flow on server with UUID %s",daemon->uuid);
		xmlrpc_client_call2f(&rpc_env, rpc_client,
				     daemon->url,
				     "start_flows", &resultP, "({s:i})",
				     "start_timestamp", now.tv_sec + 2);
		die_if_fault_occurred(&rpc_env);
		if (resultP)
			xmlrpc_DECREF(resultP);
	}

	active_flows = copt.num_flows;

	/* Reports are fetched from the daemons based on the
	 * report interval duration */
	while (!sigint_caught) {
		if ( time_diff_now(&lastreport_begin) <  copt.reporting_interval ) {
			usleep(copt.reporting_interval - time_diff(&lastreport_begin,&lastreport_end) );
			continue;
		}
		gettime(&lastreport_begin);
		fetch_reports(rpc_client);
		gettime(&lastreport_end);

		/* All flows have ended */
		if (active_flows < 1)
			return;
	}
}

/**
 * Reports are fetched from the flow endpoint daemon.
 *
 * Single daemon can maintain multiple flows endpoints and daemons combine all 
 * its flows reports and send them to the controller. So controller should call
 * a daemon in its flows only once. 
 *
 * @param[in,out] rpc_client to connect controller to daemon
 */
static void fetch_reports(xmlrpc_client *rpc_client)
{

	xmlrpc_value * resultP = 0;
	const struct list_node *node = fg_list_front(&unique_daemons);

	while (node) {
		struct daemon *daemon = node->data;
		node = node->next;
		int array_size, has_more;
		xmlrpc_value *rv = 0;

has_more_reports:

		xmlrpc_client_call2f(&rpc_env, rpc_client, daemon->url,
			"get_reports", &resultP, "()");
		if (rpc_env.fault_occurred) {
			errx("XML-RPC fault: %s (%d)", rpc_env.fault_string,
			      rpc_env.fault_code);
			continue;
		}

		if (!resultP)
			continue;

		array_size = xmlrpc_array_size(&rpc_env, resultP);
		if (!array_size) {
			warnx("empty array in get_reports reply");
			continue;
		}

		xmlrpc_array_read_item(&rpc_env, resultP, 0, &rv);
		xmlrpc_read_int(&rpc_env, rv, &has_more);
		if (rpc_env.fault_occurred) {
			errx("XML-RPC fault: %s (%d)", rpc_env.fault_string,
			      rpc_env.fault_code);
			xmlrpc_DECREF(rv);
			continue;
		}
		xmlrpc_DECREF(rv);

		for (int i = 1; i < array_size; i++) {
			xmlrpc_value *rv = 0;

			xmlrpc_array_read_item(&rpc_env, resultP, i, &rv);
			if (rv) {
				struct report report;
				int begin_sec, begin_nsec, end_sec, end_nsec;
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
				int tcpi_ca_state;
				int tcpi_snd_mss;
				int bytes_read_low, bytes_read_high;
				int bytes_written_low, bytes_written_high;

				xmlrpc_decompose_value(&rpc_env, rv,
					"("
					"{s:i,s:i,s:i,s:i,s:i,s:i,s:i,*}" /* Report data & timeval */
					"{s:i,s:i,s:i,s:i,*}" /* bytes */
					"{s:i,s:i,s:i,s:i,*}" /* blocks */
					"{s:d,s:d,s:d,s:d,s:d,s:d,s:d,s:d,s:d,*}" /* RTT, IAT, Delay */
					"{s:i,s:i,*}" /* MTU */
					"{s:i,s:i,s:i,s:i,s:i,*}" /* TCP info */
					"{s:i,s:i,s:i,s:i,s:i,*}" /* ...      */
					"{s:i,s:i,s:i,s:i,s:i,*}" /* ...      */
					"{s:i,*}"
					")",

					"id", &report.id,
					"endpoint", &report.endpoint,
					"type", &report.type,
					"begin_tv_sec", &begin_sec,
					"begin_tv_nsec", &begin_nsec,
					"end_tv_sec", &end_sec,
					"end_tv_nsec", &end_nsec,

					"bytes_read_high", &bytes_read_high,
					"bytes_read_low", &bytes_read_low,
					"bytes_written_high", &bytes_written_high,
					"bytes_written_low", &bytes_written_low,

					"request_blocks_read", &report.request_blocks_read,
					"request_blocks_written", &report.request_blocks_written,
					"response_blocks_read", &report.response_blocks_read,
					"response_blocks_written", &report.response_blocks_written,

					"rtt_min", &report.rtt_min,
					"rtt_max", &report.rtt_max,
					"rtt_sum", &report.rtt_sum,
					"iat_min", &report.iat_min,
					"iat_max", &report.iat_max,
					"iat_sum", &report.iat_sum,
					"delay_min", &report.delay_min,
					"delay_max", &report.delay_max,
					"delay_sum", &report.delay_sum,

					"pmtu", &report.pmtu,
					"imtu", &report.imtu,

					"tcpi_snd_cwnd", &tcpi_snd_cwnd,
					"tcpi_snd_ssthresh", &tcpi_snd_ssthresh,
					"tcpi_unacked", &tcpi_unacked,
					"tcpi_sacked", &tcpi_sacked,
					"tcpi_lost", &tcpi_lost,

					"tcpi_retrans", &tcpi_retrans,
					"tcpi_retransmits", &tcpi_retransmits,
					"tcpi_fackets", &tcpi_fackets,
					"tcpi_reordering", &tcpi_reordering,
					"tcpi_rtt", &tcpi_rtt,

					"tcpi_rttvar", &tcpi_rttvar,
					"tcpi_rto", &tcpi_rto,
					"tcpi_backoff", &tcpi_backoff,
					"tcpi_ca_state", &tcpi_ca_state,
					"tcpi_snd_mss", &tcpi_snd_mss,

					"status", &report.status
				);
				xmlrpc_DECREF(rv);
#ifdef HAVE_UNSIGNED_LONG_LONG_INT
				report.bytes_read = ((long long)bytes_read_high << 32) + (uint32_t)bytes_read_low;
				report.bytes_written = ((long long)bytes_written_high << 32) + (uint32_t)bytes_written_low;
#else /* HAVE_UNSIGNED_LONG_LONG_INT */
				report.bytes_read = (uint32_t)bytes_read_low;
				report.bytes_written = (uint32_t)bytes_written_low;
#endif /* HAVE_UNSIGNED_LONG_LONG_INT */

				/* FIXME Kernel metrics (tcp_info). Other OS than
				 * Linux may not send valid values here. For
				 * the moment we don't care and handle this in
				 * the output/display routines. However, this
				 * do not work in heterogeneous environments */
				report.tcp_info.tcpi_snd_cwnd = tcpi_snd_cwnd;
				report.tcp_info.tcpi_snd_ssthresh = tcpi_snd_ssthresh;
				report.tcp_info.tcpi_unacked = tcpi_unacked;
				report.tcp_info.tcpi_sacked = tcpi_sacked;
				report.tcp_info.tcpi_lost = tcpi_lost;
				report.tcp_info.tcpi_retrans = tcpi_retrans;
				report.tcp_info.tcpi_retransmits = tcpi_retransmits;
				report.tcp_info.tcpi_fackets = tcpi_fackets;
				report.tcp_info.tcpi_reordering = tcpi_reordering;
				report.tcp_info.tcpi_rtt = tcpi_rtt;
				report.tcp_info.tcpi_rttvar = tcpi_rttvar;
				report.tcp_info.tcpi_rto = tcpi_rto;
				report.tcp_info.tcpi_backoff = tcpi_backoff;
				report.tcp_info.tcpi_ca_state = tcpi_ca_state;
				report.tcp_info.tcpi_snd_mss = tcpi_snd_mss;

				report.begin.tv_sec = begin_sec;
				report.begin.tv_nsec = begin_nsec;
				report.end.tv_sec = end_sec;
				report.end.tv_nsec = end_nsec;

				report_flow(&report);
			}
		}
		xmlrpc_DECREF(resultP);

		if (has_more)
			goto has_more_reports;
	}
}

/**
 * Reports are fetched from the flow endpoint daemon
 *
 * Single daemon can maintain multiple flows endpoints and daemons combine all
 * it flows report and send the controller. So controller give the flow ID to
 * daemons, while prepare the flow.Controller flow ID is maintained by the
 * daemons to maintain its flow endpoints.So When getting back the reports from
 * the daemons, the controller use those flow ID registered for the daemon in
 * the prepare flow as reference to distinguish the @p report.
 * The daemon also send back the details regarding flow endpoints
 * i.e. source or destination. So this information is also used by the daemons
 * to distinguish the report in the report flow.
 *
 * @param[in] report report from the daemon
 */
static void report_flow(struct report* report)
{
	int *i = NULL;
	unsigned short id;
	struct cflow *f = NULL;

	/* Get matching flow for report */
	/* TODO Maybe just use compare daemon pointers? */
	for (id = 0; id < copt.num_flows; id++) {
		f = &cflow[id];

		foreach(i, SOURCE, DESTINATION)
			if (f->endpoint_id[*i] == report->id &&
			    *i == (int)report->endpoint)
				goto exit_outer_loop;
	}
exit_outer_loop:

	if (f->start_timestamp[*i].tv_sec == 0)
		f->start_timestamp[*i] = report->begin;

	if (report->type == FINAL) {
		DEBUG_MSG(LOG_DEBUG, "received final report for flow %d", id);
		/* Final report, keep it for later */
		free(f->final_report[*i]);
		f->final_report[*i] = malloc(sizeof(struct report));
		*f->final_report[*i] = *report;

		if (!f->finished[*i]) {
			f->finished[*i] = 1;
			if (f->finished[1 - *i]) {
				active_flows--;
				DEBUG_MSG(LOG_DEBUG, "remaining active flows: "
					  "%d", active_flows);
				assert(active_flows >= 0);
			}
		}
		return;
	}
	print_interval_report(id, *i, report);
}

/**
 * Stop test connections for all flows in a test
 *
 * All the test connection are stopped, but the test connection flow in the
 * controller and in daemon are different. In the controller, test connection
 * are respective to number of flows in a test,but in daemons test connection
 * are respective to flow endpoints. Single daemons can maintain multiple flows
 * endpoints, So controller should stop a daemon only once.
 */
static void close_all_flows(void)
{
	xmlrpc_env env;
	xmlrpc_client *client;

	for (unsigned short id = 0; id < copt.num_flows; id++) {
		DEBUG_MSG(LOG_WARNING, "closing flow %u", id);

		if (cflow[id].finished[SOURCE] && cflow[id].finished[DESTINATION])
			continue;

		/* We use new env and client, old one might be in fault condition */
		xmlrpc_env_init(&env);
		xmlrpc_client_create(&env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &client);
		die_if_fault_occurred(&env);
		xmlrpc_env_clean(&env);

		foreach(int *i, SOURCE, DESTINATION) {
			xmlrpc_value * resultP = 0;

			if (cflow[id].endpoint_id[*i] == -1 ||
			    cflow[id].finished[*i])
				/* Endpoint does not need closing */
				continue;

			cflow[id].finished[*i] = 1;

			xmlrpc_env_init(&env);
			xmlrpc_client_call2f(&env, client,
					     cflow[id].endpoint[*i].rpc_info->server_url,
					     "stop_flow", &resultP, "({s:i})",
					     "flow_id", cflow[id].endpoint_id[*i]);
			if (resultP)
				xmlrpc_DECREF(resultP);

			xmlrpc_env_clean(&env);
		}

		if (active_flows > 0)
			active_flows--;

		xmlrpc_client_destroy(client);
		DEBUG_MSG(LOG_WARNING, "closed flow %u", id);
	}
}

/**
 * Determines the length of the integer part of a decimal number.
 *
 * @param[in] value decimal number
 * @return length of integer part
 */
inline static size_t det_num_digits(double value)
{
	/* Avoiding divide-by-zero */
	if (unlikely((int)value == 0))
		return 1;
	else
		return floor(log10(abs((int)value))) + 1;
}

/**
 * Scale the given throughput @p thruput in either Mebibyte per seconds or in
 * Megabits per seconds.
 *
 * @param[in] thruput throughput in byte per seconds
 * @return scaled throughput in MiB/s or Mb/s
 */
inline static double scale_thruput(double thruput)
{
        if (copt.mbyte)
                return thruput / (1<<20);
        return thruput / 1e6 * (1<<3);
}

/**
 * Determines if the current column width @p column_width is larger or smaller
 * than the old one and updates the state of column @p column accordingly.
 *
 * @param[in,out] column column that state to be updated
 * @param[in] column_width current column width
 * @return true if column state has been updated, false otherwise
 */
static bool update_column_width(struct column *column, unsigned column_width)
{
	/* True if column width has changed */
	bool has_changed = false;

	if (column->state.last_width < column_width) {
		/* Column too small */
		has_changed = true;
		column->state.last_width = column_width;
		column->state.oversized = 0;
	} else if (column->state.last_width > 1 + column_width) {
		/* Column too big */
		if (column->state.oversized >= MAX_COLUM_TOO_LARGE) {
			/* Column too big for quite a while */
			has_changed = true;
			column->state.last_width = column_width;
			column->state.oversized = 0;
		} else {
			(column->state.oversized)++;
		}
	} else {
		/* This size was needed, keep it */
		column->state.oversized = 0;
	}

	return has_changed;
}

/**
 * Append measured data for interval report column @p column_id to given strings.
 *
 * For the intermediated interval report column @p column_id, append measured
 * data @p value to the destination data string @p data, and the name and unit
 * of intermediated interval column header to @p header1 and @p header2.
 *
 * @param[in,out] header1 1st header string (name) to append to
 * @param[in,out] header2 2nd header string (unit) to append to
 * @param[in,out] data data value string to append to
 * @param[in] column_id ID of intermediated interval report column
 * @param[in] value measured data string to be append
 * @return true if column width has changed, false otherwise
 */
static bool print_column_str(char **header1, char **header2, char **data,
			     enum column_id column_id, char* value)
{
	/* Only for convenience */
	struct column *column = &column_info[column_id];

	if (!column->state.visible)
		return false;

	/* Get max column width */
	unsigned data_len = strlen(value);
	unsigned header_len = MAX(strlen(column->header.name),
				  strlen(column->header.unit));
	unsigned column_width = MAX(data_len, header_len);

	/* Check if column width has changed */
	bool has_changed = update_column_width(column, column_width);

	/* Create format specifiers of right length */
	char *fmt_str = NULL;
	const size_t width = column->state.last_width;
	if (asprintf(&fmt_str, "%%%zus", width + GUARDBAND) == -1)
		critx("could not allocate memory for interval report");

	/* Print data, 1st and 2nd header row */
	asprintf_append(data, fmt_str, value);
	asprintf_append(header1, fmt_str, column->header.name);
	asprintf_append(header2, fmt_str, column->header.unit);

	free(fmt_str);
	return has_changed;
}

/**
 * Append measured data for interval report column @p column_id to given strings.
 *
 * For the intermediated interval report column @p column_id, append measured
 * data @p value to the destination data string @p data, and the name and unit
 * of intermediated interval column header to @p header1 and @p header2.
 *
 * @param[in,out] header1 1st header string (name) to append to
 * @param[in,out] header2 2nd header string (unit) to append to
 * @param[in,out] data data value string to append to
 * @param[in] column_id ID of intermediated interval report column
 * @param[in] value measured data value to be append
 * @param[in] accuracy number of decimal places to be append
 * @return true if column width has changed, false otherwise
 */
static bool print_column(char **header1, char **header2, char **data,
			 enum column_id column_id, double value,
			 unsigned accuracy)
{
	/* Print symbolic values instead of numbers */
	if (copt.symbolic) {
		switch ((int)value) {
		case INT_MAX:
			return print_column_str(header1, header2, data,
						column_id, "INT_MAX");
		case USHRT_MAX:
			return print_column_str(header1, header2, data,
						column_id, "USHRT_MAX");
		case UINT_MAX:
			return print_column_str(header1, header2, data,
						column_id, "UINT_MAX");
		}
	}

	/* Only for convenience */
	struct column *column = &column_info[column_id];

	if (!column->state.visible)
		return false;

	/* Get max column width */
	unsigned data_len = det_num_digits(value) + (accuracy ? accuracy + 1 : 0);
	unsigned header_len = MAX(strlen(column->header.name),
				  strlen(column->header.unit));
	unsigned column_width = MAX(data_len, header_len);

	/* Check if column width has changed */
	bool has_changed = update_column_width(column, column_width);

	/* Create format specifiers of right length */
	char *fmt_num = NULL, *fmt_str = NULL;
	const size_t width = column->state.last_width;
	if (asprintf(&fmt_num, "%%%zu.%df", width + GUARDBAND, accuracy) == -1 ||
	    asprintf(&fmt_str, "%%%zus", width + GUARDBAND) == -1)
		critx("could not allocate memory for interval report");

	/* Print data, 1st and 2nd header row */
	asprintf_append(data, fmt_num, value);
	asprintf_append(header1, fmt_str, column->header.name);
	asprintf_append(header2, fmt_str, column->header.unit);

	free_all(fmt_num, fmt_str);
	return has_changed;
}

/**
 * Print interval report @p report for endpoint @p e of flow @p flow_id.
 *
 * In addition, if the width of one intermediated interval report columns has
 * been changed, the interval column header will be printed again.
 *
 * @param[in] flow_id flow an interval report will be created for
 * @param[in] e flow endpoint (SOURCE or DESTINATION)
 * @param[in] report interval report to be printed
 */
static void print_interval_report(unsigned short flow_id, enum endpoint_t e,
				  struct report *report)
{
	/* Whether or not column width has been changed */
	bool changed = false;
	/* 1st header row, 2nd header row, and the actual measured data */
	char *header1 = NULL, *header2 = NULL, *data = NULL;

	/* Flow ID and endpoint (source or destination) */
	if (asprintf(&header1, "%s", column_info[COL_FLOW_ID].header.name) == -1 ||
	    asprintf(&header2, "%s", column_info[COL_FLOW_ID].header.unit) == -1 ||
	    asprintf(&data, "%s%3d", e ? "D" : "S", flow_id) == -1)
		critx("could not allocate memory for interval report");

	/* Calculate time */
	double diff_first_last = time_diff(&cflow[flow_id].start_timestamp[e],
					   &report->begin);
	double diff_first_now = time_diff(&cflow[flow_id].start_timestamp[e],
					  &report->end);
	changed |= print_column(&header1, &header2, &data, COL_BEGIN,
				diff_first_last, 3);
	changed |= print_column(&header1, &header2, &data, COL_END,
				diff_first_now, 3);

	/* Throughput */
	double thruput = (double)report->bytes_written /
			 (diff_first_now - diff_first_last);
	thruput = scale_thruput(thruput);
	changed |= print_column(&header1, &header2, &data, COL_THROUGH,
				thruput, 6);

	/* Transactions */
	double transac = (double)report->response_blocks_read /
			 (diff_first_now - diff_first_last);
	changed |= print_column(&header1, &header2, &data, COL_TRANSAC,
				transac, 2);

	/* Blocks */
	changed |= print_column(&header1, &header2, &data, COL_BLOCK_REQU,
				report->request_blocks_written, 0);
	changed |= print_column(&header1, &header2, &data, COL_BLOCK_RESP,
				report->response_blocks_written, 0);

	/* RTT */
	double rtt_avg = 0.0;
	if (report->response_blocks_read && report->rtt_sum)
		rtt_avg = report->rtt_sum /
			  (double)(report->response_blocks_read);
	else
		report->rtt_min = report->rtt_max = rtt_avg = INFINITY;
	changed |= print_column(&header1, &header2, &data, COL_RTT_MIN,
				report->rtt_min * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_RTT_AVG,
				rtt_avg * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_RTT_MAX,
				report->rtt_max * 1e3, 3);

	/* IAT */
	double iat_avg = 0.0;
	if (report->request_blocks_read && report->iat_sum)
		iat_avg = report->iat_sum /
			  (double)(report->request_blocks_read);
	else
		report->iat_min = report->iat_max = iat_avg = INFINITY;
	changed |= print_column(&header1, &header2, &data, COL_IAT_MIN,
				report->rtt_min * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_IAT_AVG,
				iat_avg * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_IAT_MAX,
				report->iat_max * 1e3, 3);

	/* Delay */
	double delay_avg = 0.0;
	if (report->request_blocks_read && report->delay_sum)
		delay_avg = report->delay_sum /
			    (double)(report->request_blocks_read);
	else
		report->delay_min = report->delay_max = delay_avg = INFINITY;
	changed |= print_column(&header1, &header2, &data, COL_DLY_MIN,
				report->delay_min * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_DLY_AVG,
				delay_avg * 1e3, 3);
	changed |= print_column(&header1, &header2, &data, COL_DLY_MAX,
				report->delay_max * 1e3, 3);

	/* TCP info struct */
	changed |= print_column(&header1, &header2, &data, COL_TCP_CWND,
				report->tcp_info.tcpi_snd_cwnd, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_SSTH,
				report->tcp_info.tcpi_snd_ssthresh, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_UACK,
				report->tcp_info.tcpi_unacked, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_SACK,
				report->tcp_info.tcpi_sacked, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_LOST,
				report->tcp_info.tcpi_lost, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_RETR,
				report->tcp_info.tcpi_retrans, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_TRET,
				report->tcp_info.tcpi_retransmits, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_FACK,
				report->tcp_info.tcpi_fackets, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_REOR,
				report->tcp_info.tcpi_reordering, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_BKOF,
				report->tcp_info.tcpi_backoff, 0);
	changed |= print_column(&header1, &header2, &data, COL_TCP_RTT,
				report->tcp_info.tcpi_rtt / 1e3, 1);
	changed |= print_column(&header1, &header2, &data, COL_TCP_RTTVAR,
				report->tcp_info.tcpi_rttvar / 1e3, 1);
	changed |= print_column(&header1, &header2, &data, COL_TCP_RTO,
				report->tcp_info.tcpi_rto / 1e3, 1);

	/* TCP CA state */
	char *ca_state = NULL;
	switch (report->tcp_info.tcpi_ca_state) {
	case TCP_CA_Open:
		ca_state = "open";
		break;
	case TCP_CA_Disorder:
		ca_state = "disorder";
		break;
	case TCP_CA_CWR:
		ca_state = "cwr";
		break;
	case TCP_CA_Recovery:
		ca_state = "recover";
		break;
	case TCP_CA_Loss:
		ca_state = "loss";
		break;
	default:
		ca_state = "unknown";
	}
	changed |= print_column_str(&header1, &header2, &data,
				    COL_TCP_CA_STATE, ca_state);

	/* SMSS & PMTU */
	changed |= print_column(&header1, &header2, &data, COL_SMSS,
				report->tcp_info.tcpi_snd_mss, 0);
	changed |= print_column(&header1, &header2, &data, COL_PMTU,
				report->pmtu, 0);

/* Internal flowgrind state */
#ifdef DEBUG
	int rc = 0;
	char *fg_state = NULL;
	if (cflow[flow_id].finished[e]) {
		rc = asprintf(&fg_state, "(stopped)");
	} else {
		/* Write status */
		char ws = (char)(report->status & 0xFF);
		if  (ws != 'd' || ws != 'l' || ws != 'o' || ws != 'f' ||
		     ws != 'c' || ws != 'n')
			ws = 'u';

		/* Read status */
		char rs = (char)(report->status >> 8);
		if  (rs != 'd' || rs != 'l' || rs != 'o' || rs != 'f' ||
		     rs != 'c' || rs != 'n')
			rs = 'u';
		rc = asprintf(&fg_state, "(%c/%c)", ws, rs);
	}

	if (rc == -1)
		critx("could not allocate memory for flowgrind status string");

	changed |= print_column_str(&header1, &header2, &data, COL_STATUS,
				    fg_state);
	free(fg_state);
#endif /* DEBUG */

	/* Print interval header again if either the column width has been
	 * changed or MAX_REPORTS_BEFORE_HEADER reports have been emited
	 * since last time header was printed */
	static unsigned short printed_reports = 0;
	if (changed || (printed_reports % MAX_REPORTS_IN_ROW) == 0) {
		print_output("%s\n", header1);
		print_output("%s\n", header2);
	}

	print_output("%s\n", data);
	printed_reports++;
	free_all(header1, header2, data);
}

/**
 * Maps common MTU sizes to network known technologies.
 *
 * @param[in] mtu MTU size
 * @return return network technology as string
 */
static char *guess_topology(unsigned mtu)
{
	struct mtu_hint {
		unsigned mtu;
		char *topology;
	};

	static const struct mtu_hint mtu_hints[] = {
		{65535,	"Hyperchannel"},		/* RFC1374 */
		{17914, "16 MB/s Token Ring"},
		{16436, "Linux Loopback device"},
		{16384, "FreeBSD Loopback device"},
		{16352, "Darwin Loopback device"},
		{9000, "Gigabit Ethernet (Jumboframes)"},
		{8166, "802.4 Token Bus"},		/* RFC1042 */
		{4464, "4 MB/s Token Ring"},
		{4352, "FDDI"},				/* RFC1390 */
		{1500, "Ethernet/PPP"},			/* RFC894, RFC1548 */
		{1492, "PPPoE"},			/* RFC2516 */
		{1472, "IP-in-IP"},			/* RFC1853 */
		{1280, "IPv6 Tunnel"},			/* RFC4213 */
		{1006, "SLIP"},				/* RFC1055 */
		{576,  "X.25 & ISDN"},			/* RFC1356 */
		{296,  "PPP (low delay)"},
	};

	size_t array_size = sizeof(mtu_hints) / sizeof(struct mtu_hint);
	for (unsigned short i = 0; i < array_size; i++)
		if (mtu == mtu_hints[i].mtu)
			return mtu_hints[i].topology;
	return "unknown";
}

/**
 * Print final report (i.e. summary line) for endpoint @p e of flow @p flow_id.
 *
 * @param[in] flow_id flow a final report will be created for
 * @param[in] e flow endpoint (SOURCE or DESTINATION)
 */
static void print_final_report(unsigned short flow_id, enum endpoint_t e)
{
	/* To store the final report */
	char *buf = NULL;

	/* For convenience only */
	struct flow_endpoint *endpoint = &cflow[flow_id].endpoint[e];
	struct flow_settings *settings = &cflow[flow_id].settings[e];
	struct report *report = cflow[flow_id].final_report[e];

	/* Flow ID and endpoint (source or destination) */
	if (asprintf(&buf, "# ID %3d %s: ", flow_id, e ? "D" : "S") == -1)
		critx("could not allocate memory for final report");;

	/* No final report received. Skip final report line for this endpoint */
	if (!report) {
		asprintf_append(&buf, "Error: no final report received");
		goto out;
	}

	/* Infos about the test connections */
	asprintf_append(&buf, "%s", endpoint->test_address);

	if (strcmp(endpoint->rpc_info->server_name, endpoint->test_address) != 0)
		asprintf_append(&buf, "/%s", endpoint->rpc_info->server_name);
	if (endpoint->rpc_info->server_port != DEFAULT_LISTEN_PORT)
		asprintf_append(&buf, ":%d", endpoint->rpc_info->server_port);

	/* Infos about the daemon OS */
	asprintf_append(&buf, " (%s %s), ",
			endpoint->daemon->os_name, endpoint->daemon->os_release);

	/* Random seed */
	asprintf_append(&buf, "random seed: %u, ", cflow[flow_id].random_seed);

	/* Sending & Receiving buffer */
	asprintf_append(&buf, "sbuf = %d/%d [B] (real/req), ",
			endpoint->send_buffer_size_real,
			settings->requested_send_buffer_size);
	asprintf_append(&buf, "rbuf = %d/%d [B] (real/req), ",
			endpoint->receive_buffer_size_real,
			settings->requested_read_buffer_size);

	/* SMSS, Path MTU, Interface MTU */
	if (report->tcp_info.tcpi_snd_mss > 0)
		asprintf_append(&buf, "SMSS = %d [B], ",
				report->tcp_info.tcpi_snd_mss);
	if (report->pmtu > 0)
		asprintf_append(&buf, "PMTU = %d [B], ", report->pmtu);
	if (report->imtu > 0)
		asprintf_append(&buf, "Interface MTU = %d (%s) [B], ",
				report->imtu, guess_topology(report->imtu));

	/* Congestion control algorithms */
	if (settings->cc_alg[0])
		asprintf_append(&buf, "CC = %s, ", settings->cc_alg);

	/* Calculate time */
	double report_time = time_diff(&report->begin, &report->end);
	double delta_write = 0.0, delta_read = 0.0;
	if (settings->duration[WRITE])
		delta_write = report_time - settings->duration[WRITE]
					  - settings->delay[SOURCE];
	if (settings->duration[READ])
		delta_read = report_time - settings->duration[READ]
					 - settings->delay[DESTINATION];

	/* Calculate delta target vs. real report time */
	double real_write = settings->duration[WRITE] + delta_write;
	double real_read = settings->duration[READ] + delta_read;
	if (settings->duration[WRITE])
		asprintf_append(&buf, "duration = %.3f/%.3f [s] (real/req), ",
				real_write, settings->duration[WRITE]);
	if (settings->delay[WRITE])
		asprintf_append(&buf, "write delay = %.3f [s], ",
				settings->delay[WRITE]);
	if (settings->delay[READ])
		asprintf_append(&buf, "read delay = %.3f [s], ",
				settings->delay[READ]);

	/* Throughput */
	double thruput_read = report->bytes_read / MAX(real_read, real_write);
	double thruput_write = report->bytes_written / MAX(real_read, real_write);
	if (isnan(thruput_read))
		thruput_read = 0.0;
	if (isnan(thruput_write))
		thruput_write = 0.0;

	thruput_read = scale_thruput(thruput_read);
	thruput_write = scale_thruput(thruput_write);

	if (copt.mbyte)
		asprintf_append(&buf, "through = %.6f/%.6f [MiB/s] (out/in)",
				thruput_write, thruput_read);
	else
		asprintf_append(&buf, "through = " "%.6f/%.6f [Mbit/s] (out/in)",
				thruput_write, thruput_read);

	/* Transactions */
	double trans = report->response_blocks_read / MAX(real_read, real_write);
	if (isnan(trans))
		trans = 0.0;
	if (trans)
		asprintf_append(&buf, ", transactions/s = %.2f [#]", trans);

	/* Blocks */
	if (report->request_blocks_written || report->request_blocks_read)
		asprintf_append(&buf, ", request blocks = %u/%u [#] (out/in)",
				report->request_blocks_written,
				report->request_blocks_read);
	if (report->response_blocks_written || report->response_blocks_read)
		asprintf_append(&buf, ", response blocks = %u/%u [#] (out/in)",
				report->response_blocks_written,
				report->response_blocks_read);

	/* RTT */
	if (report->response_blocks_read) {
		double rtt_avg = report->rtt_sum /
				 (double)(report->response_blocks_read);
		asprintf_append(&buf, ", RTT = %.3f/%.3f/%.3f [ms] (min/avg/max)",
				report->rtt_min * 1e3, rtt_avg * 1e3,
				report->rtt_max * 1e3);
	}

	/* IAT */
	if (report->request_blocks_read) {
		double iat_avg = report->iat_sum /
				 (double)(report->request_blocks_read);
		asprintf_append(&buf, ", IAT = %.3f/%.3f/%.3f [ms] (min/avg/max)",
				report->iat_min * 1e3, iat_avg * 1e3,
				report->iat_max * 1e3);
	}

	/* Delay */
	if (report->request_blocks_read) {
		double delay_avg = report->delay_sum /
				   (double)(report->request_blocks_read);
		asprintf_append(&buf, ", delay = %.3f/%.3f/%.3f [ms] (min/avg/max)",
				report->delay_min * 1e3, delay_avg * 1e3,
				report->delay_max * 1e3);
	}

	/* Fixed sending rate per second was set */
	if (settings->write_rate_str)
		asprintf_append(&buf, ", rate = %s", settings->write_rate_str);

	/* Socket options */
	if (settings->elcn)
		asprintf_append(&buf, ", ELCN");
	if (settings->cork)
		asprintf_append(&buf, ", TCP_CORK");
	if (settings->pushy)
		asprintf_append(&buf, ", PUSHY");
	if (settings->nonagle)
		asprintf_append(&buf, ", TCP_NODELAY");
	if (settings->mtcp)
		asprintf_append(&buf, ", TCP_MTCP");
	if (settings->dscp)
		asprintf_append(&buf, ", dscp = 0x%02x", settings->dscp);

	/* Other flow options */
	if (cflow[flow_id].late_connect)
		asprintf_append(&buf, ", late connecting");
	if (cflow[flow_id].shutdown)
		asprintf_append(&buf, ", calling shutdown");

out:
	print_output("%s\n", buf);
	free(buf);
}

/**
 * Print final report (i.e. summary line) for all configured flows.
 */
static void print_all_final_reports(void)
{
	for (unsigned id = 0; id < copt.num_flows; id++) {
		print_output("\n");
		foreach(int *i, SOURCE, DESTINATION) {
			print_final_report(id, *i);
			free(cflow[id].final_report[*i]);
		}
	}
}

/**
 * Add the flow endpoint XML RPC data to the Global linked list.
 *
 * @param[in] XML-RPC connection url
 * @param[in] server_name flow endpoints IP address
 * @param[in] server_port controller - daemon XML-RPC connection port Nr
 * @return rpc_info flow endpoint XML RPC structure data 
 */
static struct rpc_info * add_flow_endpoint_by_url(const char* server_url,
					  const char* server_name,
					  unsigned short server_port)
{
	struct rpc_info *flow_rpc_info;
	flow_rpc_info = malloc((sizeof(struct rpc_info)));

	if (!flow_rpc_info ) {
		logging(LOG_ALERT, "could not allocate memory for flows rpc info");
		return 0;
	}

	memset(flow_rpc_info, 0, sizeof(struct rpc_info));
	
	strcpy(flow_rpc_info->server_url, server_url);
	strcpy(flow_rpc_info->server_name, server_name);
	flow_rpc_info->server_port = server_port;
	fg_list_push_back(&flows_rpc_info, flow_rpc_info);
	return flow_rpc_info;
}

/**
 * Set the flow endpoint XML RPC data for a given server_url.
 *
 * @param[in] XML-RPC connection url
 * @param[in] server_name flow endpoints IP address
 * @param[in] server_port controller - daemon XML-RPC connection port Nr
 * @return rpc_info flow endpoint XML RPC structure data 
 */
static struct rpc_info * set_rpc_info(const char* server_url,
					  const char* server_name,
					  unsigned short server_port)
{
	if(fg_list_size(&flows_rpc_info) == 0)
		return add_flow_endpoint_by_url(server_url,server_name, server_port);
	
	/* If we have already stored flow info for this URL return a pointer to it */
	const struct list_node *node = fg_list_front(&flows_rpc_info);
	while (node) {
		struct rpc_info *flow_rpc_info= node->data;
		node = node->next;

		if (!strcmp(flow_rpc_info->server_url, server_url))
			return flow_rpc_info;
	}
	/* didn't find anything, seems to be a new one */
	return add_flow_endpoint_by_url(server_url,server_name, server_port);
}

/**
 * Parse option for stochastic traffic generation (option -G).
 *
 * @param[in] params parameter string in the form 'x=(q|p|g):(C|U|E|N|L|P|W):#1:[#2]'
 * @param[in] flow_id ID of flow to apply option to
 * @param[in] endpoint_id endpoint to apply option to
 */
static void parse_trafgen_option(const char *params, int flow_id, int endpoint_id)
{
	int rc;
	double param1 = 0, param2 = 0, unused;
	char typechar, distchar;
	enum distribution_t distr = CONSTANT;

	rc = sscanf(params, "%c:%c:%lf:%lf:%lf", &typechar, &distchar,
		    &param1, &param2, &unused);
	if (rc != 3 && rc != 4)
		PARSE_ERR("flow %i: option -G: malformed traffic generation "
			  "parameters", flow_id);

	switch (distchar) {
	case 'N':
		distr = NORMAL;
		if (!param1 || !param2)
			PARSE_ERR("flow %i: option -G: normal distribution "
				  "needs two non-zero parameters", flow_id);
		break;
	case 'W':
		distr = WEIBULL;
		if (!param1 || !param2)
			PARSE_ERR("flow %i: option -G: weibull distribution "
				  "needs two non-zero parameters", flow_id);
		break;
	case 'U':
		distr = UNIFORM;
		if  (param1 <= 0 || param2 <= 0 || (param1 > param2))
			PARSE_ERR("flow %i: option -G: uniform distribution "
				  "needs two positive parameters", flow_id);
		break;
	case 'E':
		distr = EXPONENTIAL;
		if (param1 <= 0)
			PARSE_ERR("flow %i: option -G: exponential distribution "
				  "needs one positive parameter", flow_id);
		break;
	case 'P':
		distr = PARETO;
		if (!param1 || !param2)
			PARSE_ERR("flow %i: option -G: pareto distribution "
				  "needs two non-zero parameters", flow_id);
		break;
	case 'L':
		distr = LOGNORMAL;
		if (!param1 || !param2)
			PARSE_ERR("flow %i: option -G: lognormal distribution "
				  "needs two non-zero parameters", flow_id);
		break;
	case 'C':
		distr = CONSTANT;
		if (param1 <= 0)
			PARSE_ERR("flow %i: option -G: constant distribution "
				  "needs one positive parameters", flow_id);
		break;
	default:
		PARSE_ERR("flow %i: option -G: syntax error: %c is not a "
			  "distribution", flow_id, distchar);
		break;
	}

	switch (typechar) {
	case 'p':
		cflow[flow_id].settings[endpoint_id].response_trafgen_options.distribution = distr;
		cflow[flow_id].settings[endpoint_id].response_trafgen_options.param_one = param1;
		cflow[flow_id].settings[endpoint_id].response_trafgen_options.param_two = param2;
		break;
	case 'q':
		cflow[flow_id].settings[endpoint_id].request_trafgen_options.distribution = distr;
		cflow[flow_id].settings[endpoint_id].request_trafgen_options.param_one = param1;
		cflow[flow_id].settings[endpoint_id].request_trafgen_options.param_two = param2;
		break;
	case 'g':
		cflow[flow_id].settings[endpoint_id].interpacket_gap_trafgen_options.distribution = distr;
		cflow[flow_id].settings[endpoint_id].interpacket_gap_trafgen_options.param_one = param1;
		cflow[flow_id].settings[endpoint_id].interpacket_gap_trafgen_options.param_two = param2;
		break;
	}

	/* sanity check for max block size */
	foreach(int *i, SOURCE, DESTINATION) {
		if (distr == CONSTANT &&
		    cflow[flow_id].settings[*i].maximum_block_size < param1)
			cflow[flow_id].settings[*i].maximum_block_size = param1;
		if (distr == UNIFORM &&
		    cflow[flow_id].settings[*i].maximum_block_size < param2)
			cflow[flow_id].settings[*i].maximum_block_size = param2;
	}
}

/**
 * Parse argument for option -R, which specifies the rate the endpoint will send.
 *
 * @param[in] arg argument for option -R in form of #.#(z|k|M|G)(b|B|o)
 * @param[in] flow_id ID of flow to apply option to
 * @param[in] endpoint_id endpoint to apply option to
 */
static void parse_rate_option(const char *arg, int flow_id, int endpoint_id)
{
	char unit = 0, type = 0;
	double optdouble = 0.0;
	/* last %c for catching wrong input... this is not nice. */
	int rc = sscanf(arg, "%lf%c%c%c",
			&optdouble, &unit, &type, &unit);
	if (rc < 1 || rc > 4)
		PARSE_ERR("flow %i: option -R: malformed rate", flow_id);

	if (optdouble == 0.0)
		PARSE_ERR("flow %i: option -R: rate of 0", flow_id);


	switch (unit) {
	case 0:
	case 'z':
		break;

	case 'k':
		optdouble *= 1<<10;
		break;

	case 'M':
		optdouble *= 1<<20;
		break;

	case 'G':
		optdouble *= 1<<30;
		break;

	default:
		PARSE_ERR("flow %i: option -R: illegal unit specifier", flow_id);
		break;
	}

	if (type != 'b' && type != 'B')
		PARSE_ERR("flow %i: option -R: illegal type specifier "
			  "(either 'b' or 'B')", flow_id);
	if (type == 'b')
		optdouble /=  8;

	if (optdouble > 5e9)
		warnx("rate of flow %d too high", flow_id);

	cflow[flow_id].settings[endpoint_id].write_rate_str = strdup(arg);
	cflow[flow_id].settings[endpoint_id].write_rate = optdouble;
}



/**
 * Parse argument for option -H, which specifies the endpoints of a flow.
 *
 * @param[in] hostarg argument for option -H in form of HOST[/CONTROL[:PORT]]
 *	- HOST: test address where the actual test connection goes to
 *	- CONTROL: RPC address, where this program connects to
 *	- PORT: port for the control connection
 * @param[in] flow_id ID of flow to apply option to
 * @param[in] endpoint_id endpoint to apply option to
 */
static void parse_host_option(const char* hostarg, int flow_id, int endpoint_id)
{
	struct sockaddr_in6 source_in6;
	source_in6.sin6_family = AF_INET6;
	int port = DEFAULT_LISTEN_PORT;
	bool extra_rpc = false;
	bool is_ipv6 = false;
	char *rpc_address, *url = 0, *sepptr = 0;
	char *arg = strdup(hostarg);
	struct flow_endpoint* endpoint = &cflow[flow_id].endpoint[endpoint_id];

	/* extra RPC address ? */
	sepptr = strchr(arg, '/');
	if (sepptr) {
		*sepptr = '\0';
		rpc_address = sepptr + 1;
		extra_rpc = true;
	} else {
		rpc_address = arg;
	}

	/* IPv6 Address? */
	if (strchr(arg, ':')) {
		if (inet_pton(AF_INET6, arg, (char*)&source_in6.sin6_addr) <= 0)
			PARSE_ERR("flow %i: invalid IPv6 address '%s' for "
				  "test connection", flow_id, arg);

		if (!extra_rpc)
			is_ipv6 = true;
	}

	/* optional dedicated rpc address was supplied and needs to be parsed */
	if (extra_rpc) {
		parse_rpc_address(&rpc_address, &port, &is_ipv6);
		if (is_ipv6 && (inet_pton(AF_INET6, rpc_address,
				(char*)&source_in6.sin6_addr) <= 0))
			PARSE_ERR("flow %i: invalid IPv6 address '%s' for RPC",
				  flow_id, arg);
		if (port < 1 || port > 65535)
			PARSE_ERR("flow %i: invalid port for RPC", flow_id);
	}

	if (!*arg)
		PARSE_ERR("flow %i: no test host given in argument", flow_id);

	int rc = 0;
	if (is_ipv6)
		rc = asprintf(&url, "http://[%s]:%d/RPC2", rpc_address, port);
	else
		rc = asprintf(&url, "http://%s:%d/RPC2", rpc_address, port);

	if (rc == -1)
		critx("could not allocate memory for RPC URL");

	/* Get flow endpoint server information for each flow */
	endpoint->rpc_info  = set_rpc_info(url, rpc_address, port);
	strcpy(endpoint->test_address, arg);
	free_all(arg, url);
}

/**
 * Parse flow options with endpoint.
 *
 * @param[in] code the code of the cmdline option
 * @param[in] arg the argument of the cmdline option
 * @param[in] opt_string contains the real cmdline option string
 * @param[in] flow_id ID of flow to apply option to
 * @param[in] endpoint_id endpoint to apply option to
 */
static void parse_flow_option_endpoint(int code, const char* arg,
				       const char* opt_string, int flow_id,
				       int endpoint_id)
{
	int optint = 0;
	double optdouble = 0.0;

	struct flow_settings* settings = &cflow[flow_id].settings[endpoint_id];

	switch (code) {
	case 'G':
		parse_trafgen_option(arg, flow_id, endpoint_id);
		break;
	case 'A':
		SHOW_COLUMNS(COL_RTT_MIN, COL_RTT_AVG, COL_RTT_MAX);
		settings->response_trafgen_options.distribution = CONSTANT;
		settings->response_trafgen_options.param_one = MIN_BLOCK_SIZE;
		break;
	case 'B':
		if (sscanf(arg, "%u", &optint) != 1 || optint < 0)
			PARSE_ERR("in flow %i: option %s needs positive integer",
				  flow_id, opt_string);
		settings->requested_send_buffer_size = optint;
		break;
	case 'C':
		settings->flow_control= 1;
		break;
	case 'D':
		if (sscanf(arg, "%x", &optint) != 1 || (optint & ~0x3f))
			PARSE_ERR("in flow %i: option %s service code point "
				  "is malformed", flow_id, opt_string);
		settings->dscp = optint;
		break;
	case 'H':
		parse_host_option(arg, flow_id, endpoint_id);
		break;
	case 'M':
		settings->traffic_dump = 1;
		break;
	case 'O':
		if (!*arg)
			PARSE_ERR("in flow %i: option %s requires a value "
				  "for each endpoint", flow_id, opt_string);

		if (!strcmp(arg, "TCP_CORK")) {
			settings->cork = 1;
		} else if (!strcmp(arg, "TCP_ELCN")) {
			settings->elcn = 1;
		} else if (!strcmp(arg, "TCP_LCD")) {
			settings->lcd = 1;
		} else if (!strcmp(arg, "TCP_MTCP")) {
			settings->mtcp = 1;
		} else if (!strcmp(arg, "TCP_NODELAY")) {
			settings->nonagle = 1;
		} else if (!strcmp(arg, "ROUTE_RECORD")) {
			settings->route_record = 1;
		/* keep TCP_CONG_MODULE for backward compatibility */
		} else if (!memcmp(arg, "TCP_CONG_MODULE=", 16)) {
			if (strlen(arg + 16) >= sizeof(cflow[0].settings[SOURCE].cc_alg))
				PARSE_ERR("in flow %i: option %s: too large "
					  "string for TCP_CONG_MODULE",
					  flow_id, opt_string);
			strcpy(settings->cc_alg, arg + 16);
		} else if (!memcmp(arg, "TCP_CONGESTION=", 15)) {
			if (strlen(arg + 16) >= sizeof(cflow[0].settings[SOURCE].cc_alg))
				PARSE_ERR("in flow %i: option %s: too large "
					  "string for TCP_CONGESTION",
					  flow_id, opt_string);
			strcpy(settings->cc_alg, arg + 15);
		} else if (!strcmp(arg, "SO_DEBUG")) {
			settings->so_debug = 1;
		} else if (!strcmp(arg, "IP_MTU_DISCOVER")) {
			settings->ipmtudiscover = 1;
		} else {
			PARSE_ERR("in flow %i: option %s: unknown socket "
				  "option or socket option not implemented",
				  flow_id, opt_string);
		}
		break;
	case 'P':
		settings->pushy = 1;
		break;
	case 'R':
		if (!*arg)
			PARSE_ERR("in flow %i: option %s requires a value "
				  "for each given endpoint", flow_id, opt_string);
		parse_rate_option(arg, flow_id, endpoint_id);
		break;
	case 'S':
		if (sscanf(arg, "%u", &optint) != 1 || optint < 0)
			PARSE_ERR("in flow %i: option %s needs positive integer",
				  flow_id, opt_string);
		settings->request_trafgen_options.distribution = CONSTANT;
		settings->request_trafgen_options.param_one = optint;
		for (int id = 0; id < MAX_FLOWS; id++) {
			foreach(int *i, SOURCE, DESTINATION) {
				if ((signed)optint >
				    cflow[id].settings[*i].maximum_block_size)
					cflow[id].settings[*i].maximum_block_size =
						(signed)optint;
			}
		}
		break;
	case 'T':
		if (sscanf(arg, "%lf", &optdouble) != 1 || optdouble < 0)
			PARSE_ERR("in flow %i: option %s needs positive number",
				  flow_id, opt_string);
		settings->duration[WRITE] = optdouble;
		break;
	case 'U':
		if (sscanf(arg, "%u", &optint) != 1 || optint < 0)
			PARSE_ERR("in flow %i: option %s needs positive integer",
				  flow_id, opt_string);
		settings->maximum_block_size = optint;
		break;
	case 'W':
		if (sscanf(arg, "%u", &optint) != 1 || optint < 0)
			PARSE_ERR("in flow %i: option %s needs non-negative number",
				  flow_id, opt_string);
		settings->requested_read_buffer_size = optint;
		break;
	case 'Y':
		if (sscanf(arg, "%lf", &optdouble) != 1 || optdouble < 0)
			PARSE_ERR("in flow %i: option %s needs non-negative number",
				  flow_id, opt_string);
		settings->delay[WRITE] = optdouble;
		break;
	}
}

/**
 * Parse flow options without endpoint.
 *
 * @param[in] code the code of the cmdline option
 * @param[in] arg the argument string of the cmdline option
 * @param[in] opt_string contains the real cmdline option string
 * @param[in] flow_id ID of flow to apply option to
 */
static void parse_flow_option(int code, const char* arg, const char* opt_string,
			      int flow_id)
{
	unsigned optunsigned = 0;

	switch (code) {
	/* flow options w/o endpoint identifier */
	case 'E':
		cflow[flow_id].byte_counting = 1;
		break;
	case 'I':
		SHOW_COLUMNS(COL_DLY_MIN, COL_DLY_AVG, COL_DLY_MAX);
		break;
	case 'J':
		if (sscanf(arg, "%u", &optunsigned) != 1)
			PARSE_ERR("option %s needs an integer argument",
				  opt_string);
		cflow[flow_id].random_seed = optunsigned;
		break;
	case 'L':
		cflow[flow_id].late_connect = 1;
		break;
	case 'N':
		cflow[flow_id].shutdown = 1;
		break;
	case 'Q':
		cflow[flow_id].summarize_only = 1;
		break;
	}
}

/**
 * Parse argument for option -c to hide/show intermediated interval report
 * columns.
 *
 * @param[in] arg argument for option -c
 */
static void parse_colon_option(const char *arg)
{
	/* To make it easy (independed of default values), hide all colons */
	HIDE_COLUMNS(COL_BEGIN, COL_END, COL_THROUGH, COL_TRANSAC,
		     COL_BLOCK_REQU, COL_BLOCK_RESP, COL_RTT_MIN, COL_RTT_AVG,
		     COL_RTT_MAX, COL_IAT_MIN, COL_IAT_AVG, COL_IAT_MAX,
		     COL_DLY_MIN, COL_DLY_AVG, COL_DLY_MAX, COL_TCP_CWND,
		     COL_TCP_SSTH, COL_TCP_UACK, COL_TCP_SACK, COL_TCP_LOST,
		     COL_TCP_RETR, COL_TCP_TRET, COL_TCP_FACK, COL_TCP_REOR,
		     COL_TCP_BKOF, COL_TCP_RTT, COL_TCP_RTTVAR, COL_TCP_RTO,
		     COL_TCP_CA_STATE, COL_SMSS, COL_PMTU);
#ifdef DEBUG
	HIDE_COLUMNS(COL_STATUS);
#endif /* DEBUG */

	/* Set colon visibility according option */
	char *argcpy = strdup(arg);
	for (char *token = strtok(argcpy, ","); token;
	     token = strtok(NULL, ",")) {
		if (!strcmp(token, "interval"))
			SHOW_COLUMNS(COL_BEGIN, COL_END);
		else if (!strcmp(token, "through"))
			SHOW_COLUMNS(COL_THROUGH);
		else if (!strcmp(token, "transac"))
			SHOW_COLUMNS(COL_TRANSAC);
		else if (!strcmp(token, "blocks"))
			SHOW_COLUMNS(COL_BLOCK_REQU, COL_BLOCK_RESP);
		else if (!strcmp(token, "rtt"))
			SHOW_COLUMNS(COL_RTT_MIN, COL_RTT_AVG, COL_RTT_MAX);
		else if (!strcmp(token, "iat"))
			SHOW_COLUMNS(COL_IAT_MIN, COL_IAT_AVG, COL_IAT_MAX);
		else if (!strcmp(token, "delay"))
			SHOW_COLUMNS(COL_DLY_MIN, COL_DLY_AVG, COL_DLY_MAX);
		else if (!strcmp(token, "kernel"))
			SHOW_COLUMNS(COL_TCP_CWND, COL_TCP_SSTH, COL_TCP_UACK,
				     COL_TCP_SACK, COL_TCP_LOST, COL_TCP_RETR,
				     COL_TCP_TRET, COL_TCP_FACK, COL_TCP_REOR,
				     COL_TCP_BKOF, COL_TCP_RTT, COL_TCP_RTTVAR,
				     COL_TCP_RTO, COL_TCP_CA_STATE, COL_SMSS,
				     COL_PMTU);
#ifdef DEBUG
		else if (!strcmp(token, "status"))
			SHOW_COLUMNS(COL_STATUS);
#endif /* DEBUG */
		else
			PARSE_ERR("%s", "malformed option '-c'");
	}
	free(argcpy);
}

/**
 * Parse general controller options given on the cmdline.
 *
 * @param[in] code the code of the cmdline option
 * @param[in] arg the argument string of the cmdline option
 * @param[in] opt_string contains the real cmdline option string
 */
static void parse_general_option(int code, const char* arg, const char* opt_string)
{

	switch (code) {
	case 0:
		PARSE_ERR("invalid argument: %s", arg);
	/* general options */
	case 'h':
		if (!arg || !strlen(arg))
			usage(EXIT_SUCCESS);
		else if (!strcmp(arg, "socket"))
			usage_sockopt();
		else if (!strcmp(arg, "traffic"))
			usage_trafgenopt();
		else
			PARSE_ERR("invalid argument '%s' for %s", arg, opt_string);
		break;
	case 'v':
		fprintf(stdout, "%s %s\n%s\n%s\n\n%s\n", progname,
			FLOWGRIND_VERSION, FLOWGRIND_COPYRIGHT,
			FLOWGRIND_COPYING, FLOWGRIND_AUTHORS);
		exit(EXIT_SUCCESS);

	/* controller options */
	case 'c':
		parse_colon_option(arg);
		break;
#ifdef DEBUG
	case 'd':
		increase_debuglevel();
		break;
#endif /* DEBUG */
	case 'e':
		copt.dump_prefix = strdup(arg);
		break;
	case 'i':
		if (sscanf(arg, "%lf", &copt.reporting_interval) != 1 ||
					copt.reporting_interval <= 0)
			PARSE_ERR("option %s needs a positive number "
				  "(in seconds)", opt_string);
		break;
	case LOG_FILE_OPTION:
		copt.log_to_file = true;
		if (arg)
			log_filename = strdup(arg);
		break;
	case 'm':
		copt.mbyte = true;
		column_info[COL_THROUGH].header.unit = " [MiB/s]";
		break;
	case 'n':
		if (sscanf(arg, "%hd", &copt.num_flows) != 1 ||
			   copt.num_flows > MAX_FLOWS)
			PARSE_ERR("option %s (number of flows) must be within "
				  "[1..%d]", opt_string, MAX_FLOWS);
		break;
	case 'o':
		copt.clobber = true;
		break;
	case 'p':
		copt.symbolic = false;
		break;
	case 'q':
		copt.log_to_stdout = false;
		break;
	case 's':
		if (!strcmp(arg, "segment"))
			copt.force_unit = SEGMENT_BASED;
		else if (!strcmp(arg, "byte"))
			copt.force_unit = BYTE_BASED;
		else
			PARSE_ERR("invalid argument '%s' for option %s",
				  arg, opt_string);
		break;
	case 'w':
		copt.log_to_file = true;
		break;
	/* unknown option or missing option-argument */
	default:
		PARSE_ERR("uncaught option: %s", arg);
		break;
	}

}

/**
 * Wrapper function for mutex checking and error message printing.
 *
 * Defines the cmdline options and distinguishes option types (flow, general, ...)
 * and tokenizes flow options which can have several endpoints.
 *
 * @param[in] ms array of mutex states
 * @param[in] context the mutex context of this option (see enum #mutex_contexts)
 * @param[in] argind option record index
 * @param[in] flow_id ID of the flow to show in error message
 */
static void check_mutex(struct ap_Mutex_state ms[],
			const enum mutex_context_t context,
			const int argind, int flow_id)
{
	int mutex_index;
	if (context == MUTEX_CONTEXT_CONTROLLER){
		if (ap_set_check_mutex(&parser, &ms[context], argind, &mutex_index))
			PARSE_ERR("Option %s conflicts with option %s",
				ap_opt_string(&parser, argind),
				ap_opt_string(&parser, mutex_index));
	} else {
		if (ap_set_check_mutex(&parser, &ms[context], argind, &mutex_index))
			PARSE_ERR("In flow %i: option %s conflicts with option %s",
				flow_id, ap_opt_string(&parser, argind),
				ap_opt_string(&parser, mutex_index));
	}
}

/**
 * Parse flow options for multiple endpoints.
 *
 * This iterates through the endpoints given in the argument string
 * (e.g. s=#,d=# or b=#).
 *
 * @param[in] code the code of the cmdline option
 * @param[in] arg the argument of the multi-endpoint flow option
 * @param[in] opt_string contains the real cmdline option string
 * @param[in] ms array of mutex states
 * @param[in] argind index of the option
 * @param[in] flow_id ID of flow to apply option to
 */
static void parse_multi_endpoint_option(int code, const char* arg,
					const char* opt_string,
					struct ap_Mutex_state ms[], int argind,
					int flow_id)
{
	char *argcpy = strdup(arg);
	for (char *token = strtok(argcpy, ","); token;
	     token = strtok(NULL, ",")) {

		char type = token[0];
		char* arg;

		if (token[1] == '=')
			arg = token + 2;
		else
			arg = token + 1;

		if (type != 's' && type != 'd' && type != 'b')
			PARSE_ERR("Invalid endpoint specifier in Option %s",
				  opt_string);

		/* check mutex in context of current endpoint */
		if (type == 's' || type == 'b') {
			check_mutex(ms, MUTEX_CONTEXT_SOURCE, argind, flow_id);
			parse_flow_option_endpoint(code, arg, opt_string,
						   flow_id, SOURCE);
		}
		if (type == 'd' || type == 'b') {
			check_mutex(ms, MUTEX_CONTEXT_DESTINATION, argind, flow_id);
			parse_flow_option_endpoint(code, arg, opt_string,
						   flow_id, DESTINATION);
		}
	}
	free(argcpy);
}

/**
 * The main commandline argument parsing function.
 *
 * Defines the cmdline options and distinguishes option types (flow, general,
 * ...) and tokenizes flow options which can have several endpoints.
 *
 * @param[in] argc number of arguments (as in main())
 * @param[in] argv array of argument strings (as in main())
 */
static void parse_cmdline(int argc, char *argv[])
{
	int rc = 0;
	int cur_num_flows = 0;
	int current_flow_ids[MAX_FLOWS];
	int max_flow_specifier = 0;
	int optint = 0;

	const struct ap_Option options[] = {
		{'c', "show-colon", ap_yes, OPT_CONTROLLER, 0},
#ifdef DEBUG
		{'d', "debug", ap_no, OPT_CONTROLLER, 0},
#endif /* DEBUG */
		{'e', "dump-prefix", ap_yes, OPT_CONTROLLER, 0},
		{'h', "help", ap_maybe, OPT_CONTROLLER, 0},
		{'i', "report-interval", ap_yes, OPT_CONTROLLER, 0},
		{LOG_FILE_OPTION, "log-file", ap_maybe, OPT_CONTROLLER, 0},
		{'m', 0, ap_no, OPT_CONTROLLER, 0},
		{'n', "flows", ap_yes, OPT_CONTROLLER, 0},
		{'o', 0, ap_no, OPT_CONTROLLER, 0},
		{'p', 0, ap_no, OPT_CONTROLLER, 0},
		{'q', "quiet", ap_no, OPT_CONTROLLER, 0},
		{'s', "tcp-stack", ap_yes, OPT_CONTROLLER, 0},
		{'v', "version", ap_no, OPT_CONTROLLER, 0},
		{'w', 0, ap_no, OPT_CONTROLLER, 0},
		{'A', 0, ap_yes, OPT_FLOW_ENDPOINT, (int[]){1,0}},
		{'B', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'C', 0, ap_no, OPT_FLOW_ENDPOINT, 0},
		{'D', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'E', 0, ap_no, OPT_FLOW, 0},
		{'F', 0, ap_yes, OPT_SELECTOR, 0},
		{'G', 0, ap_yes, OPT_FLOW_ENDPOINT, (int[]){1,2,3,0}},
		{'H', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'I', 0, ap_no, OPT_FLOW, 0},
		{'J', 0, ap_yes, OPT_FLOW, 0},
		{'L', 0, ap_no, OPT_FLOW, 0},
		{'M', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'N', 0, ap_no, OPT_FLOW, 0},
		{'O', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'P', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'Q', 0, ap_no, OPT_FLOW, 0},
		{'R', 0, ap_yes, OPT_FLOW_ENDPOINT, (int[]){2,0}},
		{'S', 0, ap_yes, OPT_FLOW_ENDPOINT, (int[]){3,0}},
		{'T', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'U', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'W', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{'Y', 0, ap_yes, OPT_FLOW_ENDPOINT, 0},
		{0, 0, ap_no, 0, 0}
	};

	if (!ap_init(&parser, argc, (const char* const*) argv, options, 0))
		critx("could not allocate memory for option parser");
	if (ap_error(&parser))
		PARSE_ERR("%s", ap_error(&parser));

	/* initialize 4 mutex contexts (for SOURCE+DESTINATION+CONTROLLER+BOTH ENDPOINTS) */
	struct ap_Mutex_state ms[4];
	foreach(int *i, MUTEX_CONTEXT_CONTROLLER, MUTEX_CONTEXT_TWO_SIDED,
			MUTEX_CONTEXT_TWO_SIDED, MUTEX_CONTEXT_DESTINATION)
		ap_init_mutex_state(&parser, &ms[*i]);

	/* if no option -F is given, configure all flows*/
	for (int i = 0; i < MAX_FLOWS; i++)
		current_flow_ids[i] = i;
	cur_num_flows = MAX_FLOWS;

	/* parse command line */
	for (int argind = 0; argind < ap_arguments(&parser); argind++) {
		const int code = ap_code(&parser, argind);
		const char *arg = ap_argument(&parser, argind);
		const char *opt_string = ap_opt_string(&parser, argind);
		int tag = ap_option(&parser, argind)->tag;

		/* distinguish option types by tag first */
		switch (tag) {
		case OPT_CONTROLLER:
			check_mutex(ms, MUTEX_CONTEXT_CONTROLLER, argind, 0);
			parse_general_option(code, arg, opt_string);
			break;
		case OPT_SELECTOR:
			cur_num_flows = 0;
			char *argcpy = strdup(arg);
			for (char *token = strtok(argcpy, ","); token;
			     token = strtok(NULL, ",")) {
				rc = sscanf(token, "%d", &optint);
				if (rc != 1)
					PARSE_ERR("%s", "Malformed flow specifier");

				/* all flows */
				if (optint == -1) {
					for (int i = 0; i < MAX_FLOWS; i++)
						current_flow_ids[i] = i;
					cur_num_flows = MAX_FLOWS;
					break;
				}

				current_flow_ids[cur_num_flows++] = optint;
				ASSIGN_MAX(max_flow_specifier, optint);
			}
			free(argcpy);
			/* reset mutex for each new flow */
			foreach(int *i, MUTEX_CONTEXT_SOURCE,
					MUTEX_CONTEXT_DESTINATION,
					MUTEX_CONTEXT_TWO_SIDED)
				ap_reset_mutex(&ms[*i]);
			break;
		case OPT_FLOW:
			check_mutex(ms, MUTEX_CONTEXT_TWO_SIDED, argind,
				    current_flow_ids[0]);
			for (int i = 0; i < cur_num_flows; i++)
				parse_flow_option(code, arg, opt_string,
						current_flow_ids[i]);
			break;
		case OPT_FLOW_ENDPOINT:
			for (int i = 0; i < cur_num_flows; i++)
				parse_multi_endpoint_option(code, arg,
							    opt_string, ms, argind,
							    current_flow_ids[i]);
			break;
		default:
			PARSE_ERR("%s", "uncaught option tag!");
			break;
		}
	}

	if (copt.num_flows <= max_flow_specifier)
		PARSE_ERR("%s", "must not specify option for non-existing flow");

#if 0
	/* Demonstration how to set arbitary socket options. Note that this is
	 * only intended for quickly testing new options without having to
	 * recompile and restart the daemons. To add support for a particular
	 * options in future flowgrind versions it's recommended to implement
	 * them like the other options supported by the -O argument.
	 */
	{
		assert(cflow[0].settings[SOURCE].num_extra_socket_options < MAX_EXTRA_SOCKET_OPTIONS);
		struct extra_socket_options *option = &cflow[0].settings[SOURCE].extra_socket_options[cflow[0].settings[SOURCE].num_extra_socket_options++];
		int v;

		/* The value of the TCP_NODELAY constant gets passed to the daemons.
		 * If daemons use a different system, constants may be different. In this case use
		 * a value that matches the daemons'. */
		option->optname = TCP_NODELAY; /* or option->optname = 12345; as explained above */

		option->level = level_ipproto_tcp; /* See extra_socket_option_level enum in common.h */

		/* Again, value needs to be of correct size for the daemons.
		 * Particular pitfalls can be differences in integer sizes or endianess.
		 */
		assert(sizeof(v) < MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH);
		option->optlen = sizeof(v);
		memcpy(option->optval, &v, sizeof(v));
	}
#endif /* 0 */

	for (unsigned short id = 0; id < copt.num_flows; id++) {
		cflow[id].settings[SOURCE].duration[READ] = cflow[id].settings[DESTINATION].duration[WRITE];
		cflow[id].settings[DESTINATION].duration[READ] = cflow[id].settings[SOURCE].duration[WRITE];
		cflow[id].settings[SOURCE].delay[READ] = cflow[id].settings[DESTINATION].delay[WRITE];
		cflow[id].settings[DESTINATION].delay[READ] = cflow[id].settings[SOURCE].delay[WRITE];

		foreach(int *i, SOURCE, DESTINATION) {
			/* Default to localhost, if no endpoints were set for a flow */
			if (!cflow[id].endpoint[*i].rpc_info) {
				cflow[id].endpoint[*i].rpc_info = set_rpc_info(
					"http://localhost:5999/RPC2", "localhost", DEFAULT_LISTEN_PORT);
			}
		}
	}

	foreach(int *i, MUTEX_CONTEXT_CONTROLLER, MUTEX_CONTEXT_TWO_SIDED,
			MUTEX_CONTEXT_TWO_SIDED, MUTEX_CONTEXT_DESTINATION)
		ap_free_mutex_state(&ms[*i]);
}

/**
 * Sanity checking flow options.
 */
static void sanity_check(void)
{
	for (unsigned short id = 0; id < copt.num_flows; id++) {
		DEBUG_MSG(LOG_DEBUG, "sanity checking parameter set of flow %d", id);
		if (cflow[id].settings[DESTINATION].duration[WRITE] > 0 &&
		    cflow[id].late_connect &&
		    cflow[id].settings[DESTINATION].delay[WRITE] <
		    cflow[id].settings[SOURCE].delay[WRITE]) {
			errx("server flow %d starts earlier than client "
			      "flow while late connecting", id);
			exit(EXIT_FAILURE);
		}
		if (cflow[id].settings[SOURCE].delay[WRITE] > 0 &&
		    cflow[id].settings[SOURCE].duration[WRITE] == 0) {
			errx("client flow %d has a delay but no runtime", id);
			exit(EXIT_FAILURE);
		}
		if (cflow[id].settings[DESTINATION].delay[WRITE] > 0 &&
		    cflow[id].settings[DESTINATION].duration[WRITE] == 0) {
			errx("server flow %d has a delay but no runtime", id);
			exit(EXIT_FAILURE);
		}
		if (!cflow[id].settings[DESTINATION].duration[WRITE] &&
		    !cflow[id].settings[SOURCE].duration[WRITE]) {
			errx("server and client flow have both zero runtime "
			      "for flow %d", id);
			exit(EXIT_FAILURE);
		}

		foreach(int *i, SOURCE, DESTINATION) {
			if (cflow[id].settings[*i].flow_control &&
			    !cflow[id].settings[*i].write_rate_str) {
				errx("flow %d has flow control enabled but no "
				      "rate", id);
				exit(EXIT_FAILURE);
			}

			if (cflow[id].settings[*i].write_rate &&
			    (cflow[id].settings[*i].write_rate /
			     cflow[id].settings[*i].maximum_block_size) < 1) {
				errx("client block size for flow %u is too big for "
				      "specified rate", id);
				exit(EXIT_FAILURE);
			}
		}
		DEBUG_MSG(LOG_DEBUG, "sanity check parameter set of flow %d completed", id);
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL))
		critx("could not set handler for SIGINT");

	xmlrpc_client *rpc_client = 0;
	xmlrpc_env_init(&rpc_env);
	xmlrpc_client_setup_global_const(&rpc_env);

	fg_list_init(&flows_rpc_info);
	fg_list_init(&unique_daemons);

	set_progname(argv[0]);
	init_controller_options();
	init_flow_options();
	parse_cmdline(argc, argv);
	sanity_check();
	open_logfile();
	prepare_xmlrpc_client(&rpc_client);

	DEBUG_MSG(LOG_WARNING, "check daemons in the flows");
	if (!sigint_caught)
		find_daemon(rpc_client);

	DEBUG_MSG(LOG_WARNING, "check flowgrindds versions");
	if (!sigint_caught)
		check_version(rpc_client);

	DEBUG_MSG(LOG_WARNING, "check if flowgrindds are idle");
	if (!sigint_caught)
		check_idle(rpc_client);

	DEBUG_MSG(LOG_WARNING, "prepare all flows");
	if (!sigint_caught)
		prepare_all_flows(rpc_client);

	DEBUG_MSG(LOG_WARNING, "print headline");
	if (!sigint_caught)
		print_headline();

	DEBUG_MSG(LOG_WARNING, "start all flows");
	if (!sigint_caught)
		start_all_flows(rpc_client);

	DEBUG_MSG(LOG_WARNING, "close all flows");
	close_all_flows();

	DEBUG_MSG(LOG_WARNING, "print all final report");
	fetch_reports(rpc_client);
	print_all_final_reports();

	fg_list_clear(&flows_rpc_info);
	fg_list_clear(&unique_daemons);

	close_logfile();

	xmlrpc_client_destroy(rpc_client);
	xmlrpc_env_clean(&rpc_env);
	xmlrpc_client_teardown_global_const();

	ap_free(&parser);

	DEBUG_MSG(LOG_WARNING, "bye");
}
