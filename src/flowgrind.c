/**
 * @file flowgrind.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef DEBUG
#include <assert.h>
#endif /* DEBUG */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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

#include "common.h"
#include "fg_socket.h"
#include "debug.h"
#include "flowgrind.h"

/* XXX add a brief description doxygen */
FILE *log_stream = NULL;
/* XXX add a brief description doxygen */
char *log_filename = NULL;
/* XXX add a brief description doxygen */
char sigint_caught = 0;
/* XXX add a brief description doxygen */
xmlrpc_env rpc_env;
/** Name of the executable */
static char progname[50] = "flowgrind";
/** Unique (by URL) flowgrind daemons */
static struct _daemon unique_servers[MAX_FLOWS * 2]; /* flow has 2 endpoints */
/** Number of flowgrind dameons */
static unsigned int num_unique_servers = 0;
/** General controller options */
struct _opt opt;
/** Infos about all flows including flow options */
static struct _cflow cflow[MAX_FLOWS];
/** Number of currently active flows */
static int active_flows = 0;

/** Infos about the intermediated interval report columns */
struct _column column_info[] = {
	{.type = COL_FLOW_ID, .header.name = "# ID",
	 .header.unit = "#   ", .state.visible = true},
	{.type = COL_BEGIN, .header.name = " begin",
	 .header.unit = " [s]", .state.visible = true},
	{.type = COL_END, .header.name = " end",
	 .header.unit = " [s]", .state.visible = true},
	{.type = COL_THROUGH, .header.name = " through",
	 .header.unit = " [Mbit/s]", .state.visible = true},
	{.type = COL_TRANSAC, .header.name = " transac",
	 .header.unit = " [#/s]", .state.visible = true},
	{.type = COL_BLOCK_REQU, .header.name = " requ",
	 .header.unit = " [#]", .state.visible = false},
	{.type = COL_BLOCK_RESP, .header.name = " resp",
	 .header.unit = " [#]", .state.visible = false},
	{.type = COL_RTT_MIN, .header.name = " min RTT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_RTT_AVG, .header.name = " avg RTT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_RTT_MAX, .header.name = " max RTT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_IAT_MIN, .header.name = " min IAT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_IAT_AVG, .header.name = " avg IAT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_IAT_MAX, .header.name = " max IAT",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_DLY_MIN, .header.name = " min DLY",
	 .header.unit = " [ms]", .state.visible = false},
	{.type = COL_DLY_AVG, .header.name = " avg DLY",
	 .header.unit = " [ms]", .state.visible = false},
	{.type = COL_DLY_MAX, .header.name = " max DLY",
	 .header.unit = " [ms]", .state.visible = false},
	{.type = COL_TCP_CWND, .header.name = " cwnd",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_SSTH, .header.name = " ssth",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_UACK, .header.name = " uack",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_SACK, .header.name = " sack",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_LOST, .header.name = " lost",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_RETR, .header.name = " retr",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_TRET, .header.name = " tret",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_FACK, .header.name = " fack",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_REOR, .header.name = " reor",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_BKOF, .header.name = " bkof",
	 .header.unit = " [#]", .state.visible = true},
	{.type = COL_TCP_RTT, .header.name = " rtt",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_TCP_RTTVAR, .header.name = " rttvar",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_TCP_RTO, .header.name = " rto",
	 .header.unit = " [ms]", .state.visible = true},
	{.type = COL_TCP_CA_STATE, .header.name = " ca state",
	 .header.unit = " ", .state.visible = true},
	{.type = COL_SMSS, .header.name = " smss",
	 .header.unit = "[B]", .state.visible = true},
	{.type = COL_PMTU, .header.name = " pmtu",
	 .header.unit = "[B]", .state.visible = true},
#ifdef DEBUG
	{.type = COL_STATUS, .header.name = " status",
	 .header.unit = " ", .state.visible = true}
#endif /* DEBUG */
};

/* Forward declarations */
static void prepare_flow(int id, xmlrpc_client *rpc_client);
static void fetch_reports(xmlrpc_client *);
static void report_flow(const struct _daemon* daemon, struct _report* report);
static void print_report(int id, int endpoint, struct _report* report);

static void usage(void)
{
	fprintf(stderr,
		"Usage %2$s [-h [s|g] | -v]\n"
		"      %2$s [general options] [flow options]\n\n"

		"%2$s allows you to generate traffic among hosts in your network.\n\n"

		"Miscellaneous:\n"
		"  -h           Show this help and exit\n"
		"  -h (s|g)     Show additional help for socket options or traffic generation\n"
		"  -v           Print version information and exit\n\n"

		"General options:\n"
#ifdef DEBUG
		"  -c interval,through,transac,blocks,rtt,iat,delay,kernel,status\n"
#else
		"  -c interval,through,transac,blocks,rtt,iat,delay,kernel\n"
#endif /* DEBUG */
		"               List of column groups to display in output.\n"
		"               (default: show all but blocks and delay)\n"
#ifdef DEBUG
		"  -d           Increase debugging verbosity. Add option multiple times to\n"
		"               be even more verbose.\n"
#endif /* DEBUG */
#ifdef HAVE_LIBPCAP
		"  -e PRE       Prepend prefix PRE to log and dump filename\n"
		"               (default: \"%1$s\")\n"
#else
		"  -e PRE       Prepend prefix PRE to log filename (default: \"%1$s\")\n"
#endif /* HAVE_LIBPCAP */
		"  -i #.#       Reporting interval, in seconds (default: 0.05s)\n"
		"  -l NAME      Use log filename NAME (default: timestamp)\n"
		"  -m           Report throughput in 2**20 bytes/s (default: 10**6 bit/s)\n"
		"  -n #         Number of test flows (default: 1)\n"
		"  -o           Overwrite existing log files (default: don't)\n"
		"  -p           Don't print symbolic values (like INT_MAX) instead of numbers\n"
		"  -q           Be quiet, do not log to screen (default: off)\n"
		"  -u (s|b)     Don't determine unit of Kernel TCP metrics automatically\n"
		"               Force unit to: s = segment, or b = byte\n"
		"  -w           Write output to logfile (default: off)\n\n"

		"Flow options:\n"
		"  Some of these options take the flow endpoint as argument, denoted by 'x' in\n"
		"  the option syntax. 'x' needs to be replaced with either 's' for the source\n"
		"  endpoint, 'd' for the destination endpoint or 'b' for both endpoints. To\n"
		"  specify different values for each endpoints, separate them by comma. For\n"
		"  instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"  and 4096 at the destination.\n\n"
		"  -A x         Use minimal response size needed for RTT calculation\n"
		"               (same as -G s=p,C,%3$d)\n"
		"  -B x=#       Set requested sending buffer, in bytes\n"
		"  -C x         Stop flow if it is experiencing local congestion\n"
		"  -D x=DSCP    DSCP value for TOS byte\n"
		"  -E           Enumerate bytes in payload instead of sending zeros\n"
		"  -F #{,#}     Flow options following this option apply only to flow #{,#}.\n"
		"               Useful in combination with -n to set specific options\n"
		"               for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"               to the second flow\n"
#ifdef HAVE_LIBGSL
		"  -G x=(q|p|g),(C|U|E|N|L|P|W),#1,[#2]\n"
#else
		"  -G x=(q|p|g),(C|U),#1,[#2]\n"
#endif /* HAVE_LIBGSL */
		"               Activate stochastic traffic generation and set parameters\n"
		"               according to the used distribution. See 'flowgrind -h g' for\n"
		"               additional information\n"
		"  -H x=HOST[/CONTROL[:PORT]]\n"
		"               Test from/to HOST. Optional argument is the address and port\n"
		"               for the CONTROL connection to the same host.\n"
		"               An endpoint that isn't specified is assumed to be localhost\n"
		"  -J #         Use random seed # (default: read /dev/urandom)\n"
		"  -L           Call connect() on test socket immediately before starting to\n"
		"               send data (late connect). If not specified the test connection\n"
		"               is established in the preparation phase before the test starts\n"
#ifdef HAVE_LIBPCAP
		"  -M x         dump traffic using libpcap\n"
#endif /* HAVE_LIBPCAP */
		"  -N           shutdown() each socket direction after test flow\n"
		"  -O x=OPT     Set socket option OPT on test socket. See 'flowgrind -h s' for\n"
		"               additional information\n"
		"  -P x         Do not iterate through select() to continue sending in case\n"
		"               block size did not suffice to fill sending queue (pushy)\n"
		"  -Q           Summarize only, no intermediated interval reports are\n"
		"               computed (quiet)\n"
		"  -R x=#.#(z|k|M|G)(b|B|o)\n"
		"               send at specified rate per second, where:\n"
		"               z = 2**0, k = 2**10, M = 2**20, G = 2**30\n"
		"               b = bits/s (default), B = bytes/s, o = blocks/s\n"
		"               (same as -G s=g,C,#)\n"
		"  -S x=#       Set block (message) size, in bytes (same as -G s=q,C,#)\n"
		"  -T x=#.#     Set flow duration, in seconds (default: s=10,d=0)\n"
		"  -U #         Set application buffer size, in bytes (default: 8192)\n"
		"               truncates values if used with stochastic traffic generation\n"
		"  -W x=#       Set requested receiver buffer (advertised window), in bytes\n"
		"  -Y x=#.#     Set initial delay before the host starts to send, in seconds\n"
/*		"  -Z x=#.#     Set amount of data to be send, in bytes (instead of -t)\n"*/,
		opt.log_filename_prefix, progname, MIN_BLOCK_SIZE
		);
	exit(EXIT_SUCCESS);
}

static void usage_sockopt(void)
{
	fprintf(stderr,
		"%s allows to set the following standard and non-standard socket options. \n\n"

		"All socket options take the flow endpoint as argument, denoted by 'x' in the\n"
		"option syntax. 'x' needs to be replaced with either 's' for the source endpoint,\n"
		"'d' for the destination endpoint or 'b' for both endpoints. To specify different\n"
		"values for each endpoints, separate them by comma. Moreover, it is possible to\n"
		"repeatedly pass the same endpoint in order to specify multiple socket options\n\n"

		"Standard socket options:\n", progname);
#ifdef TCP_CONGESTION
	FILE *fp;
	char buf1[1024];

	fprintf(stderr,
		"  -O x=TCP_CONGESTION=ALG\n"
		"               set congestion control algorithm ALG on test socket");

	/* TODO Do not call /sbin/sysctl. Use /proc/sys instead. It seems that
	 * we have to use a system call on FreeBSD since they deprecate
	 * procfs */

	/* Read and print available congestion control algorithms */
	sprintf(buf1, "/sbin/sysctl -n %s", SYSCTL_CC_AVAILABLE);
	fp = popen(buf1, "r");

	if (fp != NULL) {
		fprintf(stderr,
			".\n "
			"              Available algorithms are: ");
		char buf2[1024];
		while (fgets(buf2, 1024, fp) != NULL)
			fprintf(stderr, "%s", buf2);

		pclose(fp);
	}
#endif /* TCP_CONGESTION */
	fprintf(stderr,
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
		"               set SO_DEBUG and TCP_CORK as socket option at the source\n"
		);
	exit(EXIT_SUCCESS);
}

static void usage_trafgenopt(void)
{
	fprintf(stderr,
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
		"  -G x=(q|p|g),(C|U|E|N|L|P|W),#1,[#2]\n"
#else
		"  -G x=(q|p|g),(C|U),#1,[#2]\n"
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
#else
		"               advanced distributions are only available if compiled with libgsl\n"
#endif /* HAVE_LIBGSL */
		"  -U #         specify a cap for the calculated values for request and response\n"
		"               size (not needed for constant values or uniform distribution),\n"
		"               values over this cap are recalculated\n\n"

		"Examples:\n"
		"  -G s=q,C,40\n"
		"               use contant request size of 40 bytes\n"
		"  -G s=p,N,2000,50\n"
		"               use normal distributed response size with mean 2000 bytes and\n"
		"               variance 50\n"
		"  -G s=g,U,0.005,0.01\n"
		"               use uniform distributed interpacket gap with minimum 0.005s and\n"
		"               maximum 0.01s\n\n"

		"Notes: \n"
		"  - The man page contains more explained examples\n"
		"  - Using bidirectional traffic generation can lead to unexpected results\n"
		"  - Usage of -G in conjunction with -A, -R, -V is not recommended, as they\n"
		"    overwrite each other. -A, -R and -V exist as shortcut only\n",
		progname);
	exit(EXIT_SUCCESS);
}

static void usage_hint(void)
{
	fprintf(stderr, "Try '%s -h' for more information\n", progname);
	exit(EXIT_FAILURE);
}

static void sigint_handler(int sig)
{
	UNUSED_ARGUMENT(sig);

	DEBUG_MSG(LOG_ERR, "caught %s", strsignal(sig));

	if (sigint_caught == 0) {
		fprintf(stderr, "# received SIGINT, trying to gracefully "
			"close flows. Press CTRL+C again to force "
			"termination.\n");
		sigint_caught = 1;
	} else {
		exit(EXIT_FAILURE);
	}
}

static void init_general_options(void)
{
	opt.num_flows = 1;
	opt.reporting_interval = 0.05;
	opt.dont_log_stdout = false;
	opt.dont_log_logfile = true;
	opt.log_filename_prefix = "flowgrind-";
	opt.clobber = false;
	opt.mbyte = false;
	opt.symbolic = true;
	opt.force_unit = 0;
}

static void init_flow_options(void)
{
	for (int id = 0; id < MAX_FLOWS; id++) {

		cflow[id].proto = PROTO_TCP;

		for (int i = 0; i < 2; i++) {

			cflow[id].settings[i].requested_send_buffer_size = 0;
			cflow[id].settings[i].requested_read_buffer_size = 0;
			cflow[id].settings[i].delay[WRITE] = 0;
			cflow[id].settings[i].maximum_block_size = 8192;
			cflow[id].settings[i].request_trafgen_options.param_one = 8192;
			cflow[id].settings[i].response_trafgen_options.param_one = 0;
			cflow[id].settings[i].route_record = 0;
			strcpy(cflow[id].endpoint[i].test_address, "localhost");

			/* Default daemon is localhost, set in parse_cmdline */
			cflow[id].endpoint[i].daemon = 0;

			cflow[id].settings[i].pushy = 0;
			cflow[id].settings[i].cork = 0;
			cflow[id].settings[i].cc_alg[0] = 0;
			cflow[id].settings[i].elcn = 0;
			cflow[id].settings[i].lcd = 0;
			cflow[id].settings[i].mtcp = 0;
			cflow[id].settings[i].nonagle = 0;
			cflow[id].settings[i].traffic_dump = 0;
			cflow[id].settings[i].so_debug = 0;
			cflow[id].settings[i].dscp = 0;
			cflow[id].settings[i].ipmtudiscover = 0;

			cflow[id].settings[i].num_extra_socket_options = 0;
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
		if(rc == -1) {
			error(ERR_FATAL, "read /dev/urandom failed: %s", strerror(errno));
		}
	}
}

static void open_logfile(void)
{
	struct timespec now = {0, 0};
	static char buf[60] = "";
	int len = 0;

	if (opt.dont_log_logfile)
		return;

	if (opt.log_filename) {
		if (!opt.log_filename_prefix || strcmp(opt.log_filename_prefix, "log-") == 0)
			log_filename = opt.log_filename;
		else {
			log_filename = malloc(strlen(opt.log_filename_prefix) +
						strlen(opt.log_filename) + 2);
			strcpy(log_filename, opt.log_filename_prefix);
			strcat(log_filename, opt.log_filename);
		}
	} else {
		gettime(&now);
		len = strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S", localtime(&now.tv_sec));
		log_filename = malloc(strlen(opt.log_filename_prefix) + len + 1 + strlen(".log") );
		strcpy(log_filename, opt.log_filename_prefix);
		strcat(log_filename, buf);
		strcat(log_filename, ".log");
	}

	DEBUG_MSG(LOG_NOTICE, "logging to \"%s\"", log_filename);

	if (!opt.clobber && access(log_filename, R_OK) == 0)
		error(ERR_FATAL, "log file exists");

	log_stream = fopen(log_filename, "w");
	if (log_stream == NULL)
		error(ERR_FATAL, "could not open logfile %s", log_filename);
}

static void close_logfile(void)
{
	if (opt.dont_log_logfile)
		return;

	if (fclose(log_stream) == -1)
		error(ERR_FATAL, "could not close logfile %s", log_filename);
}

static void log_output(const char *msg)
{
	if (!opt.dont_log_stdout) {
		printf("%s", msg);
		fflush(stdout);
	}
	if (!opt.dont_log_logfile) {
		fprintf(log_stream, "%s", msg);
		fflush(log_stream);
	}
}

static void die_if_fault_occurred(xmlrpc_env *env)
{
    if (env->fault_occurred)
	error(ERR_FATAL, "XML-RPC Fault: %s (%d)\n", env->fault_string,
	      env->fault_code);
}

/* creates an xmlrpc_client for connect to server, uses global env rpc_env */
static void prepare_xmlrpc_client(xmlrpc_client **rpc_client) {
	struct xmlrpc_clientparms clientParms;
	size_t clientParms_cpsize = XMLRPC_CPSIZE(transport);

	/* Since version 1.21 xmlrpclib will automatically generate a
	 * rather long user_agent, we will do a lot of RPC calls so let's
	 * spare some bytes and omit this header */
#ifdef HAVE_STRUCT_XMLRPC_CURL_XPORTPARMS_DONT_ADVERTISE
	struct xmlrpc_curl_xportparms curlParms;
	memset(&curlParms, 0, sizeof(curlParms));

	curlParms.dont_advertise = 1;

	clientParms.transportparmsP    = &curlParms;
	clientParms.transportparm_size = XMLRPC_CXPSIZE(dont_advertise);
	clientParms_cpsize = XMLRPC_CPSIZE(transportparm_size);
#endif /* HAVE_STRUCT_XMLRPC_CURL_XPORTPARMS_DONT_ADVERTISE */

	/* Force usage of curl transport, we require it in configure script anyway
	 * and at least FreeBSD 9.1 will use libwww otherwise */
	clientParms.transport = "curl";

	DEBUG_MSG(LOG_WARNING, "prepare xmlrpc client");
	xmlrpc_client_create(&rpc_env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION,
			     &clientParms, clientParms_cpsize, rpc_client);
}

/* Checks that all nodes use our flowgrind version */
static void check_version(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;
	char mismatch = 0;

	for (unsigned int j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;

		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j].server_url,
					"get_version", &resultP, "()");
		if ((rpc_env.fault_occurred) && (strcasestr(rpc_env.fault_string,"response code is 400"))) {
			fprintf(stderr, "FATAL: node %s could not parse request.\n "
				"You are probably trying to use a numeric IPv6 "
				"address and the node's libxmlrpc is too old, please upgrade!\n",
				unique_servers[j].server_url);
		}
		die_if_fault_occurred(&rpc_env);

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
				fprintf(stderr, "Warning: Node %s uses version %s\n", unique_servers[j].server_url, version);
			}
			unique_servers[j].api_version = api_version;
			strncpy(unique_servers[j].os_name, os_name, 256);
			strncpy(unique_servers[j].os_release, os_release, 256);
			free(version);
			free(os_name);
			free(os_release);
			xmlrpc_DECREF(resultP);
		}
	}

	if (mismatch) {
		fprintf(stderr, "Our version is %s\n\nContinuing in 10 seconds.\n", FLOWGRIND_VERSION);
		sleep(10);
	}
}

/* Checks that all nodes are currently idle */
static void check_idle(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;

	for (unsigned int j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;

		xmlrpc_client_call2f(&rpc_env, rpc_client,
				     unique_servers[j].server_url,
				     "get_status", &resultP, "()");
		die_if_fault_occurred(&rpc_env);

		if (resultP) {
			int started;
			int num_flows;

			xmlrpc_decompose_value(&rpc_env, resultP,
					       "{s:i,s:i,*}", "started",
					       &started, "num_flows",
					       &num_flows);
			die_if_fault_occurred(&rpc_env);

			if (started || num_flows)
				error(ERR_FATAL, "node %s is busy. %d flows, "
				      "started=%d\n",
				      unique_servers[j].server_url,
				      num_flows, started);

			xmlrpc_DECREF(resultP);
		}
	}
}

/* enumerate over prepare_flow */
static void prepare_flows(xmlrpc_client *rpc_client)
{
	/* prepare all flows */
	for (int id = 0; id < opt.num_flows; id++) {
		if (sigint_caught)
			return;
		prepare_flow(id, rpc_client);
	}

	/* prepare headline */
	char headline[200];
	int rc;
	struct utsname me;
	time_t start_ts;
	char start_ts_buffer[26];

	rc = uname(&me);
	start_ts = time(NULL);
	ctime_r(&start_ts, start_ts_buffer);
	start_ts_buffer[24] = '\0';
	snprintf(headline, sizeof(headline),
		 "# %s: controlling host = %s, number of flows = %d, "
		 "reporting interval = %.2fs, [through] = %s (%s)\n",
		 (start_ts == -1 ? "(time(NULL) failed)" : start_ts_buffer),
		 (rc == -1 ? "(unknown)" : me.nodename),
		 opt.num_flows, opt.reporting_interval,
		 (opt.mbyte ? "2**20 bytes/second": "10**6 bit/second"),
		 FLOWGRIND_VERSION);
	log_output(headline);

	/* prepare column headers */

	/* We set the unit of the kernel TCP metrics to bytes if either the
	 * user forces to use bytes or the source of the first flow is not
	 * Linux and the user forces not to uses segments */
	if (opt.force_unit == BYTE_BASED ||
	    (opt.force_unit != SEGMENT_BASED &&
	     strcmp(unique_servers[0].os_name, "Linux"))) {
		column_info[COL_TCP_CWND].header.unit = " [B]";
		column_info[COL_TCP_SSTH].header.unit = " [B]";
		column_info[COL_TCP_UACK].header.unit = " [B]";
		column_info[COL_TCP_SACK].header.unit = " [B]";
		column_info[COL_TCP_LOST].header.unit = " [B]";
		column_info[COL_TCP_RETR].header.unit = " [B]";
		column_info[COL_TCP_TRET].header.unit = " [B]";
		column_info[COL_TCP_FACK].header.unit = " [B]";
		column_info[COL_TCP_REOR].header.unit = " [B]";
		column_info[COL_TCP_BKOF].header.unit = " [B]";
	}
}

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
		cflow[id].endpoint[DESTINATION].daemon->server_url,
		"add_flow_destination", &resultP,
		"("
		"{s:s}"
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
#ifdef HAVE_LIBPCAP
		"{s:s}"
#endif /* HAVE_LIBPCAP */
		"{s:i,s:A}"
		")",

		/* general flow settings */
		"bind_address", cflow[id].endpoint[DESTINATION].test_address,

		"write_delay", cflow[id].settings[DESTINATION].delay[WRITE],
		"write_duration", cflow[id].settings[DESTINATION].duration[WRITE],
		"read_delay", cflow[id].settings[SOURCE].delay[WRITE],
		"read_duration", cflow[id].settings[SOURCE].duration[WRITE],
		"reporting_interval", cflow[id].summarize_only ? 0 : opt.reporting_interval,

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
#ifdef HAVE_LIBPCAP
		"filename_prefix", opt.log_filename_prefix,
#endif /* HAVE_LIBPCAP */
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
		cflow[id].endpoint[SOURCE].daemon->server_url,
		"add_flow_source", &resultP,
		"("
		"{s:s}"
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
#ifdef HAVE_LIBPCAP
		"{s:s}"
#endif /* HAVE_LIBPCAP */
		"{s:i,s:A}"
		"{s:s,s:i,s:i}"
		")",

		/* general flow settings */
		"bind_address", cflow[id].endpoint[SOURCE].test_address,

		"write_delay", cflow[id].settings[SOURCE].delay[WRITE],
		"write_duration", cflow[id].settings[SOURCE].duration[WRITE],
		"read_delay", cflow[id].settings[DESTINATION].delay[WRITE],
		"read_duration", cflow[id].settings[DESTINATION].duration[WRITE],
		"reporting_interval", cflow[id].summarize_only ? 0 : opt.reporting_interval,

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
#ifdef HAVE_LIBPCAP
		"filename_prefix", opt.log_filename_prefix,
#endif /* HAVE_LIBPCAP */
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

/* start flows */
static void grind_flows(xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP = 0;

	struct timespec lastreport_end;
	struct timespec lastreport_begin;
	struct timespec now;

	gettime(&lastreport_end);
	gettime(&lastreport_begin);
	gettime(&now);

	for (unsigned int j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;
		DEBUG_MSG(LOG_ERR, "starting flow on server %d", j);
		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j].server_url,
			"start_flows", &resultP,
			"({s:i})", "start_timestamp", now.tv_sec + 2);
		die_if_fault_occurred(&rpc_env);
		if (resultP)
			xmlrpc_DECREF(resultP);
	}

	active_flows = opt.num_flows;

	while (!sigint_caught) {

		if ( time_diff_now(&lastreport_begin) <  opt.reporting_interval ) {
			usleep(opt.reporting_interval - time_diff(&lastreport_begin,&lastreport_end) );
			continue;
		}
		gettime(&lastreport_begin);
		fetch_reports(rpc_client);
		gettime(&lastreport_end);

		if (active_flows < 1)
			/* All flows have ended */
			return;
	}
}

/* Poll the daemons for reports */
static void fetch_reports(xmlrpc_client *rpc_client) {

	xmlrpc_value * resultP = 0;

	for (unsigned int j = 0; j < num_unique_servers; j++) {

		int array_size, has_more;
		xmlrpc_value *rv = 0;

has_more_reports:

		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j].server_url,
			"get_reports", &resultP, "()");
		if (rpc_env.fault_occurred) {
			fprintf(stderr, "XML-RPC Fault: %s (%d)\n",
			rpc_env.fault_string, rpc_env.fault_code);
			continue;
		}

		if (!resultP)
			continue;

		array_size = xmlrpc_array_size(&rpc_env, resultP);
		if (!array_size) {
			fprintf(stderr, "Empty array in get_reports reply\n");
			continue;
		}

		xmlrpc_array_read_item(&rpc_env, resultP, 0, &rv);
		xmlrpc_read_int(&rpc_env, rv, &has_more);
		if (rpc_env.fault_occurred) {
			fprintf(stderr, "XML-RPC Fault: %s (%d)\n",
			rpc_env.fault_string, rpc_env.fault_code);
			xmlrpc_DECREF(rv);
			continue;
		}
		xmlrpc_DECREF(rv);

		for (int i = 1; i < array_size; i++) {
			xmlrpc_value *rv = 0;

			xmlrpc_array_read_item(&rpc_env, resultP, i, &rv);
			if (rv) {
				struct _report report;
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
					"{s:i,s:i,s:i,s:i,s:i,s:i,*}" /* timeval */
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
#else
				report.bytes_read = (uint32_t)bytes_read_low;
				report.bytes_written = (uint32_t)bytes_written_low;
#endif /* HAVE_UNSIGNED_LONG_LONG_INT */

				/* Kernel metrics (tcp_info). Other OS than Linux may not send
				 * valid values here, for the moment we don't care and handle
				 * this in the output/display routines */
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

				report_flow(&unique_servers[j], &report);
			}
		}
		xmlrpc_DECREF(resultP);

		if (has_more)
			goto has_more_reports;
	}
}

/* This function allots an report received from one daemon (identified
 * by server_url)  to the proper flow */
static void report_flow(const struct _daemon* daemon, struct _report* report)
{
	const char* server_url = daemon->server_url;
	int endpoint;
	int id;
	struct _cflow *f;

	/* Get matching flow for report */
	/* TODO Maybe just use compare daemon pointers? */
	for (id = 0; id < opt.num_flows; id++) {
		f = &cflow[id];

		for (endpoint = 0; endpoint < 2; endpoint++) {
			if (f->endpoint_id[endpoint] == report->id &&
			    !strcmp(server_url, f->endpoint[endpoint].daemon->server_url))
				goto exit_outer_loop;
		}
	}
exit_outer_loop:

	if (id >= opt.num_flows) {
		DEBUG_MSG(LOG_ERR, "Got report from nonexistent flow, ignoring");
		return;
	}

	if (f->start_timestamp[endpoint].tv_sec == 0) {
		f->start_timestamp[endpoint] = report->begin;
	}

	if (report->type == TOTAL) {
		DEBUG_MSG(LOG_DEBUG, "received final report for flow %d", id);
		/* Final report, keep it for later */
		free(f->final_report[endpoint]);
		f->final_report[endpoint] = malloc(sizeof(struct _report));
		*f->final_report[endpoint] = *report;

		if (!f->finished[endpoint]) {
			f->finished[endpoint] = 1;
			if (f->finished[1 - endpoint]) {
				active_flows--;
				DEBUG_MSG(LOG_DEBUG, "remaining active flows: %d", active_flows);
#ifdef DEBUG
				assert(active_flows >= 0);
#endif /* DEBUG */
			}
		}
		return;
	}

	print_report(id, endpoint, report);
}

static void close_flows(void)
{
	xmlrpc_env env;
	xmlrpc_client *client;


	for (unsigned int id = 0; id < opt.num_flows; id++) {
		DEBUG_MSG(LOG_WARNING, "closing flow %d.", id);

		if (cflow[id].finished[SOURCE] && cflow[id].finished[DESTINATION])
			continue;

		/* We use new env and client, old one might be in fault condition */
		xmlrpc_env_init(&env);
		xmlrpc_client_create(&env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &client);
		die_if_fault_occurred(&env);
		xmlrpc_env_clean(&env);

		for (unsigned int endpoint = 0; endpoint < 2; endpoint++) {
			xmlrpc_value * resultP = 0;

			if (cflow[id].endpoint_id[endpoint] == -1 ||
					cflow[id].finished[endpoint]) {
				/* Endpoint does not need closing */
				continue;
			}

			cflow[id].finished[endpoint] = 1;

			xmlrpc_env_init(&env);

			xmlrpc_client_call2f(&env, client,
				cflow[id].endpoint[endpoint].daemon->server_url,
				"stop_flow", &resultP, "({s:i})", "flow_id", cflow[id].endpoint_id[endpoint]);
			if (resultP)
				xmlrpc_DECREF(resultP);

			xmlrpc_env_clean(&env);
		}


		if (active_flows > 0)
			active_flows--;

		xmlrpc_client_destroy(client);
		DEBUG_MSG(LOG_WARNING, "closed flow %d.", id);
	}
}

/* New output determines the number of digits before the comma */
static int det_output_column_size(double value)
{
	int i = 1;
	double dez = 10.0;

	if (value < 0)
		i++;
	while ((abs(value) / (dez - 1.0)) > 1.0) {
		i++;
		dez *= 10;
	}
	return i;
}

/* produces the string command for printf for the right number of digits and decimal part */
static char *outStringPart(int digits, int decimalPart)
{
	static char outstr[30] = {0};

	sprintf(outstr, "%%%d.%df", digits, decimalPart);

	return outstr;
}

static int createOutputColumn(char *strHead1Row, char *strHead2Row,
			      char *strDataRow, int column_id, double value,
			      int numDigitsDecimalPart, int *columnWidthChanged)
{
	unsigned int maxTooLongColumns = opt.num_flows * 5;
	int lengthData = 0;
	int lengthHead = 0;
	unsigned int columnSize = 0;
	char tempBuffer[50];
	struct _column *column = &column_info[column_id];
	char* number_formatstring;

	if (!column->state.visible)
		return 0;

	/* get max columnsize */
	if (opt.symbolic) {
		switch ((unsigned int)value) {
		case INT_MAX:
			lengthData = strlen("INT_MAX");
			break;
		case USHRT_MAX:
			lengthData = strlen("USHRT_MAX");
			break;
		case UINT_MAX:
			lengthData = strlen("UINT_MAX");
			break;
		default:
			lengthData = det_output_column_size(value) +
				numDigitsDecimalPart + 1;
		}
	} else {
		lengthData = det_output_column_size(value) +
			numDigitsDecimalPart + 1;
	}
	/* leading space */
	lengthData++;

	/* decimal point if necessary */
	if (numDigitsDecimalPart)
		lengthData++;

	lengthHead = MAX(strlen(column->header.name),
			 strlen(column->header.unit));
	columnSize = MAX(lengthData, lengthHead);

	/* check if columnsize has changed */
	if (column->state.last_width < columnSize) {
		/* column too small */
		*columnWidthChanged = 1;
		column->state.last_width = columnSize;
		column->state.oversized = 0;
	} else if (column->state.last_width > 1 + columnSize) {
		/* column too big */
		if (column->state.oversized >= maxTooLongColumns) {
			/* column too big for quite a while */
			*columnWidthChanged = 1;
			column->state.last_width = columnSize;
			column->state.oversized = 0;
		} else {
			(column->state.oversized)++;
		}
	} else {
		/* This size was needed, keep it */
		column->state.oversized = 0;
	}
	number_formatstring = outStringPart(column->state.last_width,
			                    numDigitsDecimalPart);

	/* create columns */

	/* output text for symbolic numbers */
	if (opt.symbolic) {
		switch ((int)value) {
		case INT_MAX:
			for (unsigned int a = lengthData;
			     a < MAX(columnSize, column->state.last_width);
			     a++)
				strcat(strDataRow, " ");
			strcat(strDataRow, " INT_MAX");
			break;
		case USHRT_MAX:
			for (unsigned int a = lengthData;
			     a < MAX(columnSize, column->state.last_width);
			     a++)
				strcat(strDataRow, " ");
			strcat(strDataRow, " USHRT_MAX");
			break;
		case UINT_MAX:
			for (unsigned int a = lengthData;
			     a < MAX(columnSize, column->state.last_width);
			     a++)
				strcat(strDataRow, " ");
			strcat(strDataRow, " UINT_MAX");
			break;
		default: /* number */
			sprintf(tempBuffer, number_formatstring, value);
			strcat(strDataRow, tempBuffer);
		}
	} else {
		sprintf(tempBuffer, number_formatstring, value);
		strcat(strDataRow, tempBuffer);
	}
	/* 1st header row */
	for (unsigned int a = column->state.last_width;
	     a > strlen(column->header.name); a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, column->header.name);

	/* 2nd header row */
	for (unsigned int a = column->state.last_width;
	     a > strlen(column->header.unit); a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, column->header.unit);

	return 0;
}

static int createOutputColumn_str(char *strHead1Row, char *strHead2Row,
				  char *strDataRow, int column_id, char* value,
				  int *columnWidthChanged)
{

	unsigned int maxTooLongColumns = opt.num_flows * 5;
	int lengthData = 0;
	int lengthHead = 0;
	unsigned int columnSize = 0;
	struct _column *column = &column_info[column_id];

	if (!column->state.visible)
		return 0;

	/* get max columnsize */
	lengthData = strlen(value);
	lengthHead = MAX(strlen(column->header.name),
			 strlen(column->header.unit));
	columnSize = MAX(lengthData, lengthHead) + 1;

	/* check if columnsize has changed */
	if (column->state.last_width < columnSize) {
		/* column too small */
		*columnWidthChanged = 1;
		column->state.last_width = columnSize;
		column->state.oversized = 0;
	} else if (column->state.last_width > 1 + columnSize) {
		/* column too big */
		if (column->state.oversized >= maxTooLongColumns) {
			/* column too big for quite a while */
			*columnWidthChanged = 1;
			column->state.last_width = columnSize;
			column->state.oversized = 0;
		} else {
			(column->state.oversized)++;
		}
	} else {
		/* This size was needed, keep it */
		column->state.oversized = 0;
	}

	/* create columns */
	for (unsigned int a = lengthData+1; a < columnSize; a++)
		strcat(strDataRow, " ");
	strcat(strDataRow, value);

	/* 1st header row */
	for (unsigned int a = column->state.last_width;
	     a > strlen(column->header.name) + 1; a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, column->header.name);

	/* 2nd header Row */
	for (unsigned int a = column->state.last_width;
	     a > strlen(column->header.unit) + 1; a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, column->header.unit);

	return 0;
}

/* Output a single report (with header if width has changed */
static char *createOutput(char hash, int id, int type, double begin, double end,
		   double throughput, double transac,
		   unsigned int request_blocks, unsigned int response_blocks,
		   double rttmin, double rttavg, double rttmax,
		   double iatmin, double iatavg, double iatmax,
		   double delaymin, double delayavg, double delaymax,
		   unsigned int cwnd, unsigned int ssth, unsigned int uack,
		   unsigned int sack, unsigned int lost, unsigned int reor,
		   unsigned int retr, unsigned int tret, unsigned int fack,
		   double linrtt, double linrttvar, double linrto,
		   unsigned int backoff, int ca_state, int snd_mss,  int pmtu,
		   char* status)
{
	int columnWidthChanged = 0;
	static int counter = 0;

	/* Create Row + Header */
	char dataString[250];
	char headerString1[250];
	char headerString2[250];
	static char outputString[1000];
	char tmp[100];

	/* output string
	param # + flow_id */
	if (hash)
		sprintf(dataString, "#");

	if (type)
		sprintf(dataString, "D%3d", id);
	else
		sprintf(dataString, "S%3d", id);

	strcpy(headerString1, column_info[COL_FLOW_ID].header.name);
	strcpy(headerString2, column_info[COL_FLOW_ID].header.unit);

	if (ca_state == TCP_CA_Open)
		strcpy(tmp, "open");
	else if (ca_state == TCP_CA_Disorder)
		strcpy(tmp, "disorder");
	else if (ca_state == TCP_CA_CWR)
		strcpy(tmp, "cwr");
	else if (ca_state == TCP_CA_Recovery)
		strcpy(tmp, "recover");
	else if (ca_state == TCP_CA_Loss)
		strcpy(tmp, "loss");
	else
		strcpy(tmp, "unknown");

	createOutputColumn(headerString1, headerString2, dataString,
			   COL_BEGIN, begin, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_END, end, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_THROUGH, throughput, 6, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TRANSAC, transac, 2, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_BLOCK_REQU, request_blocks, 0,
			   &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_BLOCK_RESP, response_blocks, 0,
			   &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_RTT_MIN, rttmin, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_RTT_AVG, rttavg, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_RTT_MAX, rttmax, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_IAT_MIN, iatmin, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_IAT_AVG, iatavg, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_IAT_MAX, iatmax, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_DLY_MIN, delaymin, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_DLY_AVG, delayavg, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_DLY_MAX, delaymax, 3, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_CWND, cwnd, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_SSTH, ssth, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_UACK, uack, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_SACK, sack, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_LOST, lost, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_RETR, retr, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_TRET, tret, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_FACK, fack, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_REOR, reor, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_BKOF, backoff, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_RTT, linrtt, 1, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_RTTVAR, linrttvar, 1, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_TCP_RTO, linrto, 1, &columnWidthChanged);
	createOutputColumn_str(headerString1, headerString2, dataString,
			       COL_TCP_CA_STATE, tmp, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_SMSS, snd_mss, 0, &columnWidthChanged);
	createOutputColumn(headerString1, headerString2, dataString,
			   COL_PMTU, pmtu, 0, &columnWidthChanged);
#ifdef DEBUG
	createOutputColumn_str(headerString1, headerString2, dataString,
			       COL_STATUS, status, &columnWidthChanged);
#else
	UNUSED_ARGUMENT(status);
#endif /* DEBUG */

	/* newline */
	strcat(headerString1, "\n");
	strcat(headerString2, "\n");
	strcat(dataString, "\n");
	/* output string end */
	if (columnWidthChanged > 0 || (counter % 25) == 0) {
		strcpy(outputString, headerString1);
		strcat(outputString, headerString2);
		strcat(outputString, dataString);
	} else {
		strcpy(outputString, dataString);
	}
	counter++;

	return outputString;
}

static void print_report(int id, int endpoint, struct _report* r)
{

	double min_rtt = r->rtt_min;
	double max_rtt = r->rtt_max;
	double avg_rtt;
	double min_iat = r->iat_min;
	double max_iat = r->iat_max;
	double avg_iat;
	double min_delay = r->delay_min;
	double max_delay = r->delay_max;
	double avg_delay;

	char comment_buffer[100] = " (";
	char report_buffer[4000] = "";

	#define COMMENT_CAT(s) do { if (strlen(comment_buffer) > 2) \
		strncat(comment_buffer, "/", sizeof(comment_buffer)-1); \
		strncat(comment_buffer, (s), sizeof(comment_buffer)-1); }while(0);

	if (r->response_blocks_read && r->rtt_sum)
		avg_rtt = r->rtt_sum / (double)(r->response_blocks_read);
	else
		min_rtt = max_rtt = avg_rtt = INFINITY;

	if (r->request_blocks_read && r->iat_sum)
		avg_iat = r->iat_sum / (double)(r->request_blocks_read);
	else
		min_iat = max_iat = avg_iat = INFINITY;

	if (r->request_blocks_read && r->delay_sum)
		avg_delay = r->delay_sum / (double)(r->request_blocks_read);
	else
		min_delay = max_delay = avg_delay = INFINITY;

#ifdef DEBUG
	if (cflow[id].finished[endpoint])
		COMMENT_CAT("stopped")
	else {
		char tmp[2];

		/* Write status */
		switch (r->status & 0xFF)
		{
			case 'd':
			case 'l':
			case 'o':
			case 'f':
			case 'c':
			case 'n':
				tmp[0] = (char)(r->status & 0xFF);
				tmp[1] = 0;
				COMMENT_CAT(tmp);
				break;
			default:
				COMMENT_CAT("u");
				break;
		}

		/* Read status */
		switch (r->status >> 8)
		{
			case 'd':
			case 'l':
			case 'o':
			case 'f':
			case 'c':
			case 'n':
				tmp[0] = (char)(r->status >> 8);
				tmp[1] = 0;
				COMMENT_CAT(tmp);
				break;
			default:
				COMMENT_CAT("u");
				break;
		}
	}
#endif /* DEBUG */
	strncat(comment_buffer, ")", sizeof(comment_buffer) - strlen(comment_buffer) - 1);
	if (strlen(comment_buffer) == 2)
		comment_buffer[0] = '\0';

	char rep_string[4000];
	double diff_first_last =
		time_diff(&cflow[id].start_timestamp[endpoint], &r->begin);
	double diff_first_now =
		time_diff(&cflow[id].start_timestamp[endpoint], &r->end);
	double thruput = scale_thruput((double)r->bytes_written /
				       (diff_first_now - diff_first_last));
	double transac = (double)r->response_blocks_read /
			 (diff_first_now - diff_first_last);

	strcpy(rep_string,
	       createOutput(0, id, endpoint, diff_first_last, diff_first_now,
		            thruput, transac,
			    (unsigned int)r->request_blocks_written,
			    (unsigned int)r->response_blocks_written,
			    min_rtt * 1e3, avg_rtt * 1e3, max_rtt * 1e3,
			    min_iat * 1e3, avg_iat * 1e3, max_iat * 1e3,
			    min_delay * 1e3, avg_delay * 1e3, max_delay * 1e3,
			    (unsigned int)r->tcp_info.tcpi_snd_cwnd,
			    (unsigned int)r->tcp_info.tcpi_snd_ssthresh,
			    (unsigned int)r->tcp_info.tcpi_unacked,
			    (unsigned int)r->tcp_info.tcpi_sacked,
			    (unsigned int)r->tcp_info.tcpi_lost,
			    (unsigned int)r->tcp_info.tcpi_reordering,
			    (unsigned int)r->tcp_info.tcpi_retrans,
			    (unsigned int)r->tcp_info.tcpi_retransmits,
			    (unsigned int)r->tcp_info.tcpi_fackets,
			    (double)r->tcp_info.tcpi_rtt / 1e3,
			    (double)r->tcp_info.tcpi_rttvar / 1e3,
			    (double)r->tcp_info.tcpi_rto / 1e3,
			    (unsigned int)r->tcp_info.tcpi_backoff,
			    r->tcp_info.tcpi_ca_state,
			    (unsigned int)r->tcp_info.tcpi_snd_mss,
			    r->pmtu, comment_buffer));
	strncpy(report_buffer, rep_string, sizeof(report_buffer));
	report_buffer[sizeof(report_buffer) - 1] = 0;
	log_output(report_buffer);
}

static char *guess_topology (int mtu)
{
	/* Mapping of common MTU sizes to network technologies */
	struct _mtu_hint {
		int mtu;
		char *topology;
	};

	static const struct _mtu_hint mtu_hints[] = {
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

	for (unsigned int i = 0;
	     i < sizeof(mtu_hints) / sizeof(struct _mtu_hint); i++)
		if (mtu == mtu_hints[i].mtu)
			return mtu_hints[i].topology;
	return "unknown";
}

static void report_final(void)
{
	char header_buffer[600] = "";
	char header_nibble[600] = "";

	for (int id = 0; id < opt.num_flows; id++) {

#define CAT(fmt, args...) do {\
	snprintf(header_nibble, sizeof(header_nibble), fmt, ##args); \
	strncat(header_buffer, header_nibble, sizeof(header_buffer) - strlen(header_buffer) - 1); } while (0)
#define CATC(fmt, args...) CAT(", "fmt, ##args)

		log_output("\n");

		for (int endpoint = 0; endpoint < 2; endpoint++) {
			header_buffer[0] = 0;

			CAT("#% 4d %s:", id, endpoint ? "D" : "S");

			CAT(" %s", cflow[id].endpoint[endpoint].test_address);
			if (strcmp(cflow[id].endpoint[endpoint].daemon->server_name,
				   cflow[id].endpoint[endpoint].test_address) != 0)
				CAT("/%s", cflow[id].endpoint[endpoint].daemon->server_name);
			if (cflow[id].endpoint[endpoint].daemon->server_port != DEFAULT_LISTEN_PORT)
				CAT(":%d", cflow[id].endpoint[endpoint].daemon->server_port);
			CAT(" (%s %s)", cflow[id].endpoint[endpoint].daemon->os_name,
					cflow[id].endpoint[endpoint].daemon->os_release);

			CATC("random seed: %u", cflow[id].random_seed);

			if (cflow[id].final_report[endpoint]) {

				CATC("sbuf = %u/%u, rbuf = %u/%u (real/req)",
					cflow[id].endpoint[endpoint].send_buffer_size_real,
					cflow[id].settings[endpoint].requested_send_buffer_size,
					cflow[id].endpoint[endpoint].receive_buffer_size_real,
					cflow[id].settings[endpoint].requested_read_buffer_size);


				/* SMSS, Path MTU, Interface MTU */
				if (cflow[id].final_report[endpoint]->tcp_info.tcpi_snd_mss > 0)
					CATC("SMSS = %d", cflow[id].final_report[endpoint]->tcp_info.tcpi_snd_mss);
				if (cflow[id].final_report[endpoint]->pmtu > 0)
					CATC("Path MTU = %d", cflow[id].final_report[endpoint]->pmtu);
				if (cflow[id].final_report[endpoint]->imtu > 0)
					CATC("Interface MTU = %d (%s)", cflow[id].final_report[endpoint]->imtu,
						guess_topology(cflow[id].final_report[endpoint]->imtu));

				if (cflow[id].settings[endpoint].cc_alg[0])
					CATC("cc = %s", cflow[id].settings[endpoint].cc_alg);


				double thruput_read, thruput_written, transactions_per_sec;
				double report_time, report_delta_write = 0, report_delta_read = 0, duration_read, duration_write;

				/* calculate time */
				report_time = time_diff(&cflow[id].final_report[endpoint]->begin, &cflow[id].final_report[endpoint]->end);
				if (cflow[id].settings[endpoint].duration[WRITE])
					report_delta_write = report_time - cflow[id].settings[endpoint].duration[WRITE] - cflow[id].settings[endpoint].delay[SOURCE];
				if (cflow[id].settings[endpoint].duration[READ])
					report_delta_read = report_time - cflow[id].settings[endpoint].duration[READ] - cflow[id].settings[endpoint].delay[DESTINATION];

				/* calculate delta target vs real report time */
				duration_write = cflow[id].settings[endpoint].duration[WRITE] + report_delta_write;
				duration_read = cflow[id].settings[endpoint].duration[READ] + report_delta_read;

				if (cflow[id].settings[endpoint].duration[WRITE])
					CATC("flow duration = %.3fs/%.3fs (real/req)",
						duration_write,
						cflow[id].settings[endpoint].duration[WRITE]);

				if (cflow[id].settings[endpoint].delay[WRITE])
				       CATC("write delay = %.3fs", cflow[id].settings[endpoint].delay[WRITE]);

				if (cflow[id].settings[endpoint].delay[READ])
				       CATC("read delay = %.3fs", cflow[id].settings[endpoint].delay[READ]);

				/* calucate throughput */
				thruput_read = cflow[id].final_report[endpoint]->bytes_read / MAX(duration_read, duration_write);
				if (isnan(thruput_read))
					thruput_read = 0.0;

				thruput_written = cflow[id].final_report[endpoint]->bytes_written / MAX(duration_read, duration_write);
				if (isnan(thruput_written))
					thruput_written = 0.0;

				thruput_read = scale_thruput(thruput_read);
				thruput_written = scale_thruput(thruput_written);

				if (opt.mbyte)
					CATC("through = %.6f/%.6fMbyte/s (out/in)", thruput_written, thruput_read);
				else
					CATC("through = %.6f/%.6fMbit/s (out/in)", thruput_written, thruput_read);

				/* transactions */

				transactions_per_sec = cflow[id].final_report[endpoint]->response_blocks_read / MAX(duration_read, duration_write);
				if (isnan(transactions_per_sec))
					transactions_per_sec = 0.0;
				if (transactions_per_sec)
					CATC("transactions/s = %.2f", transactions_per_sec);

				/* blocks */
				if (cflow[id].final_report[endpoint]->request_blocks_written || cflow[id].final_report[endpoint]->request_blocks_read)
					CATC("request blocks = %u/%u (out/in)",
					cflow[id].final_report[endpoint]->request_blocks_written,
					cflow[id].final_report[endpoint]->request_blocks_read);

				if (cflow[id].final_report[endpoint]->response_blocks_written || cflow[id].final_report[endpoint]->response_blocks_read)
					CATC("response blocks = %u/%u (out/in)",
					cflow[id].final_report[endpoint]->response_blocks_written,
					cflow[id].final_report[endpoint]->response_blocks_read);

				/* rtt */
				if (cflow[id].final_report[endpoint]->response_blocks_read) {
					double min_rtt = cflow[id].final_report[endpoint]->rtt_min;
					double max_rtt = cflow[id].final_report[endpoint]->rtt_max;
					double avg_rtt = cflow[id].final_report[endpoint]->rtt_sum /
						(double)(cflow[id].final_report[endpoint]->response_blocks_read);
					CATC("RTT = %.3f/%.3f/%.3f (min/avg/max)",
					     min_rtt*1e3, avg_rtt*1e3, max_rtt*1e3);
				}

				/* iat */
				if (cflow[id].final_report[endpoint]->request_blocks_read) {
					double min_iat = cflow[id].final_report[endpoint]->iat_min;
					double max_iat = cflow[id].final_report[endpoint]->iat_max;
					double avg_iat = cflow[id].final_report[endpoint]->iat_sum /
						(double)(cflow[id].final_report[endpoint]->request_blocks_read);
					CATC("IAT = %.3f/%.3f/%.3f (min/avg/max)",
					     min_iat*1e3, avg_iat*1e3, max_iat*1e3);
				}

				/* delay */
				if (cflow[id].final_report[endpoint]->request_blocks_read) {
					double min_delay = cflow[id].final_report[endpoint]->delay_min;
					double max_delay = cflow[id].final_report[endpoint]->delay_max;
					double avg_delay = cflow[id].final_report[endpoint]->delay_sum /
						(double)(cflow[id].final_report[endpoint]->request_blocks_read);
					CATC("DLY = %.3f/%.3f/%.3f (min/avg/max)",
					     min_delay*1e3, avg_delay*1e3, max_delay*1e3);
				}


				free(cflow[id].final_report[endpoint]);

			} else {
				CATC("ERR: no final report received");
			}
			if (cflow[id].settings[endpoint].write_rate_str)
				CATC("rate = %s", cflow[id].settings[endpoint].write_rate_str);
			if (cflow[id].settings[endpoint].elcn)
				CATC("ELCN %s", cflow[id].settings[endpoint].elcn == 1 ? "enabled" : "disabled");
			if (cflow[id].settings[endpoint].cork)
				CATC("TCP_CORK");
			if (cflow[id].settings[endpoint].pushy)
				CATC("PUSHY");
			if (cflow[id].settings[endpoint].nonagle)
				CATC("TCP_NODELAY");
			if (cflow[id].settings[endpoint].mtcp)
				CATC("TCP_MTCP");

		if (cflow[id].settings[endpoint].dscp)
			CATC("dscp = 0x%02x", cflow[id].settings[endpoint].dscp);
		if (cflow[id].late_connect)
			CATC("late connecting");
		if (cflow[id].shutdown)
			CATC("calling shutdown");
			CAT("\n");

			log_output(header_buffer);

		}
	}
}

/* Finds the daemon (or creating a new one) for a given server_url,
 * uses global static unique_servers variable for storage */
static struct _daemon * get_daemon_by_url(const char* server_url, const char* server_name, unsigned short server_port) {
	/* If we have already a daemon for this URL return a pointer to it */
	for (unsigned int i = 0; i < num_unique_servers; i++) {
		if (!strcmp(unique_servers[i].server_url, server_url))
			return &unique_servers[i];
	}
	/* didn't find anything, seems to be a new one */
	memset(&unique_servers[num_unique_servers], 0, sizeof(struct _daemon));
	strcpy(unique_servers[num_unique_servers].server_url, server_url);
	strcpy(unique_servers[num_unique_servers].server_name, server_name);
	unique_servers[num_unique_servers].server_port = server_port;
	return &unique_servers[num_unique_servers++];
}

static void parse_trafgen_option(char *params, int current_flow_ids[], int id) {
	int rc;
	char * section;
	char * arg;

	for (section = strtok(params, ":"); section; section = strtok(NULL, ":")) {

		double param1 = 0, param2 = 0, unused;
		char endpointchar, typechar, distchar;
		enum _stochastic_distributions distr = 0;
		int j = 0;
		int k = 0;

		endpointchar = section[0];
		if (section[1] == '=')
			arg = section + 2;
		else
			arg = section + 1;

		switch (endpointchar) {
		case 's':
			j = 0;
			k = 1;
			break;

		case 'd':
			j = 1;
			k = 2;
			break;

		case 'b':
			j = 0;
			k = 2;
			break;

		default:
			fprintf(stderr, "%s: syntax error in traffic generation "
				"option: %c is not a valid endpoint\n",
				progname, endpointchar);
			usage_hint();
		}

		rc = sscanf(arg, "%c,%c,%lf,%lf,%lf", &typechar, &distchar, &param1, &param2, &unused);
		if (rc != 3 && rc != 4) {
			fprintf(stderr, "malformed traffic generation parameters\n");
				usage_trafgenopt();
		}

		switch (distchar) {
		case 'N':
		case 'n':
			distr = NORMAL;
			if (!param1 || !param2) {
				fprintf(stderr, "normal distribution needs two non-zero parameters");
				usage_trafgenopt();
			}
			break;

		case 'W':
		case 'w':
			distr = WEIBULL;
			if (!param1 || !param2) {
				fprintf(stderr, "weibull distribution needs two non-zero parameters\n");
				usage_trafgenopt();
			}
			break;

		case 'U':
		case 'u':
			distr = UNIFORM;
			if  ( param1 <= 0 || param2 <= 0 || (param1 > param2) ) {
				fprintf(stderr, "uniform distribution needs two positive parameters\n");
				usage_trafgenopt();
			}
			break;

		case 'E':
		case 'e':
			distr = EXPONENTIAL;
			if (param1 <= 0) {
				fprintf(stderr, "exponential value needs one positive paramters\n");
				usage_trafgenopt();
			}
			break;

		case 'P':
		case 'p':
			distr = PARETO;
			if (!param1 || !param2) {
				fprintf(stderr, "pareto distribution needs two non-zero parameters\n");
				usage_trafgenopt();
			}
			break;

		case 'L':
		case 'l':
			distr = LOGNORMAL;
			if (!param1 || !param2) {
				fprintf(stderr, "lognormal distribution needs two non-zero parameters\n");
				usage_trafgenopt();
			}
			break;


		case 'C':
		case 'c':
			distr = CONSTANT;
			if (param1 <= 0) {
				fprintf(stderr, "constant value needs one positive paramters\n");
				usage_trafgenopt();
			}
			break;


		default:
			fprintf(stderr, "Syntax error in traffic generation option: %c is not a distribution.\n", distchar);
			usage_trafgenopt();
		}


		if (current_flow_ids[0] == -1) {
			for (int id = 0; id < MAX_FLOWS; id++) {
				for (int i = j; i < k; i++) {
					switch (typechar) {
					case 'P':
					case 'p':
						cflow[id].settings[i].response_trafgen_options.distribution = distr;
						cflow[id].settings[i].response_trafgen_options.param_one = param1;
						cflow[id].settings[i].response_trafgen_options.param_two = param2;
						break;
					case 'Q':
					case 'q':
						cflow[id].settings[i].request_trafgen_options.distribution = distr;
						cflow[id].settings[i].request_trafgen_options.param_one = param1;
						cflow[id].settings[i].request_trafgen_options.param_two = param2;
						break;
					case 'G':
					case 'g':
						cflow[id].settings[i].interpacket_gap_trafgen_options.distribution = distr;
						cflow[id].settings[i].interpacket_gap_trafgen_options.param_one = param1;
						cflow[id].settings[i].interpacket_gap_trafgen_options.param_two = param2;
						break;
					}
					/* sanity check for max block size */
					for (int i = 0; i < 2; i++) {
						if (distr == CONSTANT && cflow[id].settings[i].maximum_block_size < param1)
							cflow[id].settings[i].maximum_block_size = param1;
						if (distr == UNIFORM && cflow[id].settings[i].maximum_block_size < param2)
							cflow[id].settings[i].maximum_block_size = param2;
					}
				}
			}
		} else {
			for (int i = j; i < k; i++) {
				switch (typechar) {
				case 'P':
				case 'p':
					cflow[current_flow_ids[id]].settings[i].response_trafgen_options.distribution = distr;
					cflow[current_flow_ids[id]].settings[i].response_trafgen_options.param_one = param1;
					cflow[current_flow_ids[id]].settings[i].response_trafgen_options.param_two = param2;
					break;
				case 'Q':
				case 'q':
					cflow[current_flow_ids[id]].settings[i].request_trafgen_options.distribution = distr;
					cflow[current_flow_ids[id]].settings[i].request_trafgen_options.param_one = param1;
					cflow[current_flow_ids[id]].settings[i].request_trafgen_options.param_two = param2;
					break;
				case 'G':
				case 'g':
					cflow[current_flow_ids[id]].settings[i].interpacket_gap_trafgen_options.distribution = distr;
					cflow[current_flow_ids[id]].settings[i].interpacket_gap_trafgen_options.param_one = param1;
					cflow[current_flow_ids[id]].settings[i].interpacket_gap_trafgen_options.param_two = param2;
					break;
				}
			}
			/* sanity check for max block size */
			for (int i = 0; i < 2; i++) {
				if (distr == CONSTANT && cflow[id].settings[i].maximum_block_size < param1)
					cflow[id].settings[i].maximum_block_size = param1;
				if (distr == UNIFORM && cflow[id].settings[i].maximum_block_size < param2)
					cflow[id].settings[i].maximum_block_size = param2;
			}
		}
	}
}

/* Parse flow specific options given on the cmdline */
static void parse_flow_option(int ch, char* optarg, int current_flow_ids[], int id) {
	char* token;
	char* arg;
	char type;
	int rc = 0;
	unsigned optunsigned = 0;
	double optdouble = 0.0;
	/* only for validity check of addresses */
	struct sockaddr_in6 source_in6;
	source_in6.sin6_family = AF_INET6;
	struct _daemon* daemon;

	#define ASSIGN_ENDPOINT_SETTING(PROPERTY_NAME, PROPERTY_VALUE) \
		if (current_flow_ids[0] == -1) { \
			for (id = 0; id < MAX_FLOWS; id++) { \
				if (type != 'd') \
					cflow[id].endpoint[SOURCE].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
				if (type != 's') \
					cflow[id].endpoint[DESTINATION].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
			} \
		} else { \
			if (type != 'd') \
				cflow[current_flow_ids[id]].endpoint[SOURCE].PROPERTY_NAME = \
				(PROPERTY_VALUE); \
			if (type != 's') \
				cflow[current_flow_ids[id]].endpoint[DESTINATION].PROPERTY_NAME = \
				(PROPERTY_VALUE); \
		}

	#define ASSIGN_ENDPOINT_SETTING_STR(PROPERTY_NAME, PROPERTY_VALUE) \
		if (current_flow_ids[0] == -1) { \
			for (id = 0; id < MAX_FLOWS; id++) { \
				if (type != 'd') \
					strcpy(cflow[id].endpoint[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
				if (type != 's') \
					strcpy(cflow[id].endpoint[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
			} \
		} else { \
			if (type != 'd') \
				strcpy(cflow[current_flow_ids[id]].endpoint[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
			if (type != 's') \
				strcpy(cflow[current_flow_ids[id]].endpoint[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
		}

	#define ASSIGN_UNI_FLOW_SETTING(PROPERTY_NAME, PROPERTY_VALUE) \
		if (current_flow_ids[0] == -1) { \
			int id; \
			for (id = 0; id < MAX_FLOWS; id++) { \
				if (type != 'd') \
					cflow[id].settings[SOURCE].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
				if (type != 's') \
					cflow[id].settings[DESTINATION].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
			} \
		} else { \
			if (type != 'd') \
				cflow[current_flow_ids[id]].settings[SOURCE].PROPERTY_NAME = \
				(PROPERTY_VALUE); \
			if (type != 's') \
				cflow[current_flow_ids[id]].settings[DESTINATION].PROPERTY_NAME = \
				(PROPERTY_VALUE); \
		}

	#define ASSIGN_UNI_FLOW_SETTING_STR(PROPERTY_NAME, PROPERTY_VALUE) \
		if (current_flow_ids[0] == -1) { \
			int id; \
			for (id = 0; id < MAX_FLOWS; id++) { \
				if (type != 'd') \
					strcpy(cflow[id].settings[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
				if (type != 's') \
					strcpy(cflow[id].settings[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
			} \
		} else { \
			if (type != 'd') \
				strcpy(cflow[current_flow_ids[id]].settings[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
			if (type != 's') \
				strcpy(cflow[current_flow_ids[id]].settings[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
		}

	for (token = strtok(optarg, ","); token; token = strtok(NULL, ",")) {
		type = token[0];
		if (token[1] == '=')
			arg = token + 2;
		else
			arg = token + 1;

		if (type != 's' && type != 'd' && type != 'b') {
			fprintf(stderr, "%s: syntax error in flow option: %c is "
				"not a valid endpoint\n", progname, type);
			usage_hint();
		}

		switch (ch) {
		case 'A':
			ASSIGN_UNI_FLOW_SETTING(response_trafgen_options.distribution, CONSTANT);
			ASSIGN_UNI_FLOW_SETTING(response_trafgen_options.param_one, MIN_BLOCK_SIZE);
			break;
		case 'B':
			rc = sscanf(arg, "%u", &optunsigned);
			if (rc != 1) {
				fprintf(stderr, "send buffer size must be a positive "
					"integer (in bytes)\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(requested_send_buffer_size, optunsigned)
			break;
		case 'C':
			ASSIGN_UNI_FLOW_SETTING(flow_control, 1)
			break;
		case 'D':
			rc = sscanf(arg, "%x", &optunsigned);
			if (rc != 1 || (optunsigned & ~0x3f)) {
				fprintf(stderr, "malformed differentiated "
						"service code point.\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(dscp, optunsigned);
			break;
		case 'H':
			{
				/*      two addresses:
					- test address where the actual test connection goes to
					- RPC address, where this program connects to

					Unspecified RPC address falls back to test address
				 */
				char url[1000];
				int port = DEFAULT_LISTEN_PORT;
				int extra_rpc = 0;
				int is_ipv6 = 0;
				char *sepptr, *rpc_address = 0;

				/* RPC address */
				sepptr = strchr(arg, '/');
				if (sepptr) {
					*sepptr = '\0';
					rpc_address = sepptr + 1;
					extra_rpc = 1;
				}
				else
					rpc_address = arg;

				/* IPv6 Address? */
				if (strchr(arg, ':')) {
					if (inet_pton(AF_INET6, arg, (char*)&source_in6.sin6_addr) <= 0) {
						fprintf(stderr, "invalid IPv6 address "
							 "'%s' for test connection\n", arg);
						usage();
					}
					if (!extra_rpc)
						is_ipv6 = 1;
				}

				if (extra_rpc) {
					/* Now it's getting tricky... */
					/* 1st case: IPv6 with port, e.g. "[a:b::c]:5999"  */
					if ((sepptr = strchr(rpc_address, ']'))) {
					    is_ipv6 = 1;
						*sepptr = '\0';
						if (rpc_address[0] == '[')
							rpc_address++;
						sepptr++;
					    if (sepptr != '\0' && *sepptr == ':')
							sepptr++;
						port = atoi(sepptr);
					} else if ((sepptr = strchr(rpc_address, ':'))) {
						/* 2nd case: IPv6 without port, e.g. "a:b::c"  */
						if (strchr(sepptr+1, ':')) {
							is_ipv6 = 1;
						} else {
						/* 3rd case: IPv4 or name with port 1.2.3.4:5999*/
							*sepptr = '\0';
							sepptr++;
							if ((*sepptr != '\0') && (*sepptr == ':'))
									sepptr++;
							port = atoi(sepptr);
						}
					}
					if (is_ipv6 && (inet_pton(AF_INET6, arg, (char*)&source_in6.sin6_addr) <= 0)) {
						fprintf(stderr, "invalid IPv6 address "
							 "'%s' for RPC connection\n", arg);
						usage();
					}
					if (port < 1 || port > 65535) {
						fprintf(stderr, "invalid port for RPC connection \n");
						usage();
					}
				} /* end of extra rpc address parsing */

				if (!*arg) {
					fprintf(stderr, "No test host given in argument\n");
					usage();
				}
				if (is_ipv6)
					sprintf(url, "http://[%s]:%d/RPC2", rpc_address, port);
				else
					sprintf(url, "http://%s:%d/RPC2", rpc_address, port);

				daemon = get_daemon_by_url(url, rpc_address, port);
				ASSIGN_ENDPOINT_SETTING(daemon, daemon);
				ASSIGN_ENDPOINT_SETTING_STR(test_address, arg);
			}
			break;
		case 'M':
			ASSIGN_UNI_FLOW_SETTING(traffic_dump, 1)
			break;
		case 'O':
			if (!*arg) {
				fprintf(stderr, "-O requires a value for each given endpoint\n");
				usage_sockopt();
			}

			if (!strcmp(arg, "TCP_CORK")) {
				ASSIGN_UNI_FLOW_SETTING(cork, 1);
			}
			else if (!strcmp(arg, "TCP_ELCN")) {
				ASSIGN_UNI_FLOW_SETTING(elcn, 1);
			}
			else if (!strcmp(arg, "TCP_LCD")) {
				ASSIGN_UNI_FLOW_SETTING(lcd, 1);
			}
			else if (!strcmp(arg, "TCP_MTCP")) {
				ASSIGN_UNI_FLOW_SETTING(mtcp, 1);
			}
			else if (!strcmp(arg, "TCP_NODELAY")) {
				ASSIGN_UNI_FLOW_SETTING(nonagle, 1);
			}

			else if (!strcmp(arg, "ROUTE_RECORD")) {
				ASSIGN_UNI_FLOW_SETTING(route_record, 1);

			/* keep TCP_CONG_MODULE for backward compatibility */}
			else if (!memcmp(arg, "TCP_CONG_MODULE=", 16)) {
				if (strlen(arg + 16) >= sizeof(cflow[0].settings[SOURCE].cc_alg)) {
					fprintf(stderr, "Too large string for TCP_CONG_MODULE value");
					usage_sockopt();
				}
				ASSIGN_UNI_FLOW_SETTING_STR(cc_alg, arg + 16);
			}

			else if (!memcmp(arg, "TCP_CONGESTION=", 15)) {
				if (strlen(arg + 16) >= sizeof(cflow[0].settings[SOURCE].cc_alg)) {
					fprintf(stderr, "Too large string for TCP_CONGESTION value");
					usage_sockopt();
				}
				ASSIGN_UNI_FLOW_SETTING_STR(cc_alg, arg + 15);
			}

			else if (!strcmp(arg, "SO_DEBUG")) {
				ASSIGN_UNI_FLOW_SETTING(so_debug, 1);
			}
			else if (!strcmp(arg, "IP_MTU_DISCOVER")) {
				ASSIGN_UNI_FLOW_SETTING(ipmtudiscover, 1);
			}
			else {
				fprintf(stderr, "Unknown socket option or socket option not implemented for endpoint\n");
				usage_sockopt();
			}
			break;
		case 'P':
			ASSIGN_UNI_FLOW_SETTING(pushy, 1)
			break;
		case 'R':
			if (!*arg) {
				fprintf(stderr, "-R requires a value for each given endpoint\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(write_rate_str, arg)
			break;
		case 'S':
			rc = sscanf(arg, "%u", &optunsigned);
			ASSIGN_UNI_FLOW_SETTING(request_trafgen_options.distribution, CONSTANT);
			ASSIGN_UNI_FLOW_SETTING(request_trafgen_options.param_one, optunsigned);
			for (int id = 0; id < MAX_FLOWS; id++) {
				for (int i = 0; i < 2; i++) {
					if ((signed)optunsigned > cflow[id].settings[i].maximum_block_size)
						cflow[id].settings[i].maximum_block_size = (signed)optunsigned;
				}
			}
			break;
		case 'T':
			rc = sscanf(arg, "%lf", &optdouble);
			if (rc != 1) {
				fprintf(stderr, "malformed flow duration\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(duration[WRITE], optdouble)
			break;
		case 'U':
			rc = sscanf(arg, "%d", &optunsigned);
			if (rc != 1) {
				fprintf(stderr, "%s: block size must be a "
					"positive integer\n", progname);
				usage_hint();
			}
			ASSIGN_UNI_FLOW_SETTING(maximum_block_size, optunsigned);
			break;
		case 'W':
			rc = sscanf(arg, "%u", &optunsigned);
			if (rc != 1) {
				fprintf(stderr, "receive buffer size (advertised window) must be a positive "
					"integer (in bytes)\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(requested_read_buffer_size, optunsigned)
			break;
		case 'Y':
			rc = sscanf(arg, "%lf", &optdouble);
			if (rc != 1 || optdouble < 0) {
				fprintf(stderr, "delay must be a non-negativ "
						"number (in seconds)\n");
				usage();
			}
			ASSIGN_UNI_FLOW_SETTING(delay[WRITE], optdouble)
			break;
		}
	}
}

/**
 * Parse argument for option -c to hide/show intermediated interval report
 * columns
 *
 * @param[in] optarg argument for option -c
 */
static void parse_visible_option(char *optarg)
{
	/* Reset all default visibility settings */
	for (unsigned int i = 0;
	     i < sizeof(column_info) / sizeof(struct _column); i++)
		column_info[i].state.visible = false;

	/* Show always flow ID */
	SHOW_COLUMNS(COL_FLOW_ID);

	for (char *token = strtok(optarg, ","); token;
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
		else {
			fprintf(stderr, "%s: malformed option '-c' \n",
				progname);
			usage_hint();
		}
	}
}

static void parse_cmdline(int argc, char **argv) {
	int rc = 0;
	int ch = 0;
	int id = 0;
	int error = 0;
	char *tok = NULL;
	int current_flow_ids[MAX_FLOWS] =  {-1};
	int max_flow_specifier = 0;
	unsigned max_flow_rate = 0;
	char unit = 0, type = 0, distribution = 0;
	int optint = 0;
	double optdouble = 0.0;

	/* variables from getopt() */
	extern char *optarg;	/* the option argument */
	extern int optopt;	/* the option character */

	#define ASSIGN_BI_FLOW_SETTING(PROPERTY_NAME, PROPERTY_VALUE, id) \
		if (current_flow_ids[0] == -1) { \
			int i; \
			for (i = 0; i < MAX_FLOWS; i++) { \
				cflow[i].PROPERTY_NAME = \
				(PROPERTY_VALUE); \
			} \
		} else { \
			cflow[current_flow_ids[id]].PROPERTY_NAME = \
			(PROPERTY_VALUE); \
		}

	/* update progname from argv[0] */
	if (argc > 0) {
		/* Strip path */
		tok = strrchr(argv[0], '/');
		if (tok)
			tok++;
		else
			tok = argv[0];
		if (*tok) {
			strncpy(progname, tok, sizeof(progname));
			progname[sizeof(progname) - 1] = 0;
		}
	}

	/* parse command line */
	while ((ch = getopt(argc, argv,":h:vc:de:i:l:mn:opqu:w"
			    "A:B:CD:EF:G:H:J:LNM:O:P:QR:S:T:U:W:Y:")) != -1) {
		switch (ch) {

		/* Miscellaneous */
		case 'h':
			if (!strcmp(optarg, "s"))
				usage_sockopt();
			else if (!strcmp(optarg, "g"))
				usage_trafgenopt();
			else {
				fprintf(stderr, "%s: unknown optional "
					"argument '%s' for option '-h'\n",
					progname, optarg);
				usage_hint();
			}
			exit(EXIT_SUCCESS);
		case 'v':
			fprintf(stderr, "%s version: %s\n", progname,
				FLOWGRIND_VERSION);
			exit(EXIT_SUCCESS);

		/* general options */
		case 'c':
			parse_visible_option(optarg);
			break;
		case 'd':
			increase_debuglevel();
			break;

		case 'e':
			opt.log_filename_prefix = optarg;
			break;
		case 'i':
			rc = sscanf(optarg, "%lf", &opt.reporting_interval);
			if (rc != 1 || opt.reporting_interval <= 0) {
				fprintf(stderr, "%s: reporting interval must "
					"be a positive number (in seconds)\n",
					progname);
				usage_hint();
			}
			break;
		case 'l':
			opt.log_filename = optarg;
			break;
		case 'm':
			column_info[COL_THROUGH].header.unit = " [MB/s]";
			opt.mbyte = true;
			break;
		case 'n':
			rc = sscanf(optarg, "%hd", &opt.num_flows);
			if (rc != 1 || opt.num_flows > MAX_FLOWS) {
				fprintf(stderr, "%s: number of test flows "
					"must be within [1..%d]\n",
					progname, MAX_FLOWS);
				usage_hint();
			}
			break;
		case 'o':
			opt.clobber = true;
			break;
		case 'p':
			opt.symbolic = false;
			break;
		case 'q':
			opt.dont_log_stdout = true;
			break;
		case 'u':
			if (!strcmp(optarg, "s"))
				opt.force_unit = SEGMENT_BASED;
			else if (!strcmp(optarg, "b"))
				opt.force_unit = BYTE_BASED;
			else {
				fprintf(stderr, "%s: unknown argument '%s' "
					"for option '-u'\n", progname, optarg);
				usage_hint();
			}
		case 'w':
			opt.dont_log_logfile = false;
			break;

		/* flow options w/o endpoint identifier */
		case 'E':
			ASSIGN_BI_FLOW_SETTING(byte_counting, 1, id-1);
			break;
		/* FIXME If more than one number is given, the option is not
		 * correct handled, e.g. -F 1,2,3 */
		case 'F':
			tok = strtok(optarg, ",");
			while (tok) {
				rc = sscanf(tok, "%d", &optint);
				if (rc != 1) {
					fprintf(stderr, "%s: malformed flow "
						"specifier\n", progname);
					usage_hint();
				}
				if (optint == -1) {
					id = 0;
					break;
				}
				current_flow_ids[id++] = optint;
				ASSIGN_MAX(max_flow_specifier, optint);
				tok = strtok(NULL, ",");
			}
			current_flow_ids[id] = -1;
			break;
		case 'G':
			parse_trafgen_option(optarg, current_flow_ids, id-1);
			break;
		case 'J':
			rc = sscanf(optarg, "%u", &optint);
			if (rc != 1) {
				fprintf(stderr, "%s: random seed must be a "
					"valid unsigned integer\n", progname);
					usage_hint();
			}
			ASSIGN_BI_FLOW_SETTING(random_seed, optint, id-1);
			break;
		case 'L':
			ASSIGN_BI_FLOW_SETTING(late_connect, 1, id-1);
			break;
		case 'N':
			ASSIGN_BI_FLOW_SETTING(shutdown, 1, id-1);
			break;
		case 'Q':
			ASSIGN_BI_FLOW_SETTING(summarize_only, 1, id-1);
			break;

		/* flow options w/ endpoint identifier */
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'H':
		case 'O':
		case 'M':
		case 'P':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'W':
		case 'Y':
			parse_flow_option(ch, optarg, current_flow_ids, id-1);
			break;

		/* missing option-argument */
		case ':':
			/* Sepcial case. Option -h can called w/ and w/o an argument */
			if (optopt == 'h')
				usage();

			fprintf(stderr, "%s: option '-%c' requires an "
				"argument\n", progname, optopt);
			usage_hint();

		/* unknown option */
		case '?':
			fprintf(stderr, "%s: unknown option '-%c'\n",
				progname, optopt);
			usage_hint();
		}
	}

#if 0
	/* Demonstration how to set arbitary socket options. Note that this is
	 * only intended for quickly testing new options without having to
	 * recompile and restart the daemons. To add support for a particular
	 * options in future flowgrind versions it's recommended to implement
	 * them like the other options supported by the -O argument.
	 */
	{
		assert(cflow[0].settings[SOURCE].num_extra_socket_options < MAX_EXTRA_SOCKET_OPTIONS);
		struct _extra_socket_options *option = &cflow[0].settings[SOURCE].extra_socket_options[cflow[0].settings[SOURCE].num_extra_socket_options++];
		int v;

		/* The value of the TCP_NODELAY constant gets passed to the daemons.
		 * If daemons use a different system, constants may be different. In this case use
		 * a value that matches the daemons'. */
		option->optname = TCP_NODELAY; /* or option->optname = 12345; as explained above */

		option->level = level_ipproto_tcp; /* See _extra_socket_option_level enum in common.h */

		/* Again, value needs to be of correct size for the daemons.
		 * Particular pitfalls can be differences in integer sizes or endianess.
		 */
		assert(sizeof(v) < MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH);
		option->optlen = sizeof(v);
		memcpy(option->optval, &v, sizeof(v));
	}
#endif

	/* Sanity checking flow options */
	if (opt.num_flows <= max_flow_specifier) {
		fprintf(stderr, "Must not specify option for non-existing flow.\n");
		error = 1;
	}
	for (id = 0; id<opt.num_flows; id++) {
		DEBUG_MSG(LOG_WARNING, "sanity checking parameter set of flow %d.", id);
		if (cflow[id].settings[DESTINATION].duration[WRITE] > 0 &&
		    cflow[id].late_connect &&
		    cflow[id].settings[DESTINATION].delay[WRITE] <
		    cflow[id].settings[SOURCE].delay[WRITE]) {
			fprintf(stderr, "Server flow %d starts earlier than client "
					"flow while late connecting.\n", id);
			error = 1;
		}
		if (cflow[id].settings[SOURCE].delay[WRITE] > 0 &&
		    cflow[id].settings[SOURCE].duration[WRITE] == 0) {
			fprintf(stderr, "Client flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (cflow[id].settings[DESTINATION].delay[WRITE] > 0 &&
		    cflow[id].settings[DESTINATION].duration[WRITE] == 0) {
			fprintf(stderr, "Server flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (!cflow[id].settings[DESTINATION].duration[WRITE] &&
		    !cflow[id].settings[SOURCE].duration[WRITE]) {
			fprintf(stderr, "Server and client flow have both "
					"zero runtime for flow %d.\n", id);
			error = 1;
		}

		cflow[id].settings[SOURCE].duration[READ] = cflow[id].settings[DESTINATION].duration[WRITE];
		cflow[id].settings[DESTINATION].duration[READ] = cflow[id].settings[SOURCE].duration[WRITE];
		cflow[id].settings[SOURCE].delay[READ] = cflow[id].settings[DESTINATION].delay[WRITE];
		cflow[id].settings[DESTINATION].delay[READ] = cflow[id].settings[SOURCE].delay[WRITE];

		/* TODO Move the following stuff out of the sanity checks into
		 * a new function 'parse_rate_option' */

		for (unsigned i = 0; i < 2; i++) {

			if (cflow[id].settings[i].write_rate_str) {
				unit = type = distribution = 0;
				/* last %c for catching wrong input... this is not nice. */
				rc = sscanf(cflow[id].settings[i].write_rate_str, "%lf%c%c%c",
						&optdouble, &unit, &type, &unit);
				if (rc < 1 || rc > 4) {
					fprintf(stderr, "malformed rate for flow %u.\n", id);
					error = 1;
				}

				if (optdouble == 0.0) {
					cflow[id].settings[i].write_rate_str = NULL;
					continue;
				}

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
					fprintf(stderr, "illegal unit specifier "
							"in rate of flow %u.\n", id);
					error = 1;
				}

				switch (type) {
				case 0:
				case 'b':
					optdouble /= cflow[id].settings[SOURCE].maximum_block_size * 8;
					if (optdouble < 1) {
						fprintf(stderr, "client block size "
								"for flow %u is too "
								"big for specified "
								"rate.\n", id);
						error = 1;
					}
					break;

				case 'B':
					optdouble /= cflow[id].settings[SOURCE].maximum_block_size;
					if (optdouble < 1) {
						fprintf(stderr, "client block size "
								"for flow %u is too "
								"big for specified "
								"rate.\n", id);
						error = 1;
					}
					break;

				case 'o':
					break;

				default:
					fprintf(stderr, "illegal type specifier "
							"(either block or byte) for "
							"flow %u.\n", id);
					error = 1;
				}

				if (optdouble > 5e5)
					fprintf(stderr, "rate of flow %d too high.\n", id);
				if (optdouble > max_flow_rate)
					max_flow_rate = optdouble;
				cflow[id].settings[i].write_rate = optdouble;

			}
			if (cflow[id].settings[i].flow_control && !cflow[id].settings[i].write_rate_str) {
				fprintf(stderr, "flow %d has flow control enabled but "
						"no rate.", id);
				error = 1;
			}
			/* Default to localhost, if no endpoints were set for a flow */
			if (!cflow[id].endpoint[i].daemon) {
				cflow[id].endpoint[i].daemon = get_daemon_by_url(
					"http://localhost:5999/RPC2", "localhost", DEFAULT_LISTEN_PORT);
			}
		}
	}

	if (error) {
#ifdef DEBUG
		DEBUG_MSG(LOG_ERR, "Skipping errors discovered by sanity checks.");
#else
		usage_hint();
#endif /* DEBUG */
	}
	DEBUG_MSG(LOG_WARNING, "sanity check parameter set of flow %d. completed", id);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;

	xmlrpc_client *rpc_client = 0;

	xmlrpc_env_init(&rpc_env);
	xmlrpc_client_setup_global_const(&rpc_env);

	init_general_options();
	init_flow_options();
	parse_cmdline(argc, argv);
	open_logfile();
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL)) {
		fprintf(stderr, "Error: Could not set handler for SIGINT\n");
	}
	prepare_xmlrpc_client(&rpc_client);

	DEBUG_MSG(LOG_WARNING, "check flowgrindds versions");
	if (!sigint_caught)
		check_version(rpc_client);

	DEBUG_MSG(LOG_WARNING, "check if flowgrindds are idle");
	if (!sigint_caught)
		check_idle(rpc_client);

	DEBUG_MSG(LOG_WARNING, "prepare flows");
	if (!sigint_caught)
		prepare_flows(rpc_client);

	DEBUG_MSG(LOG_WARNING, "start flows");
	if (!sigint_caught)
		grind_flows(rpc_client);


	DEBUG_MSG(LOG_WARNING, "close flows");
	close_flows();

	DEBUG_MSG(LOG_WARNING, "report final");
	fetch_reports(rpc_client);
	report_final();

	close_logfile();

	xmlrpc_client_destroy(rpc_client);
	xmlrpc_env_clean(&rpc_env);

	xmlrpc_client_teardown_global_const();

	DEBUG_MSG(LOG_WARNING, "bye");
	return 0;
}

