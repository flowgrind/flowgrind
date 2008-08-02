#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "fg_socket.h"
#include "debug.h"
#include "flowgrind.h"
#include "svnversion.h"

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

#ifdef __LINUX__
#define TCP_REPORT_HDR_STRING_MBIT "# ID   begin     end   c/s Mb/s   s/c Mb/s RTT, ms: min        avg        max IAT, ms: min        avg        max    cwnd  ssth #uack #sack #lost #retr #fack #reor     rtt  rttvar      rto\n"
#define TCP_REPORT_HDR_STRING_MBYTE "# ID   begin     end   c/s MB/s   s/c MB/s RTT, ms: min        avg        max IAT, ms: min        avg        max    cwnd  ssth #uack #sack #lost #retr #fack #reor     rtt  rttvar      rto\n"
#define TCP_REPORT_FMT_STRING "%c%3d %7.3f %7.3f %10.6f %10.6f   %10.3f %10.3f %10.3f   %10.3f %10.3f %10.3f   %5u %5u %5u %5u %5u %5u %5u %5u %7.3f %7.3f %8.3f %s\n"
#else
#define TCP_REPORT_HDR_STRING_MBIT "# ID   begin     end   c/s Mb/s   s/c Mb/s RTT, ms: min        avg        max IAT, ms: min        avg        max\n"
#define TCP_REPORT_HDR_STRING_MBYTE "# ID   begin     end   c/s MB/s   s/c MB/s RTT, ms: min        avg        max IAT, ms: min        avg        max\n"
#define TCP_REPORT_FMT_STRING "%c%3d %7.3f %7.3f %10.6f %10.6f   %10.3f %10.3f %10.3f   %10.3f %10.3f %10.3f %s\n"
#endif


static void usage(void)
{
	fprintf(stderr,
		"Usage: flowgrind [general options] [flow options]\n"
		"       flowgrind [-h|-v]\n\n"

		"flowgrind allows you to generate traffic among hosts in your network.\n\n"

		"Miscellaneous:\n"
		"  -h [sockopt] show help and exit\n"
		"  -v           print version information and exit\n\n"

		"General options:\n"
#ifdef HAVE_LIBPCAP
		"  -a           advanced statistics (pcap)\n"
#endif
#ifdef DEBUG
		"  -d           increase debugging verbosity. Add option multiple times to\n"
						"be even more verbose.\n"
#endif
		"  -e PRE       prepend prefix PRE to log filename (default: \"%s\")\n"
		"  -i #.#       reporting interval in seconds (default: 0.05s)\n"
		"  -l NAME      use log filename NAME (default: timestamp)\n"
		"  -m           report throughput in 2**20 bytes/second\n"
		"               (default: 10**6 bit/sec)\n"
		"  -n #         number of test flows (default: 1)\n"
		"  -o           overwrite existing log files (default: don't)\n"
		"  -p PORT      use PORT as base port number of test flows (default: none)\n"
		"               (default: none)\n"
		"  -q           be quiet, do not log to screen (default: off)\n"
		"  -w           write output to logfile (default: off)\n\n"

		"Flow options:\n"
		"  -B x=#       Set requested sending buffer in bytes\n"
		"  -C x         Stop flow if it is experiencing local congestion\n"
		"  -D x=DSCP    DSCP value for TOS byte\n"
		"  -E x         Enumerate bytes in payload (default: don't)\n"
		"  -F #{,#}     Flow options following this option apply only to flow #{,#}.\n"
		"               Useful in combination with -n to set specific options\n"
		"               for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"               to the second flow\n"
		"  -H x=HOST[/HOST][:PORT]\n"
		"               Test against host. Optional control host may be specified to\n"
		"               handle connection setup via another interface/route\n"
		"               (default: s=localhost,d=unset)\n"
		"  -L x         connect() socket immediately before sending (late)\n"
		"  -N x         shutdown() each socket direction after test flow\n"
		"  -O x=OPT     Set specific socket options on test socket.\n"
		"               type \"flowgrind -h sockopt\" to see the specific values for OPT\n"
		"  -P x         Do not iterate through select() to continue sending in case\n"
		"               block size did not suffice to fill sending queue (pushy)\n"
		"  -Q x         Summarize only, skip interval reports (quite)\n"
		"  -R x=#.#[z|k|M|G][b|B][p|P]\n"
                "               send at specified rate per second, where:\n"
		"               z = 2**0, k = 2**10, M = 2**20, G = 2**30\n"
		"               b = bytes per second, B = blocks per second (default)\n"
		"               p = periodic, P = Poisson distributed (default)\n"
		"  -S x=#       Set block size (default: s=8192,d=8192)\n"
		"  -T x=#.#     Set flow duration, in seconds (default: s=5,d=0),\n"
		"               negative meaning don't stop.\n"
		"  -W x=#       Set requested receiver buffer (advertised window) in bytes\n"
		"  -Y x=#.#     Set initial delay before the host starts to send data\n\n"

		"x can be replaced with 's' for source or 'd' for destination. For all options\n"
		"which take x, an additional parameter can be specified if separated by comma.\n"
		"For instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"and 4096 at the destination.\n\n"

		"The -O option, it is also possible to repeatedly specify s or d options\n"
		"respectively. For instance -O s=SO_DEBUG,s=TCP_CORK,d=TCP_CONG_MODULE=reno.\n\n"

		"Examples:\n"
		"  flowgrind -H d=testhost\n"
		"               start bulk TCP transfer from this host to testhost\n"
		"  flowgrind -H d=192.168.0.69 -T s=0,d=5\n"
		"               start bulk TCP transfer from 192.168.0.69 to this host\n"
		"  flowgrind -n 2 -H d=192.168.0.69 -F 1 -H d=10.0.0.1\n"
		"               start two TCP transfers one to 192.168.0.69 and another in\n"
		"               parallel to 10.0.0.1\n",
		opt.log_filename_prefix
		);
	exit(1);
}

static void usage_sockopt(void)
{
	fprintf(stderr,
		"The following list contains possible values that can be set on the test socket:\n"
		"  x=TCP_CONG_MODULE=ALG\n"
		"               set congestion control algorithm ALG. The following list\n"
		"               contains possible values for ALG:\n"
		"                 //ToDo: create the list\n"
		"  x=TCP_CORK   set TCP_CORK on test socket\n"
		"  x=TCP_ELCN   set TCP_ELCN on test socket\n"
		"  x=TCP_ICMP   set TCP_ICMP on test socket\n"
		"  x=ROUTE_RECORD\n"
		"               set ROUTE_RECORD on test socket\n\n"

		"x can be replaced with 's' for source or 'd' for destination\n\n"

		"Examples:\n"
		"  flowgrind -H d=testhost -O s=TCP_CONG_MODULE=reno,d=SO_DEBUG\n"
		"  //ToDo: write more examples and descriptions\n"
		);
	exit(1);
}

void init_options_defaults(void)
{
	opt.num_flows = 1;
	opt.reporting_interval = 0.05;
	opt.log_filename_prefix = "flowlog-";
	opt.dont_log_logfile = 1;
}


void init_flows_defaults(void)
{
	int id = 1;

	for (id = 0; id<MAX_FLOWS; id++) {
		flow[id].server_name = "localhost";
		flow[id].server_name_control = "localhost";
		flow[id].server_control_port = DEFAULT_LISTEN_PORT;
		flow[id].mss = 0;

		flow[id].client_flow_duration = 1.0;
		flow[id].client_flow_delay = 0;
		flow[id].server_flow_duration = 0.0;
		flow[id].server_flow_delay = 0;

		flow[id].proto = PROTO_TCP;

		flow[id].client_window_size = 0;
		flow[id].server_window_size = 0;

		flow[id].sock = 0;
		flow[id].sock_control = 0;

		flow[id].cc_alg = NULL;
		flow[id].elcn = 0;
		flow[id].cork = 0;
		flow[id].pushy = 0;
		flow[id].dscp = 0;

		flow[id].write_errors = 0;
		flow[id].read_errors = 0;

		flow[id].read_block = NULL;
		flow[id].read_block_size = 8192;
		flow[id].read_block_bytes_read = 0;
		flow[id].write_block = NULL;
		flow[id].write_block_size = 8192;
		flow[id].write_block_bytes_written = 0;

		/* Stats */
		flow[id].bytes_read_since_first = 0;
		flow[id].bytes_read_since_last = 0;
		flow[id].bytes_written_since_first = 0;
		flow[id].bytes_written_since_last = 0;

		/* Round trip time */
		flow[id].min_rtt_since_first = +INFINITY;
		flow[id].min_rtt_since_last = +INFINITY;
		flow[id].max_rtt_since_first = -INFINITY;
		flow[id].max_rtt_since_last = -INFINITY;
		flow[id].tot_rtt_since_first = 0.0;
		flow[id].tot_rtt_since_last = 0.0;

		/* Inter arrival times */
		flow[id].min_iat_since_first = +INFINITY;
		flow[id].min_iat_since_last = +INFINITY;
		flow[id].max_iat_since_first = -INFINITY;
		flow[id].max_iat_since_last = -INFINITY;
		flow[id].tot_iat_since_first = 0.0;
		flow[id].tot_iat_since_last = 0.0;
	}
}


void init_logfile(void)
{
	struct timeval now = {0, 0};
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
		tsc_gettimeofday(&now);
		len = strftime(buf, sizeof(buf), "%Y-%m-%d-%H:%M:%S", localtime(&now.tv_sec));
		log_filename = malloc(strlen(opt.log_filename_prefix) + len + 1);
		strcpy(log_filename, opt.log_filename_prefix);
		strcat(log_filename, buf);
	}

	DEBUG_MSG(2, "logging to \"%s\"", log_filename);

	if (!opt.clobber && access(log_filename, R_OK) == 0) {
		fprintf(stderr, "fatal: log file exists\n");
		exit(2);
	}

	log_stream = fopen(log_filename, "w");
	if (log_stream == NULL) {
		perror(log_filename);
		exit(2);
	}
}


void shutdown_logfile()
{
	if (opt.dont_log_logfile)
		return;

	if (fclose(log_stream) == -1) {
		perror("close");
		exit(2);
	}
}


void log_output(const char *msg)
{
	if (!opt.dont_log_stdout) {
		printf(msg);
		fflush(stdout);
	}
	if (!opt.dont_log_logfile) {
		fprintf(log_stream, msg);
		fflush(log_stream);
	}
}


void process_reply(int id, char *buffer)
{
	/* XXX: There is actually a conversion from
		network to host byte order needed here!! */
	struct timeval *sent = (struct timeval *)buffer;
	double current_rtt;
	double *current_iat_ptr = (double *)(buffer + sizeof(struct timeval));

	tsc_gettimeofday(&now);
	current_rtt = time_diff(sent, &now);


	if ((!isnan(*current_iat_ptr) && *current_iat_ptr <= 0) || current_rtt <= 0) {
		DEBUG_MSG(5, "illegal reply_block: isnan = %d, iat = %e, rtt = %e", isnan(*current_iat_ptr), *current_iat_ptr, current_rtt);
		error(ERR_WARNING, "Found block with illegal round trip time or illegal inter arrival time, ignoring block.");
		return ;
	}

	/* Update statistics for flow. */

	/* Round trip times */
	ASSIGN_MIN(flow[id].min_rtt_since_first, current_rtt);
	ASSIGN_MIN(flow[id].min_rtt_since_last, current_rtt);
	ASSIGN_MAX(flow[id].max_rtt_since_first, current_rtt);
	ASSIGN_MAX(flow[id].max_rtt_since_last, current_rtt);
	flow[id].tot_rtt_since_first += current_rtt;
	flow[id].tot_rtt_since_last += current_rtt;

	/* Inter arrival times */
	if (!isnan(*current_iat_ptr)) {
		ASSIGN_MIN(flow[id].min_iat_since_first, *current_iat_ptr);
		ASSIGN_MIN(flow[id].min_iat_since_last, *current_iat_ptr);
		ASSIGN_MAX(flow[id].max_iat_since_first, *current_iat_ptr);
		ASSIGN_MAX(flow[id].max_iat_since_last, *current_iat_ptr);
		flow[id].tot_iat_since_first += *current_iat_ptr;
		flow[id].tot_iat_since_last += *current_iat_ptr;
	}
	// XXX: else: check that this only happens once!
	DEBUG_MSG(4, "processed reply_block of flow %d, (RTT = %.3lfms, IAT = %.3lfms)", id, current_rtt * 1e3, isnan(*current_iat_ptr) ? NAN : *current_iat_ptr * 1e3);
}


void timer_check(void)
{
	int id = 0;

	tsc_gettimeofday(&now);
	if (time_is_after(&now, &timer.next)) {
		for (id = 0; id < opt.num_flows; id++)
			report_flow(id);
		timer.last = now;
		while (time_is_after(&now, &timer.next))
			time_add(&timer.next, opt.reporting_interval);
	}
}


void timer_start(void)
{
	int id = 0;

	DEBUG_MSG(4, "starting timers");

	tsc_gettimeofday(&timer.start);
	timer.last = timer.next = timer.start;
	time_add(&timer.next, opt.reporting_interval);

	for (id=0; id<opt.num_flows; id++) {
		flow[id].client_flow_start_timestamp = timer.start;
		time_add(&flow[id].client_flow_start_timestamp,
				flow[id].client_flow_delay);
		if (flow[id].client_flow_duration >= 0) {
			flow[id].client_flow_stop_timestamp =
				flow[id].client_flow_start_timestamp;
			time_add(&flow[id].client_flow_stop_timestamp,
					flow[id].client_flow_duration);
		}
		if (flow[id].rate)
			flow[id].next_write_block_timestamp =
				flow[id].client_flow_start_timestamp;

		flow[id].server_flow_start_timestamp = timer.start;
		time_add(&flow[id].server_flow_start_timestamp,
				flow[id].server_flow_delay);
		if (flow[id].server_flow_duration >= 0) {
			flow[id].server_flow_stop_timestamp =
				flow[id].server_flow_start_timestamp;
			time_add(&flow[id].server_flow_stop_timestamp,
					flow[id].server_flow_duration);
		}
	}
}


void
print_tcp_report_line(char hash, int id, double time1, double time2,
		long bytes_written, long bytes_read, double min_rtt,
		double tot_rtt, double max_rtt, double min_iat,
		double tot_iat, double max_iat
#ifdef __LINUX__
		,unsigned cwnd, unsigned ssth, unsigned uack,
		unsigned sack, unsigned lost, unsigned retr,
		unsigned fack, unsigned reor, double rtt,
		double rttvar, double rto
#endif
)
{
	double avg_rtt = INFINITY;
	double avg_iat = INFINITY;
	unsigned blocks_written = 0;
	char comment_buffer[100] = "(";
	char report_buffer[300] = "";
	double thruput = 0.0;

#define COMMENT_CAT(s) do { if (strlen(comment_buffer) > 1) \
		strncat(comment_buffer, "/", sizeof(comment_buffer)); \
		strncat(comment_buffer, (s), sizeof(comment_buffer)); }while(0);

	if (flow[id].stopped)
		COMMENT_CAT("stopped")
	else {
		blocks_written = bytes_written / flow[id].write_block_size;
		if (blocks_written == 0) {
			if (client_flow_in_delay(id))
				COMMENT_CAT("d")
			else if (client_flow_sending(id))
				COMMENT_CAT("l")
			else if (flow[id].client_flow_duration == 0)
				COMMENT_CAT("o")
			else
				COMMENT_CAT("f")
			min_rtt = max_rtt = avg_rtt = INFINITY;
			min_iat = max_iat = avg_iat = INFINITY;
		} else {
			if (!client_flow_sending(id) && active_flows > 0)
				COMMENT_CAT("c")
			else
				COMMENT_CAT("n")
			avg_rtt = tot_rtt / (double)(blocks_written);
			avg_iat = tot_iat / (double)(blocks_written);
		}

		if (bytes_read == 0) {
			if (server_flow_in_delay(id))
				COMMENT_CAT("d")
			else if (server_flow_sending(id))
				COMMENT_CAT("l")
			else if (flow[id].server_flow_duration == 0)
				COMMENT_CAT("o")
			else
				COMMENT_CAT("f")
		} else {
			if (!server_flow_sending(id) && active_flows > 0)
				COMMENT_CAT("c")
			else
				COMMENT_CAT("n")
		}
	}
	strncat(comment_buffer, ")", sizeof(comment_buffer));
	if (strlen(comment_buffer) == 2)
		comment_buffer[0] = '\0';

	thruput = scale_thruput((double)bytes_written / (time2 - time1));
	snprintf(report_buffer, sizeof(report_buffer), TCP_REPORT_FMT_STRING,
		(hash ? '#' : ' '), id,
		time1, time2, thruput,
		scale_thruput((double)bytes_read / (time2 - time1)),
		min_rtt * 1e3, avg_rtt * 1e3, max_rtt * 1e3,
		min_iat * 1e3, avg_iat * 1e3, max_iat * 1e3
#ifdef __LINUX__
		,
		cwnd, ssth, uack, sack, lost, retr, fack, reor,
		(double)rtt / 1e3, (double)rttvar / 1e3, (double)rto / 1e3
#endif
		,
		comment_buffer
	);
	log_output(report_buffer);
}


void report_final(void)
{
	int id = 0;
	double thruput = 0.0;
	char header_buffer[300] = "";
	char header_nibble[300] = "";
#ifdef __LINUX__
	struct tcp_info *info = NULL;
#endif

	for (id = 0; id < opt.num_flows; id++) {

		snprintf(header_buffer, sizeof(header_buffer),
			"# #%d: %s", id, flow[id].server_name);

#define CAT(fmt, args...) do {\
	snprintf(header_nibble, sizeof(header_nibble), fmt, ##args); \
	strncat(header_buffer, header_nibble, sizeof(header_nibble)); } while (0)
#define CATC(fmt, args...) CAT(", "fmt, ##args)

		if (strcmp(flow[id].server_name, flow[id].server_name_control) != 0)
			CAT("/%s", flow[id].server_name_control);
		if (flow[id].server_control_port != DEFAULT_LISTEN_PORT)
			CAT(",%d", flow[id].server_control_port);
		CATC("MSS = %d", flow[id].mss);
		if (flow[id].mtu != -1)
			CATC("MTU = %d (%s)", flow[id].mtu,
					guess_topology(flow[id].mss, flow[id].mtu));
		if (flow[id].stopped)
			thruput = flow[id].bytes_written_since_first
				/ time_diff(&flow[id].client_flow_start_timestamp,
						&flow[id].stopped_timestamp);
		else
			thruput = flow[id].bytes_written_since_first /
				flow[id].client_flow_duration;
		thruput = scale_thruput(thruput);
		CATC("ws = %u/%u%s (%u/%u), bs = %u/%u, delay = %.2fs/%.2fs, "
				"duration = %.2fs/%.2fs, thruput = %.6fM%c/s "
				"(%llu blocks)",
				flow[id].client_window_size_real,
				flow[id].server_window_size_real,
				(flow[id].server_window_size ? "" : "(?)"),
				flow[id].client_window_size,
				flow[id].server_window_size,
				flow[id].write_block_size,
				flow[id].read_block_size,
				flow[id].client_flow_delay,
				flow[id].server_flow_delay,
				flow[id].client_flow_duration,
				flow[id].server_flow_duration,
				thruput, (opt.mbyte ? 'B' : 'b'),
				flow[id].write_block_count);
		if (flow[id].rate_str)
			CATC("rate = %s", flow[id].rate_str);
		if (flow[id].elcn)
			CATC("ELCN %s", flow[id].elcn==1 ? "enabled" : "disabled");
		if (flow[id].cork)
			CATC("TCP_CORK");
		if (flow[id].pushy)
			CATC("PUSHY");

#ifdef __LINUX__
		CATC("cc = \"%s\"", *flow[id].final_cc_alg ? flow[id].final_cc_alg :
				"(failed)");
		if (!flow[id].cc_alg)
			CAT(" (default)");
		else if (strcmp(flow[id].final_cc_alg, flow[id].cc_alg) != 0)
			CAT(" (was set to \"%s\")", flow[id].cc_alg);
#endif
		if (flow[id].dscp)
			CATC("dscp = 0x%02x", flow[id].dscp);
		if (flow[id].late_connect)
			CATC("late connecting");
		if (flow[id].shutdown)
			CATC("calling shutdown");
		if (flow[id].congestion_counter > CONGESTION_LIMIT)
			CAT(" (overcongested)");
		else if (flow[id].congestion_counter > 0)
			CAT(" (congested = %u)", flow[id].congestion_counter);
		if (flow[id].stopped &&
				flow[id].congestion_counter <= CONGESTION_LIMIT)
			CAT(" (stopped)");
		CAT("\n");

		log_output(header_buffer);

#ifdef __LINUX__
		if (flow[id].stopped)
			info = &flow[id].last_tcp_info;
		else
			info = &flow[id].final_tcp_info;
#endif
		if (flow[id].bytes_written_since_first == 0) {
			print_tcp_report_line(
				1, id, flow[id].client_flow_delay,
				flow[id].client_flow_duration +
				flow[id].client_flow_delay, 0, 0,
				INFINITY, INFINITY, INFINITY,
				INFINITY, INFINITY, INFINITY
#ifdef __LINUX__
				,
				info->tcpi_snd_cwnd, info->tcpi_snd_ssthresh,
				info->tcpi_unacked, info->tcpi_sacked,
				info->tcpi_lost, info->tcpi_retrans,
				info->tcpi_fackets, info->tcpi_reordering,
				info->tcpi_rtt, info->tcpi_rttvar, info->tcpi_rto
#endif
			);
			continue;
		}

		print_tcp_report_line(
			1, id, flow[id].client_flow_delay,
			time_diff(&timer.start, &flow[id].last_block_written),
			flow[id].bytes_written_since_first,
			flow[id].bytes_read_since_first,
			flow[id].min_rtt_since_first,
			flow[id].tot_rtt_since_first,
			flow[id].max_rtt_since_first,
			flow[id].min_iat_since_first,
			flow[id].tot_iat_since_first,
			flow[id].max_iat_since_first
#ifdef __LINUX__
			,
			info->tcpi_snd_cwnd, info->tcpi_snd_ssthresh,
			info->tcpi_unacked, info->tcpi_sacked,
			info->tcpi_lost, info->tcpi_retrans,
			info->tcpi_fackets, info->tcpi_reordering,
			info->tcpi_rtt, info->tcpi_rttvar, info->tcpi_rto
#endif
		);
	}
}


void report_flow(int id)
{
	double diff_first_last = 0.0;
	double diff_first_now = 0.0;

#ifdef __LINUX__
	int rc = 0;
	struct tcp_info info;
#endif

	if (flow[id].stopped || flow[id].summarize_only)
		return;

#ifdef __LINUX__
	socklen_t info_len = sizeof(struct tcp_info);

	rc = getsockopt(flow[id].sock, IPPROTO_TCP, TCP_INFO, &info, &info_len);
	if (rc == -1) {
		error(ERR_WARNING, "getsockopt() failed: %s",
				strerror(errno));
		stop_flow(id);
		return;
	}
#endif

	tsc_gettimeofday(&now);
	diff_first_last = time_diff(&timer.start, &timer.last);
	diff_first_now = time_diff(&timer.start, &now);

	print_tcp_report_line(
			0, id, diff_first_last, diff_first_now,
			flow[id].bytes_written_since_last,
			flow[id].bytes_read_since_last,
			flow[id].min_rtt_since_last,
			flow[id].tot_rtt_since_last,
			flow[id].max_rtt_since_last,
			flow[id].min_iat_since_last,
			flow[id].tot_iat_since_last,
			flow[id].max_iat_since_last
#ifdef __LINUX__
			,
			info.tcpi_snd_cwnd,
			info.tcpi_snd_ssthresh,
			info.tcpi_last_data_sent, info.tcpi_last_ack_recv,
			info.tcpi_lost,
			flow[id].last_tcp_info.tcpi_retrans - info.tcpi_retrans,
			info.tcpi_fackets,
			info.tcpi_reordering,
			info.tcpi_rtt,
			info.tcpi_rttvar,
			info.tcpi_rto
#endif
				);

	flow[id].bytes_written_since_last = 0;
	flow[id].bytes_read_since_last = 0;
	flow[id].min_rtt_since_last = +INFINITY;
	flow[id].max_rtt_since_last = -INFINITY;
	flow[id].tot_rtt_since_last = 0.0;
	flow[id].min_iat_since_last = +INFINITY;
	flow[id].max_iat_since_last = -INFINITY;
	flow[id].tot_iat_since_last = 0.0;
#ifdef __LINUX__
	flow[id].last_tcp_info = info;
#endif
}


int name2socket(char *server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp, char do_connect)
{
	int fd, n;
	struct addrinfo hints, *res, *ressave;
	char service[7];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(service, sizeof(service), "%u", port);

	if ((n = getaddrinfo(server_name, service, &hints, &res)) != 0)
		error(ERR_FATAL, "getaddrinfo() failed: %s",
				gai_strerror(n));
	ressave = res;

	do {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		if (!do_connect)
			break;

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		error(ERR_WARNING, "Failed to connect to \"%s\": %s",
				server_name, strerror(errno));
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL)
		error(ERR_FATAL, "Could not establish connection to "
				"\"%s\": %s", server_name, strerror(errno));

	if (saptr && lenp) {
		*saptr = malloc(res->ai_addrlen);
		if (*saptr == NULL) {
			error(ERR_FATAL, "malloc(): failed: %s",
					strerror(errno));
		}
		memcpy(*saptr, res->ai_addr, res->ai_addrlen);
		*lenp = res->ai_addrlen;
	}

	freeaddrinfo(ressave);

	return fd;
}


void read_greeting(int s)
{
	char buf[1024];
	int rc;
	size_t greetlen = strlen(FLOWGRIND_PROT_GREETING);

	rc = read_exactly(s, buf, greetlen);
	if (rc != (int) greetlen) {
		if (rc == -1)
			error(ERR_FATAL, "read: %s", strerror(errno));
		error(ERR_FATAL, "Server greeting is wrong in length. "
				"Not flowgrind?");
	}
	rc = strncmp(buf + strlen(FLOWGRIND_PROT_CALLSIGN FLOWGRIND_PROT_SEPERATOR),
			FLOWGRIND_PROT_VERSION, strlen(FLOWGRIND_PROT_VERSION));
	if (rc < 0)
		error(ERR_FATAL, "flowgrind client outdated for this server.");
	if (rc > 0)
		error(ERR_FATAL, "flowgrind server outdated for this client.");

	if (strncmp(&buf[greetlen - 1], FLOWGRIND_PROT_EOL, strlen(FLOWGRIND_PROT_EOL))) {
		error(ERR_WARNING, "connection rejected");
		rc = read(s, buf, sizeof(buf) - 1);
		if (rc == -1)
			error(ERR_FATAL, "Could not read rejection reason: %s",
					strerror(errno));
		buf[sizeof(buf) - 1] = '\0';
		buf[rc - 1] = '\0';
		error(ERR_FATAL, "Server said: %s", buf);
	}
}


void write_proposal(int s, char *proposal, int proposal_size)
{
	int rc;

	rc = write_exactly(s, proposal, (size_t) proposal_size);
	assert(rc <= proposal_size);
	if (rc < proposal_size) {
		if (rc == -1)
			error(ERR_FATAL, "write: %s", strerror(errno));
		error(ERR_FATAL, "Could not write session proposal."
				"Server died?");
	}
}

void stop_flow(int id)
{
	if (flow[id].stopped) {
		DEBUG_MSG(3, "flow %d already stopped", id);
		return;
	}

	DEBUG_MSG(3, "stopping flow %d", id);

	FD_CLR(flow[id].sock, &efds_orig);

	close_flow(id);

	flow[id].stopped = 1;
	tsc_gettimeofday(&flow[id].stopped_timestamp);
}

double flow_interpacket_delay(int id)
{
	double delay = 0;

	DEBUG_MSG(5, "flow %d has rate %u", id, flow[id].rate);
	if (flow[id].poisson_distributed) {
		double urand = (double)((random()+1.0)/(RANDOM_MAX+1.0));
		double erand = -log(urand) * 1/(double)flow[id].rate;
		delay = erand;
	} else {
		delay = (double)1/flow[id].rate;
	}

	DEBUG_MSG(5, "new interpacket delay %.6f for flow %d.", delay, id);
	return delay;
}

void read_test_data(int id)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;
	char cbuf[512];
	struct cmsghdr *cmsg;

	for (;;) {
		if (flow[id].read_block_bytes_read == 0)
			DEBUG_MSG(5, "new read block %llu on flow %d",
					flow[id].read_block_count, id);

		iov.iov_base = flow[id].read_block +
			flow[id].read_block_bytes_read;
		iov.iov_len = flow[id].read_block_size -
			flow[id].read_block_bytes_read;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		rc = recvmsg(flow[id].sock, &msg, 0);

		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
			flow[id].read_errors++;
			stop_flow(id);
			return;
		}

		if (rc == 0) {
			DEBUG_MSG(1, "server shut down test socket "
					"of flow %d", id);
			if (!flow[id].server_flow_finished ||
					!flow[id].shutdown)
				error(ERR_WARNING, "Premature shutdown of "
						"server flow");
			flow[id].server_flow_finished = 1;
			if (flow[id].client_flow_finished) {
				DEBUG_MSG(4, "flow %u finished", id);
				stop_flow(id);
			}
			return;
		}

		DEBUG_MSG(4, "flow %d received %u bytes", id, rc);

#if 0
		if (flow[id].server_flow_duration == 0)
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (no two-way)", id);
		else if (server_flow_in_delay(id))
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (too early)", id);
		else if (!server_flow_sending(id))
			error(ERR_WARNING, "flow %d got unexpected data "
					"from server (too late)", id);
#endif

		flow[id].bytes_read_since_last += rc;
		flow[id].bytes_read_since_first += rc;
		flow[id].read_block_bytes_read += rc;
		if (flow[id].read_block_bytes_read >=
				flow[id].read_block_size) {
			assert(flow[id].read_block_bytes_read
					== flow[id].read_block_size);
			flow[id].read_block_bytes_read = 0;
			tsc_gettimeofday(&flow[id].last_block_read);
			flow[id].read_block_count++;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			DEBUG_MSG(2, "flow %d received cmsg: type = %u, len = %u",
					id, cmsg->cmsg_type, cmsg->cmsg_len);
		}

		if (!flow[id].pushy)
			break;
	}
	return;
}

void read_control_data(int id)
{
	int rc = 0;

	for (;;) {
		rc = recv(flow[id].sock_control,
				flow[id].reply_block +
				flow[id].reply_block_bytes_read,
				sizeof(flow[id].reply_block) -
				flow[id].reply_block_bytes_read, 0);
		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
			flow[id].read_errors++;
			stop_flow(id);
			return;
		}

		if (rc == 0) {
			error(ERR_WARNING, "Premature end of test: server "
					"shut down control of flow %d.", id);
			stop_flow(id);
			return;
		}

		flow[id].reply_block_bytes_read += rc;
		if (flow[id].reply_block_bytes_read >=
				sizeof(flow[id].reply_block)) {
			process_reply(id, flow[id].reply_block);
			flow[id].reply_block_bytes_read = 0;
		} else {
			DEBUG_MSG(4, "got partial reply_block for flow %d", id);
		}

	}
	return;
}


void write_test_data(int id)
{
	int rc = 0;

	if (flow[id].stopped)
		return;

	/* Please note: you could argue that the following loop
	   is not necessary as not filling the socket send queue completely
	   would make the next select call return this very socket in wfds
	   and thus sending more blocks would immediately happen. However,
	   calling select with a non-full send queue might make the kernel
	   think we don't have more data to send. As a result, the kernel
	   might trigger some scheduling or whatever heuristics which would
	   not take place if we had written immediately. On the other hand,
	   in case the network is not a bottleneck the loop may take forever. */
	/* XXX: Detect this! */
	for (;;) {
		if (flow[id].write_block_bytes_written == 0) {
			DEBUG_MSG(5, "new write block %llu on flow %d",
					flow[id].write_block_count, id);
			tsc_gettimeofday((struct timeval *)flow[id].write_block);
		}

		rc = write(flow[id].sock,
				flow[id].write_block +
				flow[id].write_block_bytes_written,
				flow[id].write_block_size -
				flow[id].write_block_bytes_written);

		if (rc == -1) {
			if (errno == EAGAIN) {
				DEBUG_MSG(5, "write queue limit hit "
						"for flow %d", id);
				break;
			}
			error(ERR_WARNING, "Premature end of test: %s",
					strerror(errno));
			flow[id].write_errors++;
			stop_flow(id);
			return;
		}

		if (rc == 0) {
			DEBUG_MSG(5, "flow %d sent zero bytes. what does "
					"that mean?", id);
			break;
		}

		DEBUG_MSG(4, "flow %d sent %d bytes of %u (already = %u)", id, rc,
				flow[id].write_block_size,
				flow[id].write_block_bytes_written);
		flow[id].bytes_written_since_first += rc;
		flow[id].bytes_written_since_last += rc;
		flow[id].write_block_bytes_written += rc;
		if (flow[id].write_block_bytes_written >=
				flow[id].write_block_size) {
			flow[id].write_block_bytes_written = 0;
			tsc_gettimeofday(&flow[id].last_block_written);
			flow[id].write_block_count++;

			if (flow[id].rate) {
				time_add(&flow[id].next_write_block_timestamp,
						flow_interpacket_delay(id));
				if (time_is_after(&now, &flow[id].next_write_block_timestamp)) {
					/* TODO: log time_diff and check if
					 * it's growing (queue build up) */
					DEBUG_MSG(3, "incipient congestion on "
							"flow %u (block %llu): "
							"new block scheduled "
							"for %s, %.6lfs before now.",
							id,
							flow[id].write_block_count,
							ctime_us(&flow[id].next_write_block_timestamp),
							time_diff(&flow[id].next_write_block_timestamp, &now));
					flow[id].congestion_counter++;
					if (flow[id].congestion_counter >
							CONGESTION_LIMIT &&
							flow[id].flow_control)
						stop_flow(id);
				}
			}
			if (flow[id].cork && toggle_tcp_cork(flow[id].sock) == -1)
				DEBUG_MSG(4, "failed to recork test socket "
						"for flow %d: %s",
						id, strerror(errno));
		}

		if (!flow[id].pushy)
			break;
	}
	return;
}


void sigint_handler(int sig)
{
	UNUSED_ARGUMENT(sig);

	int id;

	DEBUG_MSG(1, "caught %s", strsignal(sig));
	for (id = 0; id < opt.num_flows; id++)
		stop_flow(id);

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&wfds);

	sigint_caught = 1;
}

void prepare_wfds (int id)
{
	int rc = 0;

	if (client_flow_in_delay(id)) {
		DEBUG_MSG(4, "flow %i not started yet (delayed)", id);
		return;
	}

	if (client_flow_sending(id)) {
		assert(!flow[id].client_flow_finished);
		if (client_flow_block_scheduled(id)) {
			DEBUG_MSG(4, "adding sock of flow %d to wfds", id);
			FD_SET(flow[id].sock, &wfds);
		} else {
			DEBUG_MSG(4, "no block for flow %d scheduled yet", id);
		}
	} else if (!flow[id].client_flow_finished) {
		flow[id].client_flow_finished = 1;
		if (flow[id].shutdown) {
			DEBUG_MSG(4, "shutting down flow %d (WR)", id);
			rc = shutdown(flow[id].sock, SHUT_WR);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown() SHUT_WR failed: %s",
						strerror(errno));
			}
		}
	}

	return;
}

void prepare_rfds (int id)
{
	int rc = 0;

	FD_SET(flow[id].sock_control, &rfds);

	if (!server_flow_in_delay(id) && !server_flow_sending(id)) {
		if (!flow[id].server_flow_finished && flow[id].shutdown) {
			error(ERR_WARNING, "server flow %u missed to shutdown", id);
			rc = shutdown(flow[id].sock, SHUT_RD);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown SHUT_RD "
						"failed: %s", strerror(errno));
			}
			flow[id].server_flow_finished = 1;
		}
	}

	if (flow[id].late_connect && !flow[id].connect_called ) {
		DEBUG_MSG(1, "late connecting test socket "
				"for flow %d after %.3fs delay",
				id, flow[id].client_flow_delay);
		rc = connect(flow[id].sock, flow[id].saddr,
				flow[id].saddr_len);
		if (rc == -1 && errno != EINPROGRESS) {
			error(ERR_WARNING, "Connect failed: %s",
					strerror(errno));
			stop_flow(id);
			return;
		}
		flow[id].connect_called = 1;
		flow[id].mtu = get_mtu(flow[id].sock);
	}

	/* Altough the server flow might be finished we keep the socket in
	 * rfd in order to check for buggy servers */
	if (flow[id].connect_called && !flow[id].server_flow_finished) {
		DEBUG_MSG(4, "adding sock of flow %d to rfds", id);
		FD_SET(flow[id].sock, &rfds);
	}
}

void prepare_fds (void)
{
	int id = 0;

	DEBUG_MSG(3, "preparing fds");

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	for (id = 0; id < opt.num_flows; id++) {
		if (flow[id].stopped)
			continue;

		if ((!flow[id].server_flow_duration ||
					(!server_flow_in_delay(id) &&
					 !server_flow_sending(id))) &&
				(!flow[id].client_flow_duration ||
				 (!client_flow_in_delay(id) &&
				  !client_flow_sending(id)))) {
			close_flow(id);
			continue;
		}

		prepare_wfds(id);
		prepare_rfds(id);

	}

	efds = efds_orig;
}

void grind_flows (void)
{
	int rc = 0;
	int id = 0;
	struct timeval timeout = {0, 0};

	timer_start();

	DEBUG_MSG(1, "starting TCP test...");

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		error(ERR_FATAL, "could not ignore SIGINT: %s", strerror(errno));

	tsc_gettimeofday(&now);

	while (active_flows > 0) {

		timer_check();

		prepare_fds();
		if (!active_flows)
			break;

		timeout.tv_sec = 0;
		timeout.tv_usec = select_timeout;

		DEBUG_MSG(3, "calling select() (timeout = %u)", select_timeout);
		rc = select(maxfd + 1, &rfds, &wfds, &efds, &timeout);
		DEBUG_MSG(3, "select() returned (rc = %d, active_flows = %d)",
				rc, active_flows);
		tsc_gettimeofday(&now);

		if (rc < 0) {
			if (sigint_caught)
				break;
			if (errno == EINTR)
				continue;
			error(ERR_FATAL, "select(): failed: %s",
					strerror(errno));
		}

		if (rc == 0)
			continue;

		for (id = 0; id < opt.num_flows; id++) {

			DEBUG_MSG(6, "checking socks of flow %d.", id);

			if (FD_ISSET(flow[id].sock, &efds)) {
				int error_number;
				socklen_t error_number_size =
					sizeof(error_number);
				DEBUG_MSG(5, "sock of flow %d in efds", id);
				rc = getsockopt(flow[id].sock, SOL_SOCKET,
						SO_ERROR,
						(void *)&error_number,
						&error_number_size);
				if (rc == -1) {
					error(ERR_WARNING, "failed to get "
							"errno for non-blocking "
							"connect: %s",
							strerror(errno));
					stop_flow(id);
					continue;
				}
				if (error_number != 0) {
					fprintf(stderr, "connect: %s\n",
							strerror(error_number));
					stop_flow(id);
				}
			}

			if (FD_ISSET(flow[id].sock, &rfds)) {
				DEBUG_MSG(5, "sock of flow %d in rfds", id);
				read_test_data(id);
			}

			if (FD_ISSET(flow[id].sock_control, &rfds)) {
				DEBUG_MSG(5, "sock_control of flow %d "
						"in rfds", id);
				read_control_data(id);
			}

			if (FD_ISSET(flow[id].sock, &wfds)) {
				DEBUG_MSG(5, "sock of flow %d in wfds", id);
				write_test_data(id);
			}
			DEBUG_MSG(6, "done checking socks of flow %d.", id);
		}
	}
}


void close_flow(int id)
{
#ifdef __LINUX__
	socklen_t opt_len = 0;
#endif

	DEBUG_MSG(2, "closing flow %d.", id);

	if (flow[id].stopped || flow[id].closed)
		return;

#ifdef __LINUX__
	opt_len = sizeof(flow[id].final_cc_alg);
	if (getsockopt(flow[id].sock, IPPROTO_TCP, TCP_CONG_MODULE,
				flow[id].final_cc_alg, &opt_len) == -1) {
		error(ERR_WARNING, "failed to determine congestion control "
				"algorihhm for flow %d: %s: ", id,
				strerror(errno));
		flow[id].final_cc_alg[0] = '\0';
	}

	opt_len = sizeof(flow[id].final_tcp_info);
	if (getsockopt(flow[id].sock, IPPROTO_TCP, TCP_INFO,
				&flow[id].final_tcp_info, &opt_len) == -1) {
		error(ERR_WARNING, "failed to get last tcp_info: %s",
				strerror(errno));
		flow[id].stopped = 1;
	}
#endif

	if (close(flow[id].sock) == -1)
		error(ERR_WARNING, "unable to close test socket: %s",
				strerror(errno));
	if (close(flow[id].sock_control) == -1)
		error(ERR_WARNING, "unable to close control socett: %s",
				strerror(errno));
	flow[id].closed = 1;

	FD_CLR(flow[id].sock, &efds_orig);
	FD_CLR(flow[id].sock, &rfds);
	FD_CLR(flow[id].sock, &wfds);
	FD_CLR(flow[id].sock_control, &rfds);
	maxfd = MAX(maxfd, flow[id].sock);
	maxfd = MAX(maxfd, flow[id].sock_control);

	active_flows--;
}


void close_flows(void)
{
	int id;

	for (id = 0; id < opt.num_flows; id++)
		close_flow(id);

}


struct _mtu_info {
	unsigned mtu;
	char *topology;
} mtu_list[] = {
	{ 65535,	"Hyperchannel" },		/* RFC1374 */
	{ 17914,	"16 MB/s Token Ring" },
	{ 16436,	"Linux Loopback device" },
	{ 16352,	"Darwin Loopback device"},
	{ 8166,		"802.4 Token Bus" },		/* RFC1042 */
	{ 4464,		"4 MB/s Token Ring" },
	{ 4352,		"FDDI" },			/* RFC1390 */
	{ 1500,		"Ethernet/PPP" },		/* RFC894, RFC1548 */
	{ 1492,		"IEEE 802.3" },
	{ 1006,		"SLIP" },			/* RFC1055 */
	{ 576,		"X.25 & ISDN" },		/* RFC1356 */
	{ 296,		"PPP (low delay)" },
};
#define MTU_LIST_NUM	11


char *guess_topology (unsigned mss, unsigned mtu)
{
	int i;

#ifdef IP_MTU
	if (mtu) {
		for (i = 0; i < MTU_LIST_NUM; i++) {
			if (mtu == mtu_list[i].mtu) {
				return (mtu_list[i].topology);
			}
		}
	}
	return "unknown";
#endif

	mtu = 0;
	for (i = 0; i < MTU_LIST_NUM; i++) {
		/* Both, IP and TCP headers may vary in size from 20 to 60 */
		if (((mss + 40) <= mtu_list[i].mtu)
				&& (mtu_list[i].mtu <= (mss + 120))) {
			return (mtu_list[i].topology);
		}
	}

	return "unknown";
}


void prepare_flow(int id)
{
	char buf[1024];
	int rc;
	unsigned to_write;

	DEBUG_MSG(2, "init flow %d", id);

	DEBUG_MSG(3, "connect()");
	flow[id].sock_control =
		name2socket(flow[id].server_name_control,
				flow[id].server_control_port, NULL, NULL, 1);
	read_greeting(flow[id].sock_control);

	to_write = snprintf(buf, sizeof(buf),
			"%s,t,%s,%hu,%hhd,%hhd,%u,%lf,%lf,%u,%u,%hhd,%hhd,%hhd+",
			FLOWGRIND_PROT_CALLSIGN FLOWGRIND_PROT_SEPERATOR FLOWGRIND_PROT_VERSION,
			flow[id].server_name,
			(opt.base_port ? opt.base_port++ : 0),
			opt.advstats, flow[id].so_debug,
			flow[id].server_window_size,
			flow[id].server_flow_delay,
			flow[id].server_flow_duration,
			flow[id].write_block_size,
			flow[id].read_block_size,
			flow[id].pushy,
			flow[id].shutdown,
			flow[id].route_record
			);
	DEBUG_MSG(1, "proposal: %s", buf);
	write_proposal(flow[id].sock_control, buf, to_write);
	read_until_plus(flow[id].sock_control, buf, sizeof(buf));
	DEBUG_MSG(1, "proposal reply: %s", buf);
	rc = sscanf(buf, "%u,%u+", &flow[id].server_data_port,
			&flow[id].server_window_size_real);
	if (rc != 2)
		error(ERR_FATAL, "malformed session response from server");

	if (flow[id].server_window_size != 0 &&
			flow[id].server_window_size_real !=
			flow[id].server_window_size) {
		fprintf(stderr, "warning: server failed to set requested "
				"window size %u, actual = %u\n",
				flow[id].server_window_size,
				flow[id].server_window_size_real);
	}
	flow[id].sock = name2socket(flow[id].server_name,
			flow[id].server_data_port,
			&flow[id].saddr, &flow[id].saddr_len, 0);

	flow[id].client_window_size_real =
		set_window_size(flow[id].sock, flow[id].client_window_size);
	if (flow[id].client_window_size != 0 &&
			flow[id].client_window_size_real !=
			flow[id].client_window_size) {
		fprintf(stderr, "warning: failed to set requested client "
				"window size.\n");
	}

	if (flow[id].cc_alg && set_congestion_control(
				flow[id].sock, flow[id].cc_alg) == -1)
		error(ERR_FATAL, "Unable to set congestion control "
				"algorithm for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].elcn && set_so_elcn(flow[id].sock, flow[id].elcn) == -1)
		error(ERR_FATAL, "Unable to set TCP_ELCN "
				"for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].icmp && set_so_icmp(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set TCP_ICMP "
				"for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].cork && set_tcp_cork(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set TCP_CORK "
				"for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].so_debug && set_so_debug(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set SO_DEBUG "
				"for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].route_record && set_route_record(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set route record "
				"option for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].dscp && set_dscp(flow[id].sock, flow[id].dscp) == -1)
		error(ERR_FATAL, "Unable to set DSCP value"
				"for flow %d: %s", id, strerror(errno));

	flow[id].mss = get_mss(flow[id].sock);

	if (!flow[id].late_connect) {
		DEBUG_MSG(4, "(early) connecting test socket");
		connect(flow[id].sock, flow[id].saddr, flow[id].saddr_len);
		flow[id].connect_called = 1;
		flow[id].mtu = get_mtu(flow[id].sock);
	}

	set_non_blocking(flow[id].sock);
	set_non_blocking(flow[id].sock_control);

	active_flows++;
}

void prepare_flows(void)
{
	int id;
	char headline[200];
	int rc;
	struct utsname me;
	time_t start_ts;
	char start_ts_buffer[26];

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		error(ERR_FATAL, "could not ignore SIGPIPE: %s",
				strerror(errno));
	}

	FD_ZERO(&efds_orig);

	for (id = 0; id < opt.num_flows; id++) {
		unsigned byte_idx;

		prepare_flow(id);

		FD_SET(flow[id].sock, &efds_orig);
		maxfd = (flow[id].sock > maxfd ? flow[id].sock : maxfd);

		/* Allocate memory for writing and reading blocks. */
		/* XXX: Maybe use single malloc for less memory fragmentation? */
		flow[id].write_block = calloc(1, (size_t)flow[id].write_block_size);
		flow[id].read_block = calloc(1, (size_t)flow[id].read_block_size);
		if (flow[id].read_block == NULL || flow[id].write_block == NULL) {
			error(ERR_FATAL, "malloc(): failed");
		}
		if (flow[id].byte_counting)
			for (byte_idx = 0; byte_idx < flow[id].write_block_size;
					byte_idx++)
				*(flow[id].write_block+byte_idx) =
					(unsigned char)(byte_idx & 0xff);
		flow[id].read_block_bytes_read = 0;
		flow[id].write_block_bytes_written = 0;
	}

	rc = uname(&me);
	start_ts = time(NULL);
	ctime_r(&start_ts, start_ts_buffer);
	start_ts_buffer[24] = '\0';
	snprintf(headline, sizeof(headline), "# %s: originating host = %s, "
			"number of flows = %d, reporting interval = %.2fs, "
			"[tput] = %s (%s)\n",
			(start_ts == -1 ? "(time(NULL) failed)" : start_ts_buffer),
			(rc == -1 ? "(unknown)" : me.nodename),
			opt.num_flows, opt.reporting_interval,
			(opt.mbyte ? "2**20 bytes/second": "10**6 bit/second"),
			FLOWGRIND_VERSION);
	log_output(headline);
	log_output(opt.mbyte ? TCP_REPORT_HDR_STRING_MBYTE :
			TCP_REPORT_HDR_STRING_MBIT);
}

void parse_cmdline(int argc, char **argv)
{
	int rc = 0;
	int ch = 0;
	int id = 0;
	int error = 0;
	char *sepptr = NULL;
	char *tok = NULL;
	int current_flow_ids[MAX_FLOWS] =  {-1};
	int max_flow_specifier = 0;
	unsigned max_flow_rate = 0;
	char unit = 0, type = 0, distribution = 0;
	int optint = 0;
	unsigned optunsigned = 0;
	double optdouble = 0.0;
	int argread = 0;
	enum {
		SOURCE = 0,
		DESTINATION
	};
	char *const token[] = {
		[SOURCE] = "s",
		[DESTINATION] = "d",
		NULL
	};
	char *subopts;
	char *value;

	#define ASSIGN_FLOW_OPTION(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					flow[id].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					flow[current_flow_ids[id]].PROPERTY_NAME = \
					(PROPERTY_VALUE); \
				} \
			}

	current_flow_ids[0] = -1;

	while ((ch = getopt(argc, argv, "ade:h:i:l:mn:op:qvw")) != -1)
		switch (ch) {

		case 'a':
			opt.advstats = 1;
			break;

		case 'd':
			increase_debuglevel();
			break;

		case 'e':
			opt.log_filename_prefix = optarg;
			break;

		case 'h':
			if(strcmp(optarg, "sockopt")) {
				printf("Illegal subargument: %s\n", optarg);
				usage();
			}
			else {
				usage_sockopt();
			}
			break;

		case 'i':
			rc = sscanf(optarg, "%lf", &opt.reporting_interval);
			if (rc != 1 || opt.reporting_interval <= 0) {
				fprintf(stderr, "reporting interval must be "
					"a positive number (in seconds)\n");
				usage();
			}
			break;

		case 'l':
			opt.log_filename = optarg;
			break;

		case 'm':
			opt.mbyte = 1;
			break;

		case 'n':
			rc = sscanf(optarg, "%u", &optunsigned);
			if (rc != 1 || optunsigned > MAX_FLOWS) {
				fprintf(stderr, "number of test flows must "
						"be within [1..%d]\n", MAX_FLOWS);
				usage();
			}
			opt.num_flows = (short)optunsigned;
			break;

		case 'o':
			opt.clobber = 1;
			break;

		case 'p':
			rc = sscanf(optarg, "%u", &optunsigned);
                        if (rc != 1 || optunsigned > USHRT_MAX) {
				fprintf(stderr, "base port must be within "
						"[1..%d]\n", USHRT_MAX);
				usage();
			}
			opt.base_port = (short)optunsigned;
			break;

		case 'q':
			opt.dont_log_stdout = 1;
			break;

		case 'v':
			fprintf(stderr, "flowgrind version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		case 'w':
			opt.dont_log_logfile = 0;
			break;

		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (*argv) {
		fprintf(stderr, "illegal argument: %s\n", *argv);
		usage();
	}
#undef ASSIGN_FLOW_OPTION

	/* Sanity checking flow options */
	if (opt.num_flows <= max_flow_specifier) {
		fprintf(stderr, "Must not specify option for non-existing flow.\n");
		error = 1;
	}
	for (id = 0; id<opt.num_flows; id++) {
		DEBUG_MSG(4, "sanity checking parameter set of flow %d.", id);
		if (flow[id].server_flow_duration > 0 && flow[id].late_connect &&
				flow[id].server_flow_delay <
				flow[id].client_flow_delay) {
			fprintf(stderr, "Server flow %d starts earlier than client "
					"flow while late connecting.\n", id);
			error = 1;
		}
		if (flow[id].client_flow_delay > 0 &&
				flow[id].client_flow_duration == 0) {
			fprintf(stderr, "Client flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (flow[id].server_flow_delay > 0 &&
				flow[id].server_flow_duration == 0) {
			fprintf(stderr, "Server flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (!flow[id].server_flow_duration &&
				!flow[id].client_flow_duration) {
			fprintf(stderr, "Server and client flow have both "
					"zero runtime for flow %d.\n", id);
			error = 1;
		}
		if (flow[id].two_way) {
			if (flow[id].server_flow_duration != 0 &&
					flow[id].client_flow_duration !=
					flow[id].server_flow_duration) {
				fprintf(stderr, "Server flow duration "
						"specified albeit -2.\n");
				error = 1;
			}
			flow[id].server_flow_duration =
				flow[id].client_flow_duration;
			if (flow[id].server_flow_delay != 0 &&
					flow[id].server_flow_delay !=
					flow[id].client_flow_delay) {
				fprintf(stderr, "Server flow delay specified "
						"albeit -2.\n");
				error = 1;
			}
			flow[id].server_flow_delay = flow[id].client_flow_delay;
		}
		if (flow[id].rate_str) {
			unit = type = distribution = 0;
			/* last %c for catching wrong input... this is not nice. */
			rc = sscanf(flow[id].rate_str, "%lf%c%c%c%c",
					&optdouble, &unit, &type,
					&distribution, &unit);
			if (rc < 1 || rc > 4) {
				fprintf(stderr, "malformed rate for flow %u.\n", id);
				error = 1;
			}

			if (optdouble == 0.0) {
				flow[id].rate_str = NULL;
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
				optdouble /= flow[id].write_block_size;
				if (optdouble < 1) {
					fprintf(stderr, "client block size "
							"for flow %u is too "
							"big for specified "
							"rate.\n", id);
					error = 1;
				}
				break;

			case 'B':
				/* Is default */
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
			flow[id].rate = optdouble;

			switch (distribution) {
			case 0:
			case 'p':
				flow[id].poisson_distributed = 0;
				break;

			case 'P':
				flow[id].poisson_distributed = 1;
				break;

			default:
				fprintf(stderr, "illegal distribution specifier "
						"in rate for flow %u.\n", id);
			}
		}
		if (flow[id].flow_control && !flow[id].rate_str) {
			fprintf(stderr, "flow %d has flow control enabled but "
					"no rate.", id);
			error = 1;
		}
	}

	if (error) {
#ifdef DEBUG
		DEBUG_MSG(1, "Skipping errors discovered by sanity checks.");
#else
		exit(EXIT_FAILURE);
#endif
	}

	if (max_flow_rate > 0) {
		select_timeout = 1e6/max_flow_rate/2;
		if (select_timeout > DEFAULT_SELECT_TIMEOUT)
			select_timeout = DEFAULT_SELECT_TIMEOUT;
		DEBUG_MSG(4, "setting select timeout = %uus", select_timeout);
	}
}


int main(int argc, char *argv[])
{
	init_options_defaults();
	init_flows_defaults();
	parse_cmdline(argc, argv);
	init_logfile();
	prepare_flows();
	grind_flows();
	report_final();
	close_flows();
	shutdown_logfile();
	exit(0);
}
