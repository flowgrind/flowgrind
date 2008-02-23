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

#ifndef SVNVERSION
#define SVNVERSION "(unknown)"
#endif

#ifndef SOL_IP
#ifdef IPPROTO_IP
#define SOL_IP			IPPROTO_IP
#endif
#endif

#ifndef SOL_TCP
#ifdef IPPROTO_TCP
#define SOL_TCP			IPPROTO_TCP
#endif
#endif

#ifdef __LINUX__
#include <linux/tcp.h>
#ifndef TCP_CONG_MODULE
#define TCP_CONG_MODULE 13
#endif
#else
#include <netinet/tcp.h>
#endif 

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

#define ASSIGN_MIN(s, c) if ((s)>(c)) (s) = (c)
#define ASSIGN_MAX(s, c) if ((s)<(c)) (s) = (c)

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
			"Usage: flowgrind [general options] [flow options]\n\n"

			"flowgrind allows you to generate traffic among hosts in your network.\n\n"

			"General options:\n"
				"\t-m #\t\tnumber of test flows (default: 1)\n"
				"\t-i #.#\t\treporting interval in seconds (default: 0.05s)\n"
				"\t-M\t\treport in 2**20 bytes/second (default: 10**6 bit/sec)\n"
#ifdef HAVE_LIBPCAP
				"\t-S\t\tadvanced statistics (pcap))\n"
#endif
				"\t-q\t\tdo not log to screen (default: off)\n"
				"\t-Q\t\tdo not log to logfile (default: off)\n"
				"\t-L NAME\t\tuse log filename NAME {default: timestamp)\n"
				"\t-P PRE\t\tprepend prefix PRE to log filename (default: \"%s\")\n"
				"\t-C\t\tclobber existing log files (default: don't)\n"
				"\t-O PORT\t\tuse PORT as base port number of test flows (default: none)\n"
#ifdef DEBUG
				"\t-D\t\tincrease debugging verbosity\n"
#endif
				"\t-V\t\tprint version information and exit\n"
				"\n"

			"Flow options:\n"
				"\t-H host[/control host][,port]\n"
				"\t\t\ttest against host. Optional control \n"
				"\t\t\thost may be specified to handle connection\n"
				"\t\t\tsetup via another interface/route.\n"
				"\t-2\t\tgenerate two-way traffic (default: off)\n"
				"\t-t #.#\t\tflow duration, in seconds (default: 10s),\n"
				"\t\t\tnegative meaning don't stop.\n"
				"\t-y #.#\t\tinitial delay before client flow starts\n"
				"\t-r #.#[z|k|M|G][b|B][p|P]\n"
				"\t\t\tsend at specified rate per second, where:\n"
				"\t\t\tz = 2**0, k = 2**10, M = 2**20, G = 2**30,\n"
				"\t\t\tb = bytes per second, B = blocks per second (default)\n"
				"\t\t\tp = periodic, P = Poisson distributed (default)\n"
				"\t-f\t\tstop flow if it is experiencing local congestion\n"
				"\t-w #\t\tsender and receiver window clamp, in bytes (default: unset)\n"
				"\t-b #\t\tblock size (default: 8192B)\n"
#ifdef __LINUX__
				"\t-c ALG\t\tuse congestion control algorithm ALG\n"
				"\t-k\t\tset TCP_CORK on test socket\n"
#endif
				"\t-E\t\tenable TCP_ELCN on test socket\n"
				"\t-e\t\tdisable TCP_ELCN on test socket\n"
				"\t-I\t\tset TCP_ICMP on test socket\n"
				"\t-g\t\tset SO_DEBUG on test socket\n"
				"\t-R\t\tset ROUTE RECORD on test socket\n"
				"\t-d DSCP\t\tDSCP value for TOS byte (default: unset)\n"
				"\t-l\t\tconnect() socket immediately before sending (late)\n"
				"\t-n\t\tshutdown() each socket direction after test flow\n"
				"\t-a\t\tenumerate bytes in payload (default: don't)\n"
				"\t-p\t\tDo not iterate through select to continue sending in case\n"
				"\t\t\tblock size did not suffice to fill sending queue (pushy)\n"
				"\t-s\t\tSummarize only, skip interval reports\n"
				"\n"
			
			"Options -t, -y, -w, -l have uppercase versions for the respective server setting.\n\n"
			"Flow options following -F #[,#...] apply to flow #[,#...] only (-1 = all flows).\n"
			"-x creates a new flow (with current properties), subsequent flow options are \n"
			"applied to this flow only.\n"
			"\n",
			opt.log_filename_prefix
		);
	exit(1);
}


void init_options_defaults(void)
{
	opt.num_flows = 1;
	opt.reporting_interval = 0.05;
	opt.log_filename_prefix = "flowlog-";
}


void init_flows_defaults(void)
{
	int id = 1;

	for (id = 0; id<MAX_FLOWS; id++) {
		flow[id].server_name = "localhost";
		flow[id].server_name_control = "localhost";
		flow[id].server_control_port = DEFAULT_LISTEN_PORT;
		flow[id].mss = 0;

		flow[id].client_flow_duration = 0.0;
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

	DEBUG_MSG(2, "logging to %s", log_filename);

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
	char header_buffer[300] = "";
	char header_nibble[300] = "";

#ifdef __LINUX__
	int rc;

	struct tcp_info info;
	socklen_t info_len = sizeof(struct tcp_info);

	char cc_buf[30];
	socklen_t cc_buf_len = sizeof(cc_buf);
#endif
	int id;
	double thruput;

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
		CATC("ws = %u/%u (%u/%u), bs = %u/%u, delay = %.2fs/%.2fs, "
				"duration = %.2fs/%.2fs, thruput = %.6fM%c/s "
				"(%llu blocks)", 
				flow[id].client_window_size_real,
				flow[id].server_window_size_real,
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
		rc = getsockopt( flow[id].sock, IPPROTO_TCP,
				TCP_CONG_MODULE, cc_buf, &cc_buf_len);
		if (rc == -1) {
			CATC("cc = (failed")
				if (flow[id].cc_alg) 
					CATC(" was set to %s", flow[id].cc_alg);
			CAT(")");
		} else
			CATC("cc = %s", cc_buf);
		if (!flow[id].cc_alg)
			CAT(" (default)");
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
			info = flow[id].last_tcp_info;
		else {
			rc = getsockopt(flow[id].sock, SOL_TCP, TCP_INFO,
					&info, &info_len);
			if (rc == -1)
				error(ERR_WARNING, "getsockopt() failed: %s",
						strerror(errno));
		}
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
				info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh,
				info.tcpi_unacked, info.tcpi_sacked,
				info.tcpi_lost, info.tcpi_total_retrans,
				info.tcpi_fackets, info.tcpi_reordering,
				info.tcpi_rtt, info.tcpi_rttvar, info.tcpi_rto
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
			info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh,
			info.tcpi_unacked, info.tcpi_sacked,
			info.tcpi_lost, info.tcpi_retrans,
			info.tcpi_fackets, info.tcpi_reordering,
			info.tcpi_rtt, info.tcpi_rttvar, info.tcpi_rto
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

	rc = getsockopt(flow[id].sock, SOL_TCP, TCP_INFO, &info, &info_len);
	if (rc == -1)
		error(ERR_WARNING, "getsockopt() failed");
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


int
name2socket(char *server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp, char do_connect)
{
	int fd, n;
	struct addrinfo hints, *res, *ressave;
	char service[7];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(service, sizeof(service), "%u", port);

	if ((n = getaddrinfo(server_name, service, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(n));
		error(ERR_FATAL, "getaddrinfo(): failed");
	}
	ressave = res;

	do {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;	/* ignore this one */

		if (!do_connect)
			break;
		else if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;
		error(ERR_WARNING, "failed to connect to %s: %s",
				server_name, strerror(errno));
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		error(ERR_FATAL, "could not establish connection to server");
	}

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
	size_t greetlen = strlen(FLOWGRIND_GREETING);

	rc = read_exactly(s, buf, greetlen);
	if (rc != (int) greetlen) {
		if (rc == -1)
			error(ERR_FATAL, "read: %s", strerror(errno));
		error(ERR_FATAL, "Server greeting is wrong in length. "
				"Not flowgrind?");
	}
	rc = strncmp(buf + strlen(FLOWGRIND_CALLSIGN FLOWGRIND_SEPERATOR),
			FLOWGRIND_VERSION, strlen(FLOWGRIND_VERSION));
	if (rc < 0)
		error(ERR_FATAL, "flowgrind client outdated for this server.");
	if (rc > 0)
		error(ERR_FATAL, "flowgrind server outdated for this client.");

	if (strncmp(&buf[greetlen - 1], FLOWGRIND_EOL, strlen(FLOWGRIND_EOL))) {
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

void
stop_flow(int id)
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
		rc = recvmsg(flow[id].sock, &msg, MSG_DONTROUTE);
				
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

int
read_control_data(int id)
{
	int rc;

	for (;;) {
		rc = recv(flow[id].sock_control,
				flow[id].reply_block + flow[id].reply_block_bytes_read,
				sizeof(flow[id].reply_block) - flow[id].reply_block_bytes_read, 0);
		if (rc == -1) {
			if (errno == EAGAIN)
				break;
			perror(flow[id].server_name);
			error(ERR_WARNING, "premature end of test");
			flow[id].read_errors++;
			stop_flow(id);
			return 0;
		} else if (rc == 0) { 
			DEBUG_MSG(1, "server shut down control of flow %d", id);
			stop_flow(id);
			return 1;
		}
		flow[id].reply_block_bytes_read += rc;
		if (flow[id].reply_block_bytes_read >= sizeof(flow[id].reply_block)) {
			process_reply(id, flow[id].reply_block);
			flow[id].reply_block_bytes_read = 0;
		} else {
			DEBUG_MSG(4, "got partial reply_block for flow %d", id);
		}

	}
	return 1;
}


int
write_test_data(int id)
{
	int rc;

	/* Please note: you could argue that the following while loop
	   is not necessary as not filling the socket send queue completely
	   would make the next select call return this very socket in wfds
	   and thus sending more blocks would immediately happen. However,
	   calling select with a non-full send queue might make the kernel
	   think we don't have more data to send. As a result, the kernel
	   might trigger some scheduling or whatever heuristics which would
	   not take place if we had written immediately. On the other hand,
	   in case the network is not a bottleneck the loop may take forever. */
	for (;;) {
		if (flow[id].write_block_bytes_written == 0) {
			DEBUG_MSG(5, "new write block %llu on flow %d", flow[id].write_block_count, id);
			tsc_gettimeofday((struct timeval *)flow[id].write_block);
		}

		rc = write(flow[id].sock,
				flow[id].write_block + flow[id].write_block_bytes_written,
				flow[id].write_block_size - flow[id].write_block_bytes_written);

		if (rc == -1) {
			if (errno == EAGAIN) {
				DEBUG_MSG(5, "write queue limit hit for flow %d", id);
				break;
			}
			perror(flow[id].server_name);
			error(ERR_WARNING, "premature end of test");
			flow[id].write_errors++;
			stop_flow(id);
			return 0;
		} else if (rc == 0) {
			DEBUG_MSG(5, "flow %d sent zero bytes. what does that mean?", id);
			break;
		}
		DEBUG_MSG(4, "flow %d sent %d bytes of %u (already = %u)", id, rc, 
				flow[id].write_block_size, flow[id].write_block_bytes_written);
		flow[id].bytes_written_since_first += rc;
		flow[id].bytes_written_since_last += rc;
		flow[id].write_block_bytes_written += rc;
		if (flow[id].write_block_bytes_written >= flow[id].write_block_size) {
			assert(flow[id].write_block_bytes_written == flow[id].write_block_size);
			flow[id].write_block_bytes_written = 0;
			tsc_gettimeofday(&flow[id].last_block_written);
			flow[id].write_block_count++;
			if (flow[id].rate) {
				time_add(&flow[id].next_write_block_timestamp, flow_interpacket_delay(id));
				if (time_is_after(&now, &flow[id].next_write_block_timestamp)) {
					/* TODO: log time_diff and check if it's growing (queue build up) */
					DEBUG_MSG(3, "incipient congestion on flow %u (block %llu): new block scheduled"
						" for %s, %.6lfs before now.", id, flow[id].write_block_count,
						ctime_us(&flow[id].next_write_block_timestamp), 
						time_diff(&flow[id].next_write_block_timestamp, &now));
					flow[id].congestion_counter++;
					if (flow[id].congestion_counter > CONGESTION_LIMIT && flow[id].flow_control)
						stop_flow(id);
				}
			}
		}
		if (!flow[id].pushy)
			break;
	} 
	return 1;
}


void sigint_handler(int sig)
{
	int id;

	DEBUG_MSG(1, "caught %s", strsignal(sig));
	for (id = 0; id < opt.num_flows; id++)
		stop_flow(id);

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&wfds);

	sigint_caught = 1;
}


void grind_flows (void)
{
	int rc = 0;
	int id = 0;
	struct timeval timeout = {0, 0};

	timer_start();

	DEBUG_MSG(1, "starting TCP test...");

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		perror("signal(SIGINT, SIG_IGN)");
		error(ERR_FATAL, "could not ignore SIGINT");
	}

	tsc_gettimeofday(&now);

	while (active_flows > 0) {

		timer_check();

		DEBUG_MSG(3, "preparing select()");

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		for (id = 0; id < opt.num_flows; id++) {
			if (flow[id].stopped)
				continue;

			FD_SET(flow[id].sock_control, &rfds);

			if (client_flow_in_delay(id)) {
				DEBUG_MSG(4, "flow %i not started yet (delayed)", id);
			} else {
				if (flow[id].late_connect 
						&& !flow[id].connect_called ) {
					DEBUG_MSG(1, "(late) connecting test socket for flow %d after %.3fs delay", id, flow[id].client_flow_delay);
					rc = connect(flow[id].sock, 
							flow[id].saddr, 
							flow[id].saddr_len);
					if (rc == -1 && errno != EINPROGRESS) {
						perror("connect");
						error(ERR_WARNING, "connect failed");
						stop_flow(id);
					}
					flow[id].connect_called = 1;
					flow[id].mtu = get_mtu(flow[id].sock);
				}
				if (client_flow_sending(id)) {
					if (client_flow_block_scheduled(id)) {
						DEBUG_MSG(4, "adding sock of flow %d to wfds", id);
						FD_SET(flow[id].sock, &wfds);
					} else
						DEBUG_MSG(4, "no block for flow %d scheduled yet", id);
				} else if (!flow[id].client_flow_finished) {
					flow[id].client_flow_finished = 1;
					if (flow[id].shutdown) {
						rc = shutdown(flow[id].sock, SHUT_WR);
						if (rc == -1) {
							perror("shutdown");
							error(ERR_WARNING, "shutdown SHUT_WR failed");
						}
					}
					if (flow[id].server_flow_finished) {
						DEBUG_MSG(4, "flow %u finished", id);
						active_flows--;
					}
				}
			} 

			if (!flow[id].late_connect || time_is_after(&now, &flow[id].client_flow_start_timestamp)) {
				DEBUG_MSG(4, "adding sock of flow %d to rfds", id);
				FD_SET(flow[id].sock, &rfds);
			}

			/* Check for finished server flows */
			if (flow[id].server_flow_duration >= 0 
					&& time_is_after(&now, 
						&flow[id].server_flow_stop_timestamp)) {
				if (!flow[id].server_flow_finished) {
					flow[id].server_flow_finished = 1;
					if (flow[id].shutdown) {
						rc = shutdown(flow[id].sock, SHUT_RD);
						if (rc == -1) {
							perror("shutdown");
							error(ERR_WARNING, "shutdown SHUT_RD failed");
						}
					}
					if (flow[id].client_flow_finished) {
						DEBUG_MSG(4, "flow %u finished", id);
						active_flows--;
					}
				}
			}
		}

		efds = efds_orig;
		timeout.tv_sec = 0;
		timeout.tv_usec = select_timeout;

		DEBUG_MSG(3, "calling select() (timeout = %u)", select_timeout);
		rc = select(maxfd + 1, &rfds, &wfds, &efds, &timeout);
		DEBUG_MSG(3, "select() returned (rc = %d, active_flows = %d)", rc, active_flows)

		tsc_gettimeofday(&now);

		if (rc < 0) {
			if (sigint_caught)
				break;
			if (errno == EINTR)
				continue;
			perror("select");
			error(ERR_FATAL, "select(): failed");
			/* NOTREACHED */
		}

		if (rc > 0) {
			for (id = 0; id < opt.num_flows; id++) {

				DEBUG_MSG(6, "checking socks of flow %d.", id);

				if (FD_ISSET(flow[id].sock, &efds)) {
					int error_number;
					socklen_t error_number_size = sizeof(error_number);
					DEBUG_MSG(5, "sock of flow %d in efds", id);
					rc = getsockopt(flow[id].sock, SOL_SOCKET,
							SO_ERROR,
							(void *)&error_number,
							&error_number_size);
					if (rc == -1) {
						perror("getsockopt");
						error(ERR_WARNING, "failed to get errno for non-blocking connect");
					} else if (error_number == 0)
						goto check_next;
					else
						fprintf(stderr, "connect: %s\n", strerror(error_number));
					stop_flow(id);
					break;
				}

check_next:
				if (FD_ISSET(flow[id].sock, &rfds)) {
					DEBUG_MSG(5, "sock of flow %d in rfds", id);
					if (!read_test_data(id)) {
						DEBUG_MSG(5, "read_test_data for flow %d failed", id);
						break;
					}
				}

				if (FD_ISSET(flow[id].sock_control, &rfds)) {
					DEBUG_MSG(5, "sock_control of flow %d in rfds", id);
					if (!read_control_data(id)) {
						DEBUG_MSG(5, "read_control data for flow %d failed", id);
						break;
					}
				}

				if (FD_ISSET(flow[id].sock, &wfds)) {
					DEBUG_MSG(5, "sock of flow %d in wfds", id);
					if (!write_test_data(id)) {
						DEBUG_MSG(5, "write_test_data for flow %d failed", id);
						break;
					}
				}

				DEBUG_MSG(6, "done checking socks of flow %d.", id);
			}
		}
	}
}


void close_flow(int id)
{
	if (flow[id].stopped)
		return;

	if (close(flow[id].sock) == -1)
		error(ERR_WARNING, "unable to close test socket.");
	if (close(flow[id].sock_control) == -1)
		error(ERR_WARNING, "unable to close control socket.");
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
	int opt_on = 1;

	DEBUG_MSG(2, "init flow %d", id)

	DEBUG_MSG(3, "connect()");
	flow[id].sock_control = name2socket(flow[id].server_name_control, flow[id].server_control_port, NULL, NULL, 1);
	read_greeting(flow[id].sock_control);
	to_write = snprintf(buf, sizeof(buf), "%s,t,%s,%hu,%u,%lf,%lf,%u,%u,%hhd,%hhd,%hhd+", 
		FLOWGRIND_VERSION, 
		flow[id].server_name, 
		(opt.base_port ? opt.base_port++ : 0), 
		flow[id].server_window_size, 
		flow[id].server_flow_delay, 
		flow[id].server_flow_duration,
		flow[id].write_block_size, 
		flow[id].read_block_size,
		flow[id].pushy,
		flow[id].shutdown,
		flow[id].route_record
		);
	DEBUG_MSG(1, "proposal: %s", buf)
	write_proposal(flow[id].sock_control, buf, to_write);
	read_until_plus(flow[id].sock_control, buf, sizeof(buf));
	DEBUG_MSG(1, "proposal reply: %s", buf)
	rc = sscanf(buf, "%u,%u+", &flow[id].server_data_port, &flow[id].server_window_size_real);
	if (rc != 2)
		error(ERR_FATAL, "malformed session response from server");

	if (flow[id].server_window_size != 0 && flow[id].server_window_size_real != flow[id].server_window_size) {
		fprintf(stderr, "warning: server failed to set requested window size %u, "
			"actual = %u\n", flow[id].server_window_size, flow[id].server_window_size_real);
	}
	flow[id].sock = name2socket(flow[id].server_name, flow[id].server_data_port, &flow[id].saddr, &flow[id].saddr_len, 0);


	flow[id].client_window_size_real = set_window_size(flow[id].sock, flow[id].client_window_size);
	if (flow[id].client_window_size != 0 && flow[id].client_window_size_real != flow[id].client_window_size) {
		fprintf(stderr, "warning: failed to set requested client window size. \n");
	}

	if (flow[id].cc_alg) {
#ifdef __LINUX__
		int opt_len = strlen(flow[id].cc_alg);
#ifndef TCP_CONG_MODULE
#define TCP_CONG_MODULE 13
#endif
		rc = setsockopt( flow[id].sock, IPPROTO_TCP, TCP_CONG_MODULE,
					flow[id].cc_alg, opt_len );
		if (rc == -1) { 
			fprintf(stderr, "Unable to set congestion control algorithm for flow id = %i\n", id);
			error(ERR_FATAL, "setsockopt() failed.");
		}
#else
		error(ERR_FATAL, "Setting congestion control algorithm only supported on Linux.");
#endif
	}

	if (flow[id].elcn) {
#ifndef TCP_ELCN
#define TCP_ELCN 20
#endif
		rc = setsockopt( flow[id].sock, IPPROTO_TCP, TCP_ELCN, &flow[id].elcn, sizeof(flow[id].elcn));
		if (rc == -1) { 
			fprintf(stderr, "Unable to set TCP_ELCN for flow id = %i\n", id);
			error(ERR_FATAL, "setsockopt() failed.");
		}
	}

	if (flow[id].icmp) {
#ifndef TCP_ICMP
#define TCP_ICMP 21
#endif
		rc = setsockopt( flow[id].sock, IPPROTO_TCP, TCP_ICMP, &flow[id].icmp, sizeof(flow[id].icmp));
		if (rc == -1) { 
			fprintf(stderr, "Unable to set TCP_ICMP for flow id = %i\n", id);
			error(ERR_FATAL, "setsockopt() failed.");
		}
	}

	if (flow[id].cork) {
#ifdef __LINUX__
		rc = setsockopt( flow[id].sock, IPPROTO_TCP, TCP_CORK, &opt_on, sizeof(opt_on));
		if (rc == -1) { 
			fprintf(stderr, "Unable to set TCP_CORK for flow id = %i\n", id);
			error(ERR_FATAL, "setsockopt() failed.");
		}
#else
		error(ERR_FATAL, "TCP_CORK cannot be set on OS other than Linux.");
#endif
	}

	if (flow[id].so_debug) {
		rc = setsockopt( flow[id].sock, SOL_IP, SO_DEBUG, &opt_on, sizeof(opt_on));
		if (rc == -1) { 
			fprintf(stderr, "Unable to set SO_DEBUG for flow id = %i\n", id);
			error(ERR_FATAL, "setsockopt() failed.");
		}
	}

	if (flow[id].route_record) {
		set_route_record(flow[id].sock);
	}

	if (flow[id].dscp) {
		rc = set_dscp(flow[id].sock, flow[id].dscp);
		if (rc == -1)
			error(ERR_FATAL, "Unable to set DSCP value.");
	}

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
		perror("signal(SIGPIPE, SIG_IGN)");
		error(ERR_FATAL, "could not ignore SIGPIPE");
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
			for (byte_idx = 0; byte_idx < flow[id].write_block_size; byte_idx++)
				*(flow[id].write_block+byte_idx) = (unsigned char)(byte_idx & 0xff);
		flow[id].read_block_bytes_read = flow[id].write_block_bytes_written = 0;
	}
	
	rc = uname(&me);
	start_ts = time(NULL);
	ctime_r(&start_ts, start_ts_buffer);
	start_ts_buffer[24] = '\0';
	snprintf(headline, sizeof(headline), "# %s: originating host = %s, number of flows = %d, reporting interval = %.2fs, [tput] = %s (%s)\n",
			(start_ts == -1 ? "(time(NULL) failed)" : start_ts_buffer), (rc == -1 ? "(unknown)" : me.nodename), 
			opt.num_flows, opt.reporting_interval, (opt.mbyte ? "2**20 bytes/second": "10**6 bit/second"), SVNVERSION);
	log_output(headline);
	log_output(opt.mbyte ? TCP_REPORT_HDR_STRING_MBYTE : TCP_REPORT_HDR_STRING_MBIT);
}

void parse_cmdline(int argc, char **argv)
{
	int rc = 0;
	int ch = 0;
	int id = 0;
	char *sepptr = NULL;
	char *tok = NULL;
	int current_flow_ids[MAX_FLOWS] =  {-1};
	int max_flow_specifier = 0;
	unsigned max_flow_rate = 0;
	char unit = 0, type = 0, distribution = 0;
	int optint = 0;
	unsigned optunsigned = 0;
	double optdouble = 0.0;

#define ASSIGN_FLOW_OPTION(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					flow[id].PROPERTY_NAME = (PROPERTY_VALUE); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					flow[current_flow_ids[id]].PROPERTY_NAME = (PROPERTY_VALUE); \
				} \
			}

	current_flow_ids[0] = -1;

	while ((ch = getopt(argc, argv, "2ab:B:Cc:Dd:EeF:f:ghH:Ii:lL:Mm:nO:P:pQqSRr:st:T:Uu:W:w:VxY:y:")) != -1)
		switch (ch) {
		case '2':
			ASSIGN_FLOW_OPTION(two_way, 1)
			break;

		case 'a':
			ASSIGN_FLOW_OPTION(byte_counting, 1)
			break;

		case 'b':
			rc = sscanf(optarg, "%u", &optunsigned);
                        if (rc != 1) {
				fprintf(stderr, "block size must be a positive integer (in bytes)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(write_block_size, optunsigned)
			break;

		case 'B':
			rc = sscanf(optarg, "%u", &optunsigned);
                        if (rc != 1) {
				fprintf(stderr, "block size must be a positive integer (in bytes)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(read_block_size, optunsigned)
			break;

		case 'c':
			ASSIGN_FLOW_OPTION(cc_alg, optarg)
			break;

		case 'C':
			opt.clobber = 1;
			break;

		case 'D':
			debug_level++;
			break;

		case 'd':
			rc = sscanf(optarg, "%x", &optint);
			if (rc != 1 || (optint & ~0x3f)) {
				fprintf(stderr, "malformed differentiated service code point.\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(dscp, optint);
			break; 

		case 'E':
			ASSIGN_FLOW_OPTION(elcn, 2)
			break;

		case 'e':
			ASSIGN_FLOW_OPTION(elcn, 1)
			break;

		case 'F':
			tok = strtok(optarg, ",");
			id = 0;
			while (tok) {
				rc = sscanf(tok, "%d", &optint);
				if (rc != 1) {
					fprintf(stderr, "malformed flow specifier\n");
					usage();
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

		case 'f':
			ASSIGN_FLOW_OPTION(flow_control, 1);
			break;

		case 'g':
			ASSIGN_FLOW_OPTION(so_debug, 1)
			break;

		case 'h':
			usage();
			break;

		case 'H':
			ASSIGN_FLOW_OPTION(server_name, optarg)
			sepptr = strchr(optarg, '/');
			if (sepptr == NULL) {
				ASSIGN_FLOW_OPTION(server_name_control, optarg)
			} else {
				*sepptr = '\0';
				ASSIGN_FLOW_OPTION(server_name_control, sepptr + 1)
			}
			sepptr = strchr(optarg, ',');
			if (sepptr == NULL) {
				ASSIGN_FLOW_OPTION(server_control_port, DEFAULT_LISTEN_PORT)
			} else {
				optint = atoi(optarg);
				if (optint < 1) {
					fprintf(stderr, "invalid port\n");
					usage();
				}
				*sepptr = '\0';
				ASSIGN_FLOW_OPTION(server_control_port, optint)
			}
			break;

		case 'I':
			ASSIGN_FLOW_OPTION(icmp, 1)
			break;

		case 'i':
			rc = sscanf(optarg, "%lf", &opt.reporting_interval);
			if (rc != 1 || opt.reporting_interval <= 0) {
				fprintf(stderr, "reporting interval must be "
					"a positive number (in seconds)\n");
				usage();
			}
			break;

		case 'k':
			ASSIGN_FLOW_OPTION(cork, 1)
			break;

		case 'L':
			opt.log_filename = optarg;
			break;

		case 'l':
			ASSIGN_FLOW_OPTION(late_connect, 1)
			break;

		case 'm':
			rc = sscanf(optarg, "%u", &optunsigned);
                        if (rc != 1 || optunsigned > MAX_FLOWS) {
				fprintf(stderr, "number of test flows must be within [1..%d]\n", MAX_FLOWS);
				usage();
			}
			opt.num_flows = (short)optunsigned;
			break;

		case 'M':
			opt.mbyte = 1;
			break;

		case 'n':
			ASSIGN_FLOW_OPTION(shutdown, 1);
			break;

		case 'O':
			rc = sscanf(optarg, "%u", &optunsigned);
                        if (rc != 1 || optunsigned > USHRT_MAX) {
				fprintf(stderr, "base port must be within [1..%d]\n", USHRT_MAX);
				usage();
			}
			opt.base_port = (short)optunsigned;
			break;

		case 'P':
			opt.log_filename_prefix = optarg;
			break;

		case 'p':
			ASSIGN_FLOW_OPTION(pushy, 1)
			break;

		case 'q':
			opt.dont_log_stdout = 1;
			break;

		case 'Q':
			opt.dont_log_logfile = 1;
			break;

		case 'R':
			ASSIGN_FLOW_OPTION(route_record, 1)
			break;

		case 'r':
			ASSIGN_FLOW_OPTION(rate_str, optarg)
			break;

		case 's':
			ASSIGN_FLOW_OPTION(summarize_only, 1)
			break;

		case 't':
			rc = sscanf(optarg, "%lf", &optdouble);
			if (rc != 1) {
				fprintf(stderr, "malformed flow duration\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(client_flow_duration, optdouble)
			break;

		case 'T':
			rc = sscanf(optarg, "%lf", &optdouble);
			if (rc != 1) {
				fprintf(stderr, "malformed flow duration\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(server_flow_duration, optdouble)
			break;

		case 'u':
			ASSIGN_FLOW_OPTION(proto, PROTO_UDP);
			break;

		case 'V':
			fprintf(stderr, "flowgrind version: %s\n", SVNVERSION);
			exit(0);
	
		case 'w':
			optint = atoi(optarg);
			if (optint <= 0) {
				fprintf(stderr, "window must be a positive integer (in bytes)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(client_window_size, optint)
			break;

		case 'W':
			optint = atoi(optarg);
			if (optint <= 0) {
				fprintf(stderr, "window must be a positive integer (in bytes)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(server_window_size, optint)
			break;

		case 'y':
			rc = sscanf(optarg, "%lf", &optdouble);
			if (rc != 1 || optdouble < 0) {
				fprintf(stderr, "delay must be a non-negativ number (in seconds)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(client_flow_delay, optdouble)
			break;

		case 'Y':
			rc = sscanf(optarg, "%lf", &optdouble);
			if (rc != 1 || optdouble <= 0) {
				fprintf(stderr, "delay must be a positive number (in seconds)\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(server_flow_delay, optdouble)
			break;

		case 'x':
			for (id = 0; id<MAX_FLOWS; id++)
				if (current_flow_ids[id] == -1) {
					current_flow_ids[id++] = opt.num_flows++;
					if (id == MAX_FLOWS) {
						fprintf(stderr, "maximum number of flows (%d) exceeded.\n", MAX_FLOWS);
						exit(2);
					}
					current_flow_ids[1] = -1;
					break;
				}
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
		exit(2);
	}
	for (id = 0; id<opt.num_flows; id++) {
		DEBUG_MSG(4, "sanity checking parameter set of flow %d.", id);
		if (flow[id].server_flow_duration > 0 && flow[id].late_connect && 
			flow[id].server_flow_delay < flow[id].client_flow_delay) {
			fprintf(stderr, "Server flow %d starts earlier than client "
				"flow while late connecting.\n", id);
			exit(2);
		}
		if (flow[id].client_flow_delay > 0 && flow[id].client_flow_duration == 0) {
			fprintf(stderr, "Client flow %d has a delay but no runtime.\n", id);
			exit(2);
		}
		if (flow[id].server_flow_delay > 0 && flow[id].server_flow_duration == 0) {
			fprintf(stderr, "Server flow %d has a delay but no runtime.\n", id);
			exit(2);
		}
		if (flow[id].two_way) {
			if (flow[id].server_flow_duration != 0 && 
				flow[id].client_flow_duration != flow[id].server_flow_duration) {
				fprintf(stderr, "Server flow duration specified albeit -2.\n");
				exit(2);
			}
			flow[id].server_flow_duration = flow[id].client_flow_duration;
			if (flow[id].server_flow_delay != 0 &&
				flow[id].server_flow_delay != flow[id].client_flow_delay) {
				fprintf(stderr, "Server flow delay specified albeit -2.\n");
				exit(2);
			}
			flow[id].server_flow_delay = flow[id].client_flow_delay;
		}
		if (flow[id].rate_str) {
			unit = type = distribution = 0;
			/* last %c for catching wrong input... this is not nice. */
			rc = sscanf(flow[id].rate_str, "%lf%c%c%c%c", &optdouble, &unit, &type, &distribution, &unit);
			if (rc < 1 || rc > 4) {
				fprintf(stderr, "malformed rate for flow %u.\n", id);
				usage();
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
				optdouble*=1<<10; 
				break;

			case 'M': 
				optdouble*=1<<20; 
				break;
				
			case 'G': 
				optdouble*=1<<30; 
				break;
			
			default:
				fprintf(stderr, "illegal unit specifier in rate of flow %u.\n", id);
				usage();
			}

			switch (type) {
			case 0:
			case 'b':
				optdouble /= flow[id].write_block_size;
				if (optdouble < 1) {
					fprintf(stderr, "client block size for flow %u is too big for specified rate.\n", id);
					usage();
				}
				break;

			case 'B':
				break;
			
			default:
				fprintf(stderr, "illegal type specifier (either block or byte) for flow %u.\n", id);
				usage();
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
				fprintf(stderr, "illegal distribution specifier in rate for flow %u.\n", id);
			}
		}
		if (flow[id].flow_control && !flow[id].rate_str) {
			fprintf(stderr, "flow %d has flow control enabled but no rate.", id);
			exit(2);
		}
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
