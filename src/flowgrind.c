
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
#include <fcntl.h>
#include "adt.h"

#include "common.h"
#include "fg_socket.h"
#include "debug.h"
#include "flowgrind.h"

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

char unique_servers[MAX_FLOWS * 2][1000];
unsigned int num_unique_servers = 0;

xmlrpc_env rpc_env;

void parse_visible_param(char *to_parse) {
	// {begin, end, throughput, RTT, IAT, Kernel}
	if (strstr(to_parse, "+begin"))
		visible_columns[0] = 1;
	if (strstr(to_parse, "-begin"))
		visible_columns[0] = 0;
	if (strstr(to_parse, "+end"))
		visible_columns[1] = 1;
	if (strstr(to_parse, "-end"))
		visible_columns[1] = 0;
	if (strstr(to_parse, "+thrpt"))
		visible_columns[2] = 1;
	if (strstr(to_parse, "-thrpt"))
		visible_columns[2] = 0;
	if (strstr(to_parse, "+rtt"))
		visible_columns[3] = 1;
	if (strstr(to_parse, "-rtt"))
		visible_columns[3] = 0;
	if (strstr(to_parse, "+iat"))
		visible_columns[4] = 1;
	if (strstr(to_parse, "-iat"))
		visible_columns[4] = 0;
	if (strstr(to_parse, "+kernel"))
		visible_columns[5] = 1;
	if (strstr(to_parse, "-kernel"))
		visible_columns[5] = 0;
}

/* New output
   determines the number of digits before the comma
*/
int det_output_column_size(long value) {
	int i = 1;
	double dez = 10.0;

	if (value < 0)
		i++;
	while ((abs(value) / (dez - 1)) > 1) {
		i++;
		dez *= 10;
	}
	return i;
}

// produces the string command for printf for the right number of digits and decimal part
char *outStringPart(int digits, int decimalPart) {
	static char outstr[30] = {0};

	sprintf(outstr, "%%%d.%df", digits, decimalPart);

	return outstr;
}

int createOutputColumn(char *strHead1Row, char *strHead2Row, char *strDataRow,
	char *strHead1, char *strHead2, double value, unsigned int *control0,
	unsigned int *control1, int numDigitsDecimalPart, int showColumn, int *columnWidthChanged) {

	unsigned int maxTooLongColumns = opt.num_flows * 5; // Maximum number of rows with non-optimal column width
	int lengthData = 0; // #digits of values
	int lengthHead = 0; // Length of header string
	unsigned int columnSize = 0;
	char tempBuffer[50];
	unsigned int a;

	char* number_formatstring;

	if (!showColumn)
		return 0;

	// get max columnsize
	lengthData = det_output_column_size(value) + 2 + numDigitsDecimalPart;
	lengthHead = MAX(strlen(strHead1), strlen(strHead2));
	columnSize = MAX(lengthData, lengthHead);

	// check if columnsize has changed
	if (*control1 < columnSize) {
		/* column too small */
		*columnWidthChanged = 1;
		*control1 = columnSize;
		*control0 = 0;
	}
	else if (*control1 > 1 + columnSize) {
		/* column too big */
		if (*control0 >= maxTooLongColumns) {
			/* column too big for quite a while */
			*columnWidthChanged = 1;
			*control1 = columnSize;
			*control0 = 0;
		}
		else
			(*control0)++;
	}
	else /* This size was needed,keep it */
		*control0 = 0;

	number_formatstring = outStringPart(*control1, numDigitsDecimalPart);

	// create columns
	sprintf(tempBuffer, number_formatstring, value);
	strcat(strDataRow, tempBuffer);

	// 1st header row
	for (a = *control1; a > strlen(strHead1); a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, strHead1);

	// 2nd header Row
	for (a = *control1; a > strlen(strHead2); a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, strHead2);

	return 0;
}

char *createOutput(char hash, int id, int type, double begin, double end,
		double throughput,
		double rttmin, double rttavg, double rttmax,
		double iatmin, double iatavg, double iatmax,
		int cwnd, int ssth, int uack, int sack, int lost, int reor,
		int retr, int fack, double linrtt, double linrttvar,
		double linrto, int mss, int mtu, char* comment, int unit_byte) {

	static char * const str_id = "#  ID";
	static char * const str_begin[] = {" begin", " [s]"};
	static char * const str_end[] = {" end", " [s]"};
	static char *str_cs[] = {" through", " [Mbit]"};
	if (unit_byte == 1)
		str_cs[1] = " [Mbyte]";
	static char * const str_rttmin[] = {" RTT", " min"};
	static char * const str_rttavg[] = {" RTT", " avg"};
	static char * const str_rttmax[] = {" RTT", " max"};
	static char * const str_iatmin[] = {" IAT", " min"};
	static char * const str_iatavg[] = {" IAT", " avg"};
	static char * const str_iatmax[] = {" IAT", " max"};
	static char * const str_cwnd[] = {" cwnd", " "};
	static char * const str_ssth[] = {" ssth", " "};
	static char * const str_uack[] = {" uack", " #"};
	static char * const str_sack[] = {" sack", " #"};
	static char * const str_lost[] = {" lost", " #"};
	static char * const str_retr[] = {" retr", " #"};
	static char * const str_fack[] = {" fack", " #"};
	static char * const str_reor[] = {" reor", " #"};
	static char * const str_linrtt[] = {" rtt", " "};
	static char * const str_linrttvar[] = {" rttvar", " "};
	static char * const str_linrto[] = {" rto", " "};
	static char * const str_mss[] = {" mss", " "};
	static char * const str_mtu[] = {" mtu", " "};
	static char * const str_comment[] = {" ;-)", " "};

	int columnWidthChanged = 0; //Flag: 0: column width has not changed

	/*
	ControlArray [i][x]
	i: Number of Parameter
	x=0: Number of rows with too much space
	x=1: last column width
	*/
	static unsigned int control[24][2];
	int i = 0;
	static int counter = 0;

	//Create Row + Header
	char dataString[1000];
	char headerString1[1000];
	char headerString2[1000];
	static char outputString[4000];

	//output string
	//param # + flow_id
	if (type == 0)
		sprintf(dataString, "%cS%3d", hash, id);
	else
		sprintf(dataString, "%cR%3d", hash, id);
	strcpy(headerString1, str_id);
	strcpy(headerString2, "#    ");
	i++;

	//param begin
	createOutputColumn(headerString1, headerString2, dataString, str_begin[0], str_begin[1], begin, &control[i][0], &control[i][1], 3, visible_columns[0], &columnWidthChanged);
	i++;

	//param end
	createOutputColumn(headerString1, headerString2, dataString,  str_end[0], str_end[1], end, &control[i][0], &control[i][1], 3, visible_columns[1], &columnWidthChanged);
	i++;

	//param throughput
	createOutputColumn(headerString1, headerString2, dataString, str_cs[0], str_cs[1], throughput, &control[i][0], &control[i][1], 6, visible_columns[2], &columnWidthChanged);
	i++;

	//param str_rttmin
	createOutputColumn(headerString1, headerString2, dataString, str_rttmin[0], str_rttmin[1], rttmin, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_rttavg
	createOutputColumn(headerString1, headerString2, dataString, str_rttavg[0], str_rttavg[1], rttavg, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_rttmax
	createOutputColumn(headerString1, headerString2, dataString, str_rttmax[0], str_rttmax[1], rttmax, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_iatmin
	createOutputColumn(headerString1, headerString2, dataString, str_iatmin[0], str_iatmin[1], iatmin, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//param str_iatavg
	createOutputColumn(headerString1, headerString2, dataString, str_iatavg[0], str_iatavg[1], iatavg, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//param str_iatmax
	createOutputColumn(headerString1, headerString2, dataString, str_iatmax[0], str_iatmax[1], iatmax, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//linux kernel output
	//param str_cwnd
	createOutputColumn(headerString1, headerString2, dataString, str_cwnd[0], str_cwnd[1], cwnd, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_ssth
	createOutputColumn(headerString1, headerString2, dataString, str_ssth[0], str_ssth[1], ssth, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_uack
	createOutputColumn(headerString1, headerString2, dataString, str_uack[0], str_uack[1], uack, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_sack
	createOutputColumn(headerString1, headerString2, dataString, str_sack[0], str_sack[1], sack, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_lost
	createOutputColumn(headerString1, headerString2, dataString, str_lost[0], str_lost[1], lost, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_retr
	createOutputColumn(headerString1, headerString2, dataString, str_retr[0], str_retr[1], retr, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_fack
	createOutputColumn(headerString1, headerString2, dataString, str_fack[0], str_fack[1], fack, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_reor
	createOutputColumn(headerString1, headerString2, dataString, str_reor[0], str_reor[1], reor, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrtt
	createOutputColumn(headerString1, headerString2, dataString, str_linrtt[0], str_linrtt[1], linrtt, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrttvar
	createOutputColumn(headerString1, headerString2, dataString, str_linrttvar[0], str_linrttvar[1], linrttvar, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrto
	createOutputColumn(headerString1, headerString2, dataString, str_linrto[0], str_linrto[1], linrto, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataString, str_mss[0], str_mss[1], mss, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataString, str_mtu[0], str_mtu[1], mtu, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	strcat(headerString1, str_comment[0]);
	strcat(headerString2, str_comment[1]);
	strcat(dataString, comment);

	//newline at the end of the string
	strcat(headerString1, "\n");
	strcat(headerString2, "\n");
	strcat(dataString, "\n");
	//output string end
	if (columnWidthChanged > 0 || (counter % 25) == 0) {
		strcpy(outputString, headerString1);
		strcat(outputString, headerString2);
		strcat(outputString, dataString);
	}
	else {
		strcpy(outputString, dataString);
	}
	counter++;

	// now do the anderson darlington stuff
	if (doAnderson > 0) {
/* TODO, this one needs to be reworked
		if (array_size < MAXANDERSONSIZE) {
			t_array_s[array_size] = cs ;
			r_array_s[array_size] = rttavg ;
			i_array_s[array_size] = iatavg ;
			t_array_r[array_size] = sc ;
			r_array_r[array_size] = 0 ; //dummy since nothing is available yet
			i_array_r[array_size] = 0 ; //dummy since nothing is available yet
			array_size++;
		}
		else
			anderson_outbound =1;
*/
	}

	return outputString;
}
/*New output end*/

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
		"  -b mean|lower_bound,upper_bound\n"
		"               mean for computing Anderson-Darling Test for exponential\n"
		"               distribution OR\n"
		"               lower_boud,upper_bound for computing the test for uniform\n"
		"               distribution with the given bounds\n"
		"  -o +begin,+end,+thrpt,+rtt,+iat,+kernel\n"
		"               comma separated list of parameters to investigate +: show -: hide\n"
#ifdef DEBUG
		"  -d           increase debugging verbosity. Add option multiple times to\n"
		"               be even more verbose.\n"
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
		"  -D x=DSCP      DSCP value for TOS byte\n"
		"  -E x         Enumerate bytes in payload (default: don't)\n"
		"  -F #{,#}     Flow options following this option apply only to flow #{,#}.\n"
		"               Useful in combination with -n to set specific options\n"
		"               for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"               to the second flow\n"
		"  -H x=HOST[:PORT][/HOST]\n"
		"               Test from/to host. Optional argument is the address the actual\n"
		"               test socket should bind to.\n"
		"               An endpoint that isn't specified is assumed to be localhost.\n"
		"  -L x         connect() socket immediately before sending (late)\n"
		"  -N x         shutdown() each socket direction after test flow\n"
		"  -O x=OPT     Set specific socket options on test socket.\n"
		"               type \"flowgrind -h sockopt\" to see the specific values for OPT\n"
		"  -P x         Do not iterate through select() to continue sending in case\n"
		"               block size did not suffice to fill sending queue (pushy)\n"
		"  -Q           Summarize only, skip interval reports (quite)\n"
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

		"x has to be replaced with 's' for source, 'd' for destination or 'b' for both.\n"
		"For all options which take x, an additional parameter can be specified if\n"
		"separated by comma.\n"
		"For instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"and 4096 at the destination.\n\n"

		"The -O option, it is also possible to repeatedly specify s or d options\n"
		"respectively. For instance -O s=SO_DEBUG,s=TCP_CORK,d=TCP_CONG_MODULE=reno.\n\n"

		"Examples:\n"
		"  flowgrind -H testhost\n"
		"               start bulk TCP transfer from this host to testhost\n"
		"  flowgrind -H 192.168.0.69 -T s=0,d=5\n"
		"               start bulk TCP transfer from 192.168.0.69 to this host\n"
		"  flowgrind -n 2 -H 192.168.0.69 -F 1 -H 10.0.0.1\n"
		"               start two TCP transfers one to 192.168.0.69 and another in\n"
		"               parallel to 10.0.0.1\n",
		opt.log_filename_prefix
	);
	exit(1);
}

static void usage_sockopt(void)
{
	int fd;

	fprintf(stderr,
		"The following list contains possible values that can be set on the test socket:\n"
		"  s=TCP_CONG_MODULE=ALG\n"
		"               set congestion control algorithm ALG.\n");

		// Read and print available congestion control algorithms
		fd = open("/proc/sys/net/ipv4/tcp_available_congestion_control/", O_RDONLY);
		if (fd != -1) {
			fprintf(stderr, "               The following list contains possible values for ALG:\n"
				"                 ");
			char buffer[1024];
			int r;
			while ((r = read(fd, buffer, 1024)) > 0)
				fwrite(buffer, r, 1, stderr);
			close(fd);
		}

	fprintf(stderr,
		"  x=TCP_CORK   set TCP_CORK on test socket\n"
		"  x=TCP_ELCN   set TCP_ELCN on test socket\n"
		"  x=TCP_ICMP   set TCP_ICMP on test socket\n"
		"  x=IP_MTU_DISCOVER\n"
		"               set IP_MTU_DISCOVER on test socket if not already enabled by\n"
		"               system default\n"
		"  x=ROUTE_RECORD\n"
		"               set ROUTE_RECORD on test socket\n\n"

		"x can be replaced with 's' for source or 'd' for destination\n\n"

		"Examples:\n"
		"  flowgrind -H d=testhost -O s=TCP_CONG_MODULE=reno,d=SO_DEBUG\n"
		"  //ToDo: write more examples and descriptions\n"
		);
	exit(1);
}

static void usage_flowopt(void)
{
	fprintf(stderr,
		"Some options are used like this:\n"
		"  -B x=#\n\n"
		"x has to be replaced with 's' for source, 'd' for destination or 'b' for both.\n"
		"For all options which take x, an additional parameter can be specified if\n"
		"separated by comma.\n"
		"For instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"and 4096 at the destination.\n\n"
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

	for (id = 0; id < MAX_FLOWS; id++) {
		flow[id].mss = 0;

		flow[id].proto = PROTO_TCP;

		for (int i = 0; i < 2; i++) {
			flow[id].settings[i].requested_send_buffer_size = 0;
			flow[id].settings[i].requested_read_buffer_size = 0;
			flow[id].settings[i].delay[WRITE] = 0;
			flow[id].settings[i].write_block_size = 8192;
			flow[id].settings[i].read_block_size = 8192;
			flow[id].settings[i].route_record = 0;
			strcpy(flow[id].endpoint_options[i].server_url, "http://localhost:5999/RPC2");
			strcpy(flow[id].endpoint_options[i].server_address, "localhost");
			flow[id].endpoint_options[i].server_port = DEFAULT_LISTEN_PORT;
			strcpy(flow[id].endpoint_options[i].test_address, "localhost");
			strcpy(flow[id].endpoint_options[i].bind_address, "");

			flow[id].settings[i].pushy = 0;

			flow[id].settings[i].cork = 0;
			flow[id].settings[i].cc_alg[0] = 0;
			flow[id].settings[i].elcn = 0;
			flow[id].settings[i].icmp = 0;
			flow[id].settings[i].dscp = 0;
			flow[id].settings[i].ipmtudiscover = 0;
		}
		flow[id].settings[SOURCE].duration[WRITE] = 5.0;
		flow[id].settings[DESTINATION].duration[WRITE] = 0.0;

		flow[id].endpoint_id[0] = flow[id].endpoint_id[1] = -1;
		flow[id].start_timestamp[0].tv_sec = 0;
		flow[id].start_timestamp[0].tv_usec = 0;
		flow[id].start_timestamp[1].tv_sec = 0;
		flow[id].start_timestamp[1].tv_usec = 0;

#ifdef __LINUX__
		flow[id].last_retrans[0] = 0;
		flow[id].last_retrans[1] = 0;
#endif

		flow[id].finished[0] = 0;
		flow[id].finished[1] = 0;
		flow[id].final_report[0] = NULL;
		flow[id].final_report[1] = NULL;
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
		printf("%s", msg);
		fflush(stdout);
	}
	if (!opt.dont_log_logfile) {
		fprintf(log_stream, "%s", msg);
		fflush(log_stream);
	}
}

void print_tcp_report_line(char hash, int id,
		int type, /* 0 source 1 destination */
		double time1, double time2,
		long bytes_written, long bytes_read,
		long read_reply_blocks,  double min_rtt,
		double tot_rtt, double max_rtt, double min_iat,
		double tot_iat, double max_iat,
#ifdef __LINUX__
		unsigned cwnd, unsigned ssth, unsigned uack,
		unsigned sack, unsigned lost, unsigned retr,
		unsigned fack, unsigned reor, double rtt,
		double rttvar, double rto,
		int mss, int mtu,
#endif
		int status
)
{
	double avg_rtt;
	double avg_iat;
	char comment_buffer[100] = " (";
	char report_buffer[4000] = "";
	double thruput = 0.0;

#define COMMENT_CAT(s) do { if (strlen(comment_buffer) > 2) \
		strncat(comment_buffer, "/", sizeof(comment_buffer)); \
		strncat(comment_buffer, (s), sizeof(comment_buffer)); }while(0);

	if (read_reply_blocks) {
		avg_rtt = tot_rtt / (double)(read_reply_blocks);
		avg_iat = tot_iat / (double)(read_reply_blocks);
	}
	else {
		min_rtt = max_rtt = avg_rtt = INFINITY;
		min_iat = max_iat = avg_iat = INFINITY;
	}

	if (flow[id].finished[type])
		COMMENT_CAT("stopped")
	else {
		char tmp[2];

		// Write status
		switch (status & 0xFF)
		{
			case 'd':
			case 'l':
			case 'o':
			case 'f':
			case 'c':
			case 'n':
				tmp[0] = (char)(status & 0xFF);
				tmp[1] = 0;
				COMMENT_CAT(tmp);
				break;
			default:
				COMMENT_CAT("u");
				break;
		}

		// Read status
		switch (status >> 8)
		{
			case 'd':
			case 'l':
			case 'o':
			case 'f':
			case 'c':
			case 'n':
				tmp[0] = (char)(status >> 8);
				tmp[1] = 0;
				COMMENT_CAT(tmp);
				break;
			default:
				COMMENT_CAT("u");
				break;
		}
	}
	strncat(comment_buffer, ")", sizeof(comment_buffer));
	if (strlen(comment_buffer) == 2)
		comment_buffer[0] = '\0';

	thruput = scale_thruput((double)bytes_written / (time2 - time1));

	char rep_string[4000];
#ifndef __LINUX__
	// dont show linux kernel output if there is no linux OS
	visible_columns[5] = 0;
#endif
	strcpy(rep_string, createOutput((hash ? '#' : ' '), id, type,
		time1, time2, thruput,
		min_rtt * 1e3, avg_rtt * 1e3, max_rtt * 1e3,
		min_iat * 1e3, avg_iat * 1e3, max_iat * 1e3,
#ifdef __LINUX__
		(double)cwnd, (double)ssth, (double)uack, (double)sack, (double)lost, (double)retr, (double)fack, (double)reor,
		(double)rtt / 1e3, (double)rttvar / 1e3, (double)rto / 1e3,
#else
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0,
#endif
		mss, mtu, comment_buffer, opt.mbyte
	));
	strncpy(report_buffer, rep_string, sizeof(report_buffer));
	report_buffer[sizeof(report_buffer) - 1] = 0;
	log_output(report_buffer);
}

void print_report(int id, int endpoint, struct _report* report)
{
	double diff_first_last;
	double diff_first_now;
	struct _flow_dummy *f = &flow[id];

	diff_first_last = time_diff(&f->start_timestamp[endpoint], &report->begin);
	diff_first_now = time_diff(&f->start_timestamp[endpoint], &report->end);

	print_tcp_report_line(
		0, id, endpoint, diff_first_last, diff_first_now,
		report->bytes_written,
		report->bytes_read,
		report->reply_blocks_read,
		report->rtt_min,
		report->rtt_sum,
		report->rtt_max,
		report->iat_min,
		report->iat_sum,
		report->iat_max,
#ifdef __LINUX__
		report->tcp_info.tcpi_snd_cwnd,
		report->tcp_info.tcpi_snd_ssthresh,
		report->tcp_info.tcpi_unacked, report->tcp_info.tcpi_sacked,
		/*report->tcp_info.tcpi_last_data_sent, report->tcp_info.tcpi_last_ack_recv,*/
		report->tcp_info.tcpi_lost,
		f->last_retrans[endpoint] - report->tcp_info.tcpi_retrans,
		report->tcp_info.tcpi_fackets,
		report->tcp_info.tcpi_reordering,
		report->tcp_info.tcpi_rtt,
		report->tcp_info.tcpi_rttvar,
		report->tcp_info.tcpi_rto,
#endif
		report->mss,
		report->mtu,

		report->status
	);
#ifdef __LINUX__
	f->last_retrans[endpoint] = report->tcp_info.tcpi_retrans;
#endif
}

void report_final(void)
{
	int id = 0;
	char header_buffer[400] = "";
	char header_nibble[400] = "";

	for (id = 0; id < opt.num_flows; id++) {

#define CAT(fmt, args...) do {\
	snprintf(header_nibble, sizeof(header_nibble), fmt, ##args); \
	strncat(header_buffer, header_nibble, sizeof(header_nibble)); } while (0)
#define CATC(fmt, args...) CAT(", "fmt, ##args)

		log_output("\n");

		for (int endpoint = 0; endpoint < 2; endpoint++) {
			header_buffer[0] = 0;

			int mtu;
			int mss;

			CAT("#% 4d %s:", id, endpoint ? "R" : "S");

 			CAT(" %s", flow[id].endpoint_options[endpoint].server_address);
			if (flow[id].endpoint_options[endpoint].server_port != DEFAULT_LISTEN_PORT)
				CAT(":%d", flow[id].endpoint_options[endpoint].server_port);
			if (strcmp(flow[id].endpoint_options[endpoint].server_address, flow[id].endpoint_options[endpoint].test_address) != 0)
				CAT("/%s", flow[id].endpoint_options[endpoint].test_address);

			if (flow[id].final_report[endpoint]) {
				mtu = flow[id].final_report[endpoint]->mtu;
				mss = flow[id].final_report[endpoint]->mss;
			}
			else {
				mtu = -1;
				mss = -1;
			}

			CATC("MSS = %d", mss);
			CATC("MTU = %d (%s)", mtu, guess_topology(mss, mtu));

			CATC("sb = %u (%u)",
				flow[id].endpoint_options[endpoint].send_buffer_size_real,
				flow[id].settings[endpoint].requested_send_buffer_size);

			CATC("rb = %u (%u)",
				flow[id].endpoint_options[endpoint].receive_buffer_size_real,
				flow[id].settings[endpoint].requested_read_buffer_size);

			CATC("bs = %u/%u",
				flow[id].settings[endpoint].write_block_size,
				flow[id].settings[1 - endpoint].write_block_size);

			CAT("\n         delay = %.2fs/%.2fs",
				flow[id].settings[SOURCE].delay[WRITE],
				flow[id].settings[SOURCE].delay[READ]);

			CATC("duration = %.2fs/%.2fs",
				flow[id].settings[SOURCE].duration[WRITE],
				flow[id].settings[SOURCE].duration[READ]);

			if (flow[id].final_report[endpoint]) {
				double thruput_read = 0.0;
				double thruput_written = 0.0;

				double report_diff, duration_read, duration_write;

				report_diff = time_diff(&flow[id].final_report[endpoint]->begin, &flow[id].final_report[endpoint]->end);
				/* Calculate duration the flow was receiving */
				duration_read = report_diff - flow[id].settings[endpoint].delay[DESTINATION];
				if (duration_read > flow[id].settings[endpoint].duration[DESTINATION])
					duration_read = flow[id].settings[endpoint].duration[DESTINATION];
				/* Calculate duration the flow was sending */
				duration_write = report_diff - flow[id].settings[endpoint].delay[SOURCE];
				if (duration_write > flow[id].settings[endpoint].duration[SOURCE])
					duration_write = flow[id].settings[endpoint].duration[SOURCE];

				thruput_read = flow[id].final_report[endpoint]->bytes_read / duration_read;
				thruput_written = flow[id].final_report[endpoint]->bytes_written / duration_write;

				thruput_read = scale_thruput(thruput_read);
				thruput_written = scale_thruput(thruput_written);

				CATC("thruput = %.6f/%.6fM%c/s (%lld/%lld)", thruput_written, thruput_read, (opt.mbyte ? 'B' : 'b'),
					flow[id].final_report[endpoint]->bytes_written / flow[id].settings[endpoint].write_block_size,
					flow[id].final_report[endpoint]->bytes_read / flow[id].settings[endpoint].read_block_size
					);
			}

			if (flow[id].endpoint_options[endpoint].rate_str)
				CATC("rate = %s", flow[id].endpoint_options[endpoint].rate_str);
			if (flow[id].settings[endpoint].elcn)
				CATC("ELCN %s", flow[id].settings[endpoint].elcn == 1 ? "enabled" : "disabled");
			if (flow[id].settings[endpoint].cork)
				CATC("TCP_CORK");
			if (flow[id].settings[endpoint].pushy)
				CATC("PUSHY");
/*
#ifdef __LINUX__
		CATC("cc = \"%s\"", *flow[id].final_cc_alg ? flow[id].final_cc_alg :
				"(failed)");
		if (!flow[id].cc_alg)
			CAT(" (default)");
		else if (strcmp(flow[id].final_cc_alg, flow[id].cc_alg) != 0)
			CAT(" (was set to \"%s\")", flow[id].cc_alg);
#endif
*/
		if (flow[id].settings[endpoint].dscp)
			CATC("dscp = 0x%02x", flow[id].settings[endpoint].dscp);
		if (flow[id].late_connect)
			CATC("late connecting");
		if (flow[id].shutdown)
			CATC("calling shutdown");
/*		if (flow[id].congestion_counter > CONGESTION_LIMIT)
			CAT(" (overcongested)");
		else if (flow[id].congestion_counter > 0)
			CAT(" (congested = %u)", flow[id].congestion_counter);
		if (flow[id].stopped &&
				flow[id].congestion_counter <= CONGESTION_LIMIT)
			CAT(" (stopped)");
*/
		
			CAT("\n");

			log_output(header_buffer);

		}
	}

	for (id = 0; id < opt.num_flows; id++) {

		for (int endpoint = 0; endpoint < 2; endpoint++) {

			if (!flow[id].final_report[endpoint])
				continue;

			print_report(id, endpoint, flow[id].final_report[endpoint]);
		};
	}


/*
Notes on Anderson Darlington Test

	Both routines return a significance level, as described earlier. This
   is a value between 0 and 1.  The correct use of the routines is to
   pick in advance the threshold for the significance level to test;
   generally, this will be 0.05, corresponding to 5%, as also described
   above.  Subsequently, if the routines return a value strictly less
   than this threshold, then the data are deemed to be inconsistent with
   the presumed distribution, *subject to an error corresponding to the
   significance level*.  That is, for a significance level of 5%, 5% of
   the time data that is indeed drawn from the presumed distribution
   will be erroneously deemed inconsistent.

	Thus, it is important to bear in mind that if these routines are used
   frequently, then one will indeed encounter occasional failures, even
   if the data is unblemished.


	We note, however, that the process of computing Y above might yield
   values of Y outside the range (0..1).  Such values should not occur
   if X is indeed distributed according to G(x), but easily can occur if
   it is not.  In the latter case, we need to avoid computing the
   central A2 statistic, since floating-point exceptions may occur if
   any of the values lie outside (0..1).  Accordingly, the routines
   check for this possibility, and if encountered, return a raw A2
   statistic of -1.  The routine that converts the raw A2 statistic to a
   significance level likewise propagates this value, returning a
   significance level of -1.  So, any use of these routines must be
   prepared for a possible negative significance level.

   The last important point regarding use of A2 statistic concerns n,
   the number of values being tested.  If n < 5 then the test is not
   meaningful, and in this case a significance level of -1 is returned.

   On the other hand, for "real" data the test *gains* power as n
   becomes larger.  It is well known in the statistics community that
   real data almost never exactly matches a theoretical distribution,
   even in cases such as rolling dice a great many times (see [Pa94] for
   a brief discussion and references).  The A2 test is sensitive enough
   that, for sufficiently large sets of real data, the test will almost
   always fail, because it will manage to detect slight imperfections in
   the fit of the data to the distribution.


*/

#if 0
	/* Disabled for now, needs many more commandline options to work properly */

	double t_result_s, r_result_s, i_result_s, t_result_r, r_result_r, i_result_r;

	/* now depending on which test the user wanted we make the function calls */
	if (doAnderson == 1) {

		t_result_s = exp_A2_known_mean(t_array_s, array_size, ADT1);
		r_result_s = exp_A2_known_mean(r_array_s, array_size, ADT1);
		i_result_s = exp_A2_known_mean(i_array_s, array_size, ADT1);
		t_result_r = exp_A2_known_mean(t_array_r, array_size, ADT1);
		r_result_r = exp_A2_known_mean(r_array_r, array_size, ADT1);
		i_result_r = exp_A2_known_mean(i_array_r, array_size, ADT1);

		char report_buffer[4000] = "";

		char report_string[4000];
		/* strings for sender */
		char string_t_result_s[100]; /* string_throughput_result_server */
		char string_r_result_s[100]; /* string_rtt_result_server */
		char string_i_result_s[100]; /* string_iat_result_server */
		/* strings for receiver */
		char string_t_result_r[100]; /* string_throughput_result_receiver */
		char string_r_result_r[100]; /* string_rtt_result_receiver */
		char string_i_result_r[100]; /* string_iat_result_receiver */

		/*convert double to string*/
		sprintf(string_t_result_s, "%.6f", t_result_s);
		sprintf(string_r_result_s, "%.6f", r_result_s);
		sprintf(string_i_result_s, "%.6f", i_result_s);

		sprintf(string_t_result_r, "%.6f", t_result_r);
		sprintf(string_r_result_r, "%.6f", r_result_r);
		sprintf(string_i_result_r, "%.6f", i_result_r);

		/* create the output to the logfile */
		strcpy(report_string, "\n#Anderson-Darling test statistic (A2) for Exponential Distribution with mean=");

		char buf[100];
		sprintf(buf, "%.6f", ADT1);
		strcat(report_string, buf);
		strcat(report_string, " :\n");

		strcat(report_string, "#A2 Throughput of sender = ");
		strcat(report_string, string_t_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 Throughput of receiver = ");
		strcat(report_string, string_t_result_r);
		strcat(report_string, " \n");

		strcat(report_string, "#A2 RTT of sender = ");
		strcat(report_string, string_r_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 RTT of receiver = ");
		strcat(report_string, string_r_result_r);
		strcat(report_string, " \n");

		strcat(report_string, "#A2 IAT of sender = ");
		strcat(report_string, string_i_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 RTT of receiver = ");
		strcat(report_string, string_i_result_r);
		strcat(report_string, " \n");

		if (anderson_outbound == 1) {
			strcat(report_string, "\n#Note: The Darlington test was done only on the first 1000 samples. The reason for this is that the test gives poor results for a larger sample size (as specified in literature)\n");
		}

		snprintf(report_buffer, sizeof(report_buffer), report_string);
		log_output(report_buffer);
	}
	else if (doAnderson == 2) {

		t_result_s = unif_A2_known_range(t_array_s, array_size, ADT1, ADT2);
		r_result_s = unif_A2_known_range(r_array_s, array_size, ADT1, ADT2);
		i_result_s = unif_A2_known_range(i_array_s, array_size, ADT1, ADT2);
		t_result_r = unif_A2_known_range(t_array_r, array_size, ADT1, ADT2);
		r_result_r = unif_A2_known_range(r_array_r, array_size, ADT1, ADT2);
		i_result_r = unif_A2_known_range(i_array_r, array_size, ADT1, ADT2);

		char report_buffer[4000] = "";

		char report_string[4000];
		/* strings for sender */
		char string_t_result_s[100]; /* string_throughput_result_server */
		char string_r_result_s[100]; /* string_rtt_result_server */
		char string_i_result_s[100]; /* string_iat_result_server */
		/* strings for receiver */
		char string_t_result_r[100]; /* string_throughput_result_receiver */
		char string_r_result_r[100]; /* string_rtt_result_receiver */
		char string_i_result_r[100]; /* string_iat_result_receiver */

		/*convert double to string*/
		sprintf(string_t_result_s, "%.6f", t_result_s);
		sprintf(string_r_result_s, "%.6f", r_result_s);
		sprintf(string_i_result_s, "%.6f", i_result_s);

		sprintf(string_t_result_r, "%.6f", t_result_r);
		sprintf(string_r_result_r, "%.6f", r_result_r);
		sprintf(string_i_result_r, "%.6f", i_result_r);

		/* create the output to the logfile */
		strcpy(report_string, "\n#Anderson-Darling test statistic (A2) for Uniform Distribution with lower bound ");

		char buf[100];
		sprintf(buf, "%.6f and upper bound %.6f", ADT1, ADT2);
		strcat(report_string, buf);

		strcat(report_string, ":\n#A2 Throughput of sender = ");
		strcat(report_string, string_t_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 Throughput of receiver = ");
		strcat(report_string, string_t_result_r);
		strcat(report_string, " \n");

		strcat(report_string, "#A2 RTT of sender = ");
		strcat(report_string, string_r_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 RTT of receiver = ");
		strcat(report_string, string_r_result_r);
		strcat(report_string, " \n");

		strcat(report_string, "#A2 IAT of sender = ");
		strcat(report_string, string_i_result_s);
		strcat(report_string, "; ");

		strcat(report_string, "A2 RTT of receiver = ");
		strcat(report_string, string_i_result_r);
		strcat(report_string, " \n");

		snprintf(report_buffer, sizeof(report_buffer), report_string);
		log_output(report_buffer);
	}

#endif
}

void report_flow(const char* server_url, struct _report* report)
{
	int endpoint;
	int id;
	struct _flow_dummy *f;

	/* Get matching flow for report */
	for (id = 0; id < opt.num_flows; id++) {
 		f = &flow[id];

		for (endpoint = 0; endpoint < 2; endpoint++) {
			if (f->endpoint_id[endpoint] == report->id && !strcmp(server_url, f->endpoint_options[endpoint].server_url))
				goto exit_outer_loop;
		}
	}
exit_outer_loop:

	if (id == opt.num_flows) {
		DEBUG_MSG(1, "Got report from nonexistant flow, ignoring");
		return;
	}

	if (f->start_timestamp[endpoint].tv_sec == 0) {
		f->start_timestamp[endpoint] = report->begin;
	}

	if (report->type == TOTAL) {
		/* Final report, keep it for later */
		free(f->final_report[endpoint]);
		f->final_report[endpoint] = malloc(sizeof(struct _report));
		*f->final_report[endpoint] = *report;

		if (!f->finished[endpoint]) {
			f->finished[endpoint] = 1;

			if (f->finished[1 - endpoint]) {
				active_flows--;
				assert(active_flows >= 0);
			}
		}
		return;
	}

	print_report(id, endpoint, report);
}

void sigint_handler(int sig)
{
	UNUSED_ARGUMENT(sig);

	DEBUG_MSG(1, "caught %s", strsignal(sig));

	sigint_caught = 1;
}

static void die_if_fault_occurred(xmlrpc_env *env)
{
    if (env->fault_occurred) {
        fprintf(stderr, "XML-RPC Fault: %s (%d)\n",
                env->fault_string, env->fault_code);
        exit(1);
    }
}

static void grind_flows(xmlrpc_client *rpc_client)
{
	unsigned j;
	xmlrpc_value * resultP = 0;

	struct timeval now;
	tsc_gettimeofday(&now);

	for (j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;

		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "start_flows", &resultP,
		"({s:i})",
		"start_timestamp", now.tv_sec + 2);
		die_if_fault_occurred(&rpc_env);
		if (resultP)
			xmlrpc_DECREF(resultP);
	}

	active_flows = opt.num_flows;

	while (!sigint_caught) {

		usleep(1000000 * opt.reporting_interval);

		for (j = 0; j < num_unique_servers; j++) {
			xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "get_reports", &resultP, "()");
			if (rpc_env.fault_occurred) {
				fprintf(stderr, "XML-RPC Fault: %s (%d)\n",
				rpc_env.fault_string, rpc_env.fault_code);
				continue;
			}

			if (!resultP)
				continue;

			for (int i = 0; i < xmlrpc_array_size(&rpc_env, resultP); i++) {
				xmlrpc_value *rv = 0;

				xmlrpc_array_read_item(&rpc_env, resultP, i, &rv);
				if (rv) {
					struct _report report;
					int begin_sec, begin_usec, end_sec, end_usec;

					int tcpi_snd_cwnd;
					int tcpi_snd_ssthresh;
					int tcpi_unacked;
					int tcpi_sacked;
					int tcpi_lost;
					int tcpi_retrans;
					int tcpi_fackets;
					int tcpi_reordering;
					int tcpi_rtt;
					int tcpi_rttvar;
					int tcpi_rto;
					int tcpi_last_data_sent;
					int tcpi_last_ack_recv;
					int bytes_read_low, bytes_read_high;
					int bytes_written_low, bytes_written_high;

					xmlrpc_decompose_value(&rpc_env, rv, "{"
						"s:i,s:i,s:i,s:i,s:i,s:i," "s:i,s:i,s:is:i,s:i," "s:d,s:d,s:d,s:d,s:d,s:d," "s:i,s:i,"
						"s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i" /* TCP info */
						"s:i,*}",

						"id", &report.id,
						"type", &report.type,
						"begin_tv_sec", &begin_sec,
						"begin_tv_usec", &begin_usec,
						"end_tv_sec", &end_sec,
						"end_tv_usec", &end_usec,

						"bytes_read_high", &bytes_read_high,
						"bytes_read_low", &bytes_read_low,
						"bytes_written_high", &bytes_written_high,
						"bytes_written_low", &bytes_written_low,
						"reply_blocks_read", &report.reply_blocks_read,

						"rtt_min", &report.rtt_min,
						"rtt_max", &report.rtt_max,
						"rtt_sum", &report.rtt_sum,
						"iat_min", &report.iat_min,
						"iat_max", &report.iat_max,
						"iat_sum", &report.iat_sum,

						"mss", &report.mss,
						"mtu", &report.mtu,

						"tcpi_snd_cwnd", &tcpi_snd_cwnd,
						"tcpi_snd_ssthresh", &tcpi_snd_ssthresh,
						"tcpi_unacked", &tcpi_unacked,
						"tcpi_sacked", &tcpi_sacked,
						"tcpi_lost", &tcpi_lost,
						"tcpi_retrans", &tcpi_retrans,
						"tcpi_fackets", &tcpi_fackets,
						"tcpi_reordering", &tcpi_reordering,
						"tcpi_rtt", &tcpi_rtt,
						"tcpi_rttvar", &tcpi_rttvar,
						"tcpi_rto", &tcpi_rto,
						"tcpi_last_data_sent", &tcpi_last_data_sent,
						"tcpi_last_ack_recv", &tcpi_last_ack_recv,
						"status", &report.status
					);
					xmlrpc_DECREF(rv);

					report.bytes_read = ((long long)bytes_read_high << 32) + (uint32_t)bytes_read_low;
					report.bytes_written = ((long long)bytes_written_high << 32) + (uint32_t)bytes_written_low;
#ifdef __LINUX__
					report.tcp_info.tcpi_snd_cwnd = tcpi_snd_cwnd;
					report.tcp_info.tcpi_snd_ssthresh = tcpi_snd_ssthresh;
					report.tcp_info.tcpi_unacked = tcpi_unacked;
					report.tcp_info.tcpi_sacked = tcpi_sacked;
					report.tcp_info.tcpi_lost = tcpi_lost;
					report.tcp_info.tcpi_retrans = tcpi_retrans;
					report.tcp_info.tcpi_fackets = tcpi_fackets;
					report.tcp_info.tcpi_reordering = tcpi_reordering;
					report.tcp_info.tcpi_rtt = tcpi_rtt;
					report.tcp_info.tcpi_rttvar = tcpi_rttvar;
					report.tcp_info.tcpi_rto = tcpi_rto;
					report.tcp_info.tcpi_last_data_sent = tcpi_last_data_sent;
					report.tcp_info.tcpi_last_ack_recv = tcpi_last_ack_recv;
#endif
					report.begin.tv_sec = begin_sec;
					report.begin.tv_usec = begin_usec;
					report.end.tv_sec = end_sec;
					report.end.tv_usec = end_usec;

					report_flow(unique_servers[j], &report);
				}
			}
			xmlrpc_DECREF(resultP);
		}

		if (!active_flows)
			/* All flows have ended */
			return;
	}
}

void close_flow(int id)
{
	DEBUG_MSG(2, "closing flow %d.", id);

	xmlrpc_env env;
	xmlrpc_client *client;

	if (flow[id].finished[SOURCE] && flow[id].finished[DESTINATION])
		return;

	/* We use new env and client, old one might be in fault condition */
	xmlrpc_env_init(&env);
	xmlrpc_client_create(&env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &client);
	die_if_fault_occurred(&env);
	xmlrpc_env_clean(&env);

	for (unsigned int endpoint = 0; endpoint < 2; endpoint++) {
		xmlrpc_value * resultP = 0;

		if (flow[id].endpoint_id[endpoint] == -1 ||
				flow[id].finished[endpoint]) {
			/* Endpoint does not need closing */
			continue;
		}

		flow[id].finished[endpoint] = 1;

		xmlrpc_env_init(&env);

		xmlrpc_client_call2f(&env, client, flow[id].endpoint_options[endpoint].server_url, "stop_flow", &resultP,
			"({s:i})", "flow_id", flow[id].endpoint_id[endpoint]);
		if (resultP)
			xmlrpc_DECREF(resultP);
	
		xmlrpc_env_clean(&env);
	}

	if (active_flows > 0)
		active_flows--;

	xmlrpc_client_destroy(client);
}


void close_flows(void)
{
	int id;
	for (id = 0; id < opt.num_flows; id++)
		close_flow(id);

}


struct _mtu_info {
	int mtu;
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
#define MTU_LIST_NUM	12


char *guess_topology (int mss, int mtu)
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

void prepare_flow(int id, xmlrpc_client *rpc_client)
{
	xmlrpc_value * resultP;

	int listen_data_port;
	int listen_reply_port;
	int real_listen_send_buffer_size;
	int real_listen_read_buffer_size;

	xmlrpc_client_call2f(&rpc_env, rpc_client, flow[id].endpoint_options[DESTINATION].server_url, "add_flow_destination", &resultP,
		"({s:s,s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,s:i,s:i,s:s,s:i,s:i,s:i,s:i})",

		/* general flow settings */
		"bind_address", flow[id].endpoint_options[DESTINATION].bind_address,
		"write_delay", flow[id].settings[DESTINATION].delay[WRITE],
		"write_duration", flow[id].settings[DESTINATION].duration[WRITE],
		"read_delay", flow[id].settings[SOURCE].delay[WRITE],
		"read_duration", flow[id].settings[SOURCE].duration[WRITE],
		"requested_send_buffer_size", flow[id].settings[DESTINATION].requested_send_buffer_size,
		"requested_read_buffer_size", flow[id].settings[DESTINATION].requested_read_buffer_size,
		"write_block_size", flow[id].settings[DESTINATION].write_block_size,
		"read_block_size", flow[id].settings[DESTINATION].read_block_size,
		"advstats", (int)opt.advstats,
		"so_debug", (int)flow[id].so_debug,
		"route_record", (int)flow[id].settings[DESTINATION].route_record,
		"pushy", flow[id].settings[DESTINATION].pushy,
		"shutdown", (int)flow[id].shutdown,
		"write_rate", flow[id].settings[DESTINATION].write_rate,
		"poisson_distributed", flow[id].settings[DESTINATION].poisson_distributed,
		"flow_control", flow[id].settings[DESTINATION].flow_control,
		"byte_counting", flow[id].byte_counting,
		"cork", (int)flow[id].settings[DESTINATION].cork,
		"cc_alg", flow[id].settings[DESTINATION].cc_alg,
		"elcn", flow[id].settings[DESTINATION].elcn,
		"icmp", flow[id].settings[DESTINATION].icmp,
		"dscp", (int)flow[id].settings[DESTINATION].dscp,
		"ipmtudiscover", flow[id].settings[DESTINATION].ipmtudiscover);

	die_if_fault_occurred(&rpc_env);

	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,s:i,s:i,s:i,s:i,*}",
		"flow_id", &flow[id].endpoint_id[DESTINATION],
		"listen_data_port", &listen_data_port,
		"listen_reply_port", &listen_reply_port,
		"real_listen_send_buffer_size", &real_listen_send_buffer_size,
		"real_listen_read_buffer_size", &real_listen_read_buffer_size);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);

	xmlrpc_client_call2f(&rpc_env, rpc_client, flow[id].endpoint_options[SOURCE].server_url, "add_flow_source", &resultP,
		"({s:s,s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,s:i,s:i,s:s,s:i,s:i,s:i,s:i}"
		"{s:s,s:s,s:i,s:i,s:i})",

		/* general flow settings */
		"bind_address", flow[id].endpoint_options[SOURCE].bind_address,
		"write_delay", flow[id].settings[SOURCE].delay[WRITE],
		"write_duration", flow[id].settings[SOURCE].duration[WRITE],
		"read_delay", flow[id].settings[DESTINATION].delay[WRITE],
		"read_duration", flow[id].settings[DESTINATION].duration[WRITE],
		"requested_send_buffer_size", flow[id].settings[SOURCE].requested_send_buffer_size,
		"requested_read_buffer_size", flow[id].settings[SOURCE].requested_read_buffer_size,
		"write_block_size", flow[id].settings[SOURCE].write_block_size,
		"read_block_size", flow[id].settings[SOURCE].read_block_size,
		"advstats", (int)opt.advstats,
		"so_debug", (int)flow[id].so_debug,
		"route_record", (int)flow[id].settings[SOURCE].route_record,
		"pushy", flow[id].settings[SOURCE].pushy,
		"shutdown", (int)flow[id].shutdown,
		"write_rate", flow[id].settings[SOURCE].write_rate,
		"poisson_distributed", flow[id].settings[SOURCE].poisson_distributed,
		"flow_control", flow[id].settings[SOURCE].flow_control,
		"byte_counting", flow[id].byte_counting,
		"cork", (int)flow[id].settings[SOURCE].cork,
		"cc_alg", flow[id].settings[SOURCE].cc_alg,
		"elcn", flow[id].settings[SOURCE].elcn,
		"icmp", flow[id].settings[SOURCE].icmp,
		"dscp", (int)flow[id].settings[SOURCE].dscp,
		"ipmtudiscover", flow[id].settings[SOURCE].ipmtudiscover,

		/* source settings */
		"destination_address", flow[id].endpoint_options[DESTINATION].test_address,
		"destination_address_reply", flow[id].endpoint_options[DESTINATION].test_address,
		"destination_port", listen_data_port,
		"destination_port_reply", listen_reply_port,
		"late_connect", (int)flow[id].late_connect);
	die_if_fault_occurred(&rpc_env);

	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,*}",
		"flow_id", &flow[id].endpoint_id[SOURCE]);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);
}

/* Checks that all nodes use our flowgrind version */
void check_version(xmlrpc_client *rpc_client)
{
	unsigned j;
	xmlrpc_value * resultP = 0;
	char mismatch = 0;

	for (j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;

		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "get_version", &resultP,
		"()");
		die_if_fault_occurred(&rpc_env);

		if (resultP) {
			char* version;
			xmlrpc_decompose_value(&rpc_env, resultP, "s", &version);
			die_if_fault_occurred(&rpc_env);

			if (strcmp(version, FLOWGRIND_VERSION)) {
				mismatch = 1;
				fprintf(stderr, "Warning: Node %s uses version %s\n", unique_servers[j], version);
			}

			xmlrpc_DECREF(resultP);
		}
	}

	if (mismatch) {
		fprintf(stderr, "Our version is %s\n\nContinuing in 10 seconds.\n", FLOWGRIND_VERSION);
		sleep(10);
	}
}

void prepare_flows(xmlrpc_client *rpc_client)
{
	for (int id = 0; id < opt.num_flows; id++) {

		if (sigint_caught)
			return;

		prepare_flow(id, rpc_client);
	}

	{
		char headline[200];
		int rc;
		struct utsname me;
		time_t start_ts;
		char start_ts_buffer[26];

		rc = uname(&me);
		start_ts = time(NULL);
		ctime_r(&start_ts, start_ts_buffer);
		start_ts_buffer[24] = '\0';
		snprintf(headline, sizeof(headline), "# %s: controlling host = %s, "
				"number of flows = %d, reporting interval = %.2fs, "
				"[tput] = %s (%s)\n",
				(start_ts == -1 ? "(time(NULL) failed)" : start_ts_buffer),
				(rc == -1 ? "(unknown)" : me.nodename),
				opt.num_flows, opt.reporting_interval,
				(opt.mbyte ? "2**20 bytes/second": "10**6 bit/second"),
				FLOWGRIND_VERSION);
		log_output(headline);
	}
}

int parse_Anderson_Test(char *params) {


	//int rc=-9999;
	int i=0;
	//printf("add args: %s\n",params);

	char field [ 32 ];
	int n;
	char c[1];
	strncpy (c, params, 1);

	//printf("c:%s:\n",c);
	//rc=strcmp(c[0],"-");
	//printf("rc:%d",rc);
	//  if (strcmp(c,"-")==5)  //TODO: Bug to figure out why there is an offset of 5 here!!
	//		return 0;

	while ( sscanf(params, "%31[^,]%n", field, &n) == 1 ){
		if ( i==0)  {ADT1 = atof (field); doAnderson=1;}
		if (i==1) {ADT2 = atof (field); doAnderson=2;}

		i++;
		params += n; /* advance the pointer by the number of characters read */
		if ( *params != ',' ){
			break; /* didn't find an expected delimiter, done? */
		}
		++params; /* skip the delimiter */
	}

	if (i==0) return 0;

	printf("\n values for adt params :::_  adt1 %f,adt2 %f \n", ADT1, ADT2);
	return 1;
}

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

static void parse_flow_option(int ch, char* optarg, int current_flow_ids[]) {
	char* token;
	char* arg;
	char type;
	int rc = 0;
	int optint;
	unsigned optunsigned = 0;
	double optdouble = 0.0;

	#define ASSIGN_ENDPOINT_FLOW_OPTION(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (type != 'd') \
						flow[id].endpoint_options[SOURCE].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
					if (type != 's') \
						flow[id].endpoint_options[DESTINATION].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					if (type != 'd') \
						flow[current_flow_ids[id]].endpoint_options[SOURCE].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
					if (type != 's') \
						flow[current_flow_ids[id]].endpoint_options[DESTINATION].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
				} \
			}

	#define ASSIGN_ENDPOINT_FLOW_OPTION_STR(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (type != 'd') \
						strcpy(flow[id].endpoint_options[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[id].endpoint_options[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					if (type != 'd') \
						strcpy(flow[id].endpoint_options[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[id].endpoint_options[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
				} \
			}
	#define ASSIGN_COMMON_FLOW_SETTING(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (type != 'd') \
						flow[id].settings[SOURCE].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
					if (type != 's') \
						flow[id].settings[DESTINATION].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					if (type != 'd') \
						flow[current_flow_ids[id]].settings[SOURCE].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
					if (type != 's') \
						flow[current_flow_ids[id]].settings[DESTINATION].PROPERTY_NAME = \
						(PROPERTY_VALUE); \
				} \
			}
	#define ASSIGN_COMMON_FLOW_SETTING_STR(PROPERTY_NAME, PROPERTY_VALUE) \
			if (current_flow_ids[0] == -1) { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (type != 'd') \
						strcpy(flow[id].settings[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[id].settings[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
				} \
			} else { \
				int id; \
				for (id = 0; id < MAX_FLOWS; id++) { \
					if (current_flow_ids[id] == -1) \
						break; \
					if (type != 'd') \
						strcpy(flow[id].settings[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[id].settings[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
				} \
			}
	for (token = strtok(optarg, ","); token; token = strtok(NULL, ",")) {
		type = token[0];
		if (token[1] == '=')
			arg = token + 2;
		else
			arg = token + 1;

		if (type != 's' && type != 'd' && type != 'b') {
			fprintf(stderr, "Syntax error in flow option: %c is not a valid endpoint.\n", type);
			usage_flowopt();
		}

		switch (ch) {
			case 'B':
				rc = sscanf(arg, "%u", &optunsigned);
				if (rc != 1) {
					fprintf(stderr, "send buffer size must be a positive "
						"integer (in bytes)\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(requested_send_buffer_size, optunsigned)
				break;
			case 'C':
				ASSIGN_COMMON_FLOW_SETTING(flow_control, 1)
				break;
			case 'D':
				rc = sscanf(arg, "%x", &optint);
				if (rc != 1 || (optint & ~0x3f)) {
					fprintf(stderr, "malformed differentiated "
							"service code point.\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(dscp, optint);
			break;

			case 'H':
				{
					char url[1000];
					int port = DEFAULT_LISTEN_PORT;
					char *sepptr, *test_address = 0;

					sepptr = strchr(arg, '/');
					if (sepptr) {
						*sepptr = '\0';
						test_address = sepptr + 1;
						ASSIGN_ENDPOINT_FLOW_OPTION_STR(bind_address, test_address)
					}
					sepptr = strchr(arg, ':');
					if (sepptr) {
						*sepptr = '\0';
						port = atoi(sepptr + 1);
						if (port < 1 || port > 65535) {
							fprintf(stderr, "invalid port for test host\n");
							usage();
						}
					}
					if (!*arg) {
						fprintf(stderr, "No test host given in argument\n");
						usage();
					}

					if (!test_address)
						test_address = arg;
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(test_address, test_address)
					sprintf(url, "http://%s:%d/RPC2", arg, port);
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(server_url, url);
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(server_address, arg);
					ASSIGN_ENDPOINT_FLOW_OPTION(server_port, port);
				}
				break;
			case 'O':
				if (!*arg) {
					fprintf(stderr, "-O requires a value for each given endpoint\n");
					usage_sockopt();
				}

				if (!strcmp(arg, "TCP_CORK")) {
					ASSIGN_COMMON_FLOW_SETTING(cork, 1);
				}
				else if (!strcmp(arg, "TCP_ELCN")) {
					ASSIGN_COMMON_FLOW_SETTING(elcn, 1);
				}
				else if (!strcmp(arg, "TCP_ICMP")) {
					ASSIGN_COMMON_FLOW_SETTING(icmp, 1);
				}
				else if (!strcmp(arg, "ROUTE_RECORD")) {
					ASSIGN_COMMON_FLOW_SETTING(route_record, 1);
				}
				else if (!memcmp(arg, "TCP_CONG_MODULE=", 16)) {
					if (strlen(arg + 16) >= sizeof(flow[0].settings[SOURCE].cc_alg)) {
						fprintf(stderr, "Too large string for TCP_CONG_MODULE value");
						usage_sockopt();
					}
					ASSIGN_COMMON_FLOW_SETTING_STR(cc_alg, arg + 16);
				}
				else if (!memcmp(arg, "IP_MTU_DISCOVER", 15)) {
					ASSIGN_COMMON_FLOW_SETTING(ipmtudiscover, 1);
				}
				else {
					fprintf(stderr, "Unknown socket option or socket option not implemented for endpoint\n");
					usage_sockopt();
				}

				break;
			case 'P':
				ASSIGN_COMMON_FLOW_SETTING(pushy, 1)
				break;
			case 'R':
				if (!*arg) {
					fprintf(stderr, "-R requires a value for each given endpoint\n");
					usage();
				}
				ASSIGN_ENDPOINT_FLOW_OPTION(rate_str, arg)
				break;
			case 'S':
				rc = sscanf(arg, "%u", &optunsigned);
				if (rc != 1) {
					fprintf(stderr, "block size must be a positive "
						"integer (in bytes)\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(write_block_size, optunsigned)
				break;
			case 'T':
				rc = sscanf(arg, "%lf", &optdouble);
				if (rc != 1) {
					fprintf(stderr, "malformed flow duration\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(duration[WRITE], optdouble)
				break;
			case 'W':
				rc = sscanf(arg, "%u", &optunsigned);
				if (rc != 1) {
					fprintf(stderr, "receive buffer size (advertised window) must be a positive "
						"integer (in bytes)\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(requested_read_buffer_size, optunsigned)
				break;
			case 'Y':
				rc = sscanf(arg, "%lf", &optdouble);
				if (rc != 1 || optdouble < 0) {
					fprintf(stderr, "delay must be a non-negativ "
							"number (in seconds)\n");
					usage();
				}
				ASSIGN_COMMON_FLOW_SETTING(delay[WRITE], optdouble)
				break;
		}
	}

	#undef ASSIGN_ENDPOINT_FLOW_OPTION
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
	unsigned optunsigned = 0;
	double optdouble = 0.0;

	current_flow_ids[0] = -1;

	while ((ch = getopt(argc, argv, "ab:c:de:h:i:l:mn:op:qvwB:CD:EF:H:LNO:P:QR:S:T:W:Y:")) != -1)
		switch (ch) {

		case 'a':
			opt.advstats = 1;
			break;

		case 'b':
			parse_Anderson_Test(optarg);
			break;

		case 'c':
			parse_visible_param(optarg);
			break;

		case 'd':
			increase_debuglevel();
			break;

		case 'e':
			opt.log_filename_prefix = optarg;
			break;

		case 'h':
			if(strcmp(optarg, "sockopt")) {
				fprintf(stderr, "Illegal subargument: %s\n", optarg);
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

		case 'E':
			ASSIGN_FLOW_OPTION(byte_counting, 1)
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

		case 'L':
			ASSIGN_FLOW_OPTION(late_connect, 1)
			break;

		case 'N':
			ASSIGN_FLOW_OPTION(shutdown, 1);
			break;

		case 'Q':
			ASSIGN_FLOW_OPTION(summarize_only, 1)
			break;
		case 'B':
		case 'C':
		case 'D':
		case 'H':
		case 'O':
		case 'P':
		case 'R':
		case 'S':
		case 'T':
		case 'W':
		case 'Y':
			parse_flow_option(ch, optarg, current_flow_ids);
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
		if (flow[id].settings[DESTINATION].duration[WRITE] > 0 && flow[id].late_connect &&
				flow[id].settings[DESTINATION].delay[WRITE] <
				flow[id].settings[SOURCE].delay[WRITE]) {
			fprintf(stderr, "Server flow %d starts earlier than client "
					"flow while late connecting.\n", id);
			error = 1;
		}
		if (flow[id].settings[SOURCE].delay[WRITE] > 0 &&
				flow[id].settings[SOURCE].duration[WRITE] == 0) {
			fprintf(stderr, "Client flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (flow[id].settings[DESTINATION].delay[WRITE] > 0 &&
				flow[id].settings[DESTINATION].duration[WRITE] == 0) {
			fprintf(stderr, "Server flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (!flow[id].settings[DESTINATION].duration[WRITE] &&
				!flow[id].settings[SOURCE].duration[WRITE]) {
			fprintf(stderr, "Server and client flow have both "
					"zero runtime for flow %d.\n", id);
			error = 1;
		}
		if (flow[id].two_way) {
			if (flow[id].settings[DESTINATION].duration[WRITE] != 0 &&
					flow[id].settings[SOURCE].duration[WRITE] !=
					flow[id].settings[DESTINATION].duration[WRITE]) {
				fprintf(stderr, "Server flow duration "
						"specified albeit -2.\n");
				error = 1;
			}
			flow[id].settings[DESTINATION].duration[WRITE] =
				flow[id].settings[SOURCE].duration[WRITE];
			if (flow[id].settings[DESTINATION].delay[WRITE] != 0 &&
					flow[id].settings[DESTINATION].delay[WRITE] !=
					flow[id].settings[SOURCE].delay[WRITE]) {
				fprintf(stderr, "Server flow delay specified "
						"albeit -2.\n");
				error = 1;
			}
			flow[id].settings[DESTINATION].delay[WRITE] = flow[id].settings[SOURCE].delay[WRITE];
		}
		flow[id].settings[SOURCE].read_block_size = flow[id].settings[DESTINATION].write_block_size;
		flow[id].settings[DESTINATION].read_block_size = flow[id].settings[SOURCE].write_block_size;

		flow[id].settings[SOURCE].duration[READ] = flow[id].settings[DESTINATION].duration[WRITE];
		flow[id].settings[DESTINATION].duration[READ] = flow[id].settings[SOURCE].duration[WRITE];
		flow[id].settings[SOURCE].delay[READ] = flow[id].settings[DESTINATION].delay[WRITE];
		flow[id].settings[DESTINATION].delay[READ] = flow[id].settings[SOURCE].delay[WRITE];

		for (unsigned i = 0; i < 2; i++) {
			unsigned int j;

			if (flow[id].endpoint_options[i].rate_str) {
				unit = type = distribution = 0;
				/* last %c for catching wrong input... this is not nice. */
				rc = sscanf(flow[id].endpoint_options[i].rate_str, "%lf%c%c%c%c",
						&optdouble, &unit, &type,
						&distribution, &unit);
				if (rc < 1 || rc > 4) {
					fprintf(stderr, "malformed rate for flow %u.\n", id);
					error = 1;
				}

				if (optdouble == 0.0) {
					flow[id].endpoint_options[i].rate_str = NULL;
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
					optdouble /= flow[id].settings[SOURCE].write_block_size;
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
				// TODO: Is this dependend on the destination's rate at all?
				if (optdouble > max_flow_rate)
					max_flow_rate = optdouble;
				flow[id].settings[i].write_rate = optdouble;

				switch (distribution) {
				case 0:
				case 'p':
					flow[id].settings[i].poisson_distributed = 0;
					break;

				case 'P':
					flow[id].settings[i].poisson_distributed = 1;
					break;

				default:
					fprintf(stderr, "illegal distribution specifier "
							"in rate for flow %u.\n", id);
				}
			}
			if (flow[id].settings[i].flow_control && !flow[id].endpoint_options[i].rate_str) {
				fprintf(stderr, "flow %d has flow control enabled but "
						"no rate.", id);
				error = 1;
			}

			/* Gather unique server URLs */
			for (j = 0; j < num_unique_servers; j++) {
				if (!strcmp(unique_servers[j], flow[id].endpoint_options[i].server_url))
					break;
			}
			if (j == num_unique_servers) {
				strcpy(unique_servers[num_unique_servers++], flow[id].endpoint_options[i].server_url);
			}
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
	struct sigaction sa;

	xmlrpc_client *rpc_client = 0;

	xmlrpc_env_init(&rpc_env);
	xmlrpc_client_setup_global_const(&rpc_env);

	init_options_defaults();
	init_flows_defaults();
	parse_cmdline(argc, argv);
	init_logfile();

	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL)) {
		fprintf(stderr, "Error: Could not set handler for SIGINT\n");
	}

	xmlrpc_client_create(&rpc_env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &rpc_client);

	check_version(rpc_client);
	if (!sigint_caught)
		prepare_flows(rpc_client);
	if (!sigint_caught)
		grind_flows(rpc_client);
	if (!sigint_caught)
		report_final();
	
	close_flows();

	shutdown_logfile();
	exit(0);
}
