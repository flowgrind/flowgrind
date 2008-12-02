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
#include "svnversion.h"

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

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

int createOutputColumn(char *strHead1Row, char *strHead2Row, char *strData1Row, char *strData2Row,
	char *strHead1, char *strHead2, double value1, double value2, unsigned int *control0,
	unsigned int *control1, int numDigitsDecimalPart, int showColumn, int *columnWidthChanged) {

	unsigned int maxTooLongColumns = 2; // Maximum number of rows with non-optimal column width
	int lengthData = 0; // #digits of values
	int lengthHead = 0; // Length of header string
	unsigned int columnSize = 0;
	char tempBuffer[50];
	unsigned int a;

	char* number_formatstring;

	if (!showColumn)
		return 0;

	// get max columnsize
	lengthData = MAX(det_output_column_size(value1), det_output_column_size(value2)) + 2 + numDigitsDecimalPart;
	lengthHead = MAX(strlen(strHead1), strlen(strHead2));
	columnSize = MAX(lengthData, lengthHead);

	// check if columnsize has changed
	if (*control1 < columnSize) {
		*columnWidthChanged = 1;
		*control1 = columnSize;
		*control0 = 0;
	}
	else if (*control1 > 1 + columnSize) {
		if (*control0 >= maxTooLongColumns) {
			*columnWidthChanged = 1;
			*control1 = columnSize;
			*control0 = 0;
		}
		else
			(*control0)++;
	}

	number_formatstring = outStringPart(*control1, numDigitsDecimalPart);

	// create columns
	// Data Sender -> Reciver
	sprintf(tempBuffer, number_formatstring, value1);
	strcat(strData1Row, tempBuffer);

	// Data Reciver -> Sender
	sprintf(tempBuffer, number_formatstring, value2);
	strcat(strData2Row, tempBuffer);

	// 1. Header row
	for (a = *control1; a > strlen(strHead1); a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, strHead1);

	// 2. Header Row
	for (a = *control1; a > strlen(strHead2); a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, strHead2);

	return 0;
}

char *createOutput(char hash, int id, double begin, double end,
		double cs, double sc,
		double rttmin, double rttavg, double rttmax,
		double iatmin, double iatavg, double iatmax,
		int cwnd, int ssth, int uack, int sack, int lost,int reor,
		int retr, int fack,double linrtt,double linrttvar,
		double linrto, int mss, int mtu, char* comnt, int unit_byte) {

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
	static char * const str_coment[] = {" ;-)", " "};

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
	char dataSenderString[1000];
	char dataReciverString[1000];
	char headerString1[1000];
	char headerString2[1000];
	static char outputString[4000];

	//output string
	//param # + flow_id
	sprintf(dataSenderString, "%cS%3d", hash, id);
	sprintf(dataReciverString, "%cR%3d", hash, id);
	strcpy(headerString1, str_id);
	strcpy(headerString2, "#    ");
	i++;

	//param begin
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_begin[0], str_begin[1], begin, begin, &control[i][0], &control[i][1], 3, visible_columns[0], &columnWidthChanged);
	i++;

	//param end
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_end[0], str_end[1], end, end, &control[i][0], &control[i][1], 3, visible_columns[1], &columnWidthChanged);
	i++;

	//param c/s s/c throughput
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_cs[0], str_cs[1], cs, sc, &control[i][0], &control[i][1], 6, visible_columns[2], &columnWidthChanged);
	i++;

	//param str_rttmin
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_rttmin[0], str_rttmin[1], rttmin, 0, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_rttavg
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_rttavg[0], str_rttavg[1], rttavg, 0, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_rttmax
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_rttmax[0], str_rttmax[1], rttmax, 0, &control[i][0], &control[i][1], 3, visible_columns[3], &columnWidthChanged);
	i++;

	//param str_iatmin
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_iatmin[0], str_iatmin[1], iatmin, 0, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//param str_iatavg
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_iatavg[0], str_iatavg[1], iatavg, 0, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//param str_iatmax
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_iatmax[0], str_iatmax[1], iatmax, 0, &control[i][0], &control[i][1], 3, visible_columns[4], &columnWidthChanged);
	i++;

	//linux kernel output
	//param str_cwnd
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_cwnd[0], str_cwnd[1], cwnd, 0, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_ssth
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_ssth[0], str_ssth[1], ssth, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_uack
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_uack[0], str_uack[1], uack, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_sack
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_sack[0], str_sack[1], sack, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_lost
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_lost[0], str_lost[1], lost, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_retr
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_retr[0], str_retr[1], retr, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_fack
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_fack[0], str_fack[1], fack, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_reor
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_reor[0], str_reor[1], reor, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrtt
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_linrtt[0], str_linrtt[1], linrtt, 0, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrttvar
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_linrttvar[0], str_linrttvar[1], linrttvar, 0, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	//param str_linrto
	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_linrto[0], str_linrto[1], linrto, 0, &control[i][0], &control[i][1], 3, visible_columns[5], &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_mss[0], str_mss[1], mss, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataSenderString, dataReciverString, str_mtu[0], str_mtu[1], mtu, 0, &control[i][0], &control[i][1], 0, visible_columns[5], &columnWidthChanged);
	i++;

	strcat(headerString1, str_coment[0]);
	strcat(headerString2, str_coment[1]);
	strcat(dataSenderString, comnt);
	strcat(dataReciverString, comnt);

	//newline at the end of the string
	strcat(headerString1, "\n");
	strcat(headerString2, "\n");
	strcat(dataSenderString, "\n");
	strcat(dataReciverString, "\n");
	//output string end
	if (columnWidthChanged > 0 || (counter % 25) == 0) {
		strcpy(outputString, headerString1);
		strcat(outputString, headerString2);
		strcat(outputString, dataSenderString);
		strcat(outputString, dataReciverString);
	}
	else {
		strcpy(outputString, dataSenderString);
		strcat(outputString, dataReciverString);
	}
	counter++;

	// now do the anderson darlington stuff
	if (doAnderson > 0) {

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
		"  -C           Stop flow if it is experiencing local congestion\n"
		"  -D DSCP      DSCP value for TOS byte\n"
		"  -E x         Enumerate bytes in payload (default: don't)\n"
		"  -F #{,#}     Flow options following this option apply only to flow #{,#}.\n"
		"               Useful in combination with -n to set specific options\n"
		"               for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"               to the second flow\n"
		"  -H HOST[/HOST][:PORT]\n"
		"               Test against host. Optional control host may be specified to\n"
		"               handle connection setup via another interface/route\n"
		"  -L x         connect() socket immediately before sending (late)\n"
		"  -N x         shutdown() each socket direction after test flow\n"
		"  -O x=OPT     Set specific socket options on test socket.\n"
		"               type \"flowgrind -h sockopt\" to see the specific values for OPT\n"
		"  -P           Do not iterate through select() to continue sending in case\n"
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
		"  s=TCP_CORK   set TCP_CORK on test socket\n"
		"  s=TCP_ELCN   set TCP_ELCN on test socket\n"
		"  s=TCP_ICMP   set TCP_ICMP on test socket\n"
		"  s=IP_MTU_DISCOVER\n"
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
		flow[id].server_name = "localhost";
		flow[id].server_name_control = "localhost";
		flow[id].server_control_port = DEFAULT_LISTEN_PORT;
		flow[id].mss = 0;

		flow[id].proto = PROTO_TCP;

		for (int i = 0; i < 2; i++) {
			flow[id].endpoint_options[i].send_buffer_size = 0;
			flow[id].endpoint_options[i].receive_buffer_size = 0;
			flow[id].endpoint_options[i].flow_delay = 0;
			flow[id].endpoint_options[i].block_size = 8192;
			flow[id].endpoint_options[i].route_record = 0;
		}
		flow[id].endpoint_options[SOURCE].flow_duration = 5.0;
		flow[id].endpoint_options[DESTINATION].flow_duration = 0.0;

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
		flow[id].read_block_bytes_read = 0;
		flow[id].write_block = NULL;
		flow[id].write_block_bytes_written = 0;

		/* Stats */
		flow[id].bytes_read_since_first = 0;
		flow[id].bytes_read_since_last = 0;
		flow[id].bytes_written_since_first = 0;
		flow[id].bytes_written_since_last = 0;

		flow[id].read_reply_blocks_since_first = 0;
		flow[id].read_reply_blocks_since_last = 0;

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
		printf("%s", msg);
		fflush(stdout);
	}
	if (!opt.dont_log_logfile) {
		fprintf(log_stream, "%s", msg);
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
	flow[id].read_reply_blocks_since_last++;
	flow[id].read_reply_blocks_since_first++;

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

	for (id = 0; id < opt.num_flows; id++) {
		flow[id].endpoint_options[SOURCE].flow_start_timestamp = timer.start;
		time_add(&flow[id].endpoint_options[SOURCE].flow_start_timestamp,
				flow[id].endpoint_options[SOURCE].flow_delay);
		if (flow[id].endpoint_options[SOURCE].flow_duration >= 0) {
			flow[id].endpoint_options[SOURCE].flow_stop_timestamp =
				flow[id].endpoint_options[SOURCE].flow_start_timestamp;
			time_add(&flow[id].endpoint_options[SOURCE].flow_stop_timestamp,
					flow[id].endpoint_options[SOURCE].flow_duration);
		}
		if (flow[id].endpoint_options[SOURCE].rate)
			flow[id].next_write_block_timestamp =
				flow[id].endpoint_options[SOURCE].flow_start_timestamp;

		flow[id].endpoint_options[DESTINATION].flow_start_timestamp = timer.start;
		time_add(&flow[id].endpoint_options[DESTINATION].flow_start_timestamp,
				flow[id].endpoint_options[DESTINATION].flow_delay);
		if (flow[id].endpoint_options[DESTINATION].flow_duration >= 0) {
			flow[id].endpoint_options[DESTINATION].flow_stop_timestamp =
				flow[id].endpoint_options[DESTINATION].flow_start_timestamp;
			time_add(&flow[id].endpoint_options[DESTINATION].flow_stop_timestamp,
					flow[id].endpoint_options[DESTINATION].flow_duration);
		}
	}
}


void
print_tcp_report_line(char hash, int id, double time1, double time2,
		long bytes_written, long bytes_read,
		long read_reply_blocks,  double min_rtt,
		double tot_rtt, double max_rtt, double min_iat,
		double tot_iat, double max_iat
#ifdef __LINUX__
		,unsigned cwnd, unsigned ssth, unsigned uack,
		unsigned sack, unsigned lost, unsigned retr,
		unsigned fack, unsigned reor, double rtt,
		double rttvar, double rto, int mss, int mtu
#endif
)
{
	double avg_rtt;
	double avg_iat;
	unsigned blocks_written = 0;
	char comment_buffer[100] = "(";
	char report_buffer[4000] = "";
	double thruput = 0.0;

#define COMMENT_CAT(s) do { if (strlen(comment_buffer) > 1) \
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

	if (flow[id].stopped)
		COMMENT_CAT("stopped")
	else {
		blocks_written = bytes_written / flow[id].endpoint_options[SOURCE].block_size;
		if (blocks_written == 0) {
			if (client_flow_in_delay(id))
				COMMENT_CAT("d")
			else if (client_flow_sending(id))
				COMMENT_CAT("l")
			else if (flow[id].endpoint_options[SOURCE].flow_duration == 0)
				COMMENT_CAT("o")
			else
				COMMENT_CAT("f")
		} else {
			if (!client_flow_sending(id) && active_flows > 0)
				COMMENT_CAT("c")
			else
				COMMENT_CAT("n")
		}

		if (bytes_read == 0) {
			if (server_flow_in_delay(id))
				COMMENT_CAT("d")
			else if (server_flow_sending(id))
				COMMENT_CAT("l")
			else if (flow[id].endpoint_options[DESTINATION].flow_duration == 0)
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

	//wrong
	if (!hash) {
		mss = get_mss(flow[id].sock);
		mtu = get_mtu(flow[id].sock);
		flow[id].current_mss = mss;
		flow[id].current_mtu = mtu;
	}

	char rep_string[4000];
#ifndef __LINUX__
	// dont show linux kernel output if there is no linux OS
	visible_columns[5] = 0;
#endif
	strcpy(rep_string, createOutput((hash ? '#' : ' '), id,
		time1, time2, thruput,
		scale_thruput((double)bytes_read / (time2 - time1)),
		min_rtt * 1e3, avg_rtt * 1e3, max_rtt * 1e3,
		min_iat * 1e3, avg_iat * 1e3, max_iat * 1e3,
#ifdef __LINUX__
		(double)cwnd, (double)ssth, (double)uack, (double)sack, (double)lost, (double)retr, (double)fack, (double)reor,
		(double)rtt / 1e3, (double)rttvar / 1e3, (double)rto / 1e3,
#else
		0, 0, 0, 0, 0, 0, 0,
		0, 0, 0,
#endif
		mss, mtu, comment_buffer, opt.mbyte
	));
	snprintf(report_buffer, sizeof(report_buffer), rep_string);
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
			"\n# #%d: %s", id, flow[id].server_name);

#define CAT(fmt, args...) do {\
	snprintf(header_nibble, sizeof(header_nibble), fmt, ##args); \
	strncat(header_buffer, header_nibble, sizeof(header_nibble)); } while (0)
#define CATC(fmt, args...) CAT(", "fmt, ##args)

		if (strcmp(flow[id].server_name, flow[id].server_name_control) != 0)
			CAT("/%s", flow[id].server_name_control);
		if (flow[id].server_control_port != DEFAULT_LISTEN_PORT)
			CAT(",%d", flow[id].server_control_port);
		CATC("MSS = %d", flow[id].mss);
//		if (flow[id].mtu != -1)
			CATC("MTU = %d (%s)", flow[id].current_mtu,
				guess_topology(flow[id].current_mss, flow[id].current_mtu)
	//possible correction
	//		guess_topology(get_mss(flow[id].sock), get_mtu(flow[id].sock))
			);
		if (flow[id].stopped)
			thruput = flow[id].bytes_written_since_first
				/ time_diff(&flow[id].endpoint_options[SOURCE].flow_start_timestamp,
						&flow[id].stopped_timestamp);
		else
			thruput = flow[id].bytes_written_since_first /
				flow[id].endpoint_options[SOURCE].flow_duration;
		thruput = scale_thruput(thruput);
		CATC("sb = %u/%u%s (%u/%u), rb = %u/%u%s (%u/%u), bs = %u/%u\n#delay = %.2fs/%.2fs, "
				"duration = %.2fs/%.2fs, thruput = %.6fM%c/s "
				"(%llu blocks)",
				flow[id].endpoint_options[SOURCE].send_buffer_size_real,
				flow[id].endpoint_options[DESTINATION].send_buffer_size_real,
				(flow[id].endpoint_options[DESTINATION].send_buffer_size ? "" : "(?)"),
				flow[id].endpoint_options[SOURCE].send_buffer_size,
				flow[id].endpoint_options[DESTINATION].send_buffer_size,
				flow[id].endpoint_options[SOURCE].receive_buffer_size_real,
				flow[id].endpoint_options[DESTINATION].receive_buffer_size_real,
				(flow[id].endpoint_options[DESTINATION].receive_buffer_size ? "" : "(?)"),
				flow[id].endpoint_options[SOURCE].receive_buffer_size,
				flow[id].endpoint_options[DESTINATION].receive_buffer_size,
				flow[id].endpoint_options[SOURCE].block_size,
				flow[id].endpoint_options[DESTINATION].block_size,
				flow[id].endpoint_options[SOURCE].flow_delay,
				flow[id].endpoint_options[DESTINATION].flow_delay,
				flow[id].endpoint_options[SOURCE].flow_duration,
				flow[id].endpoint_options[DESTINATION].flow_duration,
				thruput, (opt.mbyte ? 'B' : 'b'),
				flow[id].write_block_count);
		if (flow[id].endpoint_options[SOURCE].rate_str)
			CATC("rate = %s", flow[id].endpoint_options[SOURCE].rate_str);
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
				1, id, flow[id].endpoint_options[SOURCE].flow_delay,
				flow[id].endpoint_options[SOURCE].flow_duration +
				flow[id].endpoint_options[SOURCE].flow_delay, 0, 0,
				0,
				INFINITY, INFINITY, INFINITY,
				INFINITY, INFINITY, INFINITY,
#ifdef __LINUX__
				info->tcpi_snd_cwnd, info->tcpi_snd_ssthresh,
				info->tcpi_unacked, info->tcpi_sacked,
				info->tcpi_lost, info->tcpi_retrans,
				info->tcpi_fackets, info->tcpi_reordering,
				info->tcpi_rtt, info->tcpi_rttvar, info->tcpi_rto,
#endif
				flow[id].mss, flow[id].mtu
			);
			continue;
		}

		print_tcp_report_line(
			1, id, flow[id].endpoint_options[SOURCE].flow_delay,
			time_diff(&timer.start, &flow[id].last_block_written),
			flow[id].bytes_written_since_first,
			flow[id].bytes_read_since_first,
			flow[id].read_reply_blocks_since_first,
			flow[id].min_rtt_since_first,
			flow[id].tot_rtt_since_first,
			flow[id].max_rtt_since_first,
			flow[id].min_iat_since_first,
			flow[id].tot_iat_since_first,
			flow[id].max_iat_since_first,
#ifdef __LINUX__
			info->tcpi_snd_cwnd, info->tcpi_snd_ssthresh,
			info->tcpi_unacked, info->tcpi_sacked,
			info->tcpi_lost, info->tcpi_retrans,
			info->tcpi_fackets, info->tcpi_reordering,
			info->tcpi_rtt, info->tcpi_rttvar, info->tcpi_rto,
#endif
			flow[id].mss, flow[id].mtu
		);
	}

//now we can add the output for the anderson-darling test
double t_result_s, r_result_s, i_result_s, t_result_r, r_result_r, i_result_r;

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

	//now depending on which test the user wanted we make the function calls
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
			flow[id].read_reply_blocks_since_last,
			flow[id].min_rtt_since_last,
			flow[id].tot_rtt_since_last,
			flow[id].max_rtt_since_last,
			flow[id].min_iat_since_last,
			flow[id].tot_iat_since_last,
			flow[id].max_iat_since_last,
#ifdef __LINUX__
			info.tcpi_snd_cwnd,
			info.tcpi_snd_ssthresh,
			info.tcpi_last_data_sent, info.tcpi_last_ack_recv,
			info.tcpi_lost,
			flow[id].last_tcp_info.tcpi_retrans - info.tcpi_retrans,
			info.tcpi_fackets,
			info.tcpi_reordering,
			info.tcpi_rtt,
			info.tcpi_rttvar,
			info.tcpi_rto,
#endif
			flow[id].mss,
			flow[id].mtu
		);

	flow[id].read_reply_blocks_since_last = 0;
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


int name2socket(char **server_name, unsigned port, struct sockaddr **saptr,
		socklen_t *lenp, char do_connect)
{
	int fd, n;
	struct addrinfo hints, *res, *ressave;
	struct sockaddr_in *tempv4;
	struct sockaddr_in6 *tempv6;
	char service[7];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(service, sizeof(service), "%u", port);

	if ((n = getaddrinfo(*server_name, service, &hints, &res)) != 0) {
		error(ERR_FATAL, "getaddrinfo() failed: %s",
				gai_strerror(n));
	}
	ressave = res;

	do {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		if (!do_connect)
			break;

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
			if (res->ai_family == PF_INET) {
				tempv4 = (struct sockaddr_in *) res->ai_addr;
				*server_name = inet_ntoa(tempv4->sin_addr);
			}
			else if (res->ai_family == PF_INET6){
				tempv6 = (struct sockaddr_in6 *) res->ai_addr;
				inet_ntop(AF_INET6, &tempv6->sin6_addr, *server_name, 128);
			}
			break;
		}

		error(ERR_WARNING, "Failed to connect to \"%s\": %s",
				*server_name, strerror(errno));
		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL)
		error(ERR_FATAL, "Could not establish connection to "
				"\"%s\": %s", *server_name, strerror(errno));

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

	DEBUG_MSG(5, "flow %d has rate %u", id, flow[id].endpoint_options[SOURCE].rate);
	if (flow[id].endpoint_options[SOURCE].poisson_distributed) {
		double urand = (double)((random()+1.0)/(RANDOM_MAX+1.0));
		double erand = -log(urand) * 1/(double)flow[id].endpoint_options[SOURCE].rate;
		delay = erand;
	} else {
		delay = (double)1/flow[id].endpoint_options[SOURCE].rate;
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
		iov.iov_len = flow[id].endpoint_options[DESTINATION].block_size -
			flow[id].read_block_bytes_read;
		// no name required
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
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
			if (!flow[id].endpoint_options[DESTINATION].flow_finished ||
					!flow[id].shutdown)
				error(ERR_WARNING, "Premature shutdown of "
						"server flow");
			flow[id].endpoint_options[DESTINATION].flow_finished = 1;
			if (flow[id].endpoint_options[SOURCE].flow_finished) {
				DEBUG_MSG(4, "flow %u finished", id);
				stop_flow(id);
			}
			return;
		}

		DEBUG_MSG(4, "flow %d received %u bytes", id, rc);

#if 0
		if (flow[id].endpoint_options[DESTINATION].flow_duration == 0)
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
				flow[id].endpoint_options[DESTINATION].block_size) {
			assert(flow[id].read_block_bytes_read
					== flow[id].endpoint_options[DESTINATION].block_size);
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
				flow[id].endpoint_options[SOURCE].block_size -
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
				flow[id].endpoint_options[SOURCE].block_size,
				flow[id].write_block_bytes_written);
		flow[id].bytes_written_since_first += rc;
		flow[id].bytes_written_since_last += rc;
		flow[id].write_block_bytes_written += rc;
		if (flow[id].write_block_bytes_written >=
				flow[id].endpoint_options[SOURCE].block_size) {
			flow[id].write_block_bytes_written = 0;
			tsc_gettimeofday(&flow[id].last_block_written);
			flow[id].write_block_count++;

			if (flow[id].endpoint_options[SOURCE].rate) {
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
		assert(!flow[id].endpoint_options[SOURCE].flow_finished);
		if (client_flow_block_scheduled(id)) {
			DEBUG_MSG(4, "adding sock of flow %d to wfds", id);
			FD_SET(flow[id].sock, &wfds);
		} else {
			DEBUG_MSG(4, "no block for flow %d scheduled yet", id);
		}
	} else if (!flow[id].endpoint_options[SOURCE].flow_finished) {
		flow[id].endpoint_options[SOURCE].flow_finished = 1;
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
		if (!flow[id].endpoint_options[DESTINATION].flow_finished && flow[id].shutdown) {
			error(ERR_WARNING, "server flow %u missed to shutdown", id);
			rc = shutdown(flow[id].sock, SHUT_RD);
			if (rc == -1) {
				error(ERR_WARNING, "shutdown SHUT_RD "
						"failed: %s", strerror(errno));
			}
			flow[id].endpoint_options[DESTINATION].flow_finished = 1;
		}
	}

	if (flow[id].late_connect && !flow[id].connect_called ) {
		DEBUG_MSG(1, "late connecting test socket "
				"for flow %d after %.3fs delay",
				id, flow[id].endpoint_options[SOURCE].flow_delay);
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
		flow[id].mss = get_mss(flow[id].sock);
	}

	/* Altough the server flow might be finished we keep the socket in
	 * rfd in order to check for buggy servers */
	if (flow[id].connect_called && !flow[id].endpoint_options[DESTINATION].flow_finished) {
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

		if ((!flow[id].endpoint_options[DESTINATION].flow_duration ||
					(!server_flow_in_delay(id) &&
					 !server_flow_sending(id))) &&
				(!flow[id].endpoint_options[SOURCE].flow_duration ||
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


void prepare_flow(int id)
{
	char buf[1024];
	int rc;
	unsigned to_write;

	DEBUG_MSG(2, "init flow %d", id);

	DEBUG_MSG(3, "connect()");

	flow[id].sock_control =
		name2socket((&flow[id].server_name_control),
				flow[id].server_control_port, NULL, NULL, 1);
	read_greeting(flow[id].sock_control);

	to_write = snprintf(buf, sizeof(buf),
			"%s,t,%s,%hu,%hhd,%hhd,%u,%u,%lf,%lf,%u,%u,%hhd,%hhd,%hhd,%hdd+",
			FLOWGRIND_PROT_CALLSIGN FLOWGRIND_PROT_SEPERATOR FLOWGRIND_PROT_VERSION,
			flow[id].server_name_control,
			(opt.base_port ? opt.base_port++ : 0),
			opt.advstats, flow[id].so_debug,
			flow[id].endpoint_options[DESTINATION].send_buffer_size,
   			flow[id].endpoint_options[DESTINATION].receive_buffer_size,
			flow[id].endpoint_options[DESTINATION].flow_delay,
			flow[id].endpoint_options[DESTINATION].flow_duration,
			flow[id].endpoint_options[SOURCE].block_size,
			flow[id].endpoint_options[DESTINATION].block_size,
			flow[id].pushy,
			flow[id].shutdown,
			flow[id].endpoint_options[DESTINATION].route_record,
			(char)sizeof(flow[id].reply_block)
			);
	DEBUG_MSG(1, "proposal: %s", buf);
	write_proposal(flow[id].sock_control, buf, to_write);
	read_until_plus(flow[id].sock_control, buf, sizeof(buf));
	DEBUG_MSG(1, "proposal reply: %s", buf);
	rc = sscanf(buf, "%u,%u,%u+", &flow[id].server_data_port,
			&flow[id].endpoint_options[DESTINATION].send_buffer_size_real,
			&flow[id].endpoint_options[DESTINATION].receive_buffer_size_real);
	if (rc != 3)
		error(ERR_FATAL, "malformed session response from server");

	if (flow[id].endpoint_options[DESTINATION].send_buffer_size != 0 &&
			flow[id].endpoint_options[DESTINATION].send_buffer_size_real !=
			flow[id].endpoint_options[DESTINATION].send_buffer_size) {
		fprintf(stderr, "warning: server failed to set requested "
				"send buffer size %u, actual = %u\n",
				flow[id].endpoint_options[DESTINATION].send_buffer_size,
				flow[id].endpoint_options[DESTINATION].send_buffer_size_real);
	}
	if (flow[id].endpoint_options[DESTINATION].receive_buffer_size != 0 &&
			flow[id].endpoint_options[DESTINATION].receive_buffer_size_real !=
			flow[id].endpoint_options[DESTINATION].receive_buffer_size) {
		fprintf(stderr, "warning: server failed to set requested "
				"receive buffer size (advertised window) %u, actual = %u\n",
				flow[id].endpoint_options[DESTINATION].receive_buffer_size,
				flow[id].endpoint_options[DESTINATION].receive_buffer_size_real);
	}
	flow[id].sock = name2socket(&flow[id].server_name,
			flow[id].server_data_port,
			&flow[id].saddr, &flow[id].saddr_len, 0);

	flow[id].endpoint_options[SOURCE].send_buffer_size_real =
		set_window_size_directed(flow[id].sock, flow[id].endpoint_options[SOURCE].send_buffer_size, SO_SNDBUF);
	flow[id].endpoint_options[SOURCE].receive_buffer_size_real =
		set_window_size_directed(flow[id].sock, flow[id].endpoint_options[SOURCE].receive_buffer_size, SO_RCVBUF);
	if (flow[id].endpoint_options[SOURCE].send_buffer_size != 0 &&
			flow[id].endpoint_options[SOURCE].send_buffer_size_real !=
			flow[id].endpoint_options[SOURCE].send_buffer_size) {
		fprintf(stderr, "warning: failed to set requested client "
				"send buffer size %u, actual = %u\n",
				flow[id].endpoint_options[SOURCE].send_buffer_size,
				flow[id].endpoint_options[SOURCE].send_buffer_size_real);
	}
	if (flow[id].endpoint_options[SOURCE].receive_buffer_size != 0 &&
			flow[id].endpoint_options[SOURCE].receive_buffer_size_real !=
			flow[id].endpoint_options[SOURCE].receive_buffer_size) {
		fprintf(stderr, "warning: failed to set requested client "
				"receive buffer size (advertised window) %u, actual = %u\n",
				flow[id].endpoint_options[SOURCE].receive_buffer_size,
				flow[id].endpoint_options[SOURCE].receive_buffer_size_real);
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

	if (flow[id].endpoint_options[SOURCE].route_record && set_route_record(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set route record "
				"option for flow id = %i: %s",
				id, strerror(errno));

	if (flow[id].dscp && set_dscp(flow[id].sock, flow[id].dscp) == -1)
		error(ERR_FATAL, "Unable to set DSCP value"
				"for flow %d: %s", id, strerror(errno));

	if (flow[id].ipmtudiscover && set_ip_mtu_discover(flow[id].sock) == -1)
		error(ERR_FATAL, "Unable to set IP_MTU_DISCOVER value"
				"for flow %d: %s", id, strerror(errno));


	if (!flow[id].late_connect) {
		DEBUG_MSG(4, "(early) connecting test socket");
		connect(flow[id].sock, flow[id].saddr, flow[id].saddr_len);
		flow[id].connect_called = 1;
		flow[id].mtu = get_mtu(flow[id].sock);
		flow[id].mss = get_mss(flow[id].sock);
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
		flow[id].write_block = calloc(1, (size_t)flow[id].endpoint_options[SOURCE].block_size);
		flow[id].read_block = calloc(1, (size_t)flow[id].endpoint_options[DESTINATION].block_size);
		if (flow[id].read_block == NULL || flow[id].write_block == NULL) {
			error(ERR_FATAL, "malloc(): failed");
		}
		if (flow[id].byte_counting)
			for (byte_idx = 0; byte_idx < flow[id].endpoint_options[SOURCE].block_size;
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
				ASSIGN_ENDPOINT_FLOW_OPTION(send_buffer_size, optunsigned)
				break;
			case 'O':
				if (!*arg) {
					fprintf(stderr, "-O requires a value for each given endpoint\n");
					usage_sockopt();
				}

				if (!strcmp(arg, "TCP_CORK") && type == 's') {
					ASSIGN_FLOW_OPTION(cork, 1);
				}
				else if (!strcmp(arg, "TCP_ELCN") && type == 's') {
					ASSIGN_FLOW_OPTION(elcn, 1);
				}
				else if (!strcmp(arg, "TCP_ICMP") && type == 's') {
					ASSIGN_FLOW_OPTION(icmp, 1);
				}
				else if (!strcmp(arg, "ROUTE_RECORD")) {
					ASSIGN_ENDPOINT_FLOW_OPTION(route_record, 1);
				}
				else if (!memcmp(arg, "TCP_CONG_MODULE=", 16) && type == 's') {
					ASSIGN_FLOW_OPTION(cc_alg, arg + 16);
				}
				else if (!memcmp(arg, "IP_MTU_DISCOVER", 15) && type == 's') {
					ASSIGN_FLOW_OPTION(ipmtudiscover, 1);
				}
				else {
					fprintf(stderr, "Unknown socket option or socket option not implemented for endpoint\n");
					usage_sockopt();
				}

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
				ASSIGN_ENDPOINT_FLOW_OPTION(block_size, optunsigned)
				break;
			case 'T':
				rc = sscanf(arg, "%lf", &optdouble);
				if (rc != 1) {
					fprintf(stderr, "malformed flow duration\n");
					usage();
				}
				ASSIGN_ENDPOINT_FLOW_OPTION(flow_duration, optdouble)
				break;
			case 'W':
				rc = sscanf(arg, "%u", &optunsigned);
				if (rc != 1) {
					fprintf(stderr, "receive buffer size (advertised window) must be a positive "
						"integer (in bytes)\n");
					usage();
				}
				ASSIGN_ENDPOINT_FLOW_OPTION(receive_buffer_size, optunsigned)
				break;
			case 'Y':
				rc = sscanf(arg, "%lf", &optdouble);
				if (rc != 1 || optdouble < 0) {
					fprintf(stderr, "delay must be a non-negativ "
							"number (in seconds)\n");
					usage();
				}
				ASSIGN_ENDPOINT_FLOW_OPTION(flow_delay, optdouble)
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
	char *sepptr = NULL;
	char *tok = NULL;
	int current_flow_ids[MAX_FLOWS] =  {-1};
	int max_flow_specifier = 0;
	unsigned max_flow_rate = 0;
	char unit = 0, type = 0, distribution = 0;
	int optint = 0;
	unsigned optunsigned = 0;
	double optdouble = 0.0;

	current_flow_ids[0] = -1;

	while ((ch = getopt(argc, argv, "ab:c:de:h:i:l:mn:op:qvwB:CD:EF:H:LNO:PQR:S:T:W:Y:")) != -1)
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

		case 'C':
			ASSIGN_FLOW_OPTION(flow_control, 1);
			break;

		case 'D':
			rc = sscanf(optarg, "%x", &optint);
			if (rc != 1 || (optint & ~0x3f)) {
				fprintf(stderr, "malformed differentiated "
						"service code point.\n");
				usage();
			}
			ASSIGN_FLOW_OPTION(dscp, optint);
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
				ASSIGN_FLOW_OPTION(server_control_port,
						DEFAULT_LISTEN_PORT)
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

		case 'L':
			ASSIGN_FLOW_OPTION(late_connect, 1)
			break;

		case 'N':
			ASSIGN_FLOW_OPTION(shutdown, 1);
			break;

		case 'P':
			ASSIGN_FLOW_OPTION(pushy, 1)
			break;
		case 'Q':
			ASSIGN_FLOW_OPTION(summarize_only, 1)
			break;
		case 'B':
		case 'O':
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
		if (flow[id].endpoint_options[DESTINATION].flow_duration > 0 && flow[id].late_connect &&
				flow[id].endpoint_options[DESTINATION].flow_delay <
				flow[id].endpoint_options[SOURCE].flow_delay) {
			fprintf(stderr, "Server flow %d starts earlier than client "
					"flow while late connecting.\n", id);
			error = 1;
		}
		if (flow[id].endpoint_options[SOURCE].flow_delay > 0 &&
				flow[id].endpoint_options[SOURCE].flow_duration == 0) {
			fprintf(stderr, "Client flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (flow[id].endpoint_options[DESTINATION].flow_delay > 0 &&
				flow[id].endpoint_options[DESTINATION].flow_duration == 0) {
			fprintf(stderr, "Server flow %d has a delay but "
					"no runtime.\n", id);
			error = 1;
		}
		if (!flow[id].endpoint_options[DESTINATION].flow_duration &&
				!flow[id].endpoint_options[SOURCE].flow_duration) {
			fprintf(stderr, "Server and client flow have both "
					"zero runtime for flow %d.\n", id);
			error = 1;
		}
		if (flow[id].two_way) {
			if (flow[id].endpoint_options[DESTINATION].flow_duration != 0 &&
					flow[id].endpoint_options[SOURCE].flow_duration !=
					flow[id].endpoint_options[DESTINATION].flow_duration) {
				fprintf(stderr, "Server flow duration "
						"specified albeit -2.\n");
				error = 1;
			}
			flow[id].endpoint_options[DESTINATION].flow_duration =
				flow[id].endpoint_options[SOURCE].flow_duration;
			if (flow[id].endpoint_options[DESTINATION].flow_delay != 0 &&
					flow[id].endpoint_options[DESTINATION].flow_delay !=
					flow[id].endpoint_options[SOURCE].flow_delay) {
				fprintf(stderr, "Server flow delay specified "
						"albeit -2.\n");
				error = 1;
			}
			flow[id].endpoint_options[DESTINATION].flow_delay = flow[id].endpoint_options[SOURCE].flow_delay;
		}

		for (unsigned i = 0; i < 2; i++) {
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
					optdouble /= flow[id].endpoint_options[SOURCE].block_size;
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
				flow[id].endpoint_options[i].rate = optdouble;

				switch (distribution) {
				case 0:
				case 'p':
					flow[id].endpoint_options[i].poisson_distributed = 0;
					break;

				case 'P':
					flow[id].endpoint_options[i].poisson_distributed = 1;
					break;

				default:
					fprintf(stderr, "illegal distribution specifier "
							"in rate for flow %u.\n", id);
				}
			}
			if (flow[id].flow_control && !flow[id].endpoint_options[i].rate_str) {
				fprintf(stderr, "flow %d has flow control enabled but "
						"no rate.", id);
				error = 1;
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
