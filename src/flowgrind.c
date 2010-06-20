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
#include "fg_math.h"
#if HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#ifdef __SOLARIS__
#define RANDOM_MAX		4294967295UL	/* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX		LONG_MAX	/* Darwin */
#else
#define RANDOM_MAX		RAND_MAX	/* Linux, FreeBSD */
#endif

char sigint_caught = 0;

FILE *log_stream = NULL;
char *log_filename = NULL;
int active_flows = 0;
unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;

enum _column_types
{
	column_type_begin,
	column_type_end,
	column_type_thrpt,
	column_type_rtt,
	column_type_iat,
	column_type_kernel,
	column_type_other
};

// Array for the dynamical output, show all by default
int visible_columns[7] = {1, 1, 1, 1, 1, 1, 1};

// these are the 2 parameters for the ADT test. If the user wants to test for
// Exponential only ADT1 will be used and will represent the mean if the user
// wants to test for the uniform then ADT1 is the lower bound and ADT2 the
// upper bound
double ADT[adt_type_max][2];
int doAnderson = 0; // it will be 1 if we do the exponential test; it will be 2 if we do the uniform test

struct _opt opt;
static struct _flow flow[MAX_FLOWS];

char unique_servers[MAX_FLOWS * 2][1000];
unsigned int num_unique_servers = 0;

xmlrpc_env rpc_env;

void parse_visible_param(char *to_parse) {
	// {begin, end, throughput, RTT, IAT, Kernel}
	if (strstr(to_parse, "+begin"))
		visible_columns[column_type_begin] = 1;
	if (strstr(to_parse, "-begin"))
		visible_columns[column_type_begin] = 0;
	if (strstr(to_parse, "+end"))
		visible_columns[column_type_end] = 1;
	if (strstr(to_parse, "-end"))
		visible_columns[column_type_end] = 0;
	if (strstr(to_parse, "+thrpt"))
		visible_columns[column_type_thrpt] = 1;
	if (strstr(to_parse, "-thrpt"))
		visible_columns[column_type_thrpt] = 0;
	if (strstr(to_parse, "+rtt"))
		visible_columns[column_type_rtt] = 1;
	if (strstr(to_parse, "-rtt"))
		visible_columns[column_type_rtt] = 0;
	if (strstr(to_parse, "+iat"))
		visible_columns[column_type_iat] = 1;
	if (strstr(to_parse, "-iat"))
		visible_columns[column_type_iat] = 0;
	if (strstr(to_parse, "+kernel"))
		visible_columns[column_type_kernel] = 1;
	if (strstr(to_parse, "-kernel"))
		visible_columns[column_type_kernel] = 0;
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

struct _header_info
{
	const char* first;
	const char* second;
	enum _column_types column_type;
};

const struct _header_info header_info[] = {
	{ "#  ID", "#    ", column_type_other },
	{ " begin", " [s]", column_type_begin },
	{ " end", " [s]", column_type_end },
	{ " through", " [Mbit]", column_type_thrpt },
	{ " through", " [MB]", column_type_thrpt },
	{ " min RTT", " [ms]", column_type_rtt },
	{ " avg RTT", " [ms]", column_type_rtt },
	{ " max RTT", " [ms]", column_type_rtt },
	{ " min IAT", " [ms]", column_type_iat },
	{ " avg IAT", " [ms]", column_type_iat },
	{ " max IAT", " [ms]", column_type_iat },
	{ " cwnd", " [#]", column_type_kernel },
	{ " ssth", " [#]", column_type_kernel },
	{ " uack", " [#]", column_type_kernel },
	{ " sack", " [#]", column_type_kernel },
	{ " lost", " [#]", column_type_kernel },
	{ " fret", " [#]", column_type_kernel },
	{ " tret", " [#]", column_type_kernel },
	{ " fack", " [#]", column_type_kernel },
	{ " reor", " [#]", column_type_kernel },
	{ " rtt", " [ms]", column_type_kernel },
	{ " rttvar", " [ms]", column_type_kernel },
	{ " rto", " [ms]", column_type_kernel },
	{ " castate", " ", column_type_kernel },
	{ " mss", " [B]", column_type_kernel },
	{ " mtu", " [B]", column_type_kernel },
	{ " status", " ", column_type_other }
};

struct _column_state
{
	unsigned int count_oversized;
	unsigned int last_width;
};

struct _column_state column_states[sizeof(header_info) / sizeof(struct _header_info)] = {{0,0}};

int createOutputColumn(char *strHead1Row, char *strHead2Row, char *strDataRow,
	int column, double value, struct _column_state *column_state,
	int numDigitsDecimalPart, int *columnWidthChanged)
{
	unsigned int maxTooLongColumns = opt.num_flows * 5; // Maximum number of rows with non-optimal column width
	int lengthData = 0; // #digits of values
	int lengthHead = 0; // Length of header string
	unsigned int columnSize = 0;
	char tempBuffer[50];
	unsigned int a;
	const struct _header_info *header = &header_info[column];

	char* number_formatstring;

	if (!visible_columns[header->column_type])
		return 0;

	// get max columnsize
	switch ((int)value) {
		case INT_MAX:
			lengthData = strlen(" INT_MAX");
			break;

		case USHRT_MAX:
	                lengthData = strlen(" USHRT_MAX");
                        break;

		default:
			lengthData = det_output_column_size(value) + 2 + numDigitsDecimalPart;
	}

	lengthHead = MAX(strlen(header->first), strlen(header->second));
	columnSize = MAX(lengthData, lengthHead);

	// check if columnsize has changed
	if (column_state->last_width < columnSize) {
		/* column too small */
		*columnWidthChanged = 1;
		column_state->last_width = columnSize;
		column_state->count_oversized = 0;
	}
	else if (column_state->last_width > 1 + columnSize) {
		/* column too big */
		if (column_state->count_oversized >= maxTooLongColumns) {
			/* column too big for quite a while */
			*columnWidthChanged = 1;
			column_state->last_width = columnSize;
			column_state->count_oversized = 0;
		}
		else
			(column_state->count_oversized)++;
	}
	else /* This size was needed,keep it */
		column_state->count_oversized = 0;

	number_formatstring = outStringPart(column_state->last_width, numDigitsDecimalPart);

	// create columns
	//
	// output text for symbolic numbers
	switch ((int)value) {
		case INT_MAX:
			for (a = lengthData; a < columnSize; a++)
				strcat(strDataRow, " ");
			strcat(strDataRow, " INT_MAX");
			break;

                case USHRT_MAX:
                        for (a = lengthData; a < columnSize; a++)
                                strcat(strDataRow, " ");
                        strcat(strDataRow, " USHRT_MAX");
			break;
		
		default: /*  number */
			sprintf(tempBuffer, number_formatstring, value);
			strcat(strDataRow, tempBuffer);
	}
	// 1st header row
	for (a = column_state->last_width; a > strlen(header->first); a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, header->first);

	// 2nd header Row
	for (a = column_state->last_width; a > strlen(header->second); a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, header->second);

	return 0;
}

int createOutputColumn_str(char *strHead1Row, char *strHead2Row, char *strDataRow,
	int column, char* value, struct _column_state *column_state,
	int *columnWidthChanged) {

	unsigned int maxTooLongColumns = opt.num_flows * 5; // Maximum number of rows with non-optimal column width
	int lengthData = 0; // #digits of values
	int lengthHead = 0; // Length of header string
	unsigned int columnSize = 0;
	unsigned int a;
	const struct _header_info *header = &header_info[column];

	if (!visible_columns[header->column_type])
		return 0;

	// get max columnsize
	lengthData = strlen(value);
	lengthHead = MAX(strlen(header->first), strlen(header->second));
	columnSize = MAX(lengthData, lengthHead) + 2;

	// check if columnsize has changed
	if (column_state->last_width < columnSize) {
		/* column too small */
		*columnWidthChanged = 1;
		column_state->last_width = columnSize;
		column_state->count_oversized = 0;
	}
	else if (column_state->last_width > 1 + columnSize) {
		/* column too big */
		if (column_state->count_oversized >= maxTooLongColumns) {
			/* column too big for quite a while */
			*columnWidthChanged = 1;
			column_state->last_width = columnSize;
			column_state->count_oversized = 0;
		}
		else
			(column_state->count_oversized)++;
	}
	else /* This size was needed,keep it */
		column_state->count_oversized = 0;

	// create columns
	for (a = lengthData; a < columnSize; a++)
		strcat(strDataRow, " ");
	strcat(strDataRow, value);

	// 1st header row
	for (a = column_state->last_width; a > strlen(header->first); a--)
		strcat(strHead1Row, " ");
	strcat(strHead1Row, header->first);

	// 2nd header Row
	for (a = column_state->last_width; a > strlen(header->second); a--)
		strcat(strHead2Row, " ");
	strcat(strHead2Row, header->second);

	return 0;
}

char *createOutput(char hash, int id, int type, double begin, double end,
		double throughput,
		double rttmin, double rttavg, double rttmax,
		double iatmin, double iatavg, double iatmax,
		int cwnd, int ssth, int uack, int sack, int lost, int reor,
		unsigned int fret, unsigned int tret, unsigned int fack, double linrtt, double linrttvar,
		double linrto, int ca_state, int mss, int mtu, char* comment, int unit_byte)
{
	int columnWidthChanged = 0; //Flag: 0: column width has not changed

	int i = 0;
	static int counter = 0;

	//Create Row + Header
	char dataString[1000];
	char headerString1[1000];
	char headerString2[1000];
	static char outputString[4000];
	char tmp[100];

	//output string
	//param # + flow_id
	if (type == 0)
		sprintf(dataString, "%cS%3d", hash, id);
	else
		sprintf(dataString, "%cR%3d", hash, id);
	strcpy(headerString1, header_info[0].first);
	strcpy(headerString2, header_info[0].first);
	i++;

	//param begin
	createOutputColumn(headerString1, headerString2, dataString, i, begin, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param end
	createOutputColumn(headerString1, headerString2, dataString,  i, end, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param throughput
	if (unit_byte == 1)
		createOutputColumn(headerString1, headerString2, dataString, i + 1, throughput, &column_states[i], 6, &columnWidthChanged);
	else
		createOutputColumn(headerString1, headerString2, dataString, i, throughput, &column_states[i], 6, &columnWidthChanged);
	i += 2;

	//param str_rttmin
	createOutputColumn(headerString1, headerString2, dataString, i, rttmin, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param str_rttavg
	createOutputColumn(headerString1, headerString2, dataString, i, rttavg, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param str_rttmax
	createOutputColumn(headerString1, headerString2, dataString, i, rttmax, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param str_iatmin
	createOutputColumn(headerString1, headerString2, dataString, i, iatmin, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param str_iatavg
	createOutputColumn(headerString1, headerString2, dataString, i, iatavg, &column_states[i], 3, &columnWidthChanged);
	i++;

	//param str_iatmax
	createOutputColumn(headerString1, headerString2, dataString, i, iatmax, &column_states[i], 3, &columnWidthChanged);
	i++;

	//linux kernel output
	//param str_cwnd
	createOutputColumn(headerString1, headerString2, dataString, i, cwnd, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_ssth
	createOutputColumn(headerString1, headerString2, dataString, i, ssth, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_uack
	createOutputColumn(headerString1, headerString2, dataString, i, uack, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_sack
	createOutputColumn(headerString1, headerString2, dataString, i, sack, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_lost
	createOutputColumn(headerString1, headerString2, dataString, i, lost, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_fret
	createOutputColumn(headerString1, headerString2, dataString, i, fret, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_tret
	createOutputColumn(headerString1, headerString2, dataString, i, tret, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_fack
	createOutputColumn(headerString1, headerString2, dataString, i, fack, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_reor
	createOutputColumn(headerString1, headerString2, dataString, i, reor, &column_states[i], 0, &columnWidthChanged);
	i++;

	//param str_linrtt
	createOutputColumn(headerString1, headerString2, dataString, i, linrtt, &column_states[i], 1, &columnWidthChanged);
	i++;

	//param str_linrttvar
	createOutputColumn(headerString1, headerString2, dataString, i, linrttvar, &column_states[i], 1, &columnWidthChanged);
	i++;

	//param str_linrto
	createOutputColumn(headerString1, headerString2, dataString, i, linrto, &column_states[i], 1, &columnWidthChanged);
	i++;

	//param ca_state
	if (ca_state == TCP_CA_Open)
		strcpy(tmp, "open");
	else if (ca_state == TCP_CA_Disorder)
		strcpy(tmp, "disordr");
	else if (ca_state == TCP_CA_CWR)
		strcpy(tmp, "cwr");
	else if (ca_state == TCP_CA_Recovery)
		strcpy(tmp, "rcvry");
	else if (ca_state == TCP_CA_Loss)
		strcpy(tmp, "loss");
	else if (ca_state)
		sprintf(tmp, "uknwn(%d)", ca_state);
	else
		strcpy(tmp, "none");

	createOutputColumn_str(headerString1, headerString2, dataString, i, tmp, &column_states[i], &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataString, i, mss, &column_states[i], 0, &columnWidthChanged);
	i++;

	createOutputColumn(headerString1, headerString2, dataString, i, mtu, &column_states[i], 0, &columnWidthChanged);
	i++;

	strcat(headerString1, header_info[i].first);
	strcat(headerString2, header_info[i].second);
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

	return outputString;
}
/*New output end*/

/* Program name. Can get updated from argv[0] in parse_cmdline */
static char progname[50] = "flowgrind";

static void usage(void)
{
	fprintf(stderr,
		"Usage  %2$s [-h|-s|-v]\n"
		"       %2$s [general options] [flow options]\n\n"

		"flowgrind allows you to generate traffic among hosts in your network.\n\n"

		"Miscellaneous:\n"
		"  -h           show help and exit\n"
		"  -s           show help for socket options and exit\n"
		"  -v           print version information and exit\n\n"

		"General options:\n"
#if HAVE_LIBPCAP
		"  -a           advanced statistics (pcap)\n"
#endif
		"  -b mean1,mean2,mean3\n"
		"  -b lwr_bound1,upr_bound1,lwr_bound2,upr_bound2,lwr_bound3,upr_bound3\n"
		"               means for computing Anderson-Darling Test for exponential\n"
		"               distribution OR\n"
		"               lower and upper bounds for computing the test for uniform\n"
		"               distribution with the given bounds\n"
		"  -c +begin,+end,+thrpt,+rtt,+iat,+kernel\n"
		"               comma separated list of column groups to display in output.\n"
		"               Prefix with either + to show column group or - to hide\n"
		"               column group.\n"
#ifdef DEBUG
		"  -d           increase debugging verbosity. Add option multiple times to\n"
		"               be even more verbose.\n"
#endif
		"  -r #		use random seed (default: use /dev/urandom)\n"
		"  -e PRE       prepend prefix PRE to log filename (default: \"%1$s\")\n"
		"  -i #.#       reporting interval in seconds (default: 0.05s)\n"
		"  -l NAME      use log filename NAME (default: timestamp)\n"
		"  -m           report throughput in 2**20 bytes/second\n"
		"               (default: 10**6 bit/sec)\n"
		"  -n #         number of test flows (default: 1)\n"
		"  -o           overwrite existing log files (default: don't)\n"
		"  -q           be quiet, do not log to screen (default: off)\n"
		"  -w           write output to logfile (default: off)\n\n"

		"Flow options:\n\n"

		"  Some of these options take the flow endpoint as argument. Is is denoted by 'x'\n"
		"  in the option syntax. 'x' needs to be replaced with either 's' for the source\n"
		"  endpoint, 'd' for the destination endpoint or 'b' for both endpoints. To\n"
		"  specify different values for each endpoints, separate them by comma.\n"
		"  For instance -W s=8192,d=4096 sets the advertised window to 8192 at the source\n"
		"  and 4096 at the destination.\n\n"

		"  -A x         Send response with minimal blocksize for RTT and IAT calculation\n"
		"		(not needed in conjunction with -G)\n"
		"  -B x=#       Set requested sending buffer in bytes\n"
		"  -C x         Stop flow if it is experiencing local congestion\n"
		"  -D x=DSCP    DSCP value for TOS byte\n"
		"  -E x         Enumerate bytes in payload (default: don't)\n"
		"  -F #{,#}     Flow options following this option apply only to flow #{,#}.\n"
		"               Useful in combination with -n to set specific options\n"
		"               for certain flows. Numbering starts with 0, so -F 1 refers\n"
		"               to the second flow\n"
                "  -G x=[C|P],#,#\n"
		"		Activate stochastic traffic generation and set parameters\n"
		"		C = constant interpacket gap and blocksize\n"
                "               P = poisson distributed\n"
		"		W = weibull distributed (http emulation mode)\n"
		"  -H x=HOST[/CONTROL[:PORT]]\n"
		"               Test from/to HOST. Optional argument is the address and port\n"
		"               for the CONTROL connection to the same host.\n"
		"               An endpoint that isn't specified is assumed to be localhost.\n"
		"  -L x         Call connect() on test socket immediately before starting to send\n"
		"               data (late connect). If not specified the test connection is\n"
		"               established in the preparation phase before the test starts.\n"
		"  -N x         shutdown() each socket direction after test flow\n"
		"  -O x=OPT     Set specific socket options on test socket.\n"
		"               For a list of supported socket options see '%2$s -s'.\n"
		"               It is possible to repeatedly pass the same endpoint in order to\n"
		"               specify multiple socket options, e.g. s=SO_DEBUG,s=TCP_CORK\n"
		"  -P x         Do not iterate through select() to continue sending in case\n"
		"               block size did not suffice to fill sending queue (pushy)\n"
		"  -Q           Summarize only, skip interval reports (quiet)\n"
		"  -R x=#.#[z|k|M|G][b|y|B]\n"
		"               send at specified rate per second, where:\n"
		"               z = 2**0, k = 2**10, M = 2**20, G = 2**30\n"
		"               b = bits per second (default), y = bytes/second, B = blocks/s\n"
		"  -S x=#       Set block size (default: b=8192, denotes maximum value\n"
		"		for stochastic generation)\n"
		"  -T x=#.#     Set flow duration, in seconds (default: s=5,d=0)\n"
		"  -W x=#       Set requested receiver buffer (advertised window) in bytes\n"
		"  -Y x=#.#     Set initial delay before the host starts to send data\n",
		opt.log_filename_prefix,
		progname
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
				if (fwrite(buffer, r, 1, stderr) != 1)
				      fprintf(stderr, "fwrite() failed: %s\n", strerror(errno));
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
		//ToDo: write more examples and descriptions
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
	int i, j;
	opt.num_flows = 1;
	opt.reporting_interval = 0.05;
	opt.log_filename_prefix = "flowlog-";
	opt.dont_log_logfile = 1;

	for (i = 0; i < adt_type_max; i++)
		for (j = 0; j < 2; j++)
			ADT[i][j] = 0.05;
}

void init_flows_defaults(void)
{
	int id = 1;

	for (id = 0; id < MAX_FLOWS; id++) {

		flow[id].proto = PROTO_TCP;

		for (int i = 0; i < 2; i++) {

			flow[id].settings[i].requested_send_buffer_size = 0;
			flow[id].settings[i].requested_read_buffer_size = 0;
			flow[id].settings[i].delay[WRITE] = 0;
			flow[id].settings[i].default_request_block_size = 8192;
			flow[id].settings[i].default_response_block_size = 0;
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
			flow[id].settings[i].so_debug = 0;
			flow[id].settings[i].dscp = 0;
			flow[id].settings[i].ipmtudiscover = 0;

			flow[id].settings[i].num_extra_socket_options = 0;
		}
		flow[id].settings[SOURCE].duration[WRITE] = 5.0;
		flow[id].settings[DESTINATION].duration[WRITE] = 0.0;

		flow[id].endpoint_id[0] = flow[id].endpoint_id[1] = -1;
		flow[id].start_timestamp[0].tv_sec = 0;
		flow[id].start_timestamp[0].tv_usec = 0;
		flow[id].start_timestamp[1].tv_sec = 0;
		flow[id].start_timestamp[1].tv_usec = 0;

		flow[id].finished[0] = 0;
		flow[id].finished[1] = 0;
		flow[id].final_report[0] = NULL;
		flow[id].final_report[1] = NULL;

		flow[id].summarize_only = 0;
		flow[id].late_connect = 0;
		flow[id].shutdown = 0;
		flow[id].byte_counting = 0;
		flow[id].random_seed = 0;
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
		double time1, double time2, struct _report *r)
{
	double min_rtt = r->rtt_min;
	double max_rtt = r->rtt_max;
	double avg_rtt;
	double min_iat = r->iat_min;
	double max_iat = r->iat_max;
	double avg_iat;

	char comment_buffer[100] = " (";
	char report_buffer[4000] = "";
	double thruput = 0.0;

#define COMMENT_CAT(s) do { if (strlen(comment_buffer) > 2) \
		strncat(comment_buffer, "/", sizeof(comment_buffer)-1); \
		strncat(comment_buffer, (s), sizeof(comment_buffer)-1); }while(0);

	if (type == 0)
		avg_rtt = r->rtt_sum / (double)(r->response_blocks_read);
	else
		min_rtt = max_rtt = avg_rtt = INFINITY;

	if (type == 1)
		avg_iat = r->iat_sum / (double)(r->request_blocks_read);
	else
		min_iat = max_iat = avg_iat = INFINITY;

	if (flow[id].finished[type])
		COMMENT_CAT("stopped")
	else {
		char tmp[2];

		// Write status
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

		// Read status
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
	strncat(comment_buffer, ")", sizeof(comment_buffer));
	if (strlen(comment_buffer) == 2)
		comment_buffer[0] = '\0';

	thruput = scale_thruput((double)r->bytes_written / (time2 - time1));

	char rep_string[4000];
#ifndef __LINUX__
	// dont show linux kernel output if there is no linux OS
	column_type_kernel = 0;
#endif
	strcpy(rep_string, createOutput((hash ? '#' : ' '), id, type,
		time1, time2, thruput,
		min_rtt * 1e3, avg_rtt * 1e3, max_rtt * 1e3,
		min_iat * 1e3, avg_iat * 1e3, max_iat * 1e3,
#ifdef __LINUX__
		(int)r->tcp_info.tcpi_snd_cwnd, (int)r->tcp_info.tcpi_snd_ssthresh, (int)r->tcp_info.tcpi_unacked,
		(int)r->tcp_info.tcpi_sacked, (int)r->tcp_info.tcpi_lost, (int)r->tcp_info.tcpi_reordering,
		(int)r->tcp_info.tcpi_retrans, (int)r->tcp_info.tcpi_total_retrans, (int)r->tcp_info.tcpi_fackets,
		(double)r->tcp_info.tcpi_rtt / 1e3, (double)r->tcp_info.tcpi_rttvar / 1e3,
		(double)r->tcp_info.tcpi_rto / 1e3, r->tcp_info.tcpi_ca_state,
#else
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
#endif
		r->mss, r->mtu, comment_buffer, opt.mbyte
	));
	strncpy(report_buffer, rep_string, sizeof(report_buffer));
	report_buffer[sizeof(report_buffer) - 1] = 0;
	log_output(report_buffer);
}

void print_report(int id, int endpoint, struct _report* report)
{
	double diff_first_last;
	double diff_first_now;
	struct _flow *f = &flow[id];

	diff_first_last = time_diff(&f->start_timestamp[endpoint], &report->begin);
	diff_first_now = time_diff(&f->start_timestamp[endpoint], &report->end);

	print_tcp_report_line(
		0, id, endpoint, diff_first_last, diff_first_now, report);
}

void report_final(void)
{
	int id = 0;
	char header_buffer[400] = "";
	char header_nibble[400] = "";
	int i, j;

	for (id = 0; id < opt.num_flows; id++) {

#define CAT(fmt, args...) do {\
	snprintf(header_nibble, sizeof(header_nibble), fmt, ##args); \
	strncat(header_buffer, header_nibble, sizeof(header_nibble)-1); } while (0)
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

			CATC("sbuf = %u/%u, rbuf = %u/%u (real/req)",
				flow[id].endpoint_options[endpoint].send_buffer_size_real,
				flow[id].settings[endpoint].requested_send_buffer_size,
				flow[id].endpoint_options[endpoint].receive_buffer_size_real,
                                flow[id].settings[endpoint].requested_read_buffer_size);

			CATC("delay = %.2fs/%.2fs",
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
				if (isnan(thruput_read)) 
					thruput_read = 0.0;
				
				thruput_written = flow[id].final_report[endpoint]->bytes_written / duration_write;
				if (isnan(thruput_written))
					thruput_written = 0.0;
                                
                                thruput_read = scale_thruput(thruput_read);
				thruput_written = scale_thruput(thruput_written);

				CATC("through = %.6f/%.6fM%c/s, %ld/%ld request blocks, %ld/%ld response blocks (out/in)", thruput_written, thruput_read, opt.mbyte ? 'B' : 'b', 
					/* TODO: count blocks */
					flow[id].final_report[endpoint]->request_blocks_written,
                                        flow[id].final_report[endpoint]->request_blocks_read,
					flow[id].final_report[endpoint]->response_blocks_written,
					flow[id].final_report[endpoint]->response_blocks_read
					);
#ifdef DEBUG
                                /*CATC("bytes_read = %lld", flow[id].final_report[endpoint]->bytes_read);
                                CATC("bytes_written = %lld", flow[id].final_report[endpoint]->bytes_written);
				CATC("reply_bytes_read = %lld", flow[id].final_report[endpoint]->reply_bytes_read);
                                CATC("other reply_block_size = %i", flow[id].settings[!endpoint].reply_block_size);
				CATC("reply_bytes_written = %lld", flow[id].final_report[endpoint]->reply_bytes_written);
				CATC("own reply_block_size = %i", flow[id].settings[endpoint].reply_block_size);*/
#endif
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

	/* now depending on which test the user wanted we make the function calls */
	if (doAnderson) {
		char report_string[4000];
		const char names[][20] = {"Throughput", "IAT", "RTT"};

		if (doAnderson == 1) {
			log_output("# Anderson-Darling test statistic (A2) for Exponential Distribution\n");
			for (i = 0; i < 2; i++)
				for (j = 0; j < 3; j++) {
					double result = adt_get_result_mean(i, j, ADT[j][0]);
					sprintf(report_string, "# A2 %s for %s with mean %.6f: %.6f\n",
					        names[j], j ? "destination" : "source", ADT[j][0],
					        result);
					log_output(report_string);
				}
		}
		else if (doAnderson == 2) {
			log_output("# Anderson-Darling test statistic (A2) for Uniform Distribution\n");

			for (i = 0; i < 2; i++)
				for (j = 0; j < 3; j++) {
					double result = adt_get_result_range(i, j, ADT[j][0], ADT[j][1]);
					sprintf(report_string, "# A2 %s for %s with bounds %.6f, %.6f: %.6f\n",
					        names[j], j ? "destination" : "source",
					        ADT[j][0],
					        ADT[j][1],
					        result);
					log_output(report_string);
				}
		}

		if (adt_too_much_data())
			log_output("# Note: The Darlington test was done only on the first 1000 samples. The reason for this is that the test gives poor results for a larger sample size (as specified in literature)\n");
	}
}

void report_flow(const char* server_url, struct _report* report)
{
	int endpoint;
	int id;
	struct _flow *f;

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

	if (doAnderson && !id && report->type == INTERVAL) {
		/* Record ADT data on first flow */
		double delta = time_diff(&report->begin, &report->end);
		adt_add_data(report->bytes_written / delta, endpoint, adt_throughput);
		if (report->iat_sum != INFINITY)
			adt_add_data(report->iat_sum, endpoint, adt_iat);
		if (report->rtt_sum != INFINITY)
			adt_add_data(report->rtt_sum, endpoint, adt_rtt);
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
	/*UNUSED_ARGUMENT(sig);*/

	DEBUG_MSG(1, "caught %s", strsignal(sig));

	if (sigint_caught == 0) {
		fprintf(stderr, "Trying to gracefully close flows. Press CTRL+C again to force termination.\n");
		sigint_caught = 1;
	}
	else
		exit(1);
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

	struct timeval lastreport;
	struct timeval now;
	tsc_gettimeofday(&now);
	tsc_gettimeofday(&lastreport);

	for (j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;
		DEBUG_MSG(1, "starting flow on server %d", j);
		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "start_flows", &resultP,
		"({s:i})",
		"start_timestamp", now.tv_sec + 2);
		die_if_fault_occurred(&rpc_env);
		if (resultP)
			xmlrpc_DECREF(resultP);
	}

	active_flows = opt.num_flows;

	while (!sigint_caught) {

		if ( time_diff_now(&lastreport) <  opt.reporting_interval ) {
			usleep(100);
			continue; 
		}
		tsc_gettimeofday(&lastreport);

		for (j = 0; j < num_unique_servers; j++) {

			int array_size, has_more;
			xmlrpc_value *rv = 0;

has_more_reports:

			xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "get_reports", &resultP, "()");
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
					int begin_sec, begin_usec, end_sec, end_usec;

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
					int tcpi_last_data_sent;
					int tcpi_last_ack_recv;
					int tcpi_ca_state;
					int bytes_read_low, bytes_read_high;
					int bytes_written_low, bytes_written_high;
					
					xmlrpc_decompose_value(&rpc_env, rv,
						"({"
						"s:i,s:i,s:i,s:i,s:i,s:i," /* timeval */
						"s:i,s:i,s:i,s:i," /* bytes */
						"s:i,s:i,s:i,s:i," /* blocks */
						"s:d,s:d,s:d,s:d,s:d,s:d," /* RTT, IAT */
						"s:i,s:i" /* MSS, MTU */
						"s:i,s:i,s:i,s:i,s:i," /* TCP info */
						"s:i,s:i,s:i,s:i,s:i," /* ...      */
						"s:i,s:i,s:i,s:i,s:i," /* ...      */
						"s:i,*"
						"})",

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

						"mss", &report.mss,
						"mtu", &report.mtu,

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
						"tcpi_last_data_sent", &tcpi_last_data_sent,
						"tcpi_last_ack_recv", &tcpi_last_ack_recv,
						"tcpi_ca_state", &tcpi_ca_state,

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
					report.tcp_info.tcpi_retransmits = tcpi_retransmits;
					report.tcp_info.tcpi_fackets = tcpi_fackets;
					report.tcp_info.tcpi_reordering = tcpi_reordering;
					report.tcp_info.tcpi_rtt = tcpi_rtt;
					report.tcp_info.tcpi_rttvar = tcpi_rttvar;
					report.tcp_info.tcpi_rto = tcpi_rto;
					report.tcp_info.tcpi_last_data_sent = tcpi_last_data_sent;
					report.tcp_info.tcpi_last_ack_recv = tcpi_last_ack_recv;
					report.tcp_info.tcpi_ca_state = tcpi_ca_state;
#endif
					report.begin.tv_sec = begin_sec;
					report.begin.tv_usec = begin_usec;
					report.end.tv_sec = end_sec;
					report.end.tv_usec = end_usec;

					report_flow(unique_servers[j], &report);
				}
			}
			xmlrpc_DECREF(resultP);
			
			if (has_more)
			{
				/* Go back to beginning of loop */
				goto has_more_reports;
			}
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

	free(flow[id].final_report[0]);
	free(flow[id].final_report[1]);

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
	{ 9000,		"Gigabit Ethernet (Jumboframes)"},
	{ 8166,		"802.4 Token Bus" },		/* RFC1042 */
	{ 4464,		"4 MB/s Token Ring" },
	{ 4352,		"FDDI" },			/* RFC1390 */
	{ 1500,		"Ethernet/PPP" },		/* RFC894, RFC1548 */
	{ 1492,		"IEEE 802.3" },
	{ 1006,		"SLIP" },			/* RFC1055 */
	{ 576,		"X.25 & ISDN" },		/* RFC1356 */
	{ 296,		"PPP (low delay)" },
};
#define MTU_LIST_NUM	13


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
	xmlrpc_value *resultP, *extra_options;
	int i;

	int listen_data_port;
        DEBUG_MSG(1, "prepare flow %d destination", id);

	/* Contruct extra socket options array */
	extra_options = xmlrpc_array_new(&rpc_env);
	for (i = 0; i < flow[id].settings[DESTINATION].num_extra_socket_options; i++) {

		xmlrpc_value *value;
		xmlrpc_value *option = xmlrpc_build_value(&rpc_env, "{s:i,s:i}",
			 "level", flow[id].settings[DESTINATION].extra_socket_options[i].level,
			 "optname", flow[id].settings[DESTINATION].extra_socket_options[i].optname);

		value =	xmlrpc_base64_new(&rpc_env, flow[id].settings[DESTINATION].extra_socket_options[i].optlen, (unsigned char*)flow[id].settings[DESTINATION].extra_socket_options[i].optval);

		xmlrpc_struct_set_value(&rpc_env, option, "value", value);

		xmlrpc_array_append_item(&rpc_env, extra_options, option);
		xmlrpc_DECREF(value);
		xmlrpc_DECREF(option);
	}
	xmlrpc_client_call2f(&rpc_env, rpc_client, flow[id].endpoint_options[DESTINATION].server_url, "add_flow_destination", &resultP,
		"({"
		"s:s,"
		"s:d,s:d,s:d,s:d,s:d,"
		"s:i,s:i,"
		"s:i,s:i,"
		"s:b,s:b,s:b,s:b,s:b,"
		"s:i,s:i,s:d,s:d,s:i,"
		"s:b,s:b,s:i,"
		"s:s,"
		"s:i,s:i,s:i,s:i,"
		"s:i,s:A"
		"})",

		/* general flow settings */
		"bind_address", flow[id].endpoint_options[DESTINATION].bind_address,

		"write_delay", flow[id].settings[DESTINATION].delay[WRITE],
		"write_duration", flow[id].settings[DESTINATION].duration[WRITE],
		"read_delay", flow[id].settings[SOURCE].delay[WRITE],
		"read_duration", flow[id].settings[SOURCE].duration[WRITE],
		"reporting_interval", flow[id].summarize_only ? 0 : opt.reporting_interval,

		"requested_send_buffer_size", flow[id].settings[DESTINATION].requested_send_buffer_size,
		"requested_read_buffer_size", flow[id].settings[DESTINATION].requested_read_buffer_size,
		
		"default_request_block_size", flow[id].settings[DESTINATION].default_request_block_size,
		"default_response_block_size", flow[id].settings[DESTINATION].default_response_block_size,

		"advstats", (int)opt.advstats,
		"so_debug", flow[id].settings[DESTINATION].so_debug,
		"route_record", (int)flow[id].settings[DESTINATION].route_record,
		"pushy", flow[id].settings[DESTINATION].pushy,
		"shutdown", (int)flow[id].shutdown,

		"write_rate", flow[id].settings[DESTINATION].write_rate,
		"traffic_generation_type", flow[id].settings[DESTINATION].traffic_generation_type,
		"traffic_generation_parm_alpha", flow[id].settings[DESTINATION].traffic_generation_parm_alpha,
		"traffic_generation_parm_beta", flow[id].settings[DESTINATION].traffic_generation_parm_beta,
		"random_seed",flow[id].random_seed,

		"flow_control", flow[id].settings[DESTINATION].flow_control,
		"byte_counting", flow[id].byte_counting,
		"cork", (int)flow[id].settings[DESTINATION].cork,

		"cc_alg", flow[id].settings[DESTINATION].cc_alg,

		"elcn", flow[id].settings[DESTINATION].elcn,
		"icmp", flow[id].settings[DESTINATION].icmp,
		"dscp", (int)flow[id].settings[DESTINATION].dscp,
		"ipmtudiscover", flow[id].settings[DESTINATION].ipmtudiscover,
		
		"num_extra_socket_options", flow[id].settings[DESTINATION].num_extra_socket_options,
		"extra_socket_options", extra_options);

	die_if_fault_occurred(&rpc_env);
	
	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,s:i,s:i,s:i,*}",
		"flow_id", &flow[id].endpoint_id[DESTINATION],
		"listen_data_port", &listen_data_port,
		"real_listen_send_buffer_size", &flow[id].endpoint_options[DESTINATION].send_buffer_size_real,
		"real_listen_read_buffer_size", &flow[id].endpoint_options[DESTINATION].receive_buffer_size_real);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);

	/* Contruct extra socket options array */
	extra_options = xmlrpc_array_new(&rpc_env);
	for (i = 0; i < flow[id].settings[SOURCE].num_extra_socket_options; i++) {

		xmlrpc_value *value;
		xmlrpc_value *option = xmlrpc_build_value(&rpc_env, "{s:i,s:i}",
			 "level", flow[id].settings[SOURCE].extra_socket_options[i].level,
			 "optname", flow[id].settings[SOURCE].extra_socket_options[i].optname);

		value =	xmlrpc_base64_new(&rpc_env, flow[id].settings[SOURCE].extra_socket_options[i].optlen, (unsigned char*)flow[id].settings[SOURCE].extra_socket_options[i].optval);

		xmlrpc_struct_set_value(&rpc_env, option, "value", value);

		xmlrpc_array_append_item(&rpc_env, extra_options, option);
		xmlrpc_DECREF(value);
		xmlrpc_DECREF(option);
	}
        DEBUG_MSG(1, "prepare flow %d source", id);

	xmlrpc_client_call2f(&rpc_env, rpc_client, flow[id].endpoint_options[SOURCE].server_url, "add_flow_source", &resultP,
		"({"
		"s:s,"
		"s:d,s:d,s:d,s:d,s:d,"
		"s:i,s:i,"
		"s:i,s:i,"
		"s:b,s:b,s:b,s:b,s:b,"
		"s:i,s:i,s:d,s:d,s:i,"
		"s:b,s:b,s:i,"
		"s:s,"
		"s:i,s:i,s:i,s:i,"
		"s:i,s:A,"
		"s:s,s:i,s:i"
		"})",

		/* general flow settings */
		"bind_address", flow[id].endpoint_options[SOURCE].bind_address,

		"write_delay", flow[id].settings[SOURCE].delay[WRITE],
		"write_duration", flow[id].settings[SOURCE].duration[WRITE],
		"read_delay", flow[id].settings[DESTINATION].delay[WRITE],
		"read_duration", flow[id].settings[DESTINATION].duration[WRITE],
		"reporting_interval", flow[id].summarize_only ? 0 : opt.reporting_interval,

		"requested_send_buffer_size", flow[id].settings[SOURCE].requested_send_buffer_size,
		"requested_read_buffer_size", flow[id].settings[SOURCE].requested_read_buffer_size,
		
		"default_request_block_size", flow[id].settings[SOURCE].default_request_block_size,
		"default_response_block_size", flow[id].settings[SOURCE].default_response_block_size,

		"advstats", (int)opt.advstats,
		"so_debug", flow[id].settings[SOURCE].so_debug,
		"route_record", (int)flow[id].settings[SOURCE].route_record,
		"pushy", flow[id].settings[SOURCE].pushy,
		"shutdown", (int)flow[id].shutdown,

                "write_rate", flow[id].settings[SOURCE].write_rate,
                "traffic_generation_type", flow[id].settings[SOURCE].traffic_generation_type,
                "traffic_generation_parm_alpha", flow[id].settings[SOURCE].traffic_generation_parm_alpha,
                "traffic_generation_parm_beta", flow[id].settings[SOURCE].traffic_generation_parm_beta,
                "random_seed",flow[id].random_seed,

		"flow_control", flow[id].settings[SOURCE].flow_control,
		"byte_counting", flow[id].byte_counting,
		"cork", (int)flow[id].settings[SOURCE].cork,
		
		"cc_alg", flow[id].settings[SOURCE].cc_alg,
		
		"elcn", flow[id].settings[SOURCE].elcn,
		"icmp", flow[id].settings[SOURCE].icmp,
		"dscp", (int)flow[id].settings[SOURCE].dscp,
		"ipmtudiscover", flow[id].settings[SOURCE].ipmtudiscover,
	
		"num_extra_socket_options", flow[id].settings[SOURCE].num_extra_socket_options,
		"extra_socket_options", extra_options,

		/* source settings */
		"destination_address", flow[id].endpoint_options[DESTINATION].test_address,
		"destination_port", listen_data_port,
		"late_connect", (int)flow[id].late_connect);
	die_if_fault_occurred(&rpc_env);

	xmlrpc_DECREF(extra_options);

	xmlrpc_parse_value(&rpc_env, resultP, "{s:i,s:i,s:i,*}",
		"flow_id", &flow[id].endpoint_id[SOURCE],
		"real_send_buffer_size", &flow[id].endpoint_options[SOURCE].send_buffer_size_real,
		"real_read_buffer_size", &flow[id].endpoint_options[SOURCE].receive_buffer_size_real);
	die_if_fault_occurred(&rpc_env);

	if (resultP)
		xmlrpc_DECREF(resultP);
	DEBUG_MSG(1, "prepare flow %d completed", id);
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
			free(version);
			xmlrpc_DECREF(resultP);
		}
	}

	if (mismatch) {
		fprintf(stderr, "Our version is %s\n\nContinuing in 10 seconds.\n", FLOWGRIND_VERSION);
		sleep(10);
	}
}

/* Checks that all nodes are currently idle */
void check_idle(xmlrpc_client *rpc_client)
{
	unsigned j;
	xmlrpc_value * resultP = 0;

	for (j = 0; j < num_unique_servers; j++) {

		if (sigint_caught)
			return;

		xmlrpc_client_call2f(&rpc_env, rpc_client, unique_servers[j], "get_status", &resultP,
		"()");
		die_if_fault_occurred(&rpc_env);

		if (resultP) {
			int started;
			int num_flows;

			xmlrpc_decompose_value(&rpc_env, resultP, "{s:i,s:i,*}",
				"started", &started,
				"num_flows", &num_flows);
			die_if_fault_occurred(&rpc_env);

			if (started || num_flows) {
				fprintf(stderr, "Error: Node %s is busy. %d flows, started=%d\n", unique_servers[j], num_flows, started);
				exit(1);
			}

			xmlrpc_DECREF(resultP);
		}
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

	while (sscanf(params, "%31[^,]%n", field, &n) == 1 ) {
		ADT[i % 3][i / 3] = atof(field);

		i++;
		params += n; /* advance the pointer by the number of characters read */
		if ( *params != ',' ){
			break; /* didn't find an expected delimiter, done? */
		}
		++params; /* skip the delimiter */
	}

	if (i == 3)
		doAnderson = 1;
	else if (i == 6)
		doAnderson = 2;
	else
		return 0;

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
						strcpy(flow[current_flow_ids[id]].endpoint_options[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[current_flow_ids[id]].endpoint_options[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
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
						strcpy(flow[current_flow_ids[id]].settings[SOURCE].PROPERTY_NAME, (PROPERTY_VALUE)); \
					if (type != 's') \
						strcpy(flow[current_flow_ids[id]].settings[DESTINATION].PROPERTY_NAME, (PROPERTY_VALUE)); \
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
			case 'A':
				ASSIGN_COMMON_FLOW_SETTING(default_response_block_size, 2*(sizeof (int32_t) ) + (sizeof (struct timeval)) + 1)
				break;
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
					/*	two addresses:
						- test address where the actual test connection goes to
						- RPC address, where this program connects to

						Unspecified RPC address falls back to test address
					 */
					char url[1000];
					int port = DEFAULT_LISTEN_PORT;
					char *sepptr, *rpc_address = 0;

					/* RPC address */
					sepptr = strchr(arg, '/');
					if (sepptr) {
						*sepptr = '\0';
						rpc_address = sepptr + 1;
					}
					else
						rpc_address = arg;

					sepptr = strchr(arg, ':');
					if (sepptr) {
						fprintf(stderr, "port not allowed in test address\n");
						usage();
					}

					sepptr = strchr(rpc_address, ':');
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

					sprintf(url, "http://%s:%d/RPC2", rpc_address, port);
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(server_url, url);
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(server_address, rpc_address);
					ASSIGN_ENDPOINT_FLOW_OPTION_STR(test_address, arg);
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
				else if (!strcmp(arg, "SO_DEBUG")) {
					ASSIGN_COMMON_FLOW_SETTING(so_debug, 1);
				}
				else if (!strcmp(arg, "IP_MTU_DISCOVER")) {
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
				ASSIGN_COMMON_FLOW_SETTING(default_request_block_size, optunsigned)
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

#if HAVE_GETOPT_LONG
	// getopt_long isn't portable, it's GNU extension
	struct option lo[] = {	{"help", 0, 0, 'h' },
							{"version", 0, 0, 'v'},
							{0, 0, 0, 0}
				};
	while ((ch = getopt_long(argc, argv, "ab:c:de:hi:l:mn:op:qr:svwA:B:CD:EF:G:H:LNO:P:QR:S:T:W:Y:", lo, 0)) != -1)
#else
	while ((ch = getopt(argc, argv, "ab:c:de:hi:l:mn:op:qr:svwA:B:CD:EF:G:H:LNO:P:QR:S:T:W:Y:")) != -1)
#endif
		switch (ch) {

#if HAVE_LIBPCAP
		case 'a':
			opt.advstats = 1;
			break;
#endif

		case 'b':
			if (!parse_Anderson_Test(optarg)) {
				fprintf(stderr, "Failed to parse adt options\n");
				usage();
			}
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
			usage();
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

		case 'q':
			opt.dont_log_stdout = 1;
			break;

		case 'r':
                        rc = sscanf(optarg, "%d", &optint);
                        if (rc != 1) {
                                fprintf(stderr, "random seed must be a valid integer");
                                usage();
                        }
                        ASSIGN_FLOW_OPTION(random_seed, optint);
                        break;


		case 's':
			usage_sockopt();
			break;

		case 'v':
			fprintf(stderr, "flowgrind version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		case 'w':
			opt.dont_log_logfile = 0;
			break;

		case 'E':
			ASSIGN_FLOW_OPTION(byte_counting, 1);
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
		case 'A':
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

#if 0
	/* Demonstration how to set arbitary socket options. Note that this is
	 * only intended for quickly testing new options without having to
	 * recompile and restart the daemons. To add support for a particular
	 * options in future flowgrind versions it's recommended to implement
	 * them like the other options supported by the -O argument.
	 */
	{
		assert(flow[0].settings[SOURCE].num_extra_socket_options < MAX_EXTRA_SOCKET_OPTIONS);
		struct _extra_socket_options *option = &flow[0].settings[SOURCE].extra_socket_options[flow[0].settings[SOURCE].num_extra_socket_options++];
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

		flow[id].settings[SOURCE].duration[READ] = flow[id].settings[DESTINATION].duration[WRITE];
		flow[id].settings[DESTINATION].duration[READ] = flow[id].settings[SOURCE].duration[WRITE];
		flow[id].settings[SOURCE].delay[READ] = flow[id].settings[DESTINATION].delay[WRITE];
		flow[id].settings[DESTINATION].delay[READ] = flow[id].settings[SOURCE].delay[WRITE];

		for (unsigned i = 0; i < 2; i++) {
			unsigned int j;

			if (flow[id].endpoint_options[i].rate_str) {
				unit = type = distribution = 0;
				/* last %c for catching wrong input... this is not nice. */
				rc = sscanf(flow[id].endpoint_options[i].rate_str, "%lf%c%c%c",
						&optdouble, &unit, &type, &unit);
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
					optdouble /= flow[id].settings[SOURCE].default_request_block_size * 8;
					if (optdouble < 1) {
						fprintf(stderr, "client block size "
								"for flow %u is too "
								"big for specified "
								"rate.\n", id);
						error = 1;
					}
					break;

				case 'y':
					optdouble /= flow[id].settings[SOURCE].default_request_block_size;
					if (optdouble < 1) {
						fprintf(stderr, "client block size "
								"for flow %u is too "
								"big for specified "
								"rate.\n", id);
						error = 1;
					}
					break;

				case 'B':
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
	DEBUG_MSG(4, "sanity check parameter set of flow %d. completed", id);
	if (max_flow_rate > 0) {
		select_timeout = 1e6/max_flow_rate/2;
		if (select_timeout > DEFAULT_SELECT_TIMEOUT)
			select_timeout = DEFAULT_SELECT_TIMEOUT;
		DEBUG_MSG(4, "setting select timeout = %uus", select_timeout);
	}
}

void init_random_numbers() {
	
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
	init_random_numbers();
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL)) {
		fprintf(stderr, "Error: Could not set handler for SIGINT\n");
	}
	DEBUG_MSG(1, "prepare xmlrpc client");
	xmlrpc_client_create(&rpc_env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &rpc_client);
	/* Check that all nodes run a compatible flowgrind version */
        DEBUG_MSG(1, "check flowgrindds versions");
	if (!sigint_caught)
		check_version(rpc_client);
        DEBUG_MSG(1, "check if flowgrindds are idle");
	/* Check that all nodes are currently idle */
	if (!sigint_caught)
		check_idle(rpc_client);
        DEBUG_MSG(1, "prepare flows");
	/* Setup flows */
	if (!sigint_caught)
		prepare_flows(rpc_client);

        DEBUG_MSG(1, "start flows");
	/* Start the test */
	if (!sigint_caught)
		grind_flows(rpc_client);

	DEBUG_MSG(1, "report final");
	if (!sigint_caught)
		report_final();

	close_flows();

	shutdown_logfile();

	xmlrpc_client_destroy(rpc_client);
	xmlrpc_env_clean(&rpc_env);

	xmlrpc_client_teardown_global_const();

        DEBUG_MSG(1, "finished");
	return 0;
}
