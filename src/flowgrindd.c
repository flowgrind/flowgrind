#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#ifdef WIN
#  include <windows.h>
#else
#  include <unistd.h>
#endif
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#if HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#include <xmlrpc-c/util.h>

#include "common.h"
#include "daemon.h"
#include "log.h"
#include "fg_time.h"
#include "debug.h"
#include "acl.h"
#include "fg_math.h"
#if HAVE_LIBPCAP
#include "fg_pcap.h"
#endif

static char progname[50] = "flowgrindd";

static void __attribute__((noreturn)) usage(void)
{
	fprintf(stderr,
		"Usage: %1$s [-a address ] [-w#] [-p#] [-D]\n"
		"\t-a address\tadd address to list of allowed hosts (CIDR syntax)\n"
		"\t-p#\t\tserver port\n"
		"\t-d\t\tincrease debug verbosity (no daemon, log to stderr)\n"
		"\t-v\t\tPrint version information and exit\n",
		progname);
	exit(1);
}

static void sighandler(int sig)
{
	int status;

	switch (sig) {
	case SIGCHLD:
		while (waitpid(-1, &status, WNOHANG) > 0)
			logging_log(LOG_NOTICE, "child returned (status = %d)",
					status);
		break;

	case SIGHUP:
		logging_log(LOG_NOTICE, "got SIGHUP, don't know what to do.");
		break;

	case SIGALRM:
		logging_log(LOG_NOTICE, "Caught SIGALRM. don't know what to do.");
		break;

	case SIGPIPE:
		break;

	default:
		logging_log(LOG_ALERT, "got signal %d, but don't remember "
				"intercepting it, aborting...", sig);
		abort();
	}
}

static int dispatch_request(struct _request *request, int type)
{
	pthread_cond_t cond;

	request->error = NULL;
	request->type = type;
	request->next = NULL;

	/* Create synchronization mutex */
	if (pthread_cond_init(&cond, NULL)) {
		request_error(request, "Could not create synchonization mutex");
		return -1;
	}
	request->condition = &cond;

	pthread_mutex_lock(&mutex);

	if (!requests) {
		requests = request;
		requests_last = request;
	}
	else {
		requests_last->next = request;
		requests_last = request;
	}
	if ( write(daemon_pipe[1], &type, 1) != 1 ) /* Doesn't matter what we write */
		return -1;
	/* Wait until the daemon thread has processed the request */
	pthread_cond_wait(&cond, &mutex);

	pthread_mutex_unlock(&mutex);

	if (request->error)
		return -1;

	return 0;
}

static xmlrpc_value * add_flow_source(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(user_data);

	int rc, i;
	xmlrpc_value *ret = 0;
	char* destination_host = 0;
	char* cc_alg = 0;
	char* bind_address = 0;
	xmlrpc_value* extra_options = 0;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct _request_add_flow_source* request = 0;

	DEBUG_MSG(LOG_WARNING, "Method add_flow_source called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, 
		"({"
		"s:s,"
		"s:d,s:d,s:d,s:d,s:d,"
		"s:i,s:i,s:i,s:i,"
		"s:b,s:b,s:b,s:b,s:b,"
		"s:i,s:i,s:d,s:d,s:i,"
		"s:b,s:b,s:i,"
		"s:s,"
		"s:i,s:i,s:i,s:i,"
		"s:i,s:A,"
		"s:s,s:i,s:i,*"
		"})",

		/* general settings */
		"bind_address", &bind_address,

		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"reporting_interval", &settings.reporting_interval,

		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,
		"default_request_block_size", &settings.default_request_block_size,
		"default_response_block_size", &settings.default_response_block_size,

		"advstats", &settings.advstats,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,

                "write_rate", &settings.write_rate,
                "traffic_generation_type", &settings.traffic_generation_type,
                "traffic_generation_parm_alpha", &settings.traffic_generation_parm_alpha,
                "traffic_generation_parm_beta", &settings.traffic_generation_parm_beta,
                "random_seed",&settings.random_seed,
		
		"flow_control", &settings.flow_control,
		"byte_counting", &settings.byte_counting,
		"cork", &settings.cork,

		"cc_alg", &cc_alg,

		"elcn", &settings.elcn,
		"icmp", &settings.icmp,
		"dscp", &settings.dscp,
		"ipmtudiscover", &settings.ipmtudiscover,

		"num_extra_socket_options", &settings.num_extra_socket_options,
		"extra_socket_options", &extra_options,

		/* source settings */
		"destination_address", &destination_host,
		"destination_port", &source_settings.destination_port,
		"late_connect", &source_settings.late_connect);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity TODO: add traffic generation checks */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		(settings.default_request_block_size && settings.default_request_block_size < MIN_BLOCK_SIZE) || 
		(settings.default_response_block_size && settings.default_response_block_size < MIN_BLOCK_SIZE)  ||
		strlen(destination_host) >= sizeof(source_settings.destination_host) - 1||
		source_settings.destination_port <= 0 || source_settings.destination_port > 65535 ||
		strlen(cc_alg) > 255 ||
		settings.num_extra_socket_options < 0 || settings.num_extra_socket_options > MAX_EXTRA_SOCKET_OPTIONS ||
		xmlrpc_array_size(env, extra_options) != settings.num_extra_socket_options ||
		settings.dscp < 0 || settings.dscp > 255 ||
		settings.write_rate < 0 ||
		settings.reporting_interval < 0) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}
	/* initalize random number generator (use cmdline option if given, else use random data) */
	if (settings.random_seed)
		rn_set_seed(settings.random_seed);
	else
		rn_set_seed(rn_read_dev_random());
	/* Parse extra socket options */
	for (i = 0; i < settings.num_extra_socket_options; i++) {

		const unsigned char* buffer = 0;
		size_t len;
		xmlrpc_value *option, *level = 0, *optname = 0, *value = 0;
		xmlrpc_array_read_item(env, extra_options, i, &option);

		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "level", &level);
		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "optname", &optname);
		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "value", &value);
		if (!env->fault_occurred)
			xmlrpc_read_int(env, level, &settings.extra_socket_options[i].level);
		if (!env->fault_occurred)
			xmlrpc_read_int(env, optname, &settings.extra_socket_options[i].optname);
		if (!env->fault_occurred)
			xmlrpc_read_base64(env, value, &len, &buffer);
		if (level)
			xmlrpc_DECREF(level);
		if (optname)
			xmlrpc_DECREF(optname);
		if (value)
			xmlrpc_DECREF(value);
		if (!env->fault_occurred) {
			if (len > MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH) {
				free((void *)buffer);
				XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Too long extra socket option length");
			}
			settings.extra_socket_options[i].optlen = len;
			memcpy(settings.extra_socket_options[i].optval, buffer, len);
			free((void *)buffer);
		}
		if (env->fault_occurred)
			goto cleanup;
	}

	strcpy(source_settings.destination_host, destination_host);
	strcpy(settings.cc_alg, cc_alg);
	strcpy(settings.bind_address, bind_address);

	request = malloc(sizeof(struct _request_add_flow_source));
	request->settings = settings;
	request->source_settings = source_settings;
	rc = dispatch_request((struct _request*)request, REQUEST_ADD_SOURCE);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i,s:s,s:i,s:i}",
		"flow_id", request->flow_id,
		"cc_alg", request->cc_alg,
		"real_send_buffer_size", request->real_send_buffer_size,
		"real_read_buffer_size", request->real_read_buffer_size);

cleanup:
	if (request) {
		free(request->r.error);
		free(request);
	}
	free(destination_host);
	free(cc_alg);
	free(bind_address);

	if (extra_options)
		xmlrpc_DECREF(extra_options);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method add_flow_source failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method add_flow_source successful");
	}

	return ret;
}

static xmlrpc_value * add_flow_destination(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(user_data);

	int rc, i;
	xmlrpc_value *ret = 0;
	char* cc_alg = 0;
	char* bind_address = 0;
	xmlrpc_value* extra_options = 0;

	struct _flow_settings settings;

	struct _request_add_flow_destination* request = 0;

	DEBUG_MSG(LOG_WARNING, "Method add_flow_destination called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array,
		"({"
		"s:s,"
		"s:d,s:d,s:d,s:d,s:d,"
		"s:i,s:i,s:i,s:i,"
		"s:b,s:b,s:b,s:b,s:b,"
		"s:i,s:i,s:d,s:d,s:i,"
		"s:b,s:b,s:i,"
		"s:s,"
		"s:i,s:i,s:i,s:i,"
		"s:i,s:A,*"
		"})",

		/* general settings */
		"bind_address", &bind_address,
		
		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"reporting_interval", &settings.reporting_interval,
		
		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,
		"default_request_block_size", &settings.default_request_block_size,
		"default_response_block_size", &settings.default_response_block_size,

		"advstats", &settings.advstats,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,
		
                "write_rate", &settings.write_rate,
                "traffic_generation_type", &settings.traffic_generation_type,
                "traffic_generation_parm_alpha", &settings.traffic_generation_parm_alpha,
                "traffic_generation_parm_beta", &settings.traffic_generation_parm_beta,
                "random_seed",&settings.random_seed,

		"flow_control", &settings.flow_control,
		"byte_counting", &settings.byte_counting,
		"cork", &settings.cork,

		"cc_alg", &cc_alg,

		"elcn", &settings.elcn,
		"icmp", &settings.icmp,
		"dscp", &settings.dscp,
		"ipmtudiscover", &settings.ipmtudiscover,
		
		"num_extra_socket_options", &settings.num_extra_socket_options,
		"extra_socket_options", &extra_options);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity TODO: checks  */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
               (settings.default_request_block_size != 0 && settings.default_request_block_size < MIN_BLOCK_SIZE) ||
               (settings.default_response_block_size != 0 && settings.default_response_block_size < MIN_BLOCK_SIZE)  ||
		settings.write_rate < 0 ||
		strlen(cc_alg) > 255 ||
		settings.num_extra_socket_options < 0 || settings.num_extra_socket_options > MAX_EXTRA_SOCKET_OPTIONS ||
		xmlrpc_array_size(env, extra_options) != settings.num_extra_socket_options) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}

	 /* initalize random number generator (use cmdline option if given, else use random data) 
	  * (currently not used for flow_destination, but added for future use)
	  */
        if (settings.random_seed)
                rn_set_seed(settings.random_seed);
        else
                rn_set_seed(rn_read_dev_random());

	/* Parse extra socket options */
	for (i = 0; i < settings.num_extra_socket_options; i++) {

		const unsigned char* buffer = 0;
		size_t len;
		xmlrpc_value *option, *level = 0, *optname = 0, *value = 0;
		xmlrpc_array_read_item(env, extra_options, i, &option);

		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "level", &level);
		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "optname", &optname);
		if (!env->fault_occurred)
			xmlrpc_struct_read_value(env, option, "value", &value);
		if (!env->fault_occurred)
			xmlrpc_read_int(env, level, &settings.extra_socket_options[i].level);
		if (!env->fault_occurred)
			xmlrpc_read_int(env, optname, &settings.extra_socket_options[i].optname);
		if (!env->fault_occurred)
			xmlrpc_read_base64(env, value, &len, &buffer);
		if (level)
			xmlrpc_DECREF(level);
		if (optname)
			xmlrpc_DECREF(optname);
		if (value)
			xmlrpc_DECREF(value);
		if (!env->fault_occurred) {
			if (len > MAX_EXTRA_SOCKET_OPTION_VALUE_LENGTH) {
				free((void *)buffer);
				XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Too long extra socket option length");
			}
			settings.extra_socket_options[i].optlen = len;
			memcpy(settings.extra_socket_options[i].optval, buffer, len);
			free((void *)buffer);
		}
		if (env->fault_occurred)
			goto cleanup;
	}

	strcpy(settings.cc_alg, cc_alg);
	strcpy(settings.bind_address, bind_address);
	request = malloc(sizeof(struct _request_add_flow_destination));
	request->settings = settings;
	rc = dispatch_request((struct _request*)request, REQUEST_ADD_DESTINATION);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i,s:i,s:i,s:i}",
		"flow_id", request->flow_id,
		"listen_data_port", request->listen_data_port,
		"real_listen_send_buffer_size", request->real_listen_send_buffer_size,
		"real_listen_read_buffer_size", request->real_listen_read_buffer_size);

cleanup:
	if (request) {
		free(request->r.error);
		free(request);
	}
	free(cc_alg);
	free(bind_address);

	if (extra_options)
		xmlrpc_DECREF(extra_options);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method add_flow_destination failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method add_flow_destination successful");
	}

	return ret;
}

static xmlrpc_value * start_flows(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(user_data);

	int rc;
	xmlrpc_value *ret = 0;
	int start_timestamp;
	struct _request_start_flows *request = 0;

	DEBUG_MSG(LOG_WARNING, "Method start_flows called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:i,*})",

		/* general settings */
		"start_timestamp", &start_timestamp);

	if (env->fault_occurred)
		goto cleanup;

	request = malloc(sizeof(struct _request_start_flows));
	request->start_timestamp = start_timestamp;
	rc = dispatch_request((struct _request*)request, REQUEST_START_FLOWS);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "i", 0);

cleanup:
	if (request) {
		free(request->r.error);
		free(request);
	}

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method start_flows failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method start_flows successful");
	}

	return ret;
}

static xmlrpc_value * method_get_reports(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	int has_more;
	xmlrpc_value *ret = 0, *item = 0;

	UNUSED_ARGUMENT(param_array);
	UNUSED_ARGUMENT(user_data);

	DEBUG_MSG(LOG_NOTICE, "Method get_reports called");

	struct _report *report = get_reports(&has_more);

	ret = xmlrpc_array_new(env);

	/* Add information if there's more reports pending */
	item = xmlrpc_int_new(env, has_more);
	xmlrpc_array_append_item(env, ret, item);
	xmlrpc_DECREF(item);

	while (report) {
		xmlrpc_value *rv = xmlrpc_build_value(env, 
			"({"
			"s:i,s:i,s:i,s:i,s:i,s:i," /* timeval */
			"s:i,s:i,s:i,s:i," /* bytes */
			"s:i,s:i,s:i,s:i," /* block counts */
			"s:d,s:d,s:d,s:d,s:d,s:d," /* RTT, IAT */
			"s:i,s:i," /* MSS, MTU */
			"s:i,s:i,s:i,s:i,s:i," /* TCP info */
			"s:i,s:i,s:i,s:i,s:i," /* ...      */
			"s:i,s:i,s:i,s:i,s:i," /* ...      */
			"s:i"
			"})",

			"id", report->id,
			"type", report->type,
			"begin_tv_sec", (int)report->begin.tv_sec,
			"begin_tv_usec", (int)report->begin.tv_usec,
			"end_tv_sec", (int)report->end.tv_sec,
			"end_tv_usec", (int)report->end.tv_usec,

			"bytes_read_high", (int32_t)(report->bytes_read >> 32),
			"bytes_read_low", (int32_t)(report->bytes_read & 0xFFFFFFFF),
			"bytes_written_high", (int32_t)(report->bytes_written >> 32),
			"bytes_written_low", (int32_t)(report->bytes_written & 0xFFFFFFFF),
			
			"request_blocks_read", report->request_blocks_read,
			"request_blocks_written", report->request_blocks_written,
			"response_blocks_read", report->response_blocks_read,
			"response_blocks_written", report->response_blocks_written,

			"rtt_min", report->rtt_min,
			"rtt_max", report->rtt_max,
			"rtt_sum", report->rtt_sum,
			"iat_min", report->iat_min,
			"iat_max", report->iat_max,
 			"iat_sum", report->iat_sum,

			"mss", report->mss,
			"mtu", report->mtu,
#ifdef __LINUX__
			"tcpi_snd_cwnd", (int)report->tcp_info.tcpi_snd_cwnd,
			"tcpi_snd_ssthresh", (int)report->tcp_info.tcpi_snd_ssthresh,
			"tcpi_unacked", (int)report->tcp_info.tcpi_unacked,
			"tcpi_sacked", (int)report->tcp_info.tcpi_sacked,
			"tcpi_lost", (int)report->tcp_info.tcpi_lost,

			"tcpi_retrans", (int)report->tcp_info.tcpi_retrans,
			"tcpi_retransmits", (int)report->tcp_info.tcpi_retransmits,
			"tcpi_fackets", (int)report->tcp_info.tcpi_fackets,
			"tcpi_reordering", (int)report->tcp_info.tcpi_reordering,
			"tcpi_rtt", (int)report->tcp_info.tcpi_rtt,

			"tcpi_rttvar", (int)report->tcp_info.tcpi_rttvar,
			"tcpi_rto", (int)report->tcp_info.tcpi_rto,
			"tcpi_last_data_sent", (int)report->tcp_info.tcpi_last_data_sent,
			"tcpi_last_ack_recv", (int)report->tcp_info.tcpi_last_ack_recv,
			"tcpi_ca_state", (int)report->tcp_info.tcpi_ca_state,
#else
			"tcpi_snd_cwnd", 0,
			"tcpi_snd_ssthresh", 0,
			"tcpi_unacked", 0,
			"tcpi_sacked", 0,
			"tcpi_lost", 0,
			"tcpi_retrans", 0,
			"tcpi_retransmits", 0,
			"tcpi_fackets", 0,
			"tcpi_reordering", 0,
			"tcpi_rtt", 0,
			"tcpi_rttvar", 0,
			"tcpi_rto", 0,
			"tcpi_last_data_sent", 0,
			"tcpi_last_ack_recv", 0,
			"tcpi_ca_state", 0,
#endif

			"status", report->status
		);

		xmlrpc_array_append_item(env, ret, rv);

		xmlrpc_DECREF(rv);

		struct _report *next = report->next;
		free(report);
		report = next;
	}

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method get_reports failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method get_reports successful");
	}

	return ret;
}

static xmlrpc_value * method_stop_flow(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(user_data);

	int rc;
	xmlrpc_value *ret = 0;
	int flow_id;
	struct _request_stop_flow *request = 0;

	DEBUG_MSG(LOG_WARNING, "Method stop_flow called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:i,*})",

		/* flow id */
		"flow_id", &flow_id);

	if (env->fault_occurred)
		goto cleanup;

	request = malloc(sizeof(struct _request_stop_flow));
	request->flow_id = flow_id;
	rc = dispatch_request((struct _request*)request, REQUEST_STOP_FLOW);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "()");

cleanup:
	if (request) {
		free(request->r.error);
		free(request);
	}

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method stop_flow failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method stop_flow successful");
	}

	return ret;
}

/* This method returns the version number of flowgrindd as string. */
static xmlrpc_value * method_get_version(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(param_array);
	UNUSED_ARGUMENT(user_data);

	xmlrpc_value *ret = 0;

	DEBUG_MSG(LOG_WARNING, "Method get_version called");

	/* Return our result. */
	ret = xmlrpc_build_value(env, "s", FLOWGRIND_VERSION);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method get_version failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method get_version successful");
	}

	return ret;
}

/* This method returns the number of flows and if actual test has started */
static xmlrpc_value * method_get_status(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(param_array);
	UNUSED_ARGUMENT(user_data);

	int rc;
	xmlrpc_value *ret = 0;
	struct _request_get_status *request = 0;

	DEBUG_MSG(LOG_WARNING, "Method get_status called");

	request = malloc(sizeof(struct _request_get_status));
	rc = dispatch_request((struct _request*)request, REQUEST_GET_STATUS);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i,s:i}",
		"started", request->started,
		"num_flows", request->num_flows);

cleanup:
	if (request) {
		free(request->r.error);
		free(request);
	}

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method get_status failed: %s", env->fault_string);
	else {
		DEBUG_MSG(LOG_WARNING, "Method get_status successful");
	}

	return ret;
}

void create_daemon_thread()
{
	int flags;

	if (pipe(daemon_pipe) == -1) {
		fprintf(stderr, "Could not create pipe: %d", errno);
		exit(1);
	}

	if ((flags = fcntl(daemon_pipe[0], F_GETFL, 0)) == -1)
		flags = 0;
	fcntl(daemon_pipe[0], F_SETFL, flags | O_NONBLOCK);

	pthread_mutex_init(&mutex, NULL);

	int rc = pthread_create(&daemon_thread, NULL, daemon_main, 0);
	if (rc) {
		fprintf(stderr, "Could not start thread: %d", errno);
		exit(1);
	}
}

static void run_rpc_server(xmlrpc_env *env, unsigned int port)
{
	xmlrpc_server_abyss_parms serverparm;
	xmlrpc_registry * registryP;

	registryP = xmlrpc_registry_new(env);

	xmlrpc_registry_add_method(env, registryP, NULL, "add_flow_destination", &add_flow_destination, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "add_flow_source", &add_flow_source, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "start_flows", &start_flows, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "get_reports", &method_get_reports, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "stop_flow", &method_stop_flow, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "get_version", &method_get_version, NULL);
	xmlrpc_registry_add_method(env, registryP, NULL, "get_status", &method_get_status, NULL);

	/* In the modern form of the Abyss API, we supply parameters in memory
	   like a normal API.  We select the modern form by setting
	   config_file_name to NULL:
	*/
	serverparm.config_file_name = NULL;
	serverparm.registryP		= registryP;
	serverparm.port_number	  = port;
	serverparm.log_file_name	= NULL; /*"/tmp/xmlrpc_log";*/

	/* Increase HTTP keep-alive duration. Using defaults the amount of
	 * sockets in TIME_WAIT state would become too high.
	 */
	serverparm.keepalive_timeout = 60;
	serverparm.keepalive_max_conn = 1000;

	logging_log(LOG_NOTICE, "Running XML-RPC server on port %u", port);
	printf("Running XML-RPC server...\n");

	xmlrpc_server_abyss(env, &serverparm, XMLRPC_APSIZE(keepalive_max_conn));

    if (env->fault_occurred) {
        fprintf(stderr, "XML-RPC Fault: %s (%d)\n",
                env->fault_string, env->fault_code);
	}
	/* xmlrpc_server_abyss() never returns */
}

int main(int argc, char ** argv)
{
	unsigned port = DEFAULT_LISTEN_PORT;
	int rc;
	int ch;
	int argcorig = argc;
	struct sigaction sa;

	xmlrpc_env env;

	/* update progname from argv[0] */
	if (argc > 0) {
		/* Strip path */
		char *tok = strrchr(argv[0], '/');
		if (tok)
			tok++;
		else
			tok = argv[0];
		if (*tok) {
			strncpy(progname, tok, sizeof(progname));
			progname[sizeof(progname) - 1] = 0;
		}
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		error(ERR_FATAL, "Could not ignore SIGPIPE: %s",
				strerror(errno));
		/* NOTREACHED */
	}

	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	sigaction (SIGHUP, &sa, NULL);
	sigaction (SIGALRM, &sa, NULL);
	sigaction (SIGCHLD, &sa, NULL);

#if HAVE_LIBPCAP
	fg_pcap_init();
#endif

#if HAVE_GETOPT_LONG
	// getopt_long isn't portable, it's GNU extension
	struct option lo[] = {	{"help", 0, 0, 'h' },
				{"version", 0, 0, 'v'},
				{"debug", 0, 0, 'd'},
				{0, 0, 0, 0}
				};
	while ((ch = getopt_long(argc, argv, "a:dDhp:vV", lo, 0)) != -1) {
#else
	while ((ch = getopt(argc, argv, "a:dDhp:vV")) != -1) {
#endif
		switch (ch) {
		case 'a':
			if (acl_allow_add(optarg) == -1) {
				fprintf(stderr, "unable to add host to ACL "
						"list\n");
				usage();
			}
			break;

		case 'h':
			usage();
			break;

		case 'd':
		case 'D':
			log_type = LOGTYPE_STDERR;
			increase_debuglevel();
			break;

		case 'p':
			rc = sscanf(optarg, "%u", &port);
			if (rc != 1) {
				fprintf(stderr, "failed to "
					"parse port number.\n");
				usage();
			}
			break;

		case 'v':
		case 'V':
			fprintf(stderr, "flowgrindd version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		default:
			usage();
		}
	}
	argc = argcorig;

	argc -= optind;
	

	if (argc != 0)
		usage();

	logging_init();
	tsc_init();

	if (log_type == LOGTYPE_SYSLOG) {
		/* Need to call daemon() before creating the thread because
		 * it internally calls fork() which does not copy threads. */
		if (daemon(0, 0) == -1) {
			error(ERR_FATAL, "daemon() failed: %s", strerror(errno));
		}
		logging_log(LOG_NOTICE, "flowgrindd daemonized");
	}

	create_daemon_thread();

	xmlrpc_env_init(&env);

	run_rpc_server(&env, port);

	fprintf(stderr, "Control should never reach end of main()\n");

	return 0;
}
