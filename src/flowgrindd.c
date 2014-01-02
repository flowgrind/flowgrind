/**
 * @file flowgrindd.c
 * @brief Flowgrind Daemon
 */

/*
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif /* HAVE_GETOPT_LONG */

/* CPU affinity */
#ifdef __LINUX__
#include <sched.h>
#elif __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
#endif /* __LINUX__ */

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#include <xmlrpc-c/util.h>

#include "common.h"
#include "daemon.h"
#include "log.h"
#include "fg_time.h"
#include "debug.h"
#include "fg_math.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

unsigned port = DEFAULT_LISTEN_PORT;
char *rpc_bind_addr = NULL;
int cpu = -1;				    /* No CPU affinity */
static char progname[50] = "flowgrindd";

static void __attribute__((noreturn)) usage(void)
{
	fprintf(stderr,
#ifdef HAVE_LIBPCAP
		"Usage: %1$s [-p #] [-b addr] [-d] [-c #] [-w dir/] [-v]\n"
#else
		"Usage: %1$s [-p #] [-b addr] [-d] [-c #] [-v]\n"
#endif /* HAVE_LIBPCAP */
		"\t-p #\t\tXML-RPC server port\n"
		"\t-b addr\t\tXML-RPC server bind address\n"
#ifdef DEBUG
		"\t-d\t\tincrease debug verbosity, add multiple times (no daemon, log to stderr)\n"
#else
		"\t-d\t\tdon't fork into background\n"
#endif /* DEBUG */
		"\t-c #\t\tbound daemon to specific CPU\n"
#ifdef HAVE_LIBPCAP
		"\t-w\t\ttarget directory for dumps\n"
#endif /* HAVE_LIBPCAP */
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
		request_error(request, "Could not create synchronization mutex");
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
		"("
		"{s:s,*}"
		"{s:d,s:d,s:d,s:d,s:d,*}"
		"{s:i,s:i,*}"
		"{s:i,*}"
		"{s:b,s:b,s:b,s:b,s:b,*}"
		"{s:i,s:i,*}"
		"{s:i,s:d,s:d,*}" /* request */
		"{s:i,s:d,s:d,*}" /* response */
		"{s:i,s:d,s:d,*}" /* interpacket_gap */
		"{s:b,s:b,s:i,s:i,*}"
		"{s:s,*}"
		"{s:i,s:i,s:i,s:i,s:i,*}"
#ifdef HAVE_LIBPCAP
		"{s:s,*}"
#endif /* HAVE_LIBPCAP */
		"{s:i,s:A,*}"
		"{s:s,s:i,s:i,*}"
		")",

		/* general settings */
		"bind_address", &bind_address,

		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"reporting_interval", &settings.reporting_interval,

		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,

		"maximum_block_size", &settings.maximum_block_size,

		"traffic_dump", &settings.traffic_dump,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,

		"write_rate", &settings.write_rate,
		"random_seed",&settings.random_seed,

		"traffic_generation_request_distribution", &settings.request_trafgen_options.distribution,
		"traffic_generation_request_param_one", &settings.request_trafgen_options.param_one,
		"traffic_generation_request_param_two", &settings.request_trafgen_options.param_two,

		"traffic_generation_response_distribution", &settings.response_trafgen_options.distribution,
		"traffic_generation_response_param_one", &settings.response_trafgen_options.param_one,
		"traffic_generation_response_param_two", &settings.response_trafgen_options.param_two,

		"traffic_generation_gap_distribution", &settings.interpacket_gap_trafgen_options.distribution,
		"traffic_generation_gap_param_one", &settings.interpacket_gap_trafgen_options.param_one,
		"traffic_generation_gap_param_two", &settings.interpacket_gap_trafgen_options.param_two,

		"flow_control", &settings.flow_control,
		"byte_counting", &settings.byte_counting,
		"cork", &settings.cork,
		"nonagle", &settings.nonagle,

		"cc_alg", &cc_alg,

		"elcn", &settings.elcn,
		"lcd",  &settings.lcd,
		"mtcp", &settings.mtcp,
		"dscp", &settings.dscp,
		"ipmtudiscover", &settings.ipmtudiscover,
#ifdef HAVE_LIBPCAP
		"filename_prefix", &dump_filename_prefix_client,
#endif /* HAVE_LIBPCAP */
		"num_extra_socket_options", &settings.num_extra_socket_options,
		"extra_socket_options", &extra_options,

		/* source settings */
		"destination_address", &destination_host,
		"destination_port", &source_settings.destination_port,
		"late_connect", &source_settings.late_connect);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.maximum_block_size < MIN_BLOCK_SIZE ||
		strlen(destination_host) >= sizeof(source_settings.destination_host) - 1||
		source_settings.destination_port <= 0 || source_settings.destination_port > 65535 ||
		strlen(cc_alg) > TCP_CA_NAME_MAX ||
		settings.num_extra_socket_options < 0 || settings.num_extra_socket_options > MAX_EXTRA_SOCKET_OPTIONS ||
		xmlrpc_array_size(env, extra_options) != settings.num_extra_socket_options ||
		settings.dscp < 0 || settings.dscp > 255 ||
		settings.write_rate < 0 ||
		settings.reporting_interval < 0) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}

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
		"("
		"{s:s,*}"
		"{s:d,s:d,s:d,s:d,s:d,*}"
		"{s:i,s:i,*}"
		"{s:i,*}"
		"{s:b,s:b,s:b,s:b,s:b,*}"
		"{s:i,s:i,*}"
		"{s:i,s:d,s:d,*}" /* request */
		"{s:i,s:d,s:d,*}" /* response */
		"{s:i,s:d,s:d,*}" /* interpacket_gap */
		"{s:b,s:b,s:i,s:i,*}"
		"{s:s,*}"
		"{s:i,s:i,s:i,s:i,s:i,*}"
#ifdef HAVE_LIBPCAP
		"{s:s,*}"
#endif /* HAVE_LIBPCAP */
		"{s:i,s:A,*}"
		")",

		/* general settings */
		"bind_address", &bind_address,

		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"reporting_interval", &settings.reporting_interval,

		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,

		"maximum_block_size", &settings.maximum_block_size,

		"traffic_dump", &settings.traffic_dump,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,

		"write_rate", &settings.write_rate,
		"random_seed",&settings.random_seed,

		"traffic_generation_request_distribution", &settings.request_trafgen_options.distribution,
		"traffic_generation_request_param_one", &settings.request_trafgen_options.param_one,
		"traffic_generation_request_param_two", &settings.request_trafgen_options.param_two,

		"traffic_generation_response_distribution", &settings.response_trafgen_options.distribution,
		"traffic_generation_response_param_one", &settings.response_trafgen_options.param_one,
		"traffic_generation_response_param_two", &settings.response_trafgen_options.param_two,

		"traffic_generation_gap_distribution", &settings.interpacket_gap_trafgen_options.distribution,
		"traffic_generation_gap_param_one", &settings.interpacket_gap_trafgen_options.param_one,
		"traffic_generation_gap_param_two", &settings.interpacket_gap_trafgen_options.param_two,

		"flow_control", &settings.flow_control,
		"byte_counting", &settings.byte_counting,
		"cork", &settings.cork,
		"nonagle", &settings.nonagle,

		"cc_alg", &cc_alg,

		"elcn", &settings.elcn,
		"lcd", &settings.lcd,
		"mtcp", &settings.mtcp,
		"dscp", &settings.dscp,
		"ipmtudiscover", &settings.ipmtudiscover,
#ifdef HAVE_LIBPCAP
		"filename_prefix", &dump_filename_prefix_client,
#endif /* HAVE_LIBPCAP */
		"num_extra_socket_options", &settings.num_extra_socket_options,
		"extra_socket_options", &extra_options);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.maximum_block_size < MIN_BLOCK_SIZE ||
		settings.write_rate < 0 ||
		strlen(cc_alg) > TCP_CA_NAME_MAX ||
		settings.num_extra_socket_options < 0 || settings.num_extra_socket_options > MAX_EXTRA_SOCKET_OPTIONS ||
		xmlrpc_array_size(env, extra_options) != settings.num_extra_socket_options) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}

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
	DEBUG_MSG(LOG_WARNING, "bind_address=%s", bind_address);
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
			"("
			"{s:i,s:i,s:i,s:i,s:i,s:i}" /* timeval */
			"{s:i,s:i,s:i,s:i}" /* bytes */
			"{s:i,s:i,s:i,s:i}" /* block counts */
			"{s:d,s:d,s:d,s:d,s:d,s:d}" /* RTT, IAT */
			"{s:i,s:i}" /* MTU */
			"{s:i,s:i,s:i,s:i,s:i}" /* TCP info */
			"{s:i,s:i,s:i,s:i,s:i}" /* ...      */
			"{s:i,s:i,s:i,s:i,s:i}" /* ...      */
			"{s:i}"
			")",

			"id", report->id,
			"type", report->type,
			"begin_tv_sec", (int)report->begin.tv_sec,
			"begin_tv_nsec", (int)report->begin.tv_nsec,
			"end_tv_sec", (int)report->end.tv_sec,
			"end_tv_nsec", (int)report->end.tv_nsec,

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

			"pmtu", report->pmtu,
			"imtu", report->imtu,

/* Currently, not all members of the TCP_INFO socket option are used by the
 * FreeBSD kernel. Other members will contain zeroes */
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
			"tcpi_backoff", (int)report->tcp_info.tcpi_backoff,
			"tcpi_ca_state", (int)report->tcp_info.tcpi_ca_state,
			"tcpi_snd_mss", (int)report->tcp_info.tcpi_snd_mss,

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

/* This method returns version information of flowgrindd and OS as an xmlrpc struct */
static xmlrpc_value * method_get_version(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	UNUSED_ARGUMENT(param_array);
	UNUSED_ARGUMENT(user_data);
	struct utsname buf;

	xmlrpc_value *ret = 0;

	DEBUG_MSG(LOG_WARNING, "Method get_version called");

	if (uname(&buf)) {
		logging_log(LOG_WARNING, "uname() failed %s", strerror(errno));
		exit(1);
	}

	ret = xmlrpc_build_value(env, "{s:s,s:i,s:s,s:s}",
				 "version", FLOWGRIND_VERSION,
				 "api_version", FLOWGRIND_API_VERSION,
				 "os_name", buf.sysname,
				 "os_release", buf.release);

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

/* creates listen socket for the xmlrpc server */
static int bind_rpc_server(char *bind_addr, unsigned int port) {
	int rc;
	int fd;
	int optval;
	struct addrinfo hints, *res, *ressave;
	char tmp_port[100];

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	sprintf(tmp_port, "%u", port);

	if ((rc = getaddrinfo(bind_addr, tmp_port,
				&hints, &res)) != 0) {
		logging_log(LOG_ALERT, "Failed to find address to bind rpc_server: %s\n",
			gai_strerror(rc));
		return -1;
	}
	ressave = res;

	/* try to bind the first succeeding socket of
	   the returned addresses (libxmlrpc only supports one fd)
	*/
	do {
		fd = socket(res->ai_family, res->ai_socktype,
		res->ai_protocol);
		if (fd < 0)
			continue;
		/* ignore old client connections in TIME_WAIT */
		optval = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		/* Disable Nagle algorithm to reduce latency */
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

		if (bind(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		close(fd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		logging_log(LOG_ALERT, "failed to bind RPC listen socket: %s\n", strerror(errno));
		freeaddrinfo(ressave);
		return -1;
	}

	return fd;
}

static void run_rpc_server(xmlrpc_env *env, unsigned int port)
{
	xmlrpc_server_abyss_parms serverparm;
	xmlrpc_registry * registryP;
	memset(&serverparm, 0, sizeof(serverparm));

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
	serverparm.config_file_name	= NULL;
	serverparm.registryP		= registryP;
	serverparm.socket_bound		= 1;
	serverparm.log_file_name        = NULL; /*"/tmp/xmlrpc_log";*/

	/* Increase HTTP keep-alive duration. Using defaults the amount of
	 * sockets in TIME_WAIT state would become too high.
	 */
	serverparm.keepalive_timeout = 60;
	serverparm.keepalive_max_conn = 1000;

	/* Disable introspection */
	serverparm.dont_advertise = 1;

	logging_log(LOG_NOTICE, "Running XML-RPC server on port %u", port);
	printf("Running XML-RPC server...\n");

	serverparm.socket_handle = bind_rpc_server(rpc_bind_addr, port);
	xmlrpc_server_abyss(env, &serverparm, XMLRPC_APSIZE(socket_handle));

	if (env->fault_occurred) {
		logging_log(LOG_ALERT, "XML-RPC Fault: %s (%d)\n",
			env->fault_string, env->fault_code);
	}
	/* xmlrpc_server_abyss() never returns */
}

void set_affinity(int cpu)
{
#ifdef __LINUX__
	typedef cpu_set_t fg_cpuset;
#elif __FreeBSD__
	typedef cpuset_t fg_cpuset;
#endif /* __LINUX__ */
	int rc;
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);   /* number of cores */
	fg_cpuset cpuset;			    /* define cpu_set bit mask */

	/* sanity check */
	if (cpu > ncpu) {
		logging_log(LOG_WARNING, "CPU binding failed. Given cpu number "
			    "is higher then the available cores");
		return;
	}

	CPU_ZERO(&cpuset);	/* initialize to 0, i.e. no CPUs selected. */
	CPU_SET(cpu, &cpuset);	/* set bit that represents the given core */

#ifdef __LINUX__
	rc = sched_setaffinity(getpid(), sizeof(cpuset), &cpuset);
#elif __FreeBSD__
	rc = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
				sizeof(cpuset), &cpuset);
#endif /* __LINUX__ */
	if (rc)
		logging_log(LOG_WARNING, "failed to bind %s (PID %d) to "
			    "CPU %i\n", progname, getpid(), cpu);
	else
		DEBUG_MSG(LOG_WARNING, "bind %s (PID %d) to CPU %i\n",
			  progname, getpid(), cpu);
}

static void parse_option(int argc, char ** argv)
{
	int ch, rc;
	int argcorig = argc;
#ifdef HAVE_GETOPT_LONG
	/* getopt_long isn't portable, it's GNU extension */
	struct option lo[] = {  {"help", 0, 0, 'h' },
				{"version", 0, 0, 'v'},
				{"debug", 0, 0, 'd'},
				{0, 0, 0, 0}
				};
	while ((ch = getopt_long(argc, argv, "dDhp:vVw:W:b:c:", lo, 0)) != -1) {
#else
	while ((ch = getopt(argc, argv, "dDhp:vVw:W:b:c:")) != -1) {
#endif /* HAVE_GETOPT_LONG */
		switch (ch) {
		case 'h':
			usage();
			break;
		case 'd':
		case 'D':
			log_type = LOGTYPE_STDERR;
			increase_debuglevel();
			break;
		case 'c':
			rc = sscanf(optarg, "%i", &cpu);
			if (rc != 1) {
				fprintf(stderr, "failed to "
					"parse CPU number.\n");
			}
			break;
		case 'p':
			rc = sscanf(optarg, "%u", &port);
			if (rc != 1) {
				fprintf(stderr, "failed to "
					"parse port number.\n");
				usage();
			}
			// TODO check if port is in valid range
			break;
		case 'b':
			rpc_bind_addr = malloc(strlen(optarg)+1);
			rc = sscanf(optarg, "%s", rpc_bind_addr);
			if (rc != 1) {
				fprintf(stderr, "failed to "
					"parse bind address.\n");
				usage();
			}
			break;
		case 'v':
		case 'V':
			fprintf(stderr, "flowgrindd version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		case 'w':
		case 'W':
#ifdef HAVE_LIBPCAP
			dump_filename_prefix_server = optarg;
			break;
#endif /* HAVE_LIBPCAP */
		default:
			usage();
		}
	}
	argc = argcorig;
	argc -= optind;

	if (argc != 0)
		usage();
}

int main(int argc, char ** argv)
{
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

	parse_option(argc, argv);
	logging_init();
#ifdef HAVE_LIBPCAP
	fg_pcap_init();
#endif /* HAVE_LIBPCAP */
	if (log_type == LOGTYPE_SYSLOG) {
		/* Need to call daemon() before creating the thread because
		 * it internally calls fork() which does not copy threads. */
		if (daemon(0, 0) == -1) {
			error(ERR_FATAL, "daemon() failed: %s", strerror(errno));
		}
		logging_log(LOG_NOTICE, "flowgrindd daemonized");
	}

	if (cpu >= 0)
		set_affinity(cpu);

	create_daemon_thread();

	xmlrpc_env_init(&env);

	run_rpc_server(&env, port);

	fprintf(stderr, "Control should never reach end of main()\n");

	return 0;
}
