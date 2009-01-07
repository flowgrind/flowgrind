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

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#include <xmlrpc-c/util.h>

#include "config.h"  /* information about this build environment */
#include "common.h"
#include "daemon.h"
#include "log.h"
#include "fg_time.h"
#include "debug.h"
#include "acl.h"
#include "fg_pcap.h"

static void __attribute__((noreturn)) usage(void)
{
	fprintf(stderr, "Usage: flowgrindd [-a address ] [-w#] [-p#] [-d]\n");
	fprintf(stderr, "\t-a address\tadd address to list of allowed hosts "
			"(CIDR syntax)\n");
	fprintf(stderr, "\t-p#\t\tserver port\n");
	fprintf(stderr, "\t-D \t\tincrease debug verbosity (no daemon, log to "
					"stderr)\n");
	fprintf(stderr, "\t-V\t\tPrint version information and exit\n");
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
		logging_log(LOG_NOTICE, "got SIGHUP, don't know what do do.");
		break;

	case SIGALRM:
		DEBUG_MSG(1, "Caught SIGALRM.");
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
		request->error = "Could not create synchonization mutex";
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

	write(daemon_pipe[1], &type, 1); /* Doesn't matter what we write */

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
	int rc;
	xmlrpc_value *ret = 0;
	char* destination_host = 0;
	char* destination_host_reply = 0;
	char* cc_alg = 0;
	char* bind_address = 0;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct _request_add_flow_source* request = 0;

	DEBUG_MSG(1, "Method add_flow_source called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:s,s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,s:i,*}{s:s,s:s,s:i,s:i,s:s,s:i,s:i,s:i,s:i,s:i,s:i,*})",

		/* general settings */
		"bind_address", &bind_address,
		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,
		"write_block_size", &settings.write_block_size,
		"read_block_size", &settings.read_block_size,
		"advstats", &settings.advstats,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,
		"write_rate", &settings.write_rate,
		"poisson_distributed", &settings.poisson_distributed,
		"flow_control", &settings.flow_control,
		"cork", &settings.cork,

		/* source settings */
		"destination_address", &destination_host,
		"destination_address_reply", &destination_host_reply,
		"destination_port", &source_settings.destination_port,
		"destination_port_reply", &source_settings.destination_port_reply,
		"cc_alg", &cc_alg,
		"elcn", &source_settings.elcn,
		"icmp", &source_settings.icmp,
		"dscp", &source_settings.dscp,
		"ipmtudiscover", &source_settings.ipmtudiscover,
		"late_connect", &source_settings.late_connect,
		"byte_counting", &source_settings.byte_counting);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.write_block_size <= 0 || settings.read_block_size <= 0 ||
		strlen(destination_host) >= sizeof(source_settings.destination_host) - 1||
		strlen(destination_host_reply) >= sizeof(source_settings.destination_host_reply) - 1 ||
		source_settings.destination_port <= 0 || source_settings.destination_port > 65535 ||
		strlen(cc_alg) > 255 ||
		source_settings.dscp < 0 || source_settings.dscp > 255 ||
		settings.write_rate < 0) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}
	strcpy(source_settings.destination_host, destination_host);
	strcpy(source_settings.destination_host_reply, destination_host_reply);
	strcpy(source_settings.cc_alg, cc_alg);
	strcpy(settings.bind_address, bind_address);

	request = malloc(sizeof(struct _request_add_flow_source));
	request->settings = settings;
	request->source_settings = source_settings;
	rc = dispatch_request((struct _request*)request, REQUEST_ADD_SOURCE);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i,s:s}",
		"flow_id", request->flow_id,
		"cc_alg", request->cc_alg);

cleanup:
	if (request)
		free(request);
	if (destination_host)
		free(destination_host);
	if (destination_host_reply)
		free(destination_host_reply);
	if (cc_alg)
		free(cc_alg);
	if (bind_address)
		free(bind_address);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method add_flow_source failed: %s", env->fault_string);
	else {
		DEBUG_MSG(1, "Method add_flow_source successful");
	}

	return ret;
}

static xmlrpc_value * add_flow_destination(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	int rc;
	xmlrpc_value *ret = 0;
	char* bind_address = 0;

	struct _flow_settings settings;
	struct _flow_destination_settings destination_settings;

	struct _request_add_flow_destination* request = 0;

	DEBUG_MSG(1, "Method add_flow_destination called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:s,s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,s:i,*})",

		/* general settings */
		"bind_address", &bind_address,
		"write_delay", &settings.delay[WRITE],
		"write_duration", &settings.duration[WRITE],
		"read_delay", &settings.delay[READ],
		"read_duration", &settings.duration[READ],
		"requested_send_buffer_size", &settings.requested_send_buffer_size,
		"requested_read_buffer_size", &settings.requested_read_buffer_size,
		"write_block_size", &settings.write_block_size,
		"read_block_size", &settings.read_block_size,
		"advstats", &settings.advstats,
		"so_debug", &settings.so_debug,
		"route_record", &settings.route_record,
		"pushy", &settings.pushy,
		"shutdown", &settings.shutdown,
		"write_rate", &settings.write_rate,
		"poisson_distributed", &settings.poisson_distributed,
		"flow_control", &settings.flow_control,
		"cork", &settings.cork);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (strlen(bind_address) >= sizeof(settings.bind_address) - 1 ||
		settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.write_block_size <= 0 || settings.read_block_size <= 0 ||
		settings.write_rate < 0) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}

	strcpy(settings.bind_address, bind_address);
	request = malloc(sizeof(struct _request_add_flow_destination));
	request->settings = settings;
	request->destination_settings = destination_settings;
	rc = dispatch_request((struct _request*)request, REQUEST_ADD_DESTINATION);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i,s:i,s:i,s:i,s:i}",
		"flow_id", request->flow_id,
		"listen_data_port", request->listen_data_port,
		"listen_reply_port", request->listen_reply_port,
		"real_listen_send_buffer_size", request->real_listen_send_buffer_size,
		"real_listen_read_buffer_size", request->real_listen_read_buffer_size);

cleanup:
	if (request)
		free(request);
	if (bind_address)
		free(bind_address);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method add_flow_destination failed: %s", env->fault_string);
	else {
		DEBUG_MSG(1, "Method add_flow_destination successful");
	}

	return ret;
}

static xmlrpc_value * start_flows(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	int rc;
	xmlrpc_value *ret = 0;
	int start_timestamp;
	struct _request_start_flows *request = 0;

	DEBUG_MSG(1, "Method start_flows called");

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
	if (request)
		free(request);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method start_flows failed: %s", env->fault_string);
	else {
		DEBUG_MSG(1, "Method start_flows successful");
	}

	return ret;
}

static xmlrpc_value * method_get_reports(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	int rc;
	xmlrpc_value *ret = 0;
	DEBUG_MSG(2, "Method get_reports called");

	struct _report *report = get_reports();
	
	ret = xmlrpc_array_new(env);
	
	while (report) {
		xmlrpc_value *rv = xmlrpc_build_value(env, "{"
			"s:i,s:i,s:i,s:i,s:i,s:i," "s:i,s:i,s:i," "s:d,s:d,s:d,s:d,s:d,s:d," "s:i,s:i,"
			"s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i}", /* TCP info */
		
			"id", report->id,
			"type", report->type,
			"begin_tv_sec", (int)report->begin.tv_sec,
			"begin_tv_usec", (int)report->begin.tv_usec,
			"end_tv_sec", (int)report->end.tv_sec,
			"end_tv_usec", (int)report->end.tv_usec,

			"bytes_read", report->bytes_read,
			"bytes_written", report->bytes_written,
			"reply_blocks_read", report->reply_blocks_read,

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
			"tcpi_fackets", (int)report->tcp_info.tcpi_fackets,
			"tcpi_reordering", (int)report->tcp_info.tcpi_reordering,
			"tcpi_rtt", (int)report->tcp_info.tcpi_rtt,
			"tcpi_rttvar", (int)report->tcp_info.tcpi_rttvar,
			"tcpi_rto", (int)report->tcp_info.tcpi_rto,
			"tcpi_last_data_sent", (int)report->tcp_info.tcpi_last_data_sent,
			"tcpi_last_ack_recv", (int)report->tcp_info.tcpi_last_ack_recv
#else
			"tcpi_snd_cwnd", 0,
			"tcpi_snd_ssthresh", 0,
			"tcpi_unacked", 0,
			"tcpi_sacked", 0,
			"tcpi_lost", 0,
			"tcpi_retrans", 0,
			"tcpi_fackets", 0,
			"tcpi_reordering", 0,
			"tcpi_rtt", 0,
			"tcpi_rttvar", 0,
			"tcpi_rto", 0,
			"tcpi_last_data_sent", 0,
			"tcpi_last_ack_recv", 0
#endif
		);
		
		xmlrpc_array_append_item(env, ret, rv);

		xmlrpc_DECREF(rv);

		struct _report *next = report->next;
		free(report);
		report = next;
	}

cleanup:
	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method get_reports failed: %s", env->fault_string);
	else {
		DEBUG_MSG(2, "Method get_reports successful");
	}

	return ret;
}

static xmlrpc_value * method_stop_flow(xmlrpc_env * const env,
		   xmlrpc_value * const param_array,
		   void * const user_data)
{
	int rc;
	xmlrpc_value *ret = 0;
	int flow_id;
	struct _request_stop_flow *request = 0;

	DEBUG_MSG(2, "Method stop_flow called");

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
	if (request)
		free(request);

	if (env->fault_occurred)
		logging_log(LOG_WARNING, "Method stop_flow failed: %s", env->fault_string);
	else {
		DEBUG_MSG(2, "Method stop_flow successful");
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

	/* In the modern form of the Abyss API, we supply parameters in memory
	   like a normal API.  We select the modern form by setting
	   config_file_name to NULL: 
	*/
	serverparm.config_file_name = NULL;
	serverparm.registryP		= registryP;
	serverparm.port_number	  = port;
	serverparm.log_file_name	= NULL; /*"/tmp/xmlrpc_log";*/

	logging_log(LOG_NOTICE, "Running XML-RPC server on port %u", port);
	printf("Running XML-RPC server...\n");

	xmlrpc_server_abyss(env, &serverparm, XMLRPC_APSIZE(log_file_name));

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

	fg_pcap_init();

	while ((ch = getopt(argc, argv, "a:Dp:V")) != -1) {
		switch (ch) {
		case 'a':
			if (acl_allow_add(optarg) == -1) {
				fprintf(stderr, "unable to add host to ACL "
						"list\n");
				usage();
			}
			break;

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

		case 'V':
			fprintf(stderr, "flowgrindd version: %s\n", FLOWGRIND_VERSION);
			exit(0);

		default:
			usage();
		}
	}
	argc = argcorig;

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	logging_init();
	tsc_init();

	create_daemon_thread();

	if (log_type == LOGTYPE_SYSLOG) {
		if (daemon(0, 0) == -1) {
			error(ERR_FATAL, "daemon() failed: %s", strerror(errno));
		}
		logging_log(LOG_NOTICE, "flowgrindd  daemonized");
	}

	xmlrpc_env_init(&env);
	
	run_rpc_server(&env, port);

	fprintf(stderr, "Control should never reach end of main()\n");

	return 0;
}
