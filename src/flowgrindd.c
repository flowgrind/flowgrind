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

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>

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
	const char* destination_host = 0;
	const char* destination_host_reply = 0;
	const char* cc_alg = 0;

	struct _flow_settings settings;
	struct _flow_source_settings source_settings;

	struct _request_add_flow_source* request = 0;

	DEBUG_MSG(1, "Method add_flow_source called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,*}{s:s,s:s,s:i,s:i,s:s,s:i,s:i,s:i,s:i,s:i,s:i,s:i,*})",

		/* general settings */
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

		/* source settings */
		"destination_host", &destination_host,
		"destination_host_reply", &destination_host_reply,
		"destination_port", &source_settings.destination_port,
		"destination_port_reply", &source_settings.destination_port_reply,
		"cc_alg", &cc_alg,
		"elcn", &source_settings.elcn,
		"icmp", &source_settings.icmp,
		"cork", &source_settings.cork,
		"dscp", &source_settings.dscp,
		"ipmtudiscover", &source_settings.ipmtudiscover,
		"late_connect", &source_settings.late_connect,
		"byte_counting", &source_settings.byte_counting);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.write_block_size <= 0 || settings.read_block_size <= 0 ||
		strlen(destination_host) >= sizeof(source_settings.destination_host) - 1 ||
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

	request = malloc(sizeof(struct _request_add_flow_source));
	request->settings = settings;
	request->source_settings = source_settings;
	rc = dispatch_request((struct _request*)request, REQUEST_ADD_SOURCE);

	if (rc == -1) {
		XMLRPC_FAIL(env, XMLRPC_INTERNAL_ERROR, request->r.error); /* goto cleanup on failure */
	}

	/* Return our result. */
	ret = xmlrpc_build_value(env, "{s:i}",
		"flow_id", request->flow_id);

cleanup:
	if (request)
		free(request);
	if (destination_host)
		xmlrpc_strfree(destination_host);
	if (destination_host_reply)
		xmlrpc_strfree(destination_host_reply);
	if (cc_alg)
		xmlrpc_strfree(cc_alg);

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

	struct _flow_settings settings;
	struct _flow_destination_settings destination_settings;

	struct _request_add_flow_destination* request = 0;

	DEBUG_MSG(1, "Method add_flow_destination called");

	/* Parse our argument array. */
	xmlrpc_decompose_value(env, param_array, "({s:d,s:d,s:d,s:d,s:i,s:i,s:i,s:i,s:b,s:b,s:b,s:b,s:b,s:i,s:b,s:b,*})",

		/* general settings */
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
		"flow_control", &settings.flow_control);

	if (env->fault_occurred)
		goto cleanup;

	/* Check for sanity */
	if (settings.delay[WRITE] < 0 || settings.duration[WRITE] < 0 ||
		settings.delay[READ] < 0 || settings.duration[READ] < 0 ||
		settings.requested_send_buffer_size < 0 || settings.requested_read_buffer_size < 0 ||
		settings.write_block_size <= 0 || settings.read_block_size <= 0 ||
		settings.write_rate < 0) {
		XMLRPC_FAIL(env, XMLRPC_TYPE_ERROR, "Flow settings incorrect");
	}

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
	struct _request_start_flows *request;

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

void create_daemon_thread()
{
/*	if (pipe(daemon_pipe) == -1) {
		fprintf(stderr, "Could not create pipe: %d", errno);
		exit(1);
	}*/

	pthread_mutex_init(&mutex, NULL);

	int rc = pthread_create(&daemon_thread, NULL, daemon_main, 0);
	if (rc) {
		fprintf(stderr, "Could not start thread: %d", errno);
		exit(1);
	}
}

static void run_rpc_server(unsigned int port)
{
	xmlrpc_server_abyss_parms serverparm;
	xmlrpc_registry * registryP;
	xmlrpc_env env;

	xmlrpc_env_init(&env);
	registryP = xmlrpc_registry_new(&env);

	xmlrpc_registry_add_method(&env, registryP, NULL, "add_flow_destination", &add_flow_destination, NULL);
	xmlrpc_registry_add_method(&env, registryP, NULL, "add_flow_source", &add_flow_source, NULL);
	xmlrpc_registry_add_method(&env, registryP, NULL, "start_flows", &start_flows, NULL);

	/* In the modern form of the Abyss API, we supply parameters in memory
	   like a normal API.  We select the modern form by setting
	   config_file_name to NULL: 
	*/
	serverparm.config_file_name = NULL;
	serverparm.registryP		= registryP;
	serverparm.port_number	  = port;
	serverparm.log_file_name	= "/tmp/xmlrpc_log";

	logging_log(LOG_NOTICE, "Running XML-RPC server on port %u", port);
	printf("Running XML-RPC server...\n");

	xmlrpc_server_abyss(&env, &serverparm, XMLRPC_APSIZE(log_file_name));

	/* xmlrpc_server_abyss() never returns */
}

int main(int argc, char ** argv)
{
	unsigned port = DEFAULT_LISTEN_PORT;
	int rc;
	int ch;
	int argcorig = argc;
	struct sigaction sa;

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

	run_rpc_server(port);

	return 0;
}
