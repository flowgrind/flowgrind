/**
 * @file flowgrindd.c
 * @brief Flowgrind daemon
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Arnd Hannemann <arnd@arndnet.de>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
 *
 * This file is part of Flowgrind.
 *
 * Flowgrind is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Flowgrind is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Flowgrind.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef __DARWIN__
/** Temporarily renaming daemon() so compiler does not see the warning on OS X. */
#define daemon fake_daemon_function
#endif /* __DARWIN__ */

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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/stat.h>

/* xmlrpc-c */
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#include <xmlrpc-c/util.h>

#include "common.h"
#include "daemon.h"
#include "fg_log.h"
#include "fg_affinity.h"
#include "fg_error.h"
#include "fg_math.h"
#include "fg_progname.h"
#include "fg_string.h"
#include "fg_time.h"
#include "fg_definitions.h"
#include "debug.h"
#include "fg_argparser.h"
#include "fg_rpc_server.h"

#ifdef HAVE_LIBPCAP
#include "fg_pcap.h"
#endif /* HAVE_LIBPCAP */

#ifdef __DARWIN__
/** Remap daemon() function. */
#undef daemon
extern int daemon(int, int);
#endif /* __DARWIN__ */

/** Print error message, usage string and exit. Used for cmdline parsing errors. */
#define PARSE_ERR(err_msg, ...) do {	\
	errx(err_msg, ##__VA_ARGS__);	\
	usage(EXIT_FAILURE);		\
} while (0)

/* External global variables */
extern const char *progname;

/* XXX add a brief description doxygen */
static unsigned port = DEFAULT_LISTEN_PORT;

/* XXX add a brief description doxygen */
static char *rpc_bind_addr = NULL;

/** CPU core to which flowgrindd should bind to. */
static int core;

/** Command line option parser. */
static struct arg_parser parser;

/* Forward declarations */
static void usage(short status) __attribute__((noreturn));
static void tear_down_daemon(void);

/**
 * Print usage or error message and exit.
 *
 * Depending on exit status @p status print either the usage or an error
 * message. In all cases it call exit() with the given exit status @p status.
 *
 * @param[in] status exit status
 */
static void usage(short status)
{
	/* Syntax error. Emit 'try help' to stderr and exit */
	if (status != EXIT_SUCCESS) {
		fprintf(stderr, "Try '%s -h' for more information\n", progname);
		exit(status);
	}

	fprintf(stdout,
		"Usage: %1$s [OPTION]...\n"
		"Advanced TCP traffic generator for Linux, FreeBSD, and Mac OS X.\n\n"

		"Mandatory arguments to long options are mandatory for short options too.\n"
		"  -b ADDR        XML-RPC server bind address\n"
		"  -c #           bound daemon to specific CPU. First CPU is 0\n"
#ifdef DEBUG
		"  -d, --debug    increase debugging verbosity. Add option multiple times to\n"
		"                 increase the verbosity (no daemon, log to stderr)\n"
#else /* DEBUG */
		"  -d             don't fork into background, log to stderr\n"
#endif /* DEBUG */
		"  -h, --help     display this help and exit\n"
		"  -p #           XML-RPC server port\n"
#ifdef HAVE_LIBPCAP
		"  -w DIR         target directory for dump files. The daemon must be run as root\n"
#endif /* HAVE_LIBPCAP */
		"  -v, --version  print version information and exit\n",
		progname);
	exit(EXIT_SUCCESS);
}

/**
 * Signal handler to catching signals.
 *
 * @param[in] sig signal to catch
 */
static void sighandler(int sig)
{
	int status;

	switch (sig) {
	case SIGCHLD:
		while (waitpid(-1, &status, WNOHANG) > 0)
			logging(LOG_NOTICE, "child returned (status = %d)",
				status);
		break;
	case SIGHUP:
		logging(LOG_NOTICE, "caught SIGHUP. don't know what to do.");
		break;
	case SIGALRM:
		logging(LOG_NOTICE, "caught SIGALRM, don't know what to do.");
		break;
	case SIGPIPE:
		break;
	case SIGINT:
	case SIGTERM:
		logging(LOG_NOTICE, "caught SIGINT/SIGTERM, tear down daemon");
		tear_down_daemon();
		break;
	default:
		logging(LOG_ALERT, "caught signal %d, but don't remember "
			"intercepting it, aborting...", sig);
		abort();
	}
}

void create_daemon_thread()
{
	int flags;

	if (pipe(daemon_pipe) == -1)
		crit("could not create pipe");

	if ((flags = fcntl(daemon_pipe[0], F_GETFL, 0)) == -1)
		flags = 0;
	fcntl(daemon_pipe[0], F_SETFL, flags | O_NONBLOCK);

	pthread_mutex_init(&mutex, NULL);

	int rc = pthread_create(&daemon_thread, NULL, daemon_main, 0);
	if (rc)
		critc(rc, "could not start thread");
}

void bind_daemon_to_core(void)
{
	pthread_t thread = pthread_self();
	int rc = pthread_setaffinity(thread, core);

	if (rc)
		logging(LOG_WARNING, "failed to bind %s (PID %d) to CPU core %i",
			progname, getpid(), core);
	else
		DEBUG_MSG(LOG_INFO, "bind %s (PID %d) to CPU core %i",
			  progname, getpid(), core);
}

#ifdef HAVE_LIBPCAP
int process_dump_dir() {
	if (!dump_dir)
		dump_dir = getcwd(NULL, 0);

	struct stat dirstats;

	if (stat(dump_dir, &dirstats) == -1) {
		DEBUG_MSG(LOG_WARNING, "unable to stat %s: %s", dump_dir,
			  strerror(errno));
		return 0;
	}

	if (!S_ISDIR(dirstats.st_mode)) {
		DEBUG_MSG(LOG_ERR, "provided path %s is not a directory",
			  dump_dir);
		return 0;
	}

	if (access(dump_dir, W_OK | X_OK) == -1) {
		DEBUG_MSG(LOG_ERR, "insufficent permissions to access %s: %s",
			  dump_dir, strerror(errno));
		return 0;
	}

	/* ensure path contains terminating slash */
	if (dump_dir[strlen(dump_dir) - 1] != '/')
		asprintf_append(&dump_dir, "/");

	return 1;
}
#endif /* HAVE_LIBPCAP */

/**
 * Parse command line options to initialize global options.
 *
 * @param[in] argc number of command line arguments
 * @param[in] argv arguments provided by the command line
 */
static void parse_cmdline(int argc, char *argv[])
{
	const struct ap_Option options[] = {
		{'b', 0, ap_yes, 0, 0},
		{'c', 0, ap_yes, 0, 0},
#ifdef DEBUG
		{'d', "debug", ap_no, 0, 0},
#else /* DEBUG */
		{'d', 0, ap_no, 0, 0},
#endif
		{'h', "help", ap_no, 0, 0},
		{'o', 0, ap_yes, 0, 0},
		{'p', 0, ap_yes, 0, 0},
		{'v', "version", ap_no, 0, 0},
#ifdef HAVE_LIBPCAP
		{'w', 0, ap_yes, 0, 0},
#endif /* HAVE_LIBPCAP */
		{0, 0, ap_no, 0, 0}
	};

	if (!ap_init(&parser, argc, (const char* const*) argv, options, 0))
		critx("could not allocate memory for option parser");
	if (ap_error(&parser))
		PARSE_ERR("%s", ap_error(&parser));

	/* parse command line */
	for (int argind = 0; argind < ap_arguments(&parser); argind++) {
		const int code = ap_code(&parser, argind);
		const char *arg = ap_argument(&parser, argind);

		switch (code) {
		case 0:
			PARSE_ERR("invalid argument: %s", arg);
		case 'b':
			rpc_bind_addr = strdup(arg);
			if (sscanf(arg, "%s", rpc_bind_addr) != 1)
				PARSE_ERR("failed to parse bind address");
			break;
		case 'c':
			if (sscanf(arg, "%u", &core) != 1)
				PARSE_ERR("failed to parse CPU number");
			break;
		case 'd':
#ifdef DEBUG
			increase_debuglevel();
#endif /* DEBUG */
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'p':
			if (sscanf(arg, "%u", &port) != 1)
				PARSE_ERR("failed to parse port number");
			break;
#ifdef HAVE_LIBPCAP
		case 'w':
			dump_dir = strdup(arg);
			break;
#endif /* HAVE_LIBPCAP */
		case 'v':
			fprintf(stdout, "%s %s\%s\n%s\n\n%s\n", progname,
				FLOWGRIND_VERSION, FLOWGRIND_COPYRIGHT,
				FLOWGRIND_COPYING, FLOWGRIND_AUTHORS);
			exit(EXIT_SUCCESS);
			break;
		default:
			PARSE_ERR("uncaught option: %s", arg);
			break;
		}
	}

#ifdef HAVE_LIBPCAP
	if (!process_dump_dir()) {
		if (ap_is_used(&parser, 'w'))
			PARSE_ERR("the dump directory %s for tcpdumps does "
				  "either not exist or you have insufficient "
				  "permissions to write to it", dump_dir);
		else
			warnx("tcpdumping will not be available since you "
			      "don't have sufficient permissions to write to "
			      "%s", dump_dir);
	}
#endif /* HAVE_LIBPCAP */
}

static void sanity_check(void)
{
	if (core < 0) {
		errx("CPU binding failed. Given CPU ID is negative");
		exit(EXIT_FAILURE);
	}

	if (core > get_ncores(NCORE_CURRENT)) {
		errx("CPU binding failed. Given CPU ID is higher then "
		     "available CPU cores");
		exit(EXIT_FAILURE);
	}

	/* TODO more sanity checks... (e.g. if port is in valid range) */
}

/**
 * Gracefully tear down daemon
 */
static void tear_down_daemon(void)
{
	ap_free(&parser);
	close_logging();
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	/* Info about the xmlrpc server */
	struct fg_rpc_server server;

	/* Initialize sighandler */
	struct sigaction sa;
	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigemptyset (&sa.sa_mask);
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		crit("could not ignore SIGPIPE");
	if (sigaction (SIGHUP, &sa, NULL))
		critx("could not set handler for SIGUP");
	if (sigaction (SIGALRM, &sa, NULL))
		critx("could not set handler for SIGALRM");
	if (sigaction (SIGCHLD, &sa, NULL))
		critx("could not set handler for SIGCHLD");
	if (sigaction(SIGINT, &sa, NULL))
		critx("could not set handler for SIGINT");
	if (sigaction(SIGTERM, &sa, NULL))
		critx("could not set handler for SIGTERM");

	set_progname(argv[0]);
	parse_cmdline(argc, argv);
	sanity_check();

	/* Initialize logging */
	if (!ap_is_used(&parser, 'd'))
		init_logging(LOGGING_SYSLOG);
	else
		init_logging(LOGGING_STDERR);

	fg_list_init(&flows);

#ifdef HAVE_LIBPCAP
	fg_pcap_init();
#endif /* HAVE_LIBPCAP */

	init_rpc_server(&server, rpc_bind_addr, port);

	/* Push flowgrindd into the background */
	if (!ap_is_used(&parser, 'd')) {
		/* Need to call daemon() before creating the thread because
		 * it internally calls fork() which does not copy threads. */
		if (daemon(0, 0) == -1)
			crit("daemon() failed");
		logging(LOG_NOTICE, "flowgrindd daemonized");
	}

	if (ap_is_used(&parser, 'c'))
		bind_daemon_to_core();

	create_daemon_thread();

	/* This will block */
	run_rpc_server(&server);
	critx("control should never reach end of main()");
}
