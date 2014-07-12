/**
 * @file flowgrind_stop.c
 * @brief Utility to instruct the Flowgrind daemon to stop all flows
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* xmlrpc-c */
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

#include "common.h"
#include "fg_error.h"
#include "fg_progname.h"
#include "fg_argparser.h"

/* External global variables */
extern const char *progname;

/* Forward declarations */
static void usage(short status) __attribute__((noreturn));

/**
 * Print flowgrind-stop usage and exit
 */
static void usage(short status)
{
	/* Syntax error. Emit 'try help' to stderr and exit */
	if (status != EXIT_SUCCESS) {
		fprintf(stderr, "Try '%s -h' for more information\n", progname);
		exit(status);
	}

	fprintf(stderr,
		"Usage: %1$s [OPTION]... [ADDRESS]...\n"
		"Stop all flows on the daemons running at the given addresses.\n\n"

		"Mandatory arguments to long options are mandatory for short options too.\n"
		"  -h, --help     display this help and exit\n"
		"  -v, --version  print version information and exit\n\n"

		"Example:\n"
		"   %1$s localhost 127.2.3.4:5999 example.com\n",
		progname);
	exit(EXIT_SUCCESS);
}

static void stop_flows(const char* address)
{
	xmlrpc_env env;
	xmlrpc_client *client = 0;
	xmlrpc_value * resultP = 0;
	char* p;
	int port = DEFAULT_LISTEN_PORT;
	char host[1000], url[1000];

	if (strlen(address) > sizeof(url) - 50) {
		errx("address too long: %s", address);
		return;
	}

	/* Construct canonical address and URL */
	strncpy(host, address, 1000);

	p = strchr(host, ':');
	if (p) {
		if (p == host) {
			errx("no address given: %s", address);
			return;
		}
		port = atoi(p + 1);
		if (port < 1 || port > 65535) {
			errx("invalid port given: %s", address);
			return;
		}
		*p = 0;
	}
	sprintf(url, "http://%s:%d/RPC2", host, port);
	sprintf(host, "%s:%d", host, port);

	printf("Stopping all flows on %s\n", host);

	/* Stop the flows */
	xmlrpc_env_init(&env);
	xmlrpc_client_create(&env, XMLRPC_CLIENT_NO_FLAGS, "Flowgrind", FLOWGRIND_VERSION, NULL, 0, &client);
	if (env.fault_occurred)
		goto cleanup;

	xmlrpc_client_call2f(&env, client, url, "stop_flow", &resultP,
		"({s:i})", "flow_id", -1); /* -1 stops all flows */
	if (resultP)
		xmlrpc_DECREF(resultP);

cleanup:
	if (env.fault_occurred) {
		warnx("could not stop flows on %s: %s (%d)",
		      host, env.fault_string, env.fault_code);
	}
	if (client)
		xmlrpc_client_destroy(client);
	xmlrpc_env_clean(&env);

}

int main(int argc, char *argv[])
{
	/* update progname from argv[0] */
	set_progname(argv[0]);

	const struct _ap_Option options[] = {
		{'h', "help", ap_no, 0, 0},
		{'v', "version", ap_no, 0, 0},
		{0, 0, ap_no, 0, 0}
	};
	struct _arg_parser parser;

	if (!ap_init(&parser, argc, (const char* const*) argv, options, 0))
		critx("could not allocate memory for option parser");
	if (ap_error(&parser)) {
		errx("%s", ap_error(&parser));
		usage(EXIT_FAILURE);
	}

	/* parse command line */
	for (int argind = 0; argind < ap_arguments(&parser); argind++) {
		const int code = ap_code(&parser, argind);

		switch (code) {
		case 0:
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'v':
			fprintf(stderr, "%s %s\n%s\n%s\n\n%s\n", progname,
				FLOWGRIND_VERSION, FLOWGRIND_COPYRIGHT,
				FLOWGRIND_COPYING, FLOWGRIND_AUTHORS);
			exit(EXIT_SUCCESS);
			break;
		default:
			errx("uncaught option: %s", ap_argument(&parser, argind));
			usage(EXIT_FAILURE);
			break;
		}
	}

	xmlrpc_env rpc_env;
	xmlrpc_env_init(&rpc_env);
	xmlrpc_client_setup_global_const(&rpc_env);

	for (int argind = 0; argind < ap_arguments(&parser); argind++)
		/* if non-option, it is an address */
		if (!ap_code(&parser, argind))
			stop_flows(ap_argument(&parser, argind));

	xmlrpc_env_clean(&rpc_env);
	xmlrpc_client_teardown_global_const();
	ap_free(&parser);
}
