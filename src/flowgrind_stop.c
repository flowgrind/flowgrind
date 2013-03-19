/*
 * flowgrind_stop.c - Utility to instruct the Flowgrind daemon to stop all flows
 *
 * Copyright (C) Christian Samsel <christian.samsel@rwth-aachen.de>, 2010-2013
 * Copyright (C) Tim Kosse <tim.kosse@gmx.de>, 2009
 * Copyright (C) Daniel Schaffrath <daniel.schaffrath@mac.com>, 2007-2008
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#include "common.h"

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

/* Program name. Can get updated from argv[0] in parse_cmdline */
static char progname[50] = "flowgrind-stop";

void usage()
{
	printf(
		"Usage: %1$s <address list>\n"
		"       %1$s -h|-v\n\n"
		"This program stops all flows on the daemons running at the given addresses.\n\n"
		"Options: -h This help\n"
		"         -v Print version number and exit\n\n"
		"Example:\n"
		"   %1$s localhost 127.2.3.4:5999 example.com\n",
		progname);

	exit(1);
}

void stop_flows(char* address)
{
	xmlrpc_env env;
	xmlrpc_client *client = 0;
	xmlrpc_value * resultP = 0;
	char* p;
	int port = DEFAULT_LISTEN_PORT;
	char host[1000], url[1000];

	if (strlen(address) > sizeof(url) - 50) {
		fprintf(stderr, "Address too long: %s\n", address);
		return;
	}

	/* Construct canonical address and URL */
	strncpy(host, address, 1000);

	p = strchr(host, ':');
	if (p) {
		if (p == host) {
			fprintf(stderr, "Error, no address given: %s\n", address);
			return;
		}
		port = atoi(p + 1);
		if (port < 1 || port > 65535) {
			fprintf(stderr, "Error, invalid port given: %s\n", address);
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
		fprintf(stderr, "Could not stop flows on %s: %s (%d)\n",
			host, env.fault_string, env.fault_code);
	}
	if (client)
		xmlrpc_client_destroy(client);
	xmlrpc_env_clean(&env);

}

int main(int argc, char *argv[])
{
	char ch, *tok;
	int i;
	xmlrpc_env rpc_env;

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

#ifdef HAVE_GETOPT_LONG
	/* getopt_long isn't portable, it's GNU extension */
	struct option lo[] = {  {"help", 0, 0, 'h' },
							{"version", 0, 0, 'v'},
							{0, 0, 0, 0}
				};
	while ((ch = getopt_long(argc, argv, "hv", lo, 0)) != -1) {
#else
	while ((ch = getopt(argc, argv, "hv")) != -1) {
#endif
		switch (ch) {
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				fprintf(stderr, "flowgrind version: %s\n", FLOWGRIND_VERSION);
				exit(0);
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	xmlrpc_env_init(&rpc_env);
	xmlrpc_client_setup_global_const(&rpc_env);

	for (i = optind; i < argc; i++) {
		stop_flows(argv[i]);
	}

	xmlrpc_env_clean(&rpc_env);

	xmlrpc_client_teardown_global_const();

	return 0;
}
