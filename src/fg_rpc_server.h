/**
 * @file fg_rpc_server.h
 * @brief RPCServer related functions and structs used by the Flowgrind daemon
 */

/*
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

#ifndef _FG_RPC_SERVER_H_
#define _FG_RPC_SERVER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#include <xmlrpc-c/util.h>

/** Information about the daemons XMLrpc server */
struct fg_rpc_server
{
	/** Environment used by the Abyss Server */
	xmlrpc_env env;
	/** Parameters of the XMLrpc Server */
	xmlrpc_server_abyss_parms parms;
};


#endif /* _DAEMON_H_ */

/** Initializes the xmlrpc server.
  * This function initializes the xmlrpc environment, registers exported methods
  * and binds to the control port. */
void init_rpc_server(struct fg_rpc_server *server, char *rpc_bind_addr, unsigned int port);

/** Enters the xmlrpc server mainloop */
void run_rpc_server(struct fg_rpc_server *server);
