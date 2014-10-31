/**
 * @file fg_rpc_client.h
 * @brief RPC related functions used by the Flowgrind controller flowgrind-stop
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

#ifndef _FG_RPC_CLIENT_H_
#define _FG_RPC_CLIENT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdbool.h>

/**
 * Parse RPC address for the xmlrpc control connection
 *
 * @param[in,out] rpc_address string in format CONTROL[:PORT]. It will be
 * truncated to CONTROL
 * @param[out] port port if the control address @p rpc_address contains a port
 * @param[out] is_ipv6 true if control address @p rpc_address is a numerical
 */
void parse_rpc_address(char **rpc_address, int *port, bool *is_ipv6);

#endif /* _FG_RPC_CLIENT_H_ */
