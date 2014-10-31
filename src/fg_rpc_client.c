/**
 * @file fg_rpc_server.c
 * @brief Flowgrindd rpcserver implementation
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2014 Arnd Hannemann <arnd@arndnet.de>
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
#include <stdbool.h>
#include <string.h>

#include "fg_rpc_client.h"

void parse_rpc_address(char **rpc_address, int *port, bool *is_ipv6)
{
        char* sepptr = 0;

        /* 1st case: IPv6 with port, e.g. "[a:b::c]:5999"  */
        if ((sepptr = strchr(*rpc_address, ']'))) {
                *is_ipv6 = true;
                *sepptr = '\0';
                if (*rpc_address[0] == '[')
                        (*rpc_address)++;
                sepptr++;
                if (sepptr != '\0' && *sepptr == ':')
                        sepptr++;
                *port = atoi(sepptr);
        } else if ((sepptr = strchr(*rpc_address, ':'))) {
                /* 2nd case: IPv6 without port, e.g. "a:b::c"  */
                if (strchr(sepptr+1, ':')) {
                        *is_ipv6 = true;
                } else {
                /* 3rd case: IPv4 or name with port 1.2.3.4:5999 */
                        *sepptr = '\0';
                        sepptr++;
                        if ((*sepptr != '\0') && (*sepptr == ':'))
                                sepptr++;
                        *port = atoi(sepptr);
                }
        }
}
