/**
 * @file fg_socket.h
 * @brief Routines used to manipulate socket parameters for Flowgrind
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

#ifndef _FG_SOCKET_H_
#define _FG_SOCKET_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <netinet/tcp.h>
#include <sys/socket.h>

int set_congestion_control(int fd, const char *cc_alg);
int set_so_debug(int fd);
int set_keepalive(int fd, int how);
int set_nodelay(int fd);
int set_non_blocking (int fd);
int set_route_record(int fd);
int set_so_dscp(int fd, uint8_t);
int set_so_elcn(int fd, int val);
int set_so_lcd(int fd);
int set_tcp_mtcp(int fd);
int set_tcp_nodelay(int fd);
int set_dscp(int fd, int dscp);
int set_tcp_cork(int fd);
int toggle_tcp_cork(int fd);
int set_window_size(int, int);
int set_window_size_directed(int, int, int);

int set_ip_mtu_discover(int fd);
int get_pmtu(int fd);
int get_imtu(int fd);

const char *fg_nameinfo(const struct sockaddr *sa, socklen_t salen);
char sockaddr_compare(const struct sockaddr *a, const struct sockaddr *b);

int get_port(int fd);

#endif /* _FG_SOCKET_H_ */
