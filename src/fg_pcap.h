/*
 * fg_pcap.h - Package capture support for the Flowgrind Daemon
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

#include "daemon.h"
#include <pcap.h>
#include <pthread.h>

void fg_pcap_init();
void fg_pcap_go(struct _flow *);
void fg_pcap_cleanup(void* arg);

pthread_mutex_t pcap_mutex;

/* pthread barrier does not exists in Darwin */
#ifndef __DARWIN__
pthread_barrier_t pcap_barrier;
#endif /* __DARWIN__ */

pcap_if_t * alldevs;
