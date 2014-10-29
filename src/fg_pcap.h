/**
 * @file fg_pcap.h
 * @brief Packet capture support for the Flowgrind daemon
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

#ifndef _FG_PCAP_H_
#define _FG_PCAP_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <pcap.h>
#include <pthread.h>

#include "daemon.h"

/**
 * Initialize flowgrind's pcap library.
 * 
 * This method fills internal structures on which other methods of this library
 * depend.  It is therefore crucial to call it before any call to other methods
 * of this library.
 */
void fg_pcap_init(void);

/**
 * Start a tcpdump to capture traffic of the provided flow.
 * 
 * If the flow was not configured for tcp dumping or dumping is already in
 * progress the method will do nothing and return immediately. Otherwise the
 * method blocks until the actual capturing starts. In case an error occurs a
 * log message is created.
 *
 * @param[in] flow the flow whose traffic should be captured
 */
void fg_pcap_go(struct flow *flow);

#endif /* _FG_PCAP_H_ */
