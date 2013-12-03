/*
 * debug.h - Debugging routines for Flowgrind
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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

void decrease_debuglevel();
void increase_debuglevel();

#ifdef DEBUG

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

unsigned debug_level;

const char *debug_timestamp(void);

#define DEBUG_MSG(message_level, msg, args...) \
		if (debug_level>=message_level) { \
			fprintf(stderr, "%s %s:%d  [%d/%d] " msg "\n", \
					debug_timestamp(), __FUNCTION__, \
					__LINE__, getpid(), \
					(unsigned int)pthread_self()%USHRT_MAX, ##args); \
		}
#else
#define DEBUG_MSG(message_level, msg, args...) do {} while(0)
#endif /* DEBUG */

#endif /* _DEBUG_H_ */
