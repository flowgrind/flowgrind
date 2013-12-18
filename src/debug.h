/*
 * debug.h - Debugging routines for Flowgrind
 *
 * Copyright (C) Alexander Zimmermann <alexander.zimmermann@netapp.com>, 2013
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

void decrease_debuglevel(void);
void increase_debuglevel(void);

#ifdef DEBUG

#include <unistd.h>
#include <pthread.h>

unsigned int debug_level;

const char *debug_timestamp(void);

#define DEBUG_MSG(LVL, MSG, ...) \
	if (debug_level>=LVL) \
		fprintf(stderr, "%s %s:%d  [%d/%d] " MSG "\n", \
			debug_timestamp(), __FUNCTION__, __LINE__, getpid(), \
			(unsigned int)pthread_self()%USHRT_MAX, ##__VA_ARGS__);
#else /* DEBUG */

#define DEBUG_MSG(LVL, MSG, ...) do {} while(0)

#endif /* DEBUG */

#endif /* _DEBUG_H_ */
