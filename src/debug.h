/**
 * @file debug.h
 * @brief Debugging routines for Flowgrind controller and daemon
 */

/*
 * Copyright (C) 2013 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
 *
 * This file is part of Flowgrind. Flowgrind is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2 as published by the Free Software Foundation.
 *
 * Flowgrind distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** Decrease debug level */
void decrease_debuglevel(void);

/** Decrease debug level */
void increase_debuglevel(void);

#ifdef DEBUG

#include <unistd.h>
#include <pthread.h>

/**
 * Print debug message to standard error
 *
 * In case the debug level is higher than the given debug level, print debug
 * message together with current time, the delta in time since the last and
 * first debug call, the function in which the debug call occurs, and the
 * process and thread PID
 */
#define DEBUG_MSG(LVL, MSG, ...)					     \
	if (debug_level >= LVL)						     \
		fprintf(stderr, "%s %s:%d  [%d/%d] " MSG "\n",		     \
			debug_timestamp(), __FUNCTION__, __LINE__, getpid(), \
			(unsigned int)pthread_self()%USHRT_MAX, ##__VA_ARGS__);

/** Global debug level for flowgrind controller and daemon */
unsigned int debug_level;

/**
 * Helper function for DEBUG_MSG macro
 *
 * @return string with the current time in seconds and nanoseconds since the
 * Epoch together with the delta in time since the last and first function call
 */
const char *debug_timestamp(void);

#else /* DEBUG */

#define DEBUG_MSG(LVL, MSG, ...) do {} while(0)

#endif /* DEBUG */

#endif /* _DEBUG_H_ */
