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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef DEBUG

#include <limits.h>
#include <pthread.h>

/**
 * Print debug message to standard error
 *
 * If the debug level is higher than the given debug level @p LVL, print debug
 * message @p MSG together with current time, the delta in time since the last
 * and first debug call, the function in which the debug call occurs, and the
 * process and thread PID
 */
#define DEBUG_MSG(LVL, MSG, ...) do {					       \
	if (debug_level >= LVL)						       \
		fprintf(stderr, "%s %s:%d  [%d/%d] " MSG "\n",		       \
			debug_timestamp(), __FUNCTION__, __LINE__, getpid(),   \
			(unsigned int)pthread_self()%USHRT_MAX, ##__VA_ARGS__);\
} while (0)

/** Global debug level for flowgrind controller and daemon */
unsigned int debug_level;

/** Decrease debug level */
void decrease_debuglevel(void);

/** Decrease debug level */
void increase_debuglevel(void);

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
