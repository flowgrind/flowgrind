/**
 * @file debug.c
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

#include "debug.h"

#ifdef DEBUG

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <time.h>
#include <string.h>

#include "fg_time.h"

inline void decrease_debuglevel()
{
	debug_level--;
	printf("DEBUG_LEVEL=%u", debug_level);
}

inline void increase_debuglevel()
{
	debug_level++;
	printf("DEBUG_LEVEL=%u\n", debug_level);
}

const char *debug_timestamp()
{
	struct timespec now = {.tv_sec = 0, .tv_nsec = 0};
	static struct timespec first = {.tv_sec = 0, .tv_nsec = 0};
	static struct timespec last = {.tv_sec = 0, .tv_nsec = 0};
	static char buf[80];

	gettime(&now);

	if (!first.tv_sec && !first.tv_nsec)
		last = first = now;

	ctimespec_r(&now, buf, sizeof(buf));
	snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf),
		 " [+%8.6lf] (%8.6lf)",
		 time_diff(&last, &now), time_diff(&first, &now));

	last = now;
	return buf;
}

#endif /* DEBUG */
