/**
 * @file fg_gettime.h
 * @brief Missing clock_gettime implementation on OS X
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifndef _FG_GETTIME_H_
#define _FG_GETTIME_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <time.h>

#ifdef __DARWIN__

#include <mach/clock.h>

/** System-wide clock that measures real (i.e., wall-clock) time */
#define CLOCK_REALTIME CALENDAR_CLOCK
/** Monotonic time since some unspecified starting point */
#define CLOCK_MONOTONIC SYSTEM_CLOCK
/** High-resolution per-process timer from the CPU */
#define CLOCK_PROCESS_CPUTIME_ID SYSTEM_CLOCK
/** Thread-specific CPU-time clock */
#define CLOCK_THREAD_CPUTIME_ID SYSTEM_CLOCK

/** Clock identifier */
typedef clock_id_t clockid_t;

/**
 * Finds the resolution (precision) of the specified clock @p clk_id, and, if
 * @p res is non-NULL, stores it in the struct timespec pointed to by @p res
 *
 * @param[in] clk_id clock on which to act
 * @param[out] res clock resolution (precision)
 * @return return 0 for success, or -1 for failure
 */
int clock_getres(clockid_t clk_id, struct timespec *res);

/**
 * Retrieve the time of the specified clock @p clk_id, and, if @p tp is
 * non-NULL, stores it in the struct timespec pointed to by @p tp
 *
 * @param[in] clk_id clock on which to act
 * @param[out] tp current time in seconds and nanoseconds
 * @return return 0 for success, or -1 for failure
 */
int clock_gettime(clockid_t clk_id, struct timespec *tp);

#endif /* __DARWIN__ */

#endif /* _FG_TIME_H_ */
