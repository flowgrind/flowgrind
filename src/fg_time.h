/**
 * @file fg_time.h
 * @brief Timing related routines used by Flowgrind
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
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

#ifndef _FG_TIME_H_
#define _FG_TIME_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/time.h>
#include <time.h>
#include <stdbool.h>

#ifndef NSEC_PER_SEC
/** Number of nanoseconds per second */
#define NSEC_PER_SEC	1000000000L
#endif /* NSEC_PER_SEC */

/**
 * Converts timespec struct @p tp into a null-terminated string and stores the
 * string in a user-supplied buffer @p buf
 *
 * @param[in] tp point in time
 * @param[out] buf buffer with room for at least 30 bytes
 * @param[in] size size of the buffer
 * @return string of the form '2013-12-09 12:00:48.34369902'
 */
const char *ctimespec_r(const struct timespec *tp, char *buf, size_t size);

/**
 * Converts timespec struct @p tp into a null-terminated string
 *
 * @param[in] tp point in time
 * @return string of the form '2013-12-09 12:00:48.34369902'
 */
const char *ctimespec(const struct timespec *tp);

/**
 * Returns the time difference between two the specific points in time @p tp1
 * and @p tp2
 *
 * Negative if the first point in time is chronologically after the second one
 *
 * @param[in] tp1 point in time
 * @param[in] tp2 point in time
 * @return time difference in nanoseconds
 */
double time_diff(const struct timespec *tp1, const struct timespec *tp2);

/**
 * Returns time difference between now and the specific point in time @p tp
 *
 * @param[in] tp point in time
 * @return time difference in nanoseconds
 */
double time_diff_now(const struct timespec *tp);

/**
 * Returns true if second point in time @p tp2 is chronologically after the
 * first point in time @p tp1
 *
 * @param[in] tp1 point in time
 * @param[in] tp2 point in time
 * @return true or false
 */
bool time_is_after(const struct timespec *tp1, const struct timespec *tp2);

/**
 * Normalizes timespec struct @p tp
 *
 * Ensures that the equation 0 <= tp->tv_nsec < NSEC_PER_SEC holds, meaning
 * that the amount of nanoseconds is not negative less than one second
 *
 * @param[in,out] tp point in time
 * @return true if timespec struct was already normalized, otherwise false
 */
bool normalize_tp(struct timespec *tp);

/**
 * Add an amount of time @p seconds to a specific point in time @p tp
 *
 * @param[in,out] tp point in time
 * @param[in] seconds amount of time in seconds
 */
void time_add(struct timespec *tp, double seconds);

/**
 * Returns the current wall-clock time with nanosecond precision
 *
 * Since the returned time is retrieved from a system-wide clock that measures
 * real time, the time is may be affected by discontinuous jumps in the system
 * time (e.g., if admin manually changes the clock), and by the incremental
 * adjustments performed by NTP.
 *
 * @param[out] tp current time in seconds and nanoseconds since the Epoch
 * @return return 0 for success, or -1 for failure
 */
int gettime(struct timespec *tp);

#endif /* _FG_TIME_H_ */
