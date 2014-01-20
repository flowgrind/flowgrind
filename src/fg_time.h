/**
 * @file fg_time.h
 * @brief Timing related routines used by Flowgrind
 */

/*
 * Copyright (C) 2013 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
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

#ifndef _FG_TIME_H_
#define _FG_TIME_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/time.h>
#include <time.h>
#include <stdbool.h>

/** Number of nanoseconds per second */
#define NSEC_PER_SEC	1000000000L

/**
 * Converts timespec struct into a null-terminated string and stores the string
 * in a user-supplied buffer
 *
 * @param[in] tp point in time
 * @param[out] buf buffer with room for at least 30 bytes
 * @param[in] size size of the buffer
 * @return string of the form '2013-12-09 12:00:48.34369902'
 */
const char *ctimespec_r(const struct timespec *tp, char *buf, size_t size);

/**
 * Converts timespec struct into a null-terminated string
 *
 * @param[in] tp point in time
 * @return string of the form '2013-12-09 12:00:48.34369902'
 */
const char *ctimespec(const struct timespec *tp);

/**
 * Returns the time difference between two specific points in time
 *
 * Negative if the first point in time is chronologically after the second one
 *
 * @param[in] tp1 point in time
 * @param[in] tp2 point in time
 * @return time difference in nanoseconds
 */
double time_diff(const struct timespec *tp1, const struct timespec *tp2);

/**
 * Returns time difference between now and a specific point in time
 *
 * @param[in] tp point in time
 * @return time difference in nanoseconds
 */
double time_diff_now(const struct timespec *tp);

/**
 * Returns true if second point in time is chronologically after the first one
 *
 * @param[in] tp1 point in time
 * @param[in] tp2 point in time
 * @return true or false
 */
bool time_is_after(const struct timespec *tp1, const struct timespec *tp2);

/**
 * Normalizes timespec struct
 *
 * Ensures that the equation 0 <= tp->tv_nsec < NSEC_PER_SEC holds, meaning
 * that the amount of nanoseconds is not negative less than one second
 *
 * @param[in,out] tp point in time
 * @return true if timespec struct was already normalized, otherwise false
 */
bool normalize_tp(struct timespec *tp);

/**
 * Add an amount of time to a specific point in time
 *
 * @param[in,out] tp point in time
 * @param[in] seconds amount of time in seconds
 */
void time_add(struct timespec *tp, double seconds);

/**
 * Returns wall-clock time with nanosecond precision
 *
 * Get time from 'REALTIME' clock. A system-wide clock that measures real
 * time. This clock is affected by discontinuous jumps in the system time
 * (e.g., if admin manually changes the clock), and by the incremental
 * adjustments performed by NTP. The clock's time represents seconds and
 * nanoseconds since the Epoch
 *
 * @param[out] tp current time in seconds and nanoseconds since the Epoch
 * @return clock resolution
 */
int gettime(struct timespec *tp);

#endif /* _FG_TIME_H_ */
