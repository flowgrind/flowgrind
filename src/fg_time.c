/**
 * @file fg_time.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "fg_time.h"

/*
 * Converts timespec struct into a null-terminated string of the form
 * '2013-12-09 12:00:48.34369902' and stores the string in a user-supplied
 * buffer which should have room for at least 30 bytes
 */
const char *ctimespec_r(const struct timespec *tp, char *buf, size_t size)
{
        size_t len = 0;
        struct tm tm;

	/*
	 * Converts the calendar time to broken-down time representation,
	 * expressed relative to the user's specified timezone
	 */
        tzset();
        localtime_r(&tp->tv_sec, &tm);

	/* Converts broken-down time representation into a string */
        len = strftime(buf, size, "%F %T", &tm);

        /* Append nanoseconds to string */
        snprintf(buf+len, size-len, ".%09ld", tp->tv_nsec);

        return buf;
}

/*
 * Converts timespec struct into a null-terminated string of the form
 * '2013-12-09 12:00:48.34369902' and return the string
 */
const char *ctimespec(const struct timespec *tp)
{
        static char buf[30];

        ctimespec_r(tp, buf, sizeof(buf));

        return buf;
}

/*
 * Return time difference in nanoseconds between the two given times.
 * Negative if time tp1 is greater then tp2
 */
double time_diff(const struct timespec *tp1, const struct timespec *tp2)
{
	return (double) (tp2->tv_sec - tp1->tv_sec)
		+ (double) (tp2->tv_nsec - tp1->tv_nsec) / NSEC_PER_SEC;
}

/*
 * Return time difference in nanoseconds between the current time and
 * the given time
 */
double time_diff_now(const struct timespec *tp)
{
	struct timespec now;

	gettime(&now);
	return (double) (now.tv_sec - tp->tv_sec)
		+ (double) (now.tv_nsec - tp->tv_nsec) / NSEC_PER_SEC;
}

/*
 * Returns 1 (true) if time represented by tp1 is greater then tp2
 */
int time_is_after(const struct timespec *tp1, const struct timespec *tp2)
{
	if (tp1->tv_sec > tp2->tv_sec)
		return 1;
	if (tp1->tv_sec < tp2->tv_sec)
		return 0;
	return tp1->tv_nsec > tp2->tv_nsec;
}

/*
 * Make sure 0 <= tv.tv_nsec < NSEC_PER_SEC. Return 0 if it was already
 * normalized, positive number otherwise
 */
int normalize_tp(struct timespec *tp)
{
	int result = 0;

	while (tp->tv_nsec >= NSEC_PER_SEC) {
		tp->tv_nsec -= NSEC_PER_SEC;
		tp->tv_sec++;
		result++;
	}
	while (tp->tv_nsec < 0) {
		tp->tv_nsec += NSEC_PER_SEC;
		tp->tv_sec--;
		result++;
	}
	return result;
}

/*
 * Add given the seconds to the given time
 */
void time_add(struct timespec *tp, double seconds)
{
	tp->tv_sec += (time_t)seconds;
	tp->tv_nsec += (long)((seconds - (time_t)seconds) * NSEC_PER_SEC);
	normalize_tp(tp);
}

/*
 * Get time from 'REALTIME' clock. A system-wide clock  that measures real
 * time. This clock is affected by discontinuous jumps in the system time
 * (e.g., if admin manually changes the clock), and by the incremental
 * adjustments performed by NTP. The clock's time represents seconds and
 * nanoseconds since the Epoch
 */
int gettime(struct timespec *tp)
{
	if (clock_gettime(CLOCK_REALTIME, tp) != 0)
		error(ERR_FATAL, "clock_gettime() failed: %s", strerror(errno));
	return 0;
}
