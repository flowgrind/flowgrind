/**
 * @file fg_time.c
 * @brief Timing related routines used by Flowgrind
 */

/*
 * Copyright (C) 2013 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#ifdef __MACH__
#include <mach/mach_time.h>
#endif

#include "fg_error.h"
#include "fg_time.h"

const char *ctimespec_r(const struct timespec *tp, char *buf, size_t size)
{
	struct tm tm;

	/* Converts the calendar time to broken-down time representation,
	 * expressed relative to the user's specified timezone */
	tzset();
	localtime_r(&tp->tv_sec, &tm);

	/* Converts broken-down time representation into a string */
	size_t len = strftime(buf, size, "%F %T", &tm);

	/* Append nanoseconds to string */
	snprintf(buf+len, size-len, ".%09ld", tp->tv_nsec);

	return buf;
}

const char *ctimespec(const struct timespec *tp)
{
	static char buf[30];

	ctimespec_r(tp, buf, sizeof(buf));

	return buf;
}

double time_diff(const struct timespec *tp1, const struct timespec *tp2)
{
	return (double) (tp2->tv_sec - tp1->tv_sec)
		+ (double) (tp2->tv_nsec - tp1->tv_nsec) / NSEC_PER_SEC;
}

double time_diff_now(const struct timespec *tp)
{
	struct timespec now;

	gettime(&now);
	return (double) (now.tv_sec - tp->tv_sec)
		+ (double) (now.tv_nsec - tp->tv_nsec) / NSEC_PER_SEC;
}

bool time_is_after(const struct timespec *tp1, const struct timespec *tp2)
{
	if (tp1->tv_sec > tp2->tv_sec)
		return true;
	if (tp1->tv_sec < tp2->tv_sec)
		return false;
	return tp1->tv_nsec > tp2->tv_nsec;
}

bool normalize_tp(struct timespec *tp)
{
	bool normalized = true;

	while (tp->tv_nsec >= NSEC_PER_SEC) {
		tp->tv_nsec -= NSEC_PER_SEC;
		tp->tv_sec++;
		normalized = false;
	}
	while (tp->tv_nsec < 0) {
		tp->tv_nsec += NSEC_PER_SEC;
		tp->tv_sec--;
		normalized = false;
	}
	return normalized;
}

void time_add(struct timespec *tp, double seconds)
{
	tp->tv_sec += (time_t)seconds;
	tp->tv_nsec += (long)((seconds - (time_t)seconds) * NSEC_PER_SEC);
	normalize_tp(tp);
}

int gettime(struct timespec *tp)
{
#ifdef __MACH__
	static mach_timebase_info_data_t tb = {.numer = 0, .denom = 0};

	/* Find out clock resolution. Will only be retrieved on first call */
	if (!tb.numer && !tb.denom) {
		if (mach_timebase_info(&tb) != 0)
			err("unable to determine clock resolution");

		/* Clock resolution is lower than expected (1ns) */
		const double hz = tb.numer/tb.denom;
		if (hz != 1)
			warnx("low clock resolution: %lfns", hz);
	}

	/* Get wall-clock time */
	const uint64_t time = mach_absolute_time() * tb.numer / tb.denom;
	tp->tv_sec = time / NSEC_PER_SEC;
	tp->tv_nsec = time % NSEC_PER_SEC;

	return 0;
#else
	static struct timespec res = {.tv_sec = 0, .tv_nsec = 0};

	/* Find out clock resolution. Will only be retrieved on first call */
	if (!res.tv_sec && !res.tv_nsec) {
		if (clock_getres(CLOCK_REALTIME, &res) != 0)
			err("unable to determine clock resolution");

		/* Clock resolution is lower than expected (1ns) */
		if (res.tv_nsec != 1)
			warnx("low clock resolution: %ldns", res.tv_nsec);
	}

	/* Get wall-clock time */
	return clock_gettime(CLOCK_REALTIME, tp);
#endif
}
