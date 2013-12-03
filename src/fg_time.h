/*
 * fg_time.h - Timing related routines used by Flowgrind
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

#ifndef _FG_TIME_H_
#define _FG_TIME_H_

#include <sys/time.h>

double time_diff(const struct timeval *, const struct timeval *);
double time_diff_now(const struct timeval *tv1);
void time_add(struct timeval *tv, double seconds);

void tv2ntp(const struct timeval *tv, char *);
void ntp2tv(struct timeval *tv, const char *);
const char * ctime_us_r(struct timeval *tv, char *buf);
const char * ctime_us(struct timeval *tv);
const char * debug_timestamp(void);
int normalize_tv(struct timeval *);
int time_is_after(const struct timeval *, const struct timeval *);

int tsc_gettimeofday(struct timeval *tv);
#endif /* _FG_TIME_H_ */
