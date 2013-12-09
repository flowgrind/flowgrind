/*
 * fg_time.h - Timing related routines used by Flowgrind
 *
 * Copyright (C) Alexander Zimmermann <alexander.zimmermann@netapp.com>, 2013
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
#include <time.h>

const char *ctimespec_r(const struct timespec *tp, char *buf, unsigned int len);
const char *ctimespec(const struct timespec *tp);

double time_diff(const struct timespec *tp1, const struct timespec *tp2);
double time_diff_now(const struct timespec *tp);

void time_add(struct timespec *tp, double seconds);
int time_is_after(const struct timespec *tp1, const struct timespec *tp2);

int normalize_tp(struct timespec *tp);
int gettime(struct timespec *tp);
#endif /* _FG_TIME_H_ */
