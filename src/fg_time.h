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

#include <sys/time.h>
#include <time.h>

#define NSEC_PER_SEC	1000000000L

const char *ctimespec_r(const struct timespec *tp, char *buf, size_t size);
const char *ctimespec(const struct timespec *tp);

double time_diff(const struct timespec *tp1, const struct timespec *tp2);
double time_diff_now(const struct timespec *tp);

int time_is_after(const struct timespec *tp1, const struct timespec *tp2);

int normalize_tp(struct timespec *tp);
void time_add(struct timespec *tp, double seconds);

int gettime(struct timespec *tp);
#endif /* _FG_TIME_H_ */
