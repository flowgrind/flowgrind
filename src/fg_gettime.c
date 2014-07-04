/**
 * @file fg_gettime.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "fg_gettime.h"

#ifdef __DARWIN__

#include <mach/mach.h>

int clock_getres(clockid_t clk_id, struct timespec *res)
{
	kern_return_t retval = KERN_SUCCESS;
	clock_serv_t cclock;
	natural_t attribute[4];
	mach_msg_type_number_t count = sizeof(attribute)/sizeof(natural_t);

	host_get_clock_service(mach_host_self(), clk_id, &cclock);
	retval = clock_get_attributes(cclock, CLOCK_GET_TIME_RES,
				      (clock_attr_t) &attribute, &count);
	mach_port_deallocate(mach_task_self(), cclock);

	res->tv_nsec = attribute[0];

	return (retval == KERN_SUCCESS ? 0 : -1);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	kern_return_t retval = KERN_SUCCESS;
	clock_serv_t cclock;
	mach_timespec_t mts;

	host_get_clock_service(mach_host_self(), clk_id, &cclock);
	retval = clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);

	tp->tv_sec = mts.tv_sec;
	tp->tv_nsec = mts.tv_nsec;

	return (retval == KERN_SUCCESS ? 0 : -1);
}

#endif /* __DARWIN__ */
