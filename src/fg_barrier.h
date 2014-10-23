/**
 * @file fg_barrier.h
 * @brief Missing pthread barrier implemenation for OS X
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010 Brent Priddy <brent.priddy@priddysoftware.com>
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

#ifndef _FG_BARRIER_H_
#define _FG_BARRIER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <pthread.h>

/** Barrier attribute object */
typedef int pthread_barrierattr_t;

/** Object for barrier synchronization */
typedef struct {
	/** Protect shared data structures from concurrent modifications */
	pthread_mutex_t mutex;
	/** Thread to suspend its execution until the condition is satisfied */
	pthread_cond_t cond;
	/** Required number of threads have to wait at the barrier */
	int count;
	/** Current number of threads waiting at the barrier */
	int tripCount;
} pthread_barrier_t;

/**
 *  Allocates resources required to use the barrier referenced by @p barrier
 *  and initializes the barrier with attributes referenced by @p attr. If @p
 *  attr is NULL, the default barrier attributes are used. 
 *
 * @param[in] barrier barrier that should be initialized
 * @param[in] attr NULL, or the attributes @p attr that @p barrier should use
 * @param[in] count number of threads that must call pthread_barrier_wait()
 * before any of them successfully returns. Value must be greater than zero
 * @return return 0 for success, or -1 for failure (in which case errno is set
 * appropriately)
 */
int pthread_barrier_init(pthread_barrier_t *barrier,
			 const pthread_barrierattr_t *attr, unsigned int count);
/**
 * Destroys the barrier referenced by @p barrier and releases any resources
 * used by the barrier. Subsequent use of the barrier is undefined until the
 * barrier is reinitialized by pthread_barrier_init()
 *
 * @param[in] barrier barrier that should be initialized
 * @return return 0 for success, or -1 for failure (in which case errno is set
 * appropriately)
 */
int pthread_barrier_destroy(pthread_barrier_t *barrier);

/**
 * Synchronizes participating threads at the barrier referenced by @p barrier.
 * The calling thread blocks until the required number of threads have called
 * pthread_barrier_wait(), specifying the @p barrier.
 *
 * @param[in] barrier barrier that should be initialized
 * @return return 0 for success, or -1 for failure (in which case errno is set
 * appropriately)
 */
int pthread_barrier_wait(pthread_barrier_t *barrier);

#endif /* _FG_BARRIER_H_ */
