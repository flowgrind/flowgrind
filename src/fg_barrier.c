/**
 * @file fg_barrier.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <pthread.h>
#include <errno.h>

#include "fg_definitions.h"
#include "fg_barrier.h"

int pthread_barrier_init(pthread_barrier_t *barrier,
			 const pthread_barrierattr_t *attr, unsigned int count)
{
	if (unlikely(!barrier) || unlikely(count == 0)) {
		errno = EINVAL;
		return -1;
	}

	if (attr && (*attr != PTHREAD_PROCESS_PRIVATE)) {
		errno = EINVAL;
		return -1;
	}

	if (pthread_mutex_init(&barrier->mutex, NULL) != 0)
		return -1;

	if (pthread_cond_init(&barrier->cond, NULL) != 0) {
		pthread_mutex_destroy(&barrier->mutex);
		return -1;
	}

	barrier->tripCount = count;
	barrier->count = 0;

	return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	if (unlikely(!barrier)) {
		errno = EINVAL;
		return -1;
	}

	if (pthread_cond_destroy(&barrier->cond) != 0)
		return -1;

	if (pthread_mutex_destroy(&barrier->mutex) != 0)
		return -1;

	return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	if (unlikely(!barrier)) {
		errno = EINVAL;
		return -1;
	}

	if (pthread_mutex_lock(&barrier->mutex) !=0)
		return -1;
	++(barrier->count);

	/* No remaining pthreads, broadcast to wake all waiting threads */
	if (barrier->count >= barrier->tripCount) {
		barrier->count = 0;
		pthread_cond_broadcast(&barrier->cond);
	} else {
		pthread_cond_wait(&barrier->cond, &(barrier->mutex));
	}

	pthread_mutex_unlock(&barrier->mutex);

	return 0;
}
