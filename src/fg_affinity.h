/**
 * @file fg_affinity.h
 * @brief CPU affinity routines used by Flowgrind
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

#ifndef _FG_AFFINITY_H_
#define _FG_AFFINITY_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <pthread.h>

/** Query type for get_ncores()  */
enum ncore_query {
	/** Total number of processors configured */
	NCORE_CONFIG = 0,
	/** Processors available to the current process */
	NCORE_CURRENT
};

/**
 * Return either the total number of configured or available cores
 *
 * @param[in] query indicates if either the configured or available cores
 * should be be returned @see enum nproc_query
 * @return return number of processors on success, or -1 for failure
 */
int get_ncores(enum ncore_query query);

/**
 * Set CPU affinity of the thread @p thread to the core @p core 
 *
 * @param[in] thread thread ID
 * @param[in] core core to which thread @p thread will be bounded
 * @return return 0 for success, or -1 for failure
 */
int pthread_setaffinity(pthread_t thread, unsigned int core);

/**
 * Returns the CPU affinity of thread @p thread in the buffer pointed to by
 * @p core
 *
 * @param[in] thread thread ID
 * @param[out] core core to which thread @p thread is bounded 
 * @return return 0 for success, or -1 for failure
 */
int pthread_getaffinity(pthread_t thread, unsigned int *core);

#endif /* _FG_AFFINITY_H_ */
