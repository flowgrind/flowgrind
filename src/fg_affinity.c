/**
 * @file fg_affinity.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP */

#ifdef HAVE_SYS_CPUSET_H 
#include <sys/param.h>
#include <sys/cpuset.h>
#endif /* HAVE_SYS_CPUSET */

/* OS X hasn't defined pthread_[set|get]affinity_np */
#if !defined(HAVE_PTHREAD_AFFINITY_NP) && defined HAVE_THREAD_POLICY
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif /* !defined(HAVE_PTHREAD_AFFINITY_NP) && defined HAVE_THREAD_POLICY */

#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include "fg_affinity.h"

#if (!(HAVE_CPU_SET_T) && HAVE_CPUSET_T)
/** FreeBSD defines cpuset_t instead of cpu_set_t. Note kFreeBSD defines both */
typedef cpuset_t cpu_set_t;
#endif /* HAVE_CPUSET_T */

int get_ncores(enum ncore_query query)
{
	switch (query) {
	case NCORE_CONFIG:
		/* processors configured */
		return (int)sysconf(_SC_NPROCESSORS_CONF);
		break;
	case NCORE_CURRENT:
		/* processors available */
		return (int)sysconf(_SC_NPROCESSORS_ONLN);
		break;
	default:
		errno = EINVAL;
		return -1;
	}
}

/* Linux and FreeBSD have pthread_[set|get]affinity_np */
#if defined HAVE_PTHREAD_AFFINITY_NP
int pthread_setaffinity(pthread_t thread, unsigned int core)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	int rc = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	return (rc == 0 ? 0 : -1);
}

int pthread_getaffinity(pthread_t thread, unsigned int *core)
{
	cpu_set_t cpuset;
	int rc = pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (rc)
		return -1;

	/* If the cpuset contains only one CPU, then that's the answer. For
	 * all other cpuset contents, we treat the binding as unknown */
	core = NULL;
	bool core_found = false;
	for (unsigned int i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &cpuset)) {
			if (!core_found) {
				core_found = true;
				*core = i;
			} else {
				core_found = false;
				core = NULL;
				break;
			}
		}
	}

	return (core_found ? 0 : -1);
}
/* OS X hasn't defined pthread_[set|get]affinity_np */
#elif defined HAVE_THREAD_POLICY
int pthread_setaffinity(pthread_t thread, unsigned int core)
{
	/* Convert pthread ID */
	mach_port_t mach_thread = pthread_mach_thread_np(thread);
	/* core + 1 to avoid using THREAD_AFFINITY_TAG_NULL */
	thread_affinity_policy_data_t policy = { core + 1 };

	kern_return_t rc = thread_policy_set(mach_thread,
					     THREAD_AFFINITY_POLICY,
					     (thread_policy_t) &policy,
					     THREAD_AFFINITY_POLICY_COUNT);

	return (rc == KERN_SUCCESS ? 0 : -1);
}

int pthread_getaffinity(pthread_t thread, unsigned int *core)
{
	/* Convert pthread ID */
	mach_port_t mach_thread = pthread_mach_thread_np(thread);
	thread_affinity_policy_data_t policy;
	mach_msg_type_number_t count = THREAD_AFFINITY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	kern_return_t rc = thread_policy_get(mach_thread,
					     THREAD_AFFINITY_POLICY,
					     (thread_policy_t) &policy, &count,
					     &get_default);
	*core = (unsigned int)policy.affinity_tag;

	return (rc == KERN_SUCCESS ? 0 : -1);
}
#endif /* HAVE_PTHREAD_AFFINITY_NP */
