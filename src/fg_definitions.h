/**
 * @file fg_definitions.h
 * @brief Common definitions used by the Flowgrind daemon, controller, and libs
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifndef _FG_DEFINITIONS_H_
#define _FG_DEFINITIONS_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** These macros gain us a few percent of speed @{ */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)			/** @} */

/** Suppress warning for unused argument */
#define UNUSED_ARGUMENT(x) (void)x

/** To determine the number of input arguments passed to a function call */
#define NARGS(...) (sizeof((int[]){__VA_ARGS__})/sizeof(int))

/** To vectorize an arbitrary function that takes any type of pointer */
#define FN_APPLY(type, fn, ...) do {				\
	void *stopper = (int[]){0};				\
	void **list = (type*[]){__VA_ARGS__, stopper};		\
	for (int i=0; list[i] != stopper; i++)			\
		fn(list[i]);					\
} while(0)

/** To free() an arbitrary number of variables */
#define free_all(...) FN_APPLY(void, free, __VA_ARGS__);

/** Assign value if it less than current one */
#define ASSIGN_MIN(s, c)		\
	({ typeof (s) _s = (s);		\
	   typeof (c) _c = (c);		\
	   if (_s > _c) s = c; })

/** Assign value if it's greater than current one */
#define ASSIGN_MAX(s, c)		\
	({ typeof (s) _s = (s);		\
	   typeof (c) _c = (c);		\
	   if (_s < _c) s = c; })

#endif /* _FG_DEFINITIONS_H_*/
