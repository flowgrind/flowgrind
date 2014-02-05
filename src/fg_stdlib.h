/**
 * @file fg_stdlib.h
 * @brief Routines used by the Flowgrind daemon, controller, and libs
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifndef _FG_STDLIB_H_
#define _FG_STDLIB_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** These macros gain us a few percent of speed @{ */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)			    /** @} */

/** Suppress warning for unused argument */
#define UNUSED_ARGUMENT(x) (void)x

/** To determine number of parameters */
#define NARGS(...) (sizeof((int[]){__VA_ARGS__})/sizeof(int))

/** Assign value if it less than current one */
#define ASSIGN_MIN(s, c)	    \
	({ typeof (s) _s = (s);	    \
	   typeof (c) _c = (c);	    \
	   if (_s > _c) s = c; })

/** Assign value if it's greater than current one */
#define ASSIGN_MAX(s, c)	    \
	({ typeof (s) _s = (s);	    \
	   typeof (c) _c = (c);	    \
	   if (_s < _c) s = c; })

#endif /* _FG_STDLIB_H_*/
