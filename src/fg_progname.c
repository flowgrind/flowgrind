/**
 * @file fg_progname.c
 * @brief Program name management
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com
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

#include <string.h>

#include "fg_progname.h"
#include "fg_error.h"

const char *progname = NULL;

void set_progname(const char *argv0)
{
	/* Sanity check. POSIX requires the invoking process to pass a non-NULL
	 * argv[0] */
	if (argv0 == NULL)
		errx("a NULL argv[0] was passed through an exec system call");

	/* Strip path */
	const char *slash = strrchr(argv0, '/');
	const char *base = (slash != NULL ? slash + 1 : argv0);
	progname = base;
}
