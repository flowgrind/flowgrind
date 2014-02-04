/**
 * @file common.c
 * @brief Routines used by the Flowgrind Daemon and Controller
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "common.h"
#include "debug.h"

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

void error(enum error_levels level, int errnum, const char *message, ...)
{
	va_list ap;
	const char *err_prefix;
	const char *err_errnum;

	switch (level) {
	case ERR_WARNING:
		err_prefix = "warning";
		break;
	case ERR_ERROR:
	case ERR_CRIT:
		err_prefix = "error";
		break;
	default:
		err_prefix = "unknown error";
	}

	fprintf(stderr, "%s: %s: ", progname, err_prefix);

	va_start(ap, message);
	vfprintf(stderr, message, ap);
	va_end(ap);

	if (errnum) {
		err_errnum = strerror(errnum);
		if (!err_errnum)
			err_errnum = "unknown system error";
		fprintf (stderr, ": %s", err_errnum);
	}

	fprintf(stderr, "\n");
	fflush (stderr);

	if (level > ERR_ERROR)
		exit(EXIT_FAILURE);
}
