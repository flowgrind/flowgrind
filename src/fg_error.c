/**
 * @file fg_error.c
 * @brief Error-reporting routines used by Flowgrind
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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "fg_progname.h"
#include "fg_error.h"

void error(enum error_levels level, int errnum, const char *fmt, ...)
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

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
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
