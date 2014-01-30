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
	if (argv0 == NULL) {
		fprintf(stderr, "A NULL argv[0] was passed through an exec "
			"system call.\n");
		exit(EXIT_FAILURE);
	}

	/* Strip path */
	const char *slash = strrchr(argv0, '/');
	const char *base = (slash != NULL ? slash + 1 : argv0);
	progname = base;
}

void error(enum error_type errcode, const char *fmt, ...)
{
	va_list ap;
	bool terminate = false;
	const char *prefix;
	static char error_string[1024];

	switch (errcode) {
	case ERR_FATAL:
		prefix = "fatal";
		terminate = true;
		break;
	case ERR_WARNING:
		prefix = "warning";
		break;
	default:
		prefix = "(UNKNOWN ERROR TYPE)";
	}
	va_start(ap, fmt);
	vsnprintf(error_string, sizeof(error_string), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s: %s\n", prefix, error_string);
	if (terminate)
		exit(EXIT_FAILURE);
}
