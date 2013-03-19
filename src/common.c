/*
 * common.c - Routines used by the Flowgrind Daemon and Controller
 *
 * Copyright (C) Christian Samsel <christian.samsel@rwth-aachen.de>, 2010-2013
 * Copyright (C) Tim Kosse <tim.kosse@gmx.de>, 2009
 * Copyright (C) Daniel Schaffrath <daniel.schaffrath@mac.com>, 2007-2008
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "debug.h"

void
error(int errcode, const char *fmt, ...)
{
	va_list ap;
	const char *prefix;
	int fatal = 1;
	static char error_string[1024];

	switch (errcode) {
	case ERR_FATAL:
		prefix = "fatal";
		break;
	case ERR_WARNING:
		prefix = "warning";
		fatal = 0;
		break;
	default:
		prefix = "(UNKNOWN ERROR TYPE)";
	}
	va_start(ap, fmt);
	vsnprintf(error_string, sizeof(error_string), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s: %s\n", prefix, error_string);
	if (fatal)
		exit(1);
}
