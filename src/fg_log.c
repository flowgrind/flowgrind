/**
 * @file log.c
 * @brief Logging routines used by Flowgrind
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
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

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "fg_log.h"
#include "fg_time.h"
#include "fg_error.h"

static enum log_streams log_stream = LOG_SYSLOG;

void init_logging(enum log_streams stream)
{
	log_stream = stream;

	switch (log_stream) {
	case LOGGING_SYSLOG:
		openlog("flowgrindd", LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);
		break;
	case LOGGING_STDERR:
	case LOGGING_STDOUT:
		break;
	}
}

void close_logging(void)
{
	switch (log_stream) {
	case LOGGING_SYSLOG:
		closelog();
		break;
	case LOGGING_STDERR:
	case LOGGING_STDOUT:
		break;
	}
}

void logging(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlogging(priority, fmt, ap);
	va_end(ap);
}

void vlogging(int priority, const char *fmt, va_list ap)
{
	char timestamp[30] = "";
	ctimenow_r(timestamp, sizeof(timestamp), false);

	switch (log_stream) {
	case LOGGING_SYSLOG:
		vsyslog(priority, fmt, ap);
		break;
	case LOGGING_STDERR:
		fprintf(stderr, "%s ", timestamp);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
		break;
	case LOGGING_STDOUT:
		fprintf(stdout, "%s ", timestamp);
		vfprintf(stdout, fmt, ap);
		fprintf(stdout, "\n");
		fflush(stdout);
		break;
	}

}
