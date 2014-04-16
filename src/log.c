/**
 * @file log.c
 * @brief Logging routines used by Flowgrind
 */

/*
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
#include <string.h>
#include <time.h>

#include "log.h"
#include "fg_error.h"

char timestr[20];
char *logstr = NULL;
int log_type = LOGTYPE_SYSLOG;

void logging_init (void)
{
	logstr = malloc(LOGGING_MAXLEN);
	if (logstr == NULL)
		critx("unable to allocate memory for logging string");

	switch (log_type) {
	case LOGTYPE_SYSLOG:
		openlog("flowgrind_daemon", LOG_NDELAY | LOG_CONS |
			LOG_PID, LOG_DAEMON);
		break;
	case LOGTYPE_STDERR:
		break;
	}
}

void logging_exit (void)
{
	switch (log_type) {
	case LOGTYPE_SYSLOG:
		closelog();
		break;
	case LOGTYPE_STDERR:
		break;
	}

	free(logstr);
}

void logging_log (int priority, const char *fmt, ...)
{
	int n;
	va_list ap;

	memset(logstr, 0, LOGGING_MAXLEN);

	va_start(ap, fmt);
	n = vsnprintf(logstr, LOGGING_MAXLEN, fmt, ap);
	va_end(ap);

	if (n > -1 && n < LOGGING_MAXLEN)
		logging_log_string(priority, logstr);
}

void logging_log_string (int priority, const char *s)
{
	switch (log_type) {
	case LOGTYPE_SYSLOG:
		syslog(priority, "%s", s);
		break;
	case LOGTYPE_STDERR:
		fprintf(stderr, "%s %s\n", logging_time(), s);
		fflush(stderr);
		break;
	}
}

char * logging_time(void)
{
	time_t tp;
	struct tm *loc = NULL;

	tp = time(NULL);
	loc = localtime(&tp);
	memset(&timestr, 0, sizeof(timestr));
	strftime(&timestr[0], sizeof(timestr), "%Y/%m/%d %H:%M:%S", loc);

	return &timestr[0];
}
