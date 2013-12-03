/*
 * fg_log.h - Logging routines used by Flowgrind
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

#ifndef _LOG_H_
#define _LOG_H_

#define LOGGING_MAXLEN  255	/* maximum string length */

extern int log_type;

enum {
	LOGTYPE_SYSLOG,
	LOGTYPE_STDERR
};

void logging_init (void);
void logging_exit (void);
void logging_log (int priority, const char *fmt, ...);
void logging_log_string (int priority, const char *s);
char *logging_time(void);

#endif /* _LOG_H_ */
