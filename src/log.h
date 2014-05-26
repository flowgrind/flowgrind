/**
 * @file log.h
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

#ifndef _LOG_H_
#define _LOG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** Maximum length of logging string */
#define LOGGING_MAXLEN	255

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
