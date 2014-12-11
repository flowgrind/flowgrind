/**
 * @file log.h
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

#ifndef _LOG_H_
#define _LOG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** Supported output streams for logging. */
enum log_types {
	/** Log to syslog. */
	LOGGING_SYSLOG = 0,
	/** Log to stderr. */
	LOGGING_STDERR,
	/** Log to stdout. */
	LOGGING_STDOUT,
};

/** To which output stream we log */
extern enum log_types log_type;

/**
 * Open logging stream.
 */
void init_logging(void);

/**
 * Close logging stream.
 */
void close_logging(void);

/**
 * Submit log message @p fmt to logging stream.
 *
 * @param[in] priority priority code of log message
 * @param[in] fmt format string
 * @param[in] ... parameters used to fill fmt
 */
void logging(int priority, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * Submit log message @p fmt to logging stream.
 *
 * @param[in] priority priority code of log message
 * @param[in] fmt format string
 * @param[in] ap parameters used to fill fmt
 */
void vlogging(int priority, const char *fmt, va_list ap)
	__attribute__((format(printf, 2, 0)));

#endif /* _LOG_H_ */
