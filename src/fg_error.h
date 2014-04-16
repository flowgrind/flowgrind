/**
 * @file fg_error.h
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

#ifndef _FG_ERROR_H_
#define _FG_ERROR_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>

/** To report an critical error w/ the corresponding system error message */
#define crit(...) (error(ERR_CRIT, errno, __VA_ARGS__))
/** To report an critical error w/ the system error message 'code' */
#define critc(code, ...) (error(ERR_CRIT, code, __VA_ARGS__))
/** To report an critical error w/o a system error message */
#define critx(...) (error(ERR_CRIT, 0, __VA_ARGS__))

/** To report an error w/ the corresponding system error message */
#define err(...) (error(ERR_ERROR, errno, __VA_ARGS__))
/** To report an error w/ the system error message 'code' */
#define errc(code, ...) (error(ERR_ERROR, code, __VA_ARGS__))
/** To report an error w/o a system error message */
#define errx(...) (error(ERR_ERROR, 0, __VA_ARGS__))

/** To report a warning w/ the corresponding system error message */
#define warn(...) (error(ERR_WARNING, errno, __VA_ARGS__))
/** To report a warning w/ the system error message 'code' */
#define warnc(code, ...) (error(ERR_WARNING, code, __VA_ARGS__))
/** To report a warning w/ a system error message */
#define warnx(...) (error(ERR_WARNING, 0, __VA_ARGS__))

/** Error level, in order of increasing importance: */
enum error_levels {
	/** Warning conditions */
	ERR_WARNING = 0,
	/** Error conditions */
	ERR_ERROR,
	/** Critical conditions */
	ERR_CRIT,
};

/**
 * General error-reporting function
 *
 * It outputs to stderr the program name, a colon and a space, a fixed error
 * message based on the error level, and a second colon and a space followed
 * by the error message. If errnum is nonzero, a third colon and a
 * space followed by the string given by strerror(errnum) is printed
 *
 * @param[in] level error level. An error level higher then ERR_ERROR calls
 * exit() to terminate using given status
 * @param[in] errnum error number. If nonzero the corresponding system error
 * message is printed
 * @param[in] fmt error message in printf-style format with optional args
 */
void error(enum error_levels level, int errnum, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

#endif /* _FG_ERROR_H_ */
