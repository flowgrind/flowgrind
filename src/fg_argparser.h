/**
 * @file fg_argparser.h
 * @brief Commandline argument parser
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Arnd Hannemann <arnd@arndnet.de>
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

/*  _arg_parser - POSIX/GNU command line argument parser. (C version)
    Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013
    Antonio Diaz Diaz.

    This library is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this library.  If not, see <http://www.gnu.org/licenses/>.

    As a special exception, you may use this file as part of a free
    software library without restriction.  Specifically, if other files
    instantiate templates or use macros or inline functions from this
    file, or you compile this file and link it with other files to
    produce an executable, this file does not by itself cause the
    resulting executable to be covered by the GNU General Public
    License.  This exception does not however invalidate any other
    reasons why the executable file might be covered by the GNU General
    Public License.
*/

/*  _arg_parser reads the arguments in 'argv' and creates a number of
    option codes, option arguments and non-option arguments.

    In case of error, 'ap_error' returns a non-null pointer to an error
    message.

    'options' is an array of 'struct _ap_Option' terminated by an element
    containing a code which is zero. A null name means a short-only
    option. A code value outside the unsigned char range means a
    long-only option.

    _arg_parser normally makes it appear as if all the option arguments
    were specified before all the non-option arguments for the purposes
    of parsing, even if the user of your program intermixed option and
    non-option arguments. If you want the arguments in the exact order
    the user typed them, call 'ap_init' with 'in_order' = true.

    The argument '--' terminates all options; any following arguments are
    treated as non-option arguments, even if they begin with a hyphen.

    The syntax for optional option arguments is '-<short_option><argument>'
    (without whitespace), or '--<long_option>=<argument>'.
*/

#ifndef _CARG_PARSER_H_
#define _CARG_PARSER_H_

#include <stdbool.h>

/** Specifies whether a cmdline option needs an argument */
enum ap_Has_arg {
	/** Option without argument (flag) */
	ap_no = 0,
	/** Argument required */
	ap_yes, 
	/** Optional Argument */
	ap_maybe
};

/** Defines a valid cmdline option */
struct _ap_Option {
	/** Short option letter or code ( code != 0 ) */
	int code;
	/** Long option name (maybe null) */
	const char *name;
	/** Argument specifier */
	enum ap_Has_arg has_arg;
	/** A user tag for distinction of options */
	int tag;
};

/** Holds a parsed cmdline option and its argument */
struct _ap_Record {
	/** backpointer to option */
	const struct _ap_Option *option;
	/** the observed opt string (maybe the long or the short version) */
	char *opt_string;
	/** The argument string (may be empty) */
	char *argument;
};

/** The internal state of the argument parser */
struct _arg_parser {
	/** Container for parsed cmdline options */
	struct _ap_Record *data;
	/** Contains errors encountered during parsing */
	char *error;
	/** Number of parsed records */
	int data_size;
	/** The real size of the error string */
	int error_size;
};

/**
 * Initialize the arg parser given commandline options
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] argc number of cmdline arguments
 * @param[in] argv array of cmdline argument strings
 * @param[in] options defines the options to parse for
 * @param[in] in_order if set to true, arguments are stored in the order in which 
 * 		they appear. If false, non-option arguments are stored after options.
 */
char ap_init(struct _arg_parser *const ap,
	     const int argc, const char *const argv[],
	     const struct _ap_Option options[], const char in_order);

/**
 * Free internal state of arg parser
 *
 * @param[in] ap pointer to arg parser state
 */
void ap_free(struct _arg_parser *const ap);

/**
 * Get the string containing errors encountered during parsing. If no errors occured,
 * this returns null.
 *
 * @param[in] ap pointer to arg parser state
 */
const char *ap_error(const struct _arg_parser *const ap);

/**
 * The number of arguments parsed (may be different from argc)
 *
 * @param[in] ap pointer to arg parser state
 */
int ap_arguments(const struct _arg_parser *const ap);

/**
 * Returns the code of a parsed option with given index. It returns 0 for non-options.
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
int ap_code(const struct _arg_parser *const ap, const int i);

/**
 * Returns the argument of a parsed option. If the corresponding code returned 
 * by ap_code() is 0, it returns the non-option.
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const char *ap_argument(const struct _arg_parser *const ap, const int i);

/**
 * Returns a pointer to the #_ap_Option struct of the parsed option as defined 
 * during ap_init()
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const struct _ap_Option *ap_option(const struct _arg_parser *const ap, const int i);

/**
 * Returns the real cmdline option string (may be the short or long version)
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const char *ap_opt_string(const struct _arg_parser *const ap, const int i);

/**
 * Returns true iff the option specified by \p code was given at least once
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] code code of the option to check
 */
bool ap_is_used(const struct _arg_parser *const ap, int code);

#endif
