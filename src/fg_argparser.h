/**
 * @file fg_argparser.h
 * @brief Command line argument parser
 */

/*
 * Copyright (C) 2014 Felix Rietig <felix.rietig@rwth-aachen.de>
 * Copyright (C) 2006-2013 Antonio Diaz Diaz <antonio@gnu.org>
 *
 * This file is part of Flowgrind.  It is based on the POSIX/GNU
 * command line argument parser 'arg_parser' origninally written by
 * Antonio Diaz Diaz.
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

/*  _arg_parser reads the arguments in 'argv' and creates a number of
    option codes, option arguments and non-option arguments.

    In case of error, 'ap_error' returns a non-null pointer to an error
    message.

    'options' is an array of 'struct ap_Option' terminated by an element
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

#ifndef _ARG_PARSER_H_
#define _ARG_PARSER_H_

#include <stdbool.h>

/** Specifies whether a command line option needs an argument */
enum ap_Has_arg {
	/** Option without argument (flag) */
	ap_no = 0,
	/** Argument required */
	ap_yes,
	/** Optional Argument */
	ap_maybe
};

/** Defines a valid command line option */
struct ap_Option {
	/** Short option letter or code (code != 0) */
	int code;
	/** Long option name (maybe null) */
	char *name;
	/** Argument specifier */
	enum ap_Has_arg has_arg;
	/** User tag for distinction of options */
	int tag;
	/** 
	 * Null-terminated array of mutex IDs (greater zero) this option belongs to.
	 * If two options share a mutex ID, they exclude each other.
	 * If this pointer is set to zero, this means no mutex are defined for 
	 * this option
	 */	
	int *mutex;	
};

/** Holds a parsed command line option and its argument */
struct ap_Record {
	/** Observed opt string (maybe the long or the short version) */
	char *opt_string;
	/** Argument string (may be empty) */
	char *argument;
	/** Index of the option for internal use (e.g. mutex, tag) */	
	int option_index;
};

/** Internal state of the argument parser */
struct arg_parser {
	/** Pointer for user defined options */
	struct ap_Option *options;
	/** Container for parsed cmdline options */
	struct ap_Record *data;
	/** Contains errors encountered during parsing */
	char *error;
	/** Number of known options */
	int num_options;
	/** Number of parsed records */
	int data_size;
	/** Real size of the error string */
	int error_size;
	/** The number of defined mutex */	
	int num_mutex;
};

/** Contains the state of all mutex */
struct ap_Mutex_state {
	/** A table containing for each mutex the last seen option record */
	int *seen_records;
	/** The number of defined mutex */
	int num_mutex;
};

/**
 * Initialize the arg parser given command line options
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] argc number of command line arguments
 * @param[in] argv array of command line argument strings
 * @param[in] options defines the options to parse for
 * @param[in] in_order if set to true, arguments are stored in the order in
 * which they appear. If false, non-option arguments are stored after options
 */
bool ap_init(struct arg_parser *const ap,
	     const int argc, const char *const argv[],
	     const struct ap_Option options[], const char in_order);

/**
 * Free internal state of arg parser
 *
 * @param[in] ap pointer to arg parser state
 */
void ap_free(struct arg_parser *const ap);

/**
 * Get the string containing errors encountered during parsing. If no errors
 * occurred, this returns null.
 *
 * @param[in] ap pointer to arg parser state
 */
const char *ap_error(const struct arg_parser *const ap);

/**
 * Number of arguments parsed (may be different from argc)
 *
 * @param[in] ap pointer to arg parser state
 */
int ap_arguments(const struct arg_parser *const ap);

/**
 * Returns the code of a parsed option with given index. It returns 0 for
 * non-options
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
int ap_code(const struct arg_parser *const ap, const int i);

/**
 * Returns the argument of a parsed option. If the corresponding code returned
 * by ap_code() is 0, it returns the non-option.
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const char *ap_argument(const struct arg_parser *const ap, const int i);

/**
 * Returns a pointer to the #_ap_Option struct of the parsed option as defined
 * during ap_init()
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const struct ap_Option *ap_option(const struct arg_parser *const ap, const int i);

/**
 * Returns the real command line option string (may be the short or long version)
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] i index of the parsed option
 */
const char *ap_opt_string(const struct arg_parser *const ap, const int i);

/**
 * Returns true if the option specified by @p code was given at least once
 *
 * @param[in] ap pointer to arg parser state
 * @param[in] code code of the option to check
 */
bool ap_is_used(const struct arg_parser *const ap, int code);

/**
* Initialize a new mutex state table. This can be seen as a separate context for checking mutex.
* Thus, by initializing more than one mutex state, mutual exclusions of options may be evaluated
* in independent contexts.
*
* @param[in] ap pointer to arg parser state
* @param[in] ms pointer to a new mutex context. It can be used in the following
* to check and set mutex
* @return true iff successful.
*/
bool ap_init_mutex_state(const struct arg_parser *const ap, 
			 struct ap_Mutex_state *const ms);

/**
* Check a new option record for mutex.
*
* @param[in] ap pointer to arg parser state
* @param[in] ms pointer to an initialized mutex context
* @param[in] i index of the option to check for previous occurrences of mutexed
* options
* @param[in] conflict pointer to a single integer value. This will contain the conflicting
* record position, iff a conflict has been found.
* @return true iff conflict according to the state given by @p ms has occurred.
*/
bool ap_check_mutex(const struct arg_parser *const ap,
		    const struct ap_Mutex_state *const ms,
		    const int i, int *conflict);

/**
* Register an option record in a mutex context.
*
* @param[in] ap pointer to arg parser state
* @param[in] ms pointer to an initialized mutex context
* @param[in] i index of the option to register in the mutex state @p ms
* @return true iff successful.
*/
bool ap_set_mutex(const struct arg_parser *const ap, 
		  struct ap_Mutex_state *const ms, const int i);

/**
* Check a new option record for mutex and register it at the same time.
*
* @param[in] ap pointer to arg parser state
* @param[in] ms pointer to an initialized mutex context
* @param[in] i index of the option to register in the mutex state @p ms
* @param[in] conflict pointer to a single integer value. This will contain the conflicting
* record position, iff a conflict has been found.
* @return true iff conflict according to the state given by @p ms has occurred.
*/
bool ap_set_check_mutex(const struct arg_parser *const ap, 
			struct ap_Mutex_state *const ms,
			const int i, int *conflict);

/**
* Reset a mutex context.
*
* @param[in] ms pointer to an initialized mutex context
*/
void ap_reset_mutex(struct ap_Mutex_state *const ms);

/**
* Free a mutex context.
*
* @param[in] ms pointer to an initialized mutex context
*/
void ap_free_mutex_state(struct ap_Mutex_state *const ms);

#endif /* _ARG_PARSER_H_ */
