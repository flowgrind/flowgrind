/**
 * @file fg_argparser.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "fg_definitions.h"
#include "fg_argparser.h"

/**
 * Assure at least a minimum size for buffer @p buf
 *
 * @param[in] buf pointer to buffer
 * @param[in] min_size minimum size @p buf should hold in bytes
 * @return pointer to the newly allocated buffer
 */
static void *ap_resize_buffer(void *buf, const int min_size)
{
	if (buf)
		buf = realloc(buf, min_size);
	else
		buf = malloc(min_size);
	return buf;
}

/**
 * Store a parsed option in the state of the arg-parser given by @p ap
 *
 * @param[in] ap pointer to the arg-parser state
 * @param[in] option_index index of the option to store
 * @param[in] long_opt true if this option was a long option
 * @param[in] argument argument string for this option (may be empty)
 * @return return true for success, or false for failure
 */
static bool push_back_record(struct arg_parser *const ap, const int option_index,
			     bool long_opt, const char *const argument)
{
	const int len = strlen(argument);
	struct ap_Record *p;
	void *tmp = ap_resize_buffer(ap->data,
				     (ap->data_size + 1) * sizeof(struct ap_Record));
	if (!tmp)
		return false;
	ap->data = (struct ap_Record *)tmp;
	p = &(ap->data[ap->data_size]);
	p->option_index = option_index;
	p->argument = 0;
	tmp = ap_resize_buffer(p->argument, len + 1);
	if (!tmp)
		return false;
	p->argument = (char *)tmp;
	strncpy(p->argument, argument, len + 1);

	if (long_opt) {
		if (!asprintf(&p->opt_string, "--%s", ap->options[option_index].name))
			return false;
	} else {
		if (!asprintf(&p->opt_string, "-%c", ap->options[option_index].code))
			return false;
	}

	++ap->data_size;
	return true;
}

/**
 * Add an error message to the arg-parser @p ap
 *
 * @param[in] ap pointer to the arg-parser state
 * @param[in] msg error string
 * @return return true for success, or false for failure
 */
static bool add_error(struct arg_parser *const ap, const char *const msg)
{
	const int len = strlen(msg);
	void *tmp = ap_resize_buffer(ap->error, ap->error_size + len + 1);
	if (!tmp)
		return false;
	ap->error = (char *)tmp;
	strncpy(ap->error + ap->error_size, msg, len + 1);
	ap->error_size += len;

	return true;
}

/**
 * Free all space required by the arg-parser @p ap
 *
 * @param[in] ap pointer to the arg-parser state
 */
static void free_data(struct arg_parser *const ap)
{
	for (int i = 0; i < ap->data_size; ++i) {
		free(ap->data[i].argument);
		free(ap->data[i].opt_string);
	}
	if (ap->data) {
		free(ap->data);
		ap->data = 0;
	}
	ap->data_size = 0;

	for (int i = 0; i < ap->num_options; ++i) {
		free(ap->options[i].name);
		free(ap->options[i].mutex);
	}
	free(ap->options);
	ap->num_options = 0;
}

/**
 * Parses a long option and adds it to the record of arg-parser @p ap
 *
 * @param[in] ap pointer to the arg-parser state
 * @param[in] opt long option string
 * @param[in] arg option argument string
 * @param[in] options array containing all defined options which may be parsed
 * @param[in] argindp pointer to the index in the command line argument array.
 * The value will be automatically updated
 * @return return true for success, or false for failure
 */
static bool parse_long_option(struct arg_parser *const ap,
			      const char *const opt, const char *const arg,
			      const struct ap_Option options[],
			      int *const argindp)
{
	unsigned len;
	int index = -1;
	char exact = 0, ambig = 0;

	for (len = 0; opt[len + 2] && opt[len + 2] != '='; ++len) ;

	/* Test all long options for either exact match or abbreviated matches. */
	for (int i = 0; options[i].code != 0; ++i)
		if (options[i].name
		    && strncmp(options[i].name, &opt[2], len) == 0) {
			/* Exact match found */
			if (strlen(options[i].name) == len) {
				index = i;
				exact = 1;
				break;
			/* First nonexact match found */
			} else if (index < 0) {
				index = i;
			/* Second or later nonexact match found */
			} else if (options[index].code != options[i].code ||
				 options[index].has_arg != options[i].has_arg) {
				ambig = 1;
			}
		}

	if (ambig && !exact) {
		add_error(ap, "option '");
		add_error(ap, opt);
		add_error(ap, "' is ambiguous");
		return true;
	}

	/* nothing found */
	if (index < 0) {
		add_error(ap, "unrecognized option '");
		add_error(ap, opt);
		add_error(ap, "'");
		return true;
	}

	++*argindp;

	/* '--<long_option>=<argument>' syntax */
	if (opt[len + 2]) {
		if (options[index].has_arg == ap_no) {
			add_error(ap, "option '--");
			add_error(ap, options[index].name);
			add_error(ap, "' doesn't allow an argument");
			return true;
		}
		if (options[index].has_arg == ap_yes && !opt[len + 3]) {
			add_error(ap, "option '--");
			add_error(ap, options[index].name);
			add_error(ap, "' requires an argument");
			return true;
		}
		return push_back_record(ap, index, true, &opt[len + 3]);
	}

	if (options[index].has_arg == ap_yes) {
		if (!arg || !arg[0]) {
			add_error(ap, "option '--");
			add_error(ap, options[index].name);
			add_error(ap, "' requires an argument");
			return true;
		}
		++*argindp;
		return push_back_record(ap, index, true, arg);
	}

	return push_back_record(ap, index, true, "");
}

/**
 * Parses a short option and adds it to the record of arg-parser @p ap
 *
 * @param[in] ap pointer to the arg-parser state
 * @param[in] opt long option string
 * @param[in] arg option argument string
 * @param[in] options array containing all defined options which may be parsed
 * @param[in] argindp pointer to the index in the command line argument array.
 * The value will be automatically updated
 * @return return true for success, or false for failure
 */
static bool parse_short_option(struct arg_parser *const ap,
			       const char *const opt, const char *const arg,
			       const struct ap_Option options[],
			       int *const argindp)
{
	int cind = 1;	/* character index in opt */

	while (cind > 0) {
		int index = -1;
		const unsigned char code = opt[cind];
		char code_str[2];
		code_str[0] = code;
		code_str[1] = 0;

		if (code != 0)
			for (int i = 0; options[i].code; ++i)
				if (code == options[i].code) {
					index = i;
					break;
				}

		if (index < 0) {
			add_error(ap, "invalid option -- ");
			add_error(ap, code_str);
			return true;
		}

		/* opt finished */
		if (opt[++cind] == 0) {
			++*argindp;
			cind = 0;
		}

		if (options[index].has_arg != ap_no && cind > 0 && opt[cind]) {
			if (!push_back_record(ap, index, false, &opt[cind]))
				return false;
			++*argindp;
			cind = 0;
		} else if (options[index].has_arg == ap_yes) {
			if (!arg || !arg[0]) {
				add_error(ap, "option requires an argument -- ");
				add_error(ap, code_str);
				return true;
			}
			++*argindp;
			cind = 0;
			if (!push_back_record(ap, index, false, arg))
				return false;
		} else if (!push_back_record(ap, index, false, "")) {
			return false;
		}
	}

	return true;
}

/**
 * Extracts number of options in @p options. This is done by counting all
 * options until an option with code 0 is found
 *
 * @param[in] options array of user-defined options
 * @return number of options in @p options
 */
static int get_num_options(const struct ap_Option options[])
{
	int i;
	for (i=0; options[i].code; i++){}
	return i;
}

/**
 * Get the number of mutex in the option definitions. This is done by searching
 * for the greatest mutex ID in all options
 *
 * @param[in] options array of user-defined options
 * @return number of mutex in the option definitions
 */
static int get_mutex_count(const struct ap_Option options[])
{
	int num = 0;

	for (int i=0; options[i].code; i++)
		for (int *mutex = options[i].mutex; mutex && *mutex; mutex++)
			ASSIGN_MAX(num, *mutex);

	return num;
}

/**
 * Copy @p options into the arg-parser @p ap. This is a deep copy including
 * strings and arrays
 *
 * @param[in] ap arg-parser
 * @param[in] options options struct to copy
 * @return return true for success, or false for failure
 */
static bool copy_options(struct arg_parser *const ap,
			 const struct ap_Option options[])
{

	ap->num_options = get_num_options(options);
	if (!ap->num_options)
		return false;
	ap->options = malloc(sizeof(struct ap_Option)*ap->num_options);
	if (!ap->options)
		return false;

	for (int i=0; i < ap->num_options; i++) {
		ap->options[i] = options[i];
		if (options[i].name)
			ap->options[i].name = strdup(options[i].name);

		if (options[i].mutex) {
			/* get number of mutex items */
			int num;
			for (num = 0; options[i].mutex[num]; num++);

			/* now copy into new array */
			ap->options[i].mutex = malloc(sizeof(int)*
						(num+1));
			if (!ap->options[i].mutex)
				return false;
			for (int e=0; e<=num; e++)
				ap->options[i].mutex[e] = options[i].mutex[e];
		}
	}
	return true;
}

bool ap_init(struct arg_parser *const ap,
	     const int argc, const char *const argv[],
	     const struct ap_Option options[], const char in_order)
{
	const char **non_options = 0;	/* skipped non-options */
	int non_options_size = 0;	/* number of skipped non-options */
	int argind = 1;			/* index in argv */

	if (!copy_options(ap,options))
		return false;

	ap->num_mutex = get_mutex_count(options);

	ap->data = 0;
	ap->error = 0;
	ap->data_size = 0;
	ap->error_size = 0;
	if (argc < 2 || !argv || !options)
		return true;

	while (argind < argc) {
		const unsigned char ch1 = argv[argind][0];
		const unsigned char ch2 = (ch1 ? argv[argind][1] : 0);

		if (ch1 == '-' && ch2) {	/* we found an option */
			const char *const opt = argv[argind];
			const char *const arg =
			    (argind + 1 < argc) ? argv[argind + 1] : 0;
			if (ch2 == '-') {
				if (!argv[argind][2]) {
					++argind;	/* we found "--" */
					break;
				} else {
				    if (!parse_long_option
					(ap, opt, arg, options, &argind))
					return false;
				}
			} else {
			    if (!parse_short_option
				(ap, opt, arg, options, &argind))
				return false;
			}
			if (ap->error)
				break;
		} else {
			if (!in_order) {
				void *tmp = ap_resize_buffer(non_options, (non_options_size + 1) *
							     sizeof *non_options);
				if (!tmp)
					return false;
				non_options = (const char **)tmp;
				non_options[non_options_size++] = argv[argind++];
			} else if (!push_back_record(ap, ap->num_options, false, argv[argind++])) {
				return false;
			}
		}
	}

	if (ap->error) {
		free_data(ap);
	} else {
		for (int i = 0; i < non_options_size; ++i)
			if (!push_back_record(ap, ap->num_options, false, non_options[i]))
				return false;
		while (argind < argc)
			if (!push_back_record(ap, ap->num_options, false, argv[argind++]))
				return false;
	}

	if (non_options)
		free(non_options);
	return true;
}

void ap_free(struct arg_parser *const ap)
{
	free_data(ap);
	if (ap->error) {
		free(ap->error);
		ap->error = 0;
	}
	ap->error_size = 0;
}

const char *ap_error(const struct arg_parser *const ap)
{
	return ap->error;
}

int ap_arguments(const struct arg_parser *const ap)
{
	return ap->data_size;
}

int ap_code(const struct arg_parser *const ap, const int i)
{
	if (i >= 0 && i < ap_arguments(ap)) {
		int index = ap->data[i].option_index;
		return ap->options[index].code;
	} else {
		return false;
	}
}

const char *ap_argument(const struct arg_parser *const ap, const int i)
{
	if (i >= 0 && i < ap_arguments(ap))
		return ap->data[i].argument;
	else
		return "";
}

const char *ap_opt_string(const struct arg_parser *const ap, const int i)
{
	if (i >= 0 && i < ap_arguments(ap))
		return ap->data[i].opt_string;
	else
		return "";
}

const struct ap_Option *ap_option(const struct arg_parser *const ap,
				   const int i)
{
	if (i >= 0 && i < ap_arguments(ap))
		return &ap->options[ap->data[i].option_index];
	else
		return false;
}

bool ap_is_used(const struct arg_parser *const ap, int code)
{
	bool ret = false;

	for (int i=0; i < ap->data_size; i++)
		if (ap_code(ap, i) == code) {
			ret = true;
			break;
		}

	return ret;
}

bool ap_init_mutex_state(const struct arg_parser *const ap,
			 struct ap_Mutex_state *const ms)
{
	ms->seen_records = malloc(sizeof(int)*ap->num_mutex);
	if(!ap->num_mutex || !ms->seen_records)
		return false;
	memset(ms->seen_records,0,sizeof(int)*ap->num_mutex);
	ms->num_mutex = ap->num_mutex;
	return true;
}

bool ap_check_mutex(const struct arg_parser *const ap,
		    const struct ap_Mutex_state *const ms,
		    const int i, int *conflict)
{
	if(ap->num_mutex != ms->num_mutex)
		return false;

	*conflict = 0;

	if (i < 0 || i >= ap_arguments(ap) || !ap->num_mutex)
		return false;

	int index = ap->data[i].option_index;
	for (int *mutex = ap->options[index].mutex; mutex && *mutex; mutex++) {
		if (ms->seen_records[*mutex-1]) {
			*conflict = ms->seen_records[*mutex-1]-1;
			if (ap->data[*conflict].option_index != index)
				return true;
			else
				*conflict = 0;
		}
	}

	return false;
}

bool ap_set_mutex(const struct arg_parser *const ap,
		  struct ap_Mutex_state *const ms, const int i)
{
	if(ap->num_mutex != ms->num_mutex)
		return false;

	if (i < 0 || i >= ap_arguments(ap) || !ap->num_mutex)
		return false;

	int index = ap->data[i].option_index;
	for (int *mutex = ap->options[index].mutex; mutex && *mutex; mutex++)
		ms->seen_records[*mutex-1] = i+1;

	return true;
}

bool ap_set_check_mutex(const struct arg_parser *const ap,
			struct ap_Mutex_state *const ms, const int i,
			int *conflict)
{
	bool ret = ap_check_mutex(ap, ms, i, conflict);
	ap_set_mutex(ap, ms, i);
	return ret;
}

void ap_reset_mutex(struct ap_Mutex_state *const ms)
{
	memset(ms->seen_records,0,sizeof(int)*ms->num_mutex);
}

void ap_free_mutex_state(struct ap_Mutex_state *const ms)
{
	if (ms->seen_records) {
		free(ms->seen_records);
		ms->seen_records = 0;
		ms->num_mutex = 0;
	}
}

/* Parse RPC address for the xmlrpc control connection */
void parse_rpc_address(char** rpc_address, int* port, bool* is_ipv6)
{
	char* sepptr = 0;

	/* 1st case: IPv6 with port, e.g. "[a:b::c]:5999"  */
	if ((sepptr = strchr(*rpc_address, ']'))) {
		*is_ipv6 = true;
		*sepptr = '\0';
		if (*rpc_address[0] == '[')
			(*rpc_address)++;
		sepptr++;
		if (sepptr != '\0' && *sepptr == ':')
			sepptr++;
		*port = atoi(sepptr);
	} else if ((sepptr = strchr(*rpc_address, ':'))) {
		/* 2nd case: IPv6 without port, e.g. "a:b::c"  */
		if (strchr(sepptr+1, ':')) {
			*is_ipv6 = true;
		} else {
		/* 3rd case: IPv4 or name with port 1.2.3.4:5999 */
			*sepptr = '\0';
			sepptr++;
			if ((*sepptr != '\0') && (*sepptr == ':'))
					sepptr++;
			*port = atoi(sepptr);
		}
	}
}
