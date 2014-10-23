/**
 * @file fg_string.c
 * @brief Functions to manipulate strings used by Flowgrind
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "fg_string.h"
#include "fg_definitions.h"

/**
 * Append the duplication of string @p a of length @p alen to the given
 * string @p s at point @p slen
 *
 * @param[in] s destination string to append to
 * @param[in] slen length of string @p s
 * @param[in] a source string to be append
 * @param[in] alen length of string @p a
 */
static inline char *strlendup_append(char *s, size_t slen, const char *a,
				     size_t alen)
{
	char *ret = realloc(s, slen + alen + 1);
	if (unlikely(!ret))
		return NULL;

	/* append the string and the trailing \0 */
	memcpy(&ret[slen], a, alen);
	ret[slen+alen] = 0;

	return ret;
}

size_t fmtlen(const char *fmt, va_list ap)
{
	va_list ap2;
	char c;

	/* If the output of vsnprintf is truncated, its return value is the
	 * number of characters which would have been written to the string
	 * if enough space had been available */
	va_copy(ap2, ap);
	size_t length = vsnprintf(&c, 1, fmt, ap2);
	va_end(ap2);

	return length;
}

char *strdup_append(char *s, const char *a)
{
	if (unlikely(!s))
		return strdup(a);

	if (unlikely(!a))
		return s;

	return strlendup_append(s, strlen(s), a, strlen(a));
}

char *strndup_append(char *s, const char *a, size_t n)
{
	if (unlikely(!s))
		return strdup(a);

	if (unlikely(!a))
		return s;

	return strlendup_append(s, strlen(s), a, strnlen(a, n));
}

int asprintf_append(char **strp, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	size_t length = vasprintf_append(strp, fmt, ap);
	va_end(ap);

	return length;
}

int vasprintf_append(char **strp, const char *fmt, va_list ap)
{
	if (unlikely(!(*strp)))
		return vasprintf(strp, fmt, ap);

	size_t slen = strlen(*strp);
	size_t alen = fmtlen(fmt, ap);

	/* The format resulted in no characters being formatted */
	if (unlikely(alen == 0))
		return -1;

	char *new_strp = realloc(*strp, slen + alen + 1);
	if (unlikely(!(*new_strp)))
		return -1;

	*strp = new_strp;

	va_list ap2;
	va_copy(ap2, ap);
	size_t length = vsnprintf(*strp + slen, alen + 1, fmt, ap2);
	va_end(ap2);

	return length;
}
