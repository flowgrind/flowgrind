/**
 * @file fg_stack.c
 * @brief Generic stack implementation used by Flowgrind
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 *
 * This file is part of Flowgrind. Flowgrind is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2 as published by the Free Software Foundation.
 *
 * Flowgrind distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef DEBUG
#include <assert.h>
#endif /* DEBUG */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "fg_stack.h"
#include "fg_stdlib.h"

int stack_init(struct _stack *s, size_t element_size)
{
#ifdef DEBUG
	assert(element_size > 0);
#endif /* DEBUG */

	s->element_size = element_size;
	s->used = 0;
	s->allocated = INIT_STACK_SIZE;
	s->elements = malloc(INIT_STACK_SIZE * element_size);

	if (unlikely(!s->elements))
		return -1;

	return 0;
}

void stack_destroy(struct _stack *s)
{
	free(s->elements);
}

bool stack_empty(const struct _stack *s)
{
	return (s->used == 0);
}

int stack_push(struct _stack *s, const void *elem)
{
	/* Stack is full, we need to realloc() */
	if (s->used == s->allocated) {
		s->allocated *= 2;
		s->elements = realloc(s->elements,
				      s->allocated * s->element_size);
		if (unlikely(!s->elements))
			return -1;
	}

	void *dst = (void *)s->elements + s->used * s->element_size;
	memcpy(dst, elem, s->element_size);
	s->used++;

	return 0;
}

int stack_pop(struct _stack *s, void *elem)
{
	if (unlikely(stack_empty(s)))
		return -1;

	/* Note: for the sake of convenience we do not reallocate the array to
	 * be smaller, even if we dip below some 50% saturation value. In
	 * practice, it depends on the realloc implementation if a request to
	 * shrink an array is immediately processed or not */

	s->used--;
	void *src = (void *)s->elements + s->used * s->element_size;
	memcpy(elem, src, s->element_size);

	return 0;
}
