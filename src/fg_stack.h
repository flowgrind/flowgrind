/**
 * @file fg_stack.h
 * @brief Generic stack implementation used by Flowgrind
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

#ifndef _FG_STACK_H_
#define _FG_STACK_H_

#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** Inital size of a stack */
#define INIT_STACK_SIZE 4

/** Generic stack type */
struct _stack {
	/** Content of the stack */
	void *elements;
	/** Size of one stack element */
	size_t element_size;
	/** Number of elements in the stack */
	unsigned int used;
	/** Number of elements allocated space for */
	unsigned int allocated;
};

/**
 * Initialize the given stack @p s by allocating memory for INIT_STACK_SIZE
 * elements
 *
 * @param[in,out] s generic stack
 * @param[in] element_size size of one stack element
 * @return return 0 for success, or -1 for failure
 */
int stack_init(struct _stack *s, size_t element_size);

/**
 * Frees all memory space associated with the given stack @p s
 *
 * Stack @p s may not be used again unless stack_init() is first called on
 * the stack again
 *
 * @param[in,out] s generic stack
 */
void stack_destroy(struct _stack *s);

/**
 * Test if the given stack @p s empty
 *
 * @param[in] s generic stack
 * @return return true is the stack @p s is empty, false otherwise
 */
bool stack_empty(const struct _stack *s)
	__attribute__((pure));

/**
 * Add element @p elem to the top of the stack @p s
 *
 * @param[in,out] s generic stack
 * @param[in] elem element to be added to the stack
 * @return return 0 for success, or -1 for failure
 */
int stack_push(struct _stack *s, const void *elem);

/**
 * Remove element @p elem from the top of the stack @p s
 *
 * @param[in,out] s generic stack
 * @param[out] elem removed element from the stack
 * @return return 0 for success, or -1 for failure
 */
int stack_pop(struct _stack *s, void *elem);

#endif /* _FG_STACK_H_ */
