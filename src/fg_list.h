/**
 * @file fg_list.h
 * @brief Generic doubly linked list implementation
 */

/*
* Copyright (C) 2014 Marcel Nehring <marcel.nehring@rwth-aachen.de>
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
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Flowgrind. If not, see <http://www.gnu.org/licenses/>.
*
*/

#ifndef _FG_LIST_H_
#define _FG_LIST_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stddef.h>

/** Single element in a doubly linked list */
struct list_node {
	/** Pointer to user defined data stored with this node */
	void* data;
	/** Pointer to the previous node in the list. NULL if head of the list */
	struct list_node* next;
	/** Pointer to the next node in the list. NULL if tail of the list */
	struct list_node* previous;
};

/** A doubly linked list */
struct linked_list {
	/** Pointer to the first element in the list. NULL if the list is empty */
	struct list_node* head;
	/** Pointer to the last element in the list. NULL if the list is empty */
	struct list_node* tail;
	/** Size of the list i.e. the number of elements stored in the list */
	size_t size;
};

/**
 * Initializes the list by setting its head and tail to NULL and its size to 0
 *
 * @param[in] list list to initialize
 * @return zero on success, non-zero otherwise
 */
int fg_list_init(struct linked_list * const list);

/**
 * Returns the first element of the list The element is not removed from the list
 *
 * @param[in] list to operate on
 * @return a pointer to the first element in @p list
 */
const struct list_node* fg_list_front(struct linked_list * const list);

/**
 * Returns the last element of the list. The element is not removed from the list
 *
 * @param[in] list to operate on
 * @return a pointer to the last element in @p list
 */
const struct list_node* fg_list_back(struct linked_list * const list);

/**
 * Removes from the list the first element whose data points to @p data reducing
 * the list size by one. The data contained in this element will not be modified
 *
 * @param[in] list to operate on
 * @param[in] data of the element to be removed
 * @return zero on success, non-zero otherwise
 */
int fg_list_remove(struct linked_list * const list, const void * const data);

/**
 * Inserts a new element at the beginning of the list, right before its current
 * first element. The data of the new element will point to the same memory
 * location as @p data. This effectively increases the list's size by one
 *
 * @param[in] list to operate on
 * @param[in] data of inserted element
 * @return zero on success, non-zero otherwise
 */
int fg_list_push_front(struct linked_list * const list, void * const data);

/**
 * Removes the first element in the list, effectively reducing its size by one.
 * This destroys the removed element. The data contained in this element will
 * not be modified
 *
 * @param[in] list to operate on
 * @return pointer to the data that was contained in the removed element, NULL
 * on failure
 */
void* fg_list_pop_front(struct linked_list * const list);

/**
 * Inserts a new element at the end of the list, right after its current last
 * element. The data of the new element will point to the same memory location
 * as @p data. This effectively increases the list's size by one
 *
 * @param[in] list to operate on
 * @param[in] data of inserted element
 * @return zero on success, non-zero otherwise
 */
int fg_list_push_back(struct linked_list * const list, void * const data);

/**
 * Removes the last element in the list, effectively reducing its size by one.
 * This destroys the removed element. The data contained in this element will
 * not be modified
 *
 * @param[in] list to operate on
 * @return pointer to the data that was contained in the removed element, NULL
 * on failure
 */
void* fg_list_pop_back(struct linked_list * const list);

/**
 * Returns the number of elements in the list
 *
 * @param[in] list to operate on
 * @return the number of elements in the list.
 */
size_t fg_list_size(struct linked_list * const list);

/**
 * Removes and destroys all elements from the list, leaving it with a size of 0
 *
 * @param[in] list to operate on
 * @return zero on success, non-zero otherwise
 */
int fg_list_clear(struct linked_list * const list);

#endif /* _FG_LIST_H_ */
