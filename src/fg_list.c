/**
 * @file fg_list.c
 * @brief Generic doubly linked list implementation
 */

/*
 * Copyright (C) 2014 Marcel Nehring <marcel.nehring@rwth-aachen.de>
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

#include "fg_list.h"

#include <stdlib.h>

/**
 * Initializes the list by setting its head and
 * tail to NULL and its size to 0.
 *
 * @param[in] list list to initialize
 * @return zero on success, non-zero otherwise
 */
int fg_list_init(LinkedList * const list) {
	if (!list) {
		return -1;
	}

	if (list->head) {
		if (!fg_list_clear(list)){
			return -2;
		}
	}

	list->head = NULL;
	list->tail = NULL;
	list->size = 0;

	return 0;
}

/**
 * Returns the first element of the list
 * The element is not removed from the list.
 *
 * @param[in] list to operate on
 * @return a pointer to the first element in @p list
 */
const ListNode * fg_list_front(LinkedList * const list) {
	if (!list) {
		return NULL;
	}

	return list->head;
}

/**
 * Returns the last element of the list.
 * The element is not removed from the list.
 *
 * @param[in] list to operate on
 * @return a pointer to the last element in @p list
 */
const ListNode * fg_list_back(LinkedList * const list) {
	if (!list) {
		return NULL;
	}
	
	return list->tail;
}

/**
 * Removes from the list the first element whose data points to @p data
 * reducing the list size by one. The data contained in this element
 * will not be modified.
 *
 * @param[in] list to operate on
 * @param[in] data of the element to be removed
 * @return zero on success, non-zero otherwise
 */
int fg_list_remove(LinkedList * const list, const void * const data) {
	if (!list) {
		return -1;
	}

	if (!list->head) {
		return -3;
	}

	ListNode *node = list->head;

	while (node->data != data) {
		node = node->next;

		if (!node) {
			return -4;
		}
	}

	if (list->head == node) {
		list->head = node->next;
	}

	if (list->tail == node) {
		list->tail = node->previous;
	}

	if (node->previous) {
		node->previous->next = node->next;
	}

	if (node->next) {
		node->next->previous = node->previous;
	}

	free(node);

	--list->size;

	return 0;
}

/**
 * Helper function for internal use only!
 * Creates a new list element on the heap and prepares it for
 * insertion into the list between elements pointed to by @p previous and
 * @p next. The data of the newly created element will point to the same
 * memory location as @p data
 *
 * @param[in] data of newly created element
 * @param[in] existing list element the new element is going to be inserted after
 * @param[in] existing list element the new element is going to be inserted before
 * @return a pointer to the newly created list element or NULL on failure
 */
ListNode* create_node(void * const data, ListNode * const previous, ListNode * const next) {
	ListNode *new_node = (ListNode*)malloc(sizeof(ListNode));

	if (!new_node) {
		return NULL;
	}

	new_node->data = data;
	new_node->previous = previous;
	new_node->next = next;

	return new_node;
}

/**
 * Inserts a new element at the beginning of the list,
 * right before its current first element. The data of the
 * new element will point to the same memory location as @p data.
 * This effectively increases the list's size by one.
 *
 * @param[in] list to operate on
 * @param[in] data of inserted element
 * @return zero on success, non-zero otherwise
 */
int fg_list_push_front(LinkedList * const list, void * const data) {
	if (!list) {
		return -1;
	}

	ListNode *new_node = create_node(data, NULL, list->head);

	if (!new_node) {
		return -5;
	}

	if (!list->head) {
		list->tail = new_node;
	}
	else {
		list->head->previous = new_node;
	}

	list->head = new_node;
	++list->size;

	return 0;
}

/**
 * Removes the first element in the list, effectively
 * reducing its size by one. This destroys the removed element.
 * The data contained in this element will not be modified.
 *
 * @param[in] list to operate on
 * @return pointer to the data that was contained in the removed element, NULL on failure
 */
void* fg_list_pop_front(LinkedList * const list) {
	if (!list) {
		return NULL;
	}

	if (!list->head) {
		return NULL;
	}

	ListNode *head = list->head;

	if (list->head == list->tail) {
		list->tail = NULL;
	}

	if (head->next) {
		head->next->previous = NULL;
	}

	list->head = head->next;
	void *data = head->data;

	free(head);

	--list->size;

	return data;
}

/**
 * Inserts a new element at the end of the list,
 * right after its current last element. The data of the
 * new element will point to the same memory location as @p data.
 * This effectively increases the list's size by one.
 *
 * @param[in] list to operate on
 * @param[in] data of inserted element
 * @return zero on success, non-zero otherwise
 */
int fg_list_push_back(LinkedList * const list, void * const data) {
	if (!list) {
		return -1;
	}

	ListNode *new_node = create_node(data, list->tail, NULL);

	if (!new_node) {
		return -5;
	}

	if (!list->head) {
		list->head = new_node;
	}

	if (list->tail) {
		list->tail->next = new_node;
	}

	list->tail = new_node;
	++list->size;

	return 0;
}

/**
 * Removes the last element in the list, effectively
 * reducing its size by one. This destroys the removed element.
 * The data contained in this element will not be modified.
 *
 * @param[in] list to operate on
 * @return pointer to the data that was contained in the removed element, NULL on failure
 */
void* fg_list_pop_back(LinkedList * const list) {
	if (!list) {
		return NULL;
	}

	if (!list->tail) {
		return NULL;
	}

	ListNode *tail = list->tail;
	void *data = tail->data;

	if (tail->previous) {
		tail->previous->next = NULL;
	}

	if (list->tail == list->head) {
		list->head = NULL;
	}

	list->tail = tail->previous;

	free(tail);

	--list->size;

	return data;
}

/**
 * Returns the number of elements in the list.
 *
 * @param[in] list to operate on
 * @return the number of elements in the list.
 */
int fg_list_size(LinkedList * const list) {
	if (!list) {
		return -1;
	}

	return list->size;
}

/**
 * Removes and destroys all elements from the list,
 * leaving it with a size of 0.
 *
 * @param[in] list to operate on
 * @return zero on success, non-zero otherwise
 */
int fg_list_clear(LinkedList * const list) {
	if (!list) {
		return -1;
	}

	while (fg_list_size(list)) {
		void * data = fg_list_pop_front(list);
		free(data);
	}

	return 0;
}