/**
 * @file fg_list.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

#include "fg_list.h"

int fg_list_init(struct linked_list * const list)
{
	if (!list)
		return -1;
	if (list->head)
		if (!fg_list_clear(list))
			return -2;

	list->head = NULL;
	list->tail = NULL;
	list->size = 0;

	return 0;
}

const struct list_node* fg_list_front(struct linked_list * const list)
{
	if (!list)
		return NULL;

	return list->head;
}

const struct list_node* fg_list_back(struct linked_list * const list)
{
	if (!list)
		return NULL;

	return list->tail;
}

int fg_list_remove(struct linked_list * const list, const void * const data)
{
	if (!list)
		return -1;
	if (!list->head)
		return -3;

	struct list_node *node = list->head;

	while (node->data != data) {
		node = node->next;
		if (!node)
			return -4;
	}

	if (list->head == node)
		list->head = node->next;
	if (list->tail == node)
		list->tail = node->previous;
	if (node->previous)
		node->previous->next = node->next;
	if (node->next)
		node->next->previous = node->previous;

	free(node);
	--list->size;

	return 0;
}

/**
 * Creates a new list element on the heap and prepares it for insertion into
 * the list between elements pointed to by @p previous and @p next. The data of
 * the newly created element will point to the same memory location as @p data
 *
 * @param[in] data data of newly created element
 * @param[in] previous existing list element the new element will be inserted after
 * @param[in] next existing list element the new element will be inserted before
 * @return pointer to the newly created list element or NULL on failure
 */
static struct list_node* create_node(void * const data,
				      struct list_node * const previous,
				      struct list_node * const next)
{
	struct list_node *new_node = (struct list_node*)malloc(sizeof(struct list_node));

	if (!new_node)
		return NULL;

	new_node->data = data;
	new_node->previous = previous;
	new_node->next = next;

	return new_node;
}

int fg_list_push_front(struct linked_list * const list, void * const data)
{
	if (!list)
		return -1;

	struct list_node *new_node = create_node(data, NULL, list->head);

	if (!new_node)
		return -5;

	if (!list->head)
		list->tail = new_node;
	else
		list->head->previous = new_node;

	list->head = new_node;
	++list->size;

	return 0;
}

void* fg_list_pop_front(struct linked_list * const list)
{
	if (!list)
		return NULL;
	if (!list->head)
		return NULL;

	struct list_node *head = list->head;

	if (list->head == list->tail)
		list->tail = NULL;
	if (head->next)
		head->next->previous = NULL;

	list->head = head->next;
	void *data = head->data;

	free(head);
	--list->size;

	return data;
}

int fg_list_push_back(struct linked_list * const list, void * const data)
{
	if (!list)
		return -1;

	struct list_node *new_node = create_node(data, list->tail, NULL);

	if (!new_node)
		return -5;

	if (!list->head)
		list->head = new_node;
	if (list->tail)
		list->tail->next = new_node;

	list->tail = new_node;
	++list->size;

	return 0;
}

void* fg_list_pop_back(struct linked_list * const list)
{
	if (!list)
		return NULL;
	if (!list->tail)
		return NULL;

	struct list_node *tail = list->tail;
	void *data = tail->data;

	if (tail->previous)
		tail->previous->next = NULL;
	if (list->tail == list->head)
		list->head = NULL;

	list->tail = tail->previous;

	free(tail);
	--list->size;

	return data;
}

size_t fg_list_size(struct linked_list * const list)
{
	if (!list)
		return -1;

	return list->size;
}

int fg_list_clear(struct linked_list * const list)
{
	if (!list)
		return -1;

	while (fg_list_size(list)) {
		void * data = fg_list_pop_front(list);
		free(data);
	}

	return 0;
}
