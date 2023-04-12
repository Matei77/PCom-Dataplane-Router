/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef LINKEDLIST_H_
#define LINKEDLIST_H_

#include "types.h"

/* This function creates a new linked list and returns it */
linked_list_t *ll_create(unsigned int data_size);

/* This function adds a new node to a linked list at position n */
void ll_add_nth_node(linked_list_t *list, unsigned int n, const void *new_data);

/* this function removes the nth node from a linked list */
ll_node_t *ll_remove_nth_node(linked_list_t *list, unsigned int n);

/* This function return the size of a list */
unsigned int ll_get_size(linked_list_t *list);

/* This function frees a linked list */
void ll_free(linked_list_t **pp_list);

#endif /* LINKEDLIST_H_ */
