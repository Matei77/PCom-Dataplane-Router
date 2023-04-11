// Copyright Ionescu Matei-Stefan - 313CAb - 2021-2022
#ifndef LINKEDLIST_H_
#define LINKEDLIST_H_

#include "types.h"

linked_list_t *ll_create(unsigned int data_size);

void ll_add_nth_node(linked_list_t *list, unsigned int n, const void *new_data);

ll_node_t *ll_remove_nth_node(linked_list_t *list, unsigned int n);

unsigned int ll_get_size(linked_list_t *list);

void ll_free(linked_list_t **pp_list);

#endif  // LINKEDLIST_H_
