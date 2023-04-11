// Copyright Ionescu Matei-Stefan - 313CAb - 2021-2022
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linkedlist.h"
#include "types.h"
#include "lib.h"

// This function creates a new linked list and returns it
linked_list_t *ll_create(unsigned int data_size)
{
	linked_list_t *ll;

	ll = malloc(sizeof(linked_list_t));
	DIE(ll == NULL, "linked_list malloc");

	ll->head = NULL;
	ll->data_size = data_size;
	ll->size = 0;

	return ll;
}

// This function adds a new node to a linked list at position n
void ll_add_nth_node(linked_list_t *list, unsigned int n, const void *new_data)
{
	ll_node_t *prev = NULL, *curr = NULL;
	ll_node_t *new_node = NULL;

	if (!list) {
		return;
	}

	if (n > list->size) {
		n = list->size;
	}
	curr = list->head;
	prev = NULL;
	while (n > 0) {
		prev = curr;
		curr = curr->next;
		--n; 
	}
	new_node = (ll_node_t *)malloc(sizeof(ll_node_t));
	DIE(new_node == NULL, "new_node malloc");
	new_node->data = malloc(list->data_size);
	DIE(new_node->data == NULL, "new_node->data malloc");
	memcpy(new_node->data, new_data, list->data_size);

	new_node->next = curr;
	
	if (prev == NULL) {
		list->head = new_node;
	} else {
		prev->next = new_node;
	}

	list->size++;
}

// this function removes the nth node from a linked list
ll_node_t *ll_remove_nth_node(linked_list_t *list, unsigned int n)
{
	ll_node_t *prev, *curr;

	if (!list || !list->head) {
		return NULL;
	}

	if (n > list->size - 1) {
		n = list->size - 1;
	}

	curr = list->head;
	prev = NULL;
	while (n > 0) {
		prev = curr;
		curr = curr->next;
		--n;
	}

	if (prev == NULL) {
		list->head = curr->next;
	} else {
		prev->next = curr->next;
	}

	list->size--;

	return curr;
}

// This function return the size of a list
unsigned int ll_get_size(linked_list_t *list)
{
	if (!list) {
		return -1;
	}

	return list->size;
}

// This function frees a linked list
void ll_free(linked_list_t **pp_list)
{
	ll_node_t *currNode;

	if (!pp_list || !*pp_list) {
		return;
	}

	while (ll_get_size(*pp_list) > 0) {
		currNode = ll_remove_nth_node(*pp_list, 0);
		free(currNode->data);
		currNode->data = NULL;
		free(currNode);
		currNode = NULL;
	}

	free(*pp_list);
	*pp_list = NULL;
}
