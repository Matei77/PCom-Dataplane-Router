/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "types.h"
#include "linkedlist.h"
#include "lib.h"

/* Key comaparison function for uint32_t integers */
int compare_function_uint32(void *a, void *b)
{
	uint32_t uint32_a = *((uint32_t *)a);
	uint32_t uint32_b = *((uint32_t *)b);

	if (uint32_a == uint32_b) {
		return 0;
	} else if (uint32_a < uint32_b) {
		return -1;
	} else {
		return 1;
	}
}

/* Key comaparison function for strings */
int compare_function_strings(void *a, void *b)
{
	char *str_a = (char *)a;
	char *str_b = (char *)b;

	return strcmp(str_a, str_b);
}

/* Hash function for integers */
unsigned int hash_function_int(void *a)
{
	/* Credits: https://stackoverflow.com/a/12996028/7883884 */

	unsigned int uint_a = *((unsigned int *)a);

	uint_a = ((uint_a >> 16u) ^ uint_a) * 0x45d9f3b;
	uint_a = ((uint_a >> 16u) ^ uint_a) * 0x45d9f3b;
	uint_a = (uint_a >> 16u) ^ uint_a;
	return uint_a;
}

/* Hash function for strings */
unsigned int hash_function_string(void *a)
{
	/* Credits: http://www.cse.yorku.ca/~oz/hash.html */

	unsigned char *puchar_a = (unsigned char *)a;
	unsigned int hash = 5381;
	int c;

	while ((c = *puchar_a++))
		hash = ((hash << 5u) + hash) + c; /* hash * 33 + c */

	return hash;
}

/* This function creates a new hashtable */
hashtable_t *ht_create(unsigned int hmax, unsigned int (*hash_function)(void *),
					   int (*compare_function)(void *, void *))
{
	hashtable_t *hashtable = malloc(sizeof(hashtable_t));
	DIE(hashtable == NULL, "hashtable malloc");

	hashtable->buckets = malloc(hmax * sizeof(linked_list_t));
	DIE(hashtable->buckets == NULL, "hashtable->buckets malloc");

	for (unsigned int i = 0; i < hmax; i++) {
		hashtable->buckets[i] = ll_create(sizeof(info));
	}

	hashtable->size = 0;
	hashtable->hmax = hmax;
	hashtable->hash_function = hash_function;
	hashtable->compare_function = compare_function;

	return hashtable;
}

/* This function checks if the key is already in the hashtable */
int ht_has_key(hashtable_t *ht, void *key)
{
	unsigned int index = ht->hash_function(key) % ht->hmax;

	ll_node_t *it = ht->buckets[index]->head;

	while (it) {
		if (ht->compare_function(((info *)it->data)->key, key) == 0)
			return 1;
		it = it->next;
	}

	return 0;
}

/* This function returns the value associated with a key */
void *ht_get(hashtable_t *ht, void *key)
{
	unsigned int index = ht->hash_function(key) % ht->hmax;

	ll_node_t *it = ht->buckets[index]->head;

	while (it) {
		if (ht->compare_function(((info *)it->data)->key, key) == 0)
			return ((info *)it->data)->value;
		it = it->next;
	}

	return NULL;
}

/* This function adds a new pair of key - value in the hashtable */
void ht_put(hashtable_t *ht, void *key, unsigned int key_size, void *value,
			unsigned int value_size)
{
	void *p = ht_get(ht, key);

	if (p) {
		ht_remove_entry(ht, key);
	}

	unsigned int index = ht->hash_function(key) % ht->hmax;

	info *node_data = malloc(sizeof(info));
	DIE(node_data == NULL, "node_data malloc");

	node_data->key = malloc(key_size);
	DIE(node_data->key == NULL, "node_data->key malloc");

	node_data->value = malloc(value_size);
	DIE(node_data->value == NULL, "node_data->value malloc");

	memmove(node_data->key, key, key_size);
	memmove(node_data->value, value, value_size);

	ll_add_nth_node(ht->buckets[index], ht->buckets[index]->size + 1,
					node_data);

	free(node_data);

	ht->size++;
}

/* This function removes the entry with the given key from the hashtable */
void ht_remove_entry(hashtable_t *ht, void *key)
{
	if (ht_has_key(ht, key) == 0)
		return;

	unsigned int index = ht->hash_function(key) % ht->hmax;

	ll_node_t *it = ht->buckets[index]->head;
	unsigned int n = 0;

	while (it) {
		if (ht->compare_function(((info *)it->data)->key, key) == 0) {
			free(((info *)it->data)->key);
			free(((info *)it->data)->value);
			ll_node_t *p = ll_remove_nth_node(ht->buckets[index], n);
			if (p) {
				free(p->data);
				p->data = NULL;
				free(p);
				p = NULL;
			}
			return;
		}
		it = it->next;
		n++;
	}
}

/* This function frees the memory allocated for a hashtable */
void ht_free(hashtable_t *ht)
{
	for (unsigned int i = 0; i < ht->hmax; i++) {
		ll_node_t *it = ht->buckets[i]->head;
		while (it) {
			free(((info *)it->data)->key);
			free(((info *)it->data)->value);
			it = it->next;
		}
		ll_free(&(ht->buckets[i]));
	}
	free(ht->buckets);
	free(ht);
}

/* This function returns the number of elements in the hashtable */
unsigned int ht_get_size(hashtable_t *ht)
{
	if (ht == NULL)
		return 0;

	return ht->size;
}

/* This function returns the number of buckets in the hashtable */
unsigned int ht_get_hmax(hashtable_t *ht)
{
	if (ht == NULL)
		return 0;

	return ht->hmax;
}

/* This function checks if the MAX_LOAD_FACTOR has been reached and resizes the
 hashtable if this is the case */
void ht_check_and_resize(hashtable_t *ht)
{
	float load_factor = (float)ht->size / (float)ht->hmax;

	if (load_factor < MAX_LOAD_FACTOR)
		return;

	unsigned int last_hmax = ht->hmax;
	ht->hmax *= 2;

	ht->buckets = realloc(ht->buckets, ht->hmax * sizeof(linked_list_t));

	for (unsigned int i = last_hmax; i < ht->hmax; i++) {
		ht->buckets[i] = ll_create(sizeof(info));
	}

	for (unsigned int i = 0; i < last_hmax; i++) {
		ll_node_t *it = ht->buckets[i]->head;
		ll_node_t *next;
		int n = 0;
		while (it) {
			next = it->next;
			info *node_data = (info *)it->data;
			void *key = node_data->key;
			unsigned int index = ht->hash_function(key) % ht->hmax;

			if (index != i) {
				ll_add_nth_node(ht->buckets[index],
								ht->buckets[index]->size + 1, node_data);

				ll_node_t *node = ll_remove_nth_node(ht->buckets[i], n);
				n--;
				free(node);
				free(node_data);
			}

			it = next;
			n++;
		}
	}
}
