/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef _HASHTABLE_H_
#define _HASHTABLE_H_

#include "types.h"

#define MAX_LOAD_FACTOR 1

/* Key comaparison function for uint32_t integers */
int compare_function_uint32(void *a, void *b);

/* Key comaparison function for strings */
int compare_function_strings(void *a, void *b);

/* Hash function for integers */
unsigned int hash_function_int(void *a);

/* Hash function for strings */
unsigned int hash_function_string(void *a);

/* This function creates a new hashtable */
hashtable_t *ht_create(unsigned int hmax, unsigned int (*hash_function)(void *),
					   int (*compare_function)(void *, void *));

/* This function checks if the key is already in the hashtable */
int ht_has_key(hashtable_t *ht, void *key);

/* This function returns the value associated with a key */
void *ht_get(hashtable_t *ht, void *key);

/* This function adds a new pair of key - value in the hashtable */
void ht_put(hashtable_t *ht, void *key, unsigned int key_size, void *value,
			unsigned int value_size);

/* This function removes the entry with the given key from the hashtable */
void ht_remove_entry(hashtable_t *ht, void *key);

/* This function frees the memory allocated for a hashtable */
void ht_free(hashtable_t *ht);

/* This function returns the number of elements in the hashtable */
unsigned int ht_get_size(hashtable_t *ht);

/* This function returns the number of buckets in the hashtable */
unsigned int ht_get_hmax(hashtable_t *ht);

/* This function checks if the MAX_LOAD_FACTOR has been reached and resizes the
 hashtable if this is the case */
void ht_check_and_resize(hashtable_t *ht);

#endif /* _HASHTABLE_H_ */
