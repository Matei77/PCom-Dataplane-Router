// Copyright Ionescu Matei-Stefan - 313CAb - 2021-2022
#ifndef TYPES_H_
#define TYPES_H_

#define INITIAL_BUCKETS_NR 20

typedef struct ll_node_t {
	void *data;
	struct ll_node_t *next;
} ll_node_t;

typedef struct linked_list_t {
	ll_node_t *head;
	unsigned int data_size;
	unsigned int size;
} linked_list_t;

typedef struct info info;
struct info {
	void *key;
	void *value;
};

typedef struct hashtable_t hashtable_t;
struct hashtable_t {
	linked_list_t **buckets;
	unsigned int size;  // total number of elements
	unsigned int hmax;  // number of buckets
	unsigned int (*hash_function)(void *);
	int (*compare_function)(void *, void *);
};

#endif  // TYPES_H_
