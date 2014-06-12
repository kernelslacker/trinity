#pragma once

#include "list.h"

extern char *page_rand;

#define MAP_GLOBAL 1
#define MAP_LOCAL 2

struct map {
	struct list_head list;
	void *ptr;
	char *name;
	unsigned long size;
	int prot;
	unsigned char type;
};

extern unsigned int num_shared_mappings;
extern struct map *shared_mappings;

void setup_shared_mappings(void);
void destroy_shared_mappings(void);

void delete_mapping(struct map *map);

struct map * get_map(void);

struct map * common_set_mmap_ptr_len(void);

void dirty_mapping(struct map *map);
