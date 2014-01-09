#pragma once

#include "list.h"

extern char *page_zeros;
extern char *page_0xff;
extern char *page_rand;
extern unsigned long *page_allocs;
extern unsigned long *page_maps;

void init_shared_pages(void);

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

void delete_mapping(int childno, struct map *map);

struct map * get_map(void);

struct map * common_set_mmap_ptr_len(int childno);

void dirty_mapping(struct map *map);
