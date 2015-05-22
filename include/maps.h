#pragma once

#include "list.h"

#define TRINITY_MAP_INITIAL 1
#define TRINITY_MAP_CHILD 2

struct map {
	struct list_head list;
	void *ptr;
	char *name;
	unsigned long size;
	int prot;
	unsigned char type;
};

extern unsigned int num_initial_mappings;
extern struct map *initial_mappings;

void setup_initial_mappings(void);
void destroy_initial_mappings(void);

struct map * get_map(void);

struct map * common_set_mmap_ptr_len(void);

void dirty_mapping(struct map *map);
void dirty_random_mapping(void);

struct faultfn {
	void (*func)(struct map *map);
};

void random_map_readfn(struct map *map);
void random_map_writefn(struct map *map);
