#pragma once

#include "list.h"

#define TRINITY_MAP_INITIAL 1
#define TRINITY_MAP_CHILD 2

struct map {
	void *ptr;
	char *name;
	unsigned long size;
	int prot;
	unsigned char type;
};

extern unsigned int num_initial_mappings;
extern struct map *initial_mappings;

#define NR_MAPPING_SIZES 6
extern unsigned long mapping_sizes[NR_MAPPING_SIZES];

struct object;
void map_destructor(struct object *obj);

void setup_initial_mappings(void);

struct map * get_map(void);

struct map * common_set_mmap_ptr_len(void);

void dirty_mapping(struct map *map);
void dirty_random_mapping(void);

struct faultfn {
	void (*func)(struct map *map);
};

void random_map_readfn(struct map *map);
void random_map_writefn(struct map *map);
