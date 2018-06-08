#pragma once

#include <limits.h>
#include "types.h"
#include "list.h"
#include "object-types.h"

#define INITIAL_ANON 1
#define CHILD_ANON 2
#define MMAPED_FILE 3

#define MAPS_NAME_MAX_LEN PATH_MAX

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
void map_dump(struct object *obj, bool global);

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

unsigned long get_rand_mmap_flags(void);

void mmap_fd(int fd, const char *name, size_t len, int prot, bool global, enum objecttype type);
