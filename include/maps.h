#ifndef _MAPS_H
#define _MAPS_H 1

#include "list.h"

extern char *page_zeros;
extern char *page_0xff;
extern char *page_rand;
extern char *page_allocs;

struct map {
	struct list_head list;
	void *ptr;
	char *name;
	unsigned long size;
	int prot;
};

void setup_global_mappings(void);
void destroy_global_mappings(void);

void delete_local_mapping(int childno, struct map *map);

struct map * get_map(void);

struct map * common_set_mmap_ptr_len(int childno);

#endif	/* _MAPS_H */
