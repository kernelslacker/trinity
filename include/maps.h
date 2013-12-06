#ifndef _MAPS_H
#define _MAPS_H 1

#include "list.h"

void generate_random_page(char *page);

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

struct map * get_map(void);

void init_buffers(void);

#endif	/* _MAPS_H */
