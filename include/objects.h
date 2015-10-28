#pragma once

#include "list.h"
#include "maps.h"
#include "trinity.h"

enum objecttype {
	OBJ_MMAP,
	MAX_OBJECT_TYPES,
};

struct object {
	struct list_head *list;
	union {
		struct map map;
	};
};

struct objhead {
	struct list_head *list;
	unsigned int num_entries;
	void (*destroy)(void *ptr);
};

#define OBJ_GLOBAL 0
#define OBJ_LOCAL 1

struct object * alloc_object(void *ptr);
void add_object(struct object *obj, bool global, enum objecttype type);
void destroy_object(struct object *obj, bool global, enum objecttype type);
void init_object_lists(bool global);
struct object * get_random_object(enum objecttype type, bool global);
