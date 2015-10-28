#pragma once

#include "list.h"
#include "trinity.h"

enum objecttype {
	OBJ_MMAP,
	MAX_OBJECT_TYPES,
};

struct object {
	struct list_head *list;
	void *ptr;
	void (*destroy)(void *ptr);
	bool dereferencable;
};

struct objhead {
	struct list_head *list;
	unsigned int num_entries;
};

#define OBJ_GLOBAL 0
#define OBJ_LOCAL 1

struct object * alloc_object(void *ptr);
void add_object(struct object *obj, bool global, enum objecttype type);
void destroy_object(struct object *obj, bool global, enum objecttype type);
