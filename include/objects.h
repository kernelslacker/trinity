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
	enum objecttype type;
	bool dereferencable;
};

struct object * alloc_object(void *ptr, enum objecttype type);
void add_to_global_objects(struct object *obj);
void add_to_child_objects(struct object *obj);
void destroy_object(struct object *obj);
