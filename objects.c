#include "list.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

struct object * alloc_object(void *ptr, enum objecttype type)
{
	struct object *obj;

	obj = zmalloc(sizeof(struct object));

	obj->type = type;
	obj->ptr = ptr;

	return obj;
}

void add_to_global_objects(struct object *obj)
{
	list_add(obj->list, shm->global_objects[obj->type].list);
	shm->global_objects[obj->type].num_entries++;
}

void add_to_child_objects(struct object *obj)
{
	list_add(obj->list, this_child->objects[obj->type].list);
	this_child->objects[obj->type].num_entries++;
}

void destroy_object(struct object *obj, bool global)
{
	struct objhead *head;

	if (global == TRUE)
		head = &shm->global_objects[obj->type];
	else
		head = &this_child->objects[obj->type];

	list_del(obj->list);

	head->num_entries--;

	obj->destroy(obj->ptr);

	free(obj);
}
