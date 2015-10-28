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

void add_object(struct object *obj, bool global)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[obj->type];
	else
		head = &this_child->objects[obj->type];

	list_add(obj->list, head->list);
	head->num_entries++;
}

void destroy_object(struct object *obj, bool global)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[obj->type];
	else
		head = &this_child->objects[obj->type];

	list_del(obj->list);

	head->num_entries--;

	obj->destroy(obj->ptr);

	free(obj);
}
