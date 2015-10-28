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
}

void add_to_child_objects(struct object *obj)
{
	list_add(obj->list, this_child->objects[obj->type].list);
}

void destroy_object(struct object *obj)
{
	// Remove it from the list first so nothing else uses it.
	list_del(obj->list);

	// Call the destructor
	obj->destroy(obj->ptr);

	// free obj
	free(obj);
}
