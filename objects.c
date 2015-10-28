#include "list.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

struct object * alloc_object(void *ptr)
{
	struct object *obj;

	obj = zmalloc(sizeof(struct object));

	obj->ptr = ptr;

	return obj;
}

void add_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else
		head = &this_child->objects[type];

	list_add(obj->list, head->list);
	head->num_entries++;
}

void destroy_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else
		head = &this_child->objects[type];

	list_del(obj->list);

	head->num_entries--;

	obj->destroy(obj->ptr);

	free(obj);
}

void init_object_lists(bool global)
{
	struct objhead *head;
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		if (global == OBJ_GLOBAL)
			head = &shm->global_objects[i];
		else
			head = &this_child->objects[i];

		INIT_LIST_HEAD(head->list);
	}
}

struct object * get_random_object(enum objecttype type, bool global)
{
	struct objhead *head;
	struct list_head *node, *list;
	unsigned int i, j = 0;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else
		head = &this_child->objects[type];

	list = head->list;

	i = rand() % head->num_entries;

	list_for_each(node, list) {
		struct object *m;

		m = (struct object *) node;

		if (i == j)
			return m;
		j++;
	}
	return NULL;
}
