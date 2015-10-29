#include "list.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

void add_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else
		head = &this_child->objects[type];

	if (head->list == NULL) {
		head->list = zmalloc(sizeof(struct object));
		INIT_LIST_HEAD(head->list);
	}

	list_add_tail(&obj->list, head->list);
	head->num_entries++;
}

void destroy_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else
		head = &this_child->objects[type];

	list_del(&obj->list);

	head->num_entries--;

	if (head->destroy != NULL)
		head->destroy(obj);

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

		head->list = NULL;
		head->num_entries = 0;
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
