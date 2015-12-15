#include "list.h"
#include "objects.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

struct object * alloc_object(void)
{
	struct object *obj;
	obj = zmalloc(sizeof(struct object));
	INIT_LIST_HEAD(&obj->list);
	return obj;
}

void add_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;
	struct childdata *child;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		child = this_child();
		head = &child->objects[type];
	}

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
	struct childdata *child;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		child = this_child();
		head = &child->objects[type];
	}

	list_del(&obj->list);

	head->num_entries--;

	if (head->destroy != NULL)
		head->destroy(obj);

	free(obj);
}

void init_object_lists(bool global)
{
	struct objhead *head;
	struct childdata *child;
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		if (global == OBJ_GLOBAL)
			head = &shm->global_objects[i];
		else {
			child = this_child();
			head = &child->objects[i];
		}

		head->list = NULL;
		head->num_entries = 0;
	}
}

struct object * get_random_object(enum objecttype type, bool global)
{
	struct objhead *head;
	struct list_head *node, *list;
	struct childdata *child;
	unsigned int i, j = 0;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		child = this_child();
		head = &child->objects[type];
	}

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

bool no_objects(enum objecttype type)
{
	if (shm->global_objects[type].num_entries == 0)
		return TRUE;
	return FALSE;
}
