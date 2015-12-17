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

static struct objhead * get_objhead(bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		struct childdata *child;

		child = this_child();
		head = &child->objects[type];
	}
	return head;
}


void add_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	head = get_objhead(global, type);
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

	list_del(&obj->list);

	head = get_objhead(global, type);
	head->num_entries--;

	if (head->destroy != NULL)
		head->destroy(obj);

	free(obj);
}

void init_object_lists(bool global)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		head = get_objhead(global, i);
		head->list = NULL;
		head->num_entries = 0;
	}
}

struct object * get_random_object(enum objecttype type, bool global)
{
	struct objhead *head;
	struct list_head *node, *list;
	unsigned int i, j = 0;

	head = get_objhead(global, type);

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
