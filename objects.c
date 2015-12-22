#include "list.h"
#include "objects.h"
#include "random.h"
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

struct objhead * get_objhead(bool global, enum objecttype type)
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

	i = rnd() % head->num_entries;

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

/*
 * Call the destructor for this object, and then release it.
 */
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

/*
 * Destroy a whole list of objects.
 */
static void destroy_objects(enum objecttype type, bool global)
{
	struct list_head *node, *list, *tmp;
	struct objhead *head;

	head = get_objhead(global, type);
	list = head->list;

	list_for_each_safe(node, tmp, list) {
		struct object *obj;

		obj = (struct object *) node;

		destroy_object(obj, global, type);
	}

	head->num_entries = 0;
}

/* Destroy all the global objects.
 *
 * We close this before quitting. All OBJ_LOCAL's got destroyed
 * when the children exited, leaving just these OBJ_GLOBALs
 * to clean up.
 */
void destroy_global_objects(void)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++)
		destroy_objects(i, OBJ_GLOBAL);
}

/*
 * Think of this as a poor mans garbage collector, to prevent
 * us from exhausting all the available fd's in the system etc.
 */
static void __prune_objects(enum objecttype type, bool global)
{
	struct objhead *head;
	unsigned int num_to_prune;

	if (RAND_BOOL())
		return;

	head = get_objhead(global, type);

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	num_to_prune = rand() % head->max_entries;

	while (num_to_prune > 0) {
		struct list_head *node, *list, *tmp;

		list = head->list;

		list_for_each_safe(node, tmp, list) {
			struct object *obj;

			if (ONE_IN(10)) {
				obj = (struct object *) node;
				destroy_object(obj, global, type);
				num_to_prune--;
				//TODO: log something
			}
		}
	}
}

void prune_objects(void)
{
	unsigned int i;

	/* We don't want to over-prune things and growing a little
	 * bit past the ->max is fine, we'll clean it up next time.
	 */
	if (!(ONE_IN(10)))
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		__prune_objects(i, OBJ_LOCAL);
		// For now, we're only pruning local objects.
		// __prune_objects(i, OBJ_GLOBAL);
	}
}
