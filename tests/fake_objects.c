/*
 * Object pool and name pool stand-ins for the sanitisers that
 * sanitiser_owned_mask_test.c runs.  Both pools are empty, so a sanitiser
 * takes its empty-pool arm.  What only a post handler or a pool initialiser
 * reaches aborts the test, unless a test installs a hook for the call it
 * drives: dup_pool_test.c hooks find_local_object_by_fd() and get_objhead().
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "name-pool.h"
#include "objects.h"
#include "prop_ring.h"
#include "sanitise.h"

struct object *(*fake_find_local_object_by_fd)(enum objecttype type, int fd);
struct objhead *(*fake_get_objhead)(enum obj_scope scope, enum objecttype type);

struct object *alloc_object(void)
{
	fprintf(stderr, "fake alloc_object called unexpectedly\n");
	abort();
}

void add_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	(void)obj; (void)scope; (void)type;
	fprintf(stderr, "fake add_object called unexpectedly\n");
	abort();
}

void set_object_fd(struct object *obj, enum objecttype type, int fd)
{
	(void)obj; (void)type; (void)fd;
	fprintf(stderr, "fake set_object_fd called unexpectedly\n");
	abort();
}

void prop_ring_push_scalar(unsigned int nr, long scalar_val,
			   enum scalar_kind kind)
{
	(void)nr; (void)scalar_val; (void)kind;
	fprintf(stderr, "fake prop_ring_push_scalar called unexpectedly\n");
	abort();
}

void register_returned_pid(pid_t pid)
{
	(void)pid;
	fprintf(stderr, "fake register_returned_pid called unexpectedly\n");
	abort();
}

struct object *find_local_object_by_fd(enum objecttype type, int fd)
{
	if (fake_find_local_object_by_fd != NULL)
		return fake_find_local_object_by_fd(type, fd);
	fprintf(stderr, "fake find_local_object_by_fd called unexpectedly\n");
	abort();
}

/* REG_GLOBAL_OBJ() runs this from a constructor in each TU that uses it. */
void register_global_obj_init(struct global_obj_entry *entry)
{
	(void)entry;
}

struct objhead *get_objhead(enum obj_scope scope, enum objecttype type)
{
	if (fake_get_objhead != NULL)
		return fake_get_objhead(scope, type);
	fprintf(stderr, "fake get_objhead called unexpectedly\n");
	abort();
}

struct object *get_random_object(enum objecttype type, enum obj_scope scope)
{
	(void)type; (void)scope;
	return NULL;
}

bool objpool_check(const struct object *obj, enum objecttype expected)
{
	(void)obj; (void)expected;
	return false;
}

bool objects_empty(enum objecttype type)
{
	(void)type;
	return true;
}

bool objects_pool_empty(enum obj_scope scope, enum objecttype type)
{
	(void)scope; (void)type;
	return true;
}

size_t name_pool_draw_mutated(enum name_kind kind, char *out, size_t out_cap)
{
	(void)kind; (void)out; (void)out_cap;
	return 0;
}

void name_pool_record(enum name_kind kind, const char *name, size_t len)
{
	(void)kind; (void)name; (void)len;
}
