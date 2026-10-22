/*
 * Object pool and name pool stand-ins for the sanitisers that
 * sanitiser_owned_mask_test.c runs.  Both pools are empty, so a
 * sanitiser takes its empty-pool arm.  What only a post handler or a
 * pool initialiser reaches aborts the test instead of answering.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "name-pool.h"
#include "objects.h"

/* REG_GLOBAL_OBJ() runs this from a constructor in each TU that uses it. */
void register_global_obj_init(struct global_obj_entry *entry)
{
	(void)entry;
}

struct objhead *get_objhead(enum obj_scope scope, enum objecttype type)
{
	(void)scope; (void)type;
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
