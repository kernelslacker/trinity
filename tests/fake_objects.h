/*
 * Hooks of fake_objects.c for the code that allocates a pool object and
 * adds it to a pool.  tests/Makefile wraps alloc_object() and add_object();
 * a test that drives such code sets the hooks for its call and clears them
 * after.  Unset, alloc_object() is the real one from objects/registry.c and
 * add_object() the fake in fake_objects.c, which aborts the run.
 */
#pragma once

#include "objects.h"

extern struct object *(*fake_alloc_object)(void);
extern void (*fake_add_object)(struct object *obj, enum obj_scope scope,
			       enum objecttype type);
