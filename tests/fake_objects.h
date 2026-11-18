/*
 * Hooks of fake_objects.c for the code that looks a pool up, allocates a
 * pool object and adds it to a pool.  tests/Makefile wraps get_objhead(),
 * alloc_object() and add_object(); a test that drives such code sets the
 * hooks for its call and clears them after.  Unset, get_objhead() and
 * add_object() are fakes in fake_objects.c, which abort the run, and
 * alloc_object() is the real one from objects/registry.c.
 */
#pragma once

#include "objects.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);
extern struct object *(*fake_alloc_object)(void);
extern void (*fake_add_object)(struct object *obj, enum obj_scope scope,
			       enum objecttype type);

/* A fake_get_objhead hook under which no pool exists, so code that
 * draws from one takes its empty-pool arm. */
struct objhead *fake_no_objhead(enum obj_scope scope, enum objecttype type);
