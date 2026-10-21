/*
 * Environment for linking fds/fds.c and fds/fds-registry.c into the test
 * binary: the allocator and list validator the registry needs, and stubs
 * for the object-pool lookups only the fd-to-provider walk reaches.  The
 * stubs abort when called, so a test that wanders into that walk fails
 * loudly instead of quietly seeing an untracked fd.
 */

#include <stdio.h>
#include <stdlib.h>

#include "list.h"
#include "objects.h"
#include "utils.h"

/* Owned by utils/zmalloc.c in production.  The registry relies on zeroed nodes. */
void *__zmalloc(size_t size, const char *func)
{
	void *p = calloc(1, size);

	if (p == NULL) {
		fprintf(stderr, "fake __zmalloc: calloc(%zu) failed in %s\n",
			size, func);
		abort();
	}
	return p;
}

/*
 * Owned by utils/debug.c in production, where it checks the links around
 * an insertion.  The lists the tests build come from the registry itself.
 */
void __list_add_valid_or_die(struct list_head *new, struct list_head *prev,
			     struct list_head *next, const char *file,
			     const char *func, unsigned int line)
{
	(void)new; (void)prev; (void)next;
	(void)file; (void)func; (void)line;
}

struct fd_hash_entry *fd_hash_lookup(int fd)
{
	(void)fd;
	fprintf(stderr, "fake fd_hash_lookup called unexpectedly\n");
	abort();
}

struct object *local_fd_find_by_fd(int fd)
{
	(void)fd;
	fprintf(stderr, "fake local_fd_find_by_fd called unexpectedly\n");
	abort();
}
