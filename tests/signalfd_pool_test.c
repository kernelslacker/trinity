/*
 * Self-check for the signalfd provider: its init makes the signalfds of its
 * pool, which takes signalfd4() handed the kernel's 8-byte sigset_t (glibc's
 * is 128 bytes, which the kernel refuses with -EINVAL).  The pool is a fake.
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fds/fds-internal.h"	/* fd_providers */
#include "objects.h"		/* struct objhead */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

static struct objhead fake_head;
static struct object objs[8];
static unsigned int nr_objs, pooled;

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return &fake_head;
}

static struct object *alloc_hook(void)
{
	if (nr_objs == ARRAY_SIZE(objs))
		BUG("signalfd: the provider allocated more objects than expected");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

/* A pooled fd must be a signalfd, which the test closes again. */
static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	char path[64], target[PATH_MAX];
	ssize_t len;

	if (scope != OBJ_GLOBAL || type != OBJ_FD_SIGNALFD)
		BUG("signalfd: the provider pooled into another pool");
	snprintf(path, sizeof(path), "/proc/self/fd/%d", obj->signalfdobj.fd);
	len = readlink(path, target, sizeof(target) - 1);
	if (len < 0)
		BUG("signalfd: the provider pooled an fd it does not hold");
	target[len] = '\0';
	if (strcmp(target, "anon_inode:[signalfd]") != 0)
		BUG("signalfd: the provider pooled an fd that is no signalfd");
	close(obj->signalfdobj.fd);
	pooled++;
}

void signalfd_pool_self_check(void);
void signalfd_pool_self_check(void)
{
	int (*init)(void) = NULL;
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "signalfd") == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("signalfd: the signalfd provider is not registered");

	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	if (!init())
		BUG("signalfd: the provider's init failed");
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;

	if (pooled == 0)
		BUG("signalfd: the provider made no signalfd");
}
