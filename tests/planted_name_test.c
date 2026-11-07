/*
 * Self-check for the fd providers that unlink a name of their own in the
 * run's cwd, tmp/ when there is one, then create it afresh: a symlink the
 * unlink() stand-in of fake_fds.c plants under the name in between must
 * fail the create, so init neither resizes nor writes the file it names,
 * nor holds an fd on it, and the provider's other names still make a
 * pool.  Each init runs through the provider's hook against fake
 * object-pool hooks.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fd.h"
#include "fds/fds-internal.h"	/* fd_providers */
#include "list.h"
#include "objects.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern const char *fake_unlink_plant;	/* fake_fds.c */
extern const char *fake_unlink_target;	/* fake_fds.c */

static struct object objs[16];
static struct object *added[16];
static unsigned int nr_objs, nr_added;
static struct objhead fake_head;

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void)scope;
	(void)type;
	return &fake_head;
}

/* Zeroed, as alloc_object() hands them out. */
static struct object *alloc_hook(void)
{
	if (nr_objs == ARRAY_SIZE(objs))
		BUG("planted name: init allocated more objects than expected");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	(void)scope;
	(void)type;
	added[nr_added++] = obj;
}

/* Whether any fd of this process sits on @victim. */
static bool fd_held_on(const struct stat *victim)
{
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *de;
	bool held = false;

	if (dir == NULL)
		BUG("planted name: cannot list /proc/self/fd");
	while ((de = readdir(dir)) != NULL) {
		struct stat st;

		if (fstatat(dirfd(dir), de->d_name, &st, 0) == 0 &&
		    st.st_dev == victim->st_dev && st.st_ino == victim->st_ino)
			held = true;
	}
	closedir(dir);
	return held;
}

/* Run @provider's init with a symlink planted under @name, a file it
 * makes, between its unlink and its create. */
static void check_planted(const char *provider, const char *name)
{
	char base[] = "/tmp/trinity-planted-test.XXXXXX";
	int (*init)(void) = NULL;
	struct list_head *node;
	struct stat victim, st;
	const char *why = NULL;
	unsigned int i;
	int fd, cwd;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, provider) == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("planted name: a provider is not registered");

	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0)
		BUG("planted name: cannot set up the test directory");
	fd = open("victim", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || write(fd, "x", 1) != 1 || fstat(fd, &victim) != 0)
		BUG("planted name: cannot make the planted link's target");
	close(fd);

	nr_objs = nr_added = 0;
	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	fake_unlink_target = "victim";
	fake_unlink_plant = name;
	(void) init();
	fake_unlink_plant = NULL;
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;

	if (stat("victim", &st) != 0 || st.st_size != 1)
		why = "init wrote the file a planted link names";
	else if (fd_held_on(&victim))
		why = "init holds an fd on the file a planted link names";
	else if (nr_added == 0)
		why = "a planted name kept every file out of the pool";
	if (why != NULL) {
		fprintf(stderr, "planted name: %s: %s\n", provider, why);
		BUG("planted name: a check failed");
	}

	for (i = 0; i < nr_added; i++)
		fake_head.destroy(added[i]);
	if (unlink(name) != 0 || unlink("victim") != 0 ||
	    fchdir(cwd) != 0 || rmdir(base) != 0)
		BUG("planted name: cannot remove the test directory");
	close(cwd);
}

void planted_name_self_check(void);
void planted_name_self_check(void)
{
	check_planted("sparse-file", "trinity-sparsefile0");
	check_planted("writeable-pagecache", "trinity-writepc-0");
}
