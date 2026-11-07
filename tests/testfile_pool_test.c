/*
 * Self-check for the testfile pool (fds/testfiles.c): every fd sits on one
 * of the linked trinity-testfile inodes, the files the path-side calls
 * reach, and each fd is mapped page_size into the testfile mmap pool.  Init
 * runs through the provider's hook, against fake object-pool hooks.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fd.h"
#include "fds/fds-internal.h"	/* fd_providers */
#include "list.h"
#include "maps.h"
#include "objects.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils-mem.h"		/* free_shared_str */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

static struct object objs[64];
static unsigned int nr_objs;
static struct object *files[32], *maps[32];
static unsigned int nr_files, nr_maps;
static struct objhead file_head, map_head;

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void)scope;
	return type == OBJ_MMAP_TESTFILE ? &map_head : &file_head;
}

/* Zeroed, as alloc_object() hands them out. */
static struct object *alloc_hook(void)
{
	if (nr_objs == ARRAY_SIZE(objs))
		BUG("testfile pool: init allocated more objects than expected");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	(void)scope;
	if (type == OBJ_FD_TESTFILE && nr_files < ARRAY_SIZE(files))
		files[nr_files++] = obj;
	else if (type == OBJ_MMAP_TESTFILE && nr_maps < ARRAY_SIZE(maps))
		maps[nr_maps++] = obj;
	else
		BUG("testfile pool: init added an unexpected object");
}

void testfile_pool_self_check(void);
void testfile_pool_self_check(void)
{
	char base[] = "/tmp/trinity-testfile-test.XXXXXX";
	int (*init)(void) = NULL;
	struct list_head *node;
	unsigned int i;
	int cwd;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "testfile") == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("testfile pool: the testfile provider is not registered");

	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0)
		BUG("testfile pool: cannot set up the test directory");

	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	init();
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;

	if (nr_files == 0)
		BUG("testfile pool: init opened no testfile");
	for (i = 0; i < nr_files; i++) {
		struct stat st;

		if (fstat(files[i]->testfileobj.fd, &st) != 0 || st.st_nlink == 0)
			BUG("testfile pool: a testfile fd sits on an unlinked inode");
	}
	if (nr_maps != nr_files)
		BUG("testfile pool: not every testfile fd was mapped");
	for (i = 0; i < nr_maps; i++) {
		if (maps[i]->map.size != page_size)
			BUG("testfile pool: a testfile mapping is not page_size long");
		munmap(maps[i]->map.ptr, page_size);
		free_shared_str(maps[i]->map.name);
	}

	for (i = 0; i < nr_files; i++) {
		(void) unlink(files[i]->testfileobj.filename);
		close(files[i]->testfileobj.fd);
		free_shared_str((void *) files[i]->testfileobj.filename);
	}
	if (fchdir(cwd) != 0 || rmdir(base) != 0)
		BUG("testfile pool: cannot remove the test directory");
	close(cwd);
}
