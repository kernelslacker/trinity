/*
 * Self-check for the testfile pool (fds/testfiles.c): every fd sits on one
 * of the linked trinity-testfile inodes, the files the path-side calls
 * reach from any cwd, wherever init made them, each fd is mapped
 * page_size into the testfile mmap pool, and a root run hands every file
 * to nobody, whom its children run as.  A symlink planted under a name
 * between init's unlink and its create keeps that name out of the pool.
 * Init runs through the provider's hook, as a root run, against fake
 * object-pool hooks and an fchown() that only records.
 */

#include <fcntl.h>
#include <stdio.h>
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
#include "pathnames.h"		/* get_testfile_path_indexed */
#include "uid.h"		/* orig_uid, nobody_uid, nobody_gid */
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils-mem.h"		/* free_shared_str */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern const char *fake_unlink_plant;	/* fake_fds.c */
extern const char *fake_unlink_target;	/* fake_fds.c */

static struct object objs[64];
static unsigned int nr_objs;
static struct object *files[32], *maps[32];
static unsigned int nr_files, nr_maps;
static struct objhead file_head, map_head;
static ino_t chowned[32];
static unsigned int nr_chowned;
static bool fchown_armed, fchown_stranger;

/* Records the inode a root run's init hands to nobody, rather than ask a
 * kernel that refuses a non-root test; forwards while unarmed. */
int __real_fchown(int fd, uid_t owner, gid_t group);
int __wrap_fchown(int fd, uid_t owner, gid_t group);
int __wrap_fchown(int fd, uid_t owner, gid_t group)
{
	struct stat st;

	if (!fchown_armed)
		return __real_fchown(fd, owner, group);
	if (owner != nobody_uid || group != nobody_gid)
		fchown_stranger = true;
	if (fstat(fd, &st) == 0 && nr_chowned < ARRAY_SIZE(chowned))
		chowned[nr_chowned++] = st.st_ino;
	return 0;
}

static bool inode_chowned(int fd)
{
	struct stat st;
	unsigned int i;

	if (fstat(fd, &st) != 0)
		return false;
	for (i = 0; i < nr_chowned; i++) {
		if (chowned[i] == st.st_ino)
			return true;
	}
	return false;
}

/* Whether a pool fd opened as trinity-testfile<index> sits on @ino. */
static bool pool_holds(ino_t ino, unsigned int index)
{
	char name[32];
	unsigned int i;

	snprintf(name, sizeof(name), "trinity-testfile%u", index);
	for (i = 0; i < nr_files; i++) {
		struct stat st;

		if (strcmp(files[i]->testfileobj.filename, name) == 0 &&
		    fstat(files[i]->testfileobj.fd, &st) == 0 &&
		    st.st_ino == ino)
			return true;
	}
	return false;
}

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

/* Run the provider's init hook as a root run's open_fds() does, against
 * the fake object-pool hooks and the recording fchown(). */
static void run_init_as_root(int (*init)(void))
{
	uid_t saved_uid = orig_uid, saved_nobody_uid = nobody_uid;
	gid_t saved_nobody_gid = nobody_gid;

	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	orig_uid = 0;
	nobody_uid = 65534;
	nobody_gid = 65533;
	fchown_armed = true;
	init();
	fchown_armed = false;
	orig_uid = saved_uid;
	nobody_uid = saved_nobody_uid;
	nobody_gid = saved_nobody_gid;
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;
}

/* Unmap, close and unlink what an init built, and start the records over. */
static void release_pool(void)
{
	unsigned int i;

	for (i = 0; i < nr_maps; i++) {
		munmap(maps[i]->map.ptr, maps[i]->map.size);
		free_shared_str(maps[i]->map.name);
	}
	for (i = 0; i < nr_files; i++) {
		(void) unlink(files[i]->testfileobj.filename);
		close(files[i]->testfileobj.fd);
		free_shared_str((void *) files[i]->testfileobj.filename);
	}
	nr_objs = nr_files = nr_maps = nr_chowned = 0;
}

/*
 * A symlink planted under a testfile's name between init's unlink and its
 * create, as a local user racing into a world-writable tmp/ can: the file
 * it names is neither pooled, resized nor handed to nobody, and the other
 * names still fill the pool.
 */
static void check_planted_name(int (*init)(void))
{
	char base[] = "/tmp/trinity-testfile-plant.XXXXXX";
	struct stat victim, st;
	unsigned int i;
	int fd;

	if (mkdtemp(base) == NULL || chdir(base) != 0)
		BUG("testfile pool: cannot set up the planted directory");
	fd = open("victim", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || write(fd, "x", 1) != 1 || fstat(fd, &victim) != 0)
		BUG("testfile pool: cannot make the planted link's target");
	close(fd);

	fake_unlink_target = "victim";
	fake_unlink_plant = "trinity-testfile1";
	run_init_as_root(init);
	fake_unlink_plant = NULL;

	if (stat("victim", &st) != 0 || st.st_size != 1)
		BUG("testfile pool: init resized the file a planted link names");
	for (i = 0; i < nr_files; i++) {
		if (fstat(files[i]->testfileobj.fd, &st) == 0 &&
		    st.st_ino == victim.st_ino)
			BUG("testfile pool: init pooled the file a planted link names");
	}
	for (i = 0; i < nr_chowned; i++) {
		if (chowned[i] == victim.st_ino)
			BUG("testfile pool: init gave nobody the file a planted link names");
	}
	if (nr_files == 0)
		BUG("testfile pool: a planted name kept every testfile out of the pool");

	release_pool();
	if (unlink("trinity-testfile1") != 0 || unlink("victim") != 0 ||
	    chdir("/") != 0 || rmdir(base) != 0)
		BUG("testfile pool: cannot remove the planted directory");
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

	run_init_as_root(init);

	if (nr_files == 0)
		BUG("testfile pool: init opened no testfile");
	for (i = 0; i < nr_files; i++) {
		struct stat st;

		if (fstat(files[i]->testfileobj.fd, &st) != 0 || st.st_nlink == 0)
			BUG("testfile pool: a testfile fd sits on an unlinked inode");
		if (!inode_chowned(files[i]->testfileobj.fd))
			BUG("testfile pool: a root run kept a testfile from nobody");
	}
	if (fchown_stranger)
		BUG("testfile pool: a testfile went to someone other than nobody");
	if (nr_maps != nr_files)
		BUG("testfile pool: not every testfile fd was mapped");
	for (i = 0; i < nr_maps; i++) {
		if (maps[i]->map.size != page_size)
			BUG("testfile pool: a testfile mapping is not page_size long");
	}

	/* Init ran in a directory that is no tmp/ of trinity's, as in a
	 * run launched where there is none; ask from another cwd, as a
	 * child whose cwd a fuzzed chdir() moved. */
	if (chdir("/") != 0)
		BUG("testfile pool: cannot leave the test directory");
	for (i = 0; i < 16; i++) {
		unsigned int index;
		char *path = get_testfile_path_indexed(&index);
		struct stat st;

		if (path == NULL || stat(path, &st) != 0 ||
		    !pool_holds(st.st_ino, index))
			BUG("testfile pool: a testfile path names a file init did not create");
		free(path);
	}
	if (chdir(base) != 0)
		BUG("testfile pool: cannot return to the test directory");

	release_pool();
	if (chdir("/") != 0 || rmdir(base) != 0)
		BUG("testfile pool: cannot remove the test directory");

	check_planted_name(init);

	if (fchdir(cwd) != 0)
		BUG("testfile pool: cannot return to the starting directory");
	close(cwd);
}
