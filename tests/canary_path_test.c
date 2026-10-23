/*
 * Self-check for the canary pool (fds/canary.c) and its verifier childop
 * (childops/mm/pagecache-canary-check.c): the pool sits in the directory init
 * ran in, by absolute paths, so a child whose cwd a fuzzed chdir() moved still
 * opens its own files and reads no same-named file of the new directory.  Init
 * runs through the provider's hook, against fake object-pool hooks.
 */

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "canary.h"
#include "child.h"
#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fake_parent.h"	/* fake_output_log */
#include "fd.h"
#include "fds/fds-internal.h"	/* fd_providers */
#include "list.h"
#include "objects.h"
#include "shm.h"
#include "tmpdir.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/* Verifier passes per case: enough that a case which must see corruption
 * cannot miss it by the luck of the read-path draw. */
#define NR_VERIFY	64

/* Nested directories that take the cwd past what getcwd() can name. */
#define DEEP_NAME_LEN	100
#define DEEP_LEVELS	(PATH_MAX / (DEEP_NAME_LEN + 1) + 2)

static struct object objs[NR_CANARY_FILES];
static unsigned int nr_objs;
static struct objhead fake_head;
static struct childdata fake_child;
static const char *case_name;
static unsigned int failed;

/* Owned by child/child-altop-score.c in production, where it feeds the op's
 * score; the checks read the stats the verifier bumps itself. */
void childop_direct_syscalls_add(enum child_op_type op, unsigned long n)
{
	(void)op;
	(void)n;
}

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
		BUG("canary path: the pool allocated more objects than it has files");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	(void)obj;
	(void)scope;
	(void)type;
}

static void expect(bool ok, const char *what, unsigned long got)
{
	if (ok)
		return;
	fprintf(stderr, "canary path: %s: %s (got %lu)\n", case_name, what, got);
	failed++;
}

/* Run the provider's init hook as open_fds() does, against the fake hooks. */
static int run_init(int (*init)(void))
{
	int ok;

	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	ok = init();
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;
	return ok;
}

/* Close the fds a pool published, and let the next init start over. */
static void release_pool(void)
{
	unsigned int i;

	for (i = 0; i < nr_objs; i++)
		close(objs[i].fileobj.fd);
	nr_objs = 0;
}

/* Run the verifier NR_VERIFY times, and count the passes that opened a file
 * and the corruptions it reported. */
static void run_verifier(unsigned long *opened, unsigned long *corrupt)
{
	const enum child_op_type op = CHILD_OP_PAGECACHE_CANARY_CHECK;
	unsigned long opened_before = shm->stats.childop.setup_accepted[op];
	unsigned long corrupt_before =
		shm->stats.diag.pagecache_canary_corrupt_caught;
	unsigned int i;

	fake_child.op_type = op;
	for (i = 0; i < NR_VERIFY; i++)
		pagecache_canary_check(&fake_child);

	*opened = shm->stats.childop.setup_accepted[op] - opened_before;
	*corrupt = shm->stats.diag.pagecache_canary_corrupt_caught -
		   corrupt_before;
}

/*
 * Bring the pool up with @run as the cwd, and check where it landed and that
 * a child moved away by a chdir() still reaches it.  @away has no canary/ in
 * it, @decoy holds one.  @in_tmp_dir says whether @run is trinity_tmpdir_abs().
 */
static void check_pool(int (*init)(void), const char *run, const char *away,
		       const char *decoy, bool in_tmp_dir)
{
	char cwd[PATH_MAX], want[PATH_MAX + sizeof("/canary/")];
	unsigned long opened, corrupt;
	unsigned int i, bad = 0;

	if (chdir(run) != 0 || getcwd(cwd, sizeof(cwd)) == NULL)
		BUG("canary path: cannot enter the run directory");
	if ((strcmp(cwd, trinity_tmpdir_abs()) == 0) != in_tmp_dir)
		BUG("canary path: the run directory is not set up as the case says");

	if (!run_init(init) || canary_pool_size() != NR_CANARY_FILES)
		BUG("canary path: the pool did not come up");

	/* In the directory init ran in, the tmp dir when there is one. */
	snprintf(want, sizeof(want), "%s/canary/", cwd);
	for (i = 0; i < NR_CANARY_FILES; i++) {
		if (strncmp(canary_file_get(i)->path, want, strlen(want)) != 0)
			bad++;
	}
	expect(bad == 0, "pool paths outside canary/ of the init directory", bad);

	/* A directory with no canary/ in it: the files must still be found. */
	if (chdir(away) != 0)
		BUG("canary path: cannot enter the other directory");
	run_verifier(&opened, &corrupt);
	expect(opened == NR_VERIFY,
	       "passes that could not open a pool file after a chdir",
	       NR_VERIFY - opened);

	/* A directory holding canary/<idx> files of the right sizes and the
	 * wrong bytes: none of them is the pool's. */
	if (chdir(decoy) != 0)
		BUG("canary path: cannot enter the decoy directory");
	for (i = 0; i < NR_CANARY_FILES; i++) {
		char name[16];
		int fd;

		snprintf(name, sizeof(name), "canary/%u", i);
		fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0 || ftruncate(fd, canary_file_get(i)->size) != 0)
			BUG("canary path: cannot make the decoy files");
		close(fd);
	}
	run_verifier(&opened, &corrupt);
	expect(corrupt == 0,
	       "corruption reported from a file of the new directory", corrupt);

	/* The oracle still catches what it exists to catch: a pool file whose
	 * first byte is wrong, seen from a directory the child moved to. */
	if (chdir(run) != 0)
		BUG("canary path: cannot return to the run directory");
	for (i = 0; i < NR_CANARY_FILES; i++) {
		unsigned char wrong = canary_expected_byte(i, 0) ^ 0xff;
		int fd = open(canary_file_get(i)->path, O_WRONLY);

		if (fd < 0 || pwrite(fd, &wrong, 1, 0) != 1)
			BUG("canary path: cannot corrupt a pool file");
		close(fd);
	}
	if (chdir(away) != 0)
		BUG("canary path: cannot enter the other directory");
	run_verifier(&opened, &corrupt);
	expect(corrupt > 0,
	       "no corruption reported for pool files with a wrong byte, "
	       "after a chdir", corrupt);

	release_pool();
}

/*
 * A cwd getcwd() cannot name: init has nothing to anchor the pool at, so it
 * must fail without creating one, not store a path relative to it.
 */
static void check_unnameable_cwd(int (*init)(void))
{
	char name[DEEP_NAME_LEN + 1], path[16], cwd[PATH_MAX];
	struct stat st;
	unsigned int i;
	int ok;

	memset(name, 'd', DEEP_NAME_LEN);
	name[DEEP_NAME_LEN] = '\0';
	for (i = 0; i < DEEP_LEVELS; i++) {
		if (mkdir(name, 0700) != 0 || chdir(name) != 0)
			BUG("canary path: cannot make the deep directories");
	}
	if (getcwd(cwd, sizeof(cwd)) != NULL)
		BUG("canary path: getcwd() still names the deep directory");

	ok = run_init(init);
	expect(!ok, "init succeeded in a cwd getcwd() cannot name", ok);
	expect(canary_pool_size() == 0,
	       "files in a pool built in a cwd getcwd() cannot name",
	       canary_pool_size());
	expect(stat("canary", &st) != 0,
	       "a canary/ made in a cwd getcwd() cannot name", 1);

	/* Whatever a pool built here left behind goes before the climb. */
	for (i = 0; i < NR_CANARY_FILES; i++) {
		snprintf(path, sizeof(path), "canary/%u", i);
		unlink(path);
	}
	rmdir("canary");
	for (i = 0; i < DEEP_LEVELS; i++) {
		if (chdir("..") != 0 || rmdir(name) != 0)
			BUG("canary path: cannot remove the deep directories");
	}
	release_pool();
}

static int remove_entry(const char *path, const struct stat *sb, int type,
			struct FTW *ftw)
{
	(void)sb;
	(void)type;
	(void)ftw;
	return remove(path);
}

void canary_path_self_check(void);
void canary_path_self_check(void)
{
	char base[] = "/tmp/trinity-canary-test.XXXXXX";
	char away[sizeof(base) + sizeof("/away")];
	char decoy[sizeof(base) + sizeof("/decoy")];
	char launch[sizeof(base) + sizeof("/launch")];
	int (*init)(void) = NULL;
	struct list_head *node;
	int cwd;

	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0 ||
	    mkdir("tmp", 0700) != 0 || mkdir("away", 0700) != 0 ||
	    mkdir("decoy", 0700) != 0 || mkdir("decoy/canary", 0700) != 0 ||
	    mkdir("launch", 0700) != 0)
		BUG("canary path: cannot set up the test tree");
	snprintf(away, sizeof(away), "%s/away", base);
	snprintf(decoy, sizeof(decoy), "%s/decoy", base);
	snprintf(launch, sizeof(launch), "%s/launch", base);

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "canary") == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("canary path: the canary provider is not registered");

	case_name = "cwd past what getcwd() names";
	check_unnameable_cwd(init);

	/* main() has moved into tmp/ by the time open_fds() runs. */
	change_tmp_dir();
	case_name = "with a tmp/ dir";
	check_pool(init, trinity_tmpdir_abs(), away, decoy, true);

	/* No tmp/ here: change_tmp_dir() leaves the cwd alone, and
	 * trinity_tmpdir_abs() keeps naming the dir above, standing in for the
	 * fixed /tmp a run that never had one gets.  The pool stays in the cwd. */
	if (chdir(launch) != 0)
		BUG("canary path: cannot enter the launch directory");
	change_tmp_dir();
	case_name = "without a tmp/ dir";
	check_pool(init, launch, away, decoy, false);

	if (fchdir(cwd) != 0)
		BUG("canary path: cannot return to the starting directory");
	close(cwd);
	fake_output_log[0] = '\0';
	if (nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS) != 0)
		BUG("canary path: cannot remove the test tree");

	if (failed != 0)
		BUG("canary path: a check failed");
}
