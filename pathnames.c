#include <ftw.h>
#include <ctype.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "exit.h"
#include "params.h"
#include "pathnames.h"
#include "random.h"
#include "shm.h"
#include "uid.h"
#include "utils.h"

#ifndef FTW_ACTIONRETVAL
#define FTW_ACTIONRETVAL 0
#define FTW_CONTINUE 0
#define FTW_SKIP_SUBTREE 0
#define FTW_STOP 1
#endif

/*
 * Maximum number of paths collected by the startup walk.  Caps memory and
 * walk time — large /sys trees can contain tens of thousands of entries.
 */
#define MAX_WALKED_PATHS 10000

/*
 * Probability (0-100) that generate_pathname() draws from the walked pool
 * rather than from the hardcoded interesting-paths list.  The hardcoded
 * list is a lightweight fallback that guarantees coverage of a few
 * high-value paths even when the walk yields nothing (e.g. running
 * unprivileged in a container with a minimal /proc).
 */
#define WALKED_PATH_RATIO 50

unsigned int files_in_index = 0;
const char **fileindex;

#define MAX_PATHNAME_POOLS 4

struct pathname_pool {
	unsigned int start;	/* index into fileindex[] */
	unsigned int count;
};

static struct pathname_pool pools[MAX_PATHNAME_POOLS];
static unsigned int num_pools;

/* Set to true when the walk terminates early due to MAX_WALKED_PATHS. */
static bool pool_cap_reached;

struct namelist {
	struct list_head list;
	const char *name;
};

static struct namelist *names = NULL;

/*
 * Hardcoded paths that are guaranteed to exist on a standard Linux system.
 * Used when WALKED_PATH_RATIO says to skip the walked pool, ensuring that
 * a few high-signal paths always get exercised regardless of walk results.
 */
static const char * const interesting_paths[] = {
	"/dev/null", "/dev/zero", "/dev/urandom", "/dev/full",
	"/dev/stdin", "/dev/stdout",
	"/proc/self/status", "/proc/self/maps", "/proc/self/cmdline",
	"/proc/version", "/proc/meminfo", "/proc/cpuinfo",
	"/sys/kernel/vmcoreinfo",
	NULL
};

static int ignore_files(const char *path)
{
	unsigned int i;

	/* These are exact matches. */
	const char *ignored_paths[] = {
		".", "..",

		/* dangerous/noisy/annoying stuff in /proc */
		"/proc/sysrq-trigger", "/proc/kmem", "/proc/kcore",

		/* dangerous/noisy/annoying stuff in /dev */
		"/dev/log", "/dev/mem", "/dev/kmsg", "/dev/kmem",
		NULL
	};

	/*
	 * Prefix matches: skip entire subtrees that are privileged,
	 * dangerous, or have no fuzzing value.
	 *
	 * /sys/kernel/debug  — debugfs, requires CAP_SYS_ADMIN; most nodes
	 *                      are not readable unprivileged and walking it is
	 *                      noisy.
	 * /sys/firmware/efi/efivars — EFI variables: writing to these can
	 *                      permanently brick the machine.  Skip entirely.
	 */
	const char *ignored_prefixes[] = {
		"/sys/kernel/debug/",
		"/sys/firmware/efi/efivars/",
		/*
		 * Pseudo-terminal device files.  The basename-pattern check
		 * below catches /dev/tty* but a /dev/pts/<N> entry has the
		 * basename "<N>" (just a number) and slips through.  A child
		 * that opens the operator's pts and writes to it spews garbage
		 * bytes into the controlling terminal even with the dup2-to-
		 * /dev/null + setsid() guards in init_child, because /dev/pts
		 * opens are by-path and bypass the controlling-terminal layer.
		 */
		"/dev/pts/",
		NULL
	};

	/* Basename patterns matched with fnmatch(). */
	const char *ignored_patterns[] = {
		/* dangerous/noisy/annoying per-process stuff. */
		"coredump_filter",
		"make-it-fail",
		"oom_adj",
		"oom_score_adj",

		/* tty and sd devices */
		"tty*",
		"sd*",
		NULL
	};

	for (i = 0; ignored_paths[i]; i++) {
		if (strcmp(path, ignored_paths[i]) == 0) {
			debugf("Skipping %s\n", path);
			return 1;
		}
	}

	for (i = 0; ignored_prefixes[i]; i++) {
		if (strncmp(path, ignored_prefixes[i], strlen(ignored_prefixes[i])) == 0) {
			debugf("Skipping prefix %s\n", path);
			return 1;
		}
	}

	/* Match patterns against the basename component of the path. */
	const char *base = strrchr(path, '/');
	if (base == NULL)
		return 0;
	base++;

	for (i = 0; ignored_patterns[i]; i++) {
		if (fnmatch(ignored_patterns[i], base, 0) == 0) {
			debugf("Skipping pattern %s\n", path);
			return 1;
		}
	}

	return 0;
}

static void add_to_namelist(const char *name)
{
	struct namelist *newnode;

	newnode = zmalloc(sizeof(struct namelist));
	newnode->name = strdup(name);
	if (!newnode->name) {
		free(newnode);
		return;
	}
	INIT_LIST_HEAD(&newnode->list);
	list_add_tail(&newnode->list, &names->list);
}

int check_stat_file(const struct stat *sb)
{
	int openflag = 0;
	bool set_read = false;
	bool set_write = false;
	uid_t target_uid = orig_uid;
	gid_t target_gid = orig_gid;

	if (dropprivs == true) {
		target_uid = nobody_uid;
		target_gid = nobody_gid;
	}

	if (S_ISLNK(sb->st_mode))
		return -1;

	if (sb->st_uid == target_uid) {
		if (sb->st_mode & S_IRUSR)
			set_read = true;
		if (sb->st_mode & S_IWUSR)
			set_write = true;
	}

	if (sb->st_gid == target_gid) {
		if (sb->st_mode & S_IRGRP)
			set_read = true;
		if (sb->st_mode & S_IWGRP)
			set_write = true;
	}

	if (sb->st_mode & S_IROTH)
		set_read = true;
	if (sb->st_mode & S_IWOTH)
		set_write = true;


	if (set_read == 0 && set_write == 0)
		return -1;

	if (set_read == true)
		openflag = O_RDONLY;
	if (set_write == true)
		openflag = O_WRONLY;
	if ((set_read == true) && (set_write == true))
		openflag = O_RDWR;

	if (S_ISDIR(sb->st_mode))
		openflag = O_RDONLY;

	return openflag;
}

static int file_tree_callback(const char *fpath, const struct stat *sb, int typeflag, __unused__ struct FTW *ftwbuf)
{
	if (typeflag == FTW_DNR)
		return FTW_CONTINUE;

	if (typeflag == FTW_NS)
		return FTW_CONTINUE;

	if (ignore_files(fpath))
		return FTW_SKIP_SUBTREE;

	/* Skip /proc/<pid>/ directories — operations on per-process procfs
	 * files trigger ptrace_may_access() checks against random pids.
	 * TODO: Revisit this once we have proper child isolation (unshare).
	 * With a pid namespace we could safely fuzz /proc/<pid>/ without
	 * affecting processes outside the sandbox. */
	if (strncmp(fpath, "/proc/", 6) == 0 && isdigit(fpath[6]))
		return FTW_SKIP_SUBTREE;

	/* Stop collecting once the pool cap is reached. */
	if (files_in_index >= MAX_WALKED_PATHS) {
		pool_cap_reached = true;
		return FTW_STOP;
	}

	// Check we can read it.
	if (check_stat_file(sb) == -1)
		return FTW_CONTINUE;

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		return FTW_STOP;

	add_to_namelist(fpath);
	files_in_index++;

	return FTW_CONTINUE;
}

static void open_fds_from_path(const char *dirpath)
{
	int before = files_in_index;
	int flags = FTW_DEPTH | FTW_ACTIONRETVAL | FTW_MOUNT;
	int ret;

	pool_cap_reached = false;

	/* By default, don't follow symlinks so we only get each file once.
	 * But, if we do something like -V /lib, then follow it
	 *
	 * I'm not sure about this, might remove later.
	 */
	if (nr_victim_paths == 0)
		flags |= FTW_PHYS;

	ret = nftw(dirpath, file_tree_callback, 32, flags);
	if (ret != 0 && !pool_cap_reached) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != EXIT_SIGINT)
			output(0, "Something went wrong during nftw(%s). (%d:%s)\n",
				dirpath, ret, strerror(errno));
		return;
	}

	output(0, "Added %d filenames from %s\n", files_in_index - before, dirpath);
}

/*
 * Build the fileindex from the namelist, storing all strings in a single
 * alloc_shared_global() slab so children inherit them via MAP_SHARED rather
 * than as COW heap pages.  The index array itself is also shared-global so
 * freeze_global_objects() can mprotect it read-only before the first child
 * is forked.
 */
static const char ** list_to_index(struct namelist *namelist)
{
	struct list_head *node, *tmp;
	struct namelist *nl;
	const char **findex;
	unsigned int i = 0;
	unsigned int total_str_bytes = 0;
	char *slab;
	unsigned int slab_off = 0;

	/* First pass: measure total string storage needed. */
	list_for_each(node, &namelist->list) {
		nl = (struct namelist *) node;
		total_str_bytes += strlen(nl->name) + 1;
	}

	{
		size_t findex_bytes;

		if (!shared_size_mul(files_in_index, sizeof(char *), &findex_bytes)) {
			outputerr("list_to_index: files_in_index=%u * sizeof(char *) overflows size_t\n",
				  files_in_index);
			exit(EXIT_FAILURE);
		}
		findex = alloc_shared_global(findex_bytes);
	}
	slab = alloc_shared_global(total_str_bytes ? total_str_bytes : 1);

	/* Second pass: copy strings into the slab and build the index. */
	list_for_each_safe(node, tmp, &namelist->list) {
		nl = (struct namelist *) node;
		unsigned int len = strlen(nl->name) + 1;

		memcpy(slab + slab_off, nl->name, len);
		findex[i++] = slab + slab_off;
		slab_off += len;

		list_del(&nl->list);
		free((char *) nl->name);
		free(nl);
	}
	free(names);
	names = NULL;

	return findex;
}

static void add_pool(const char *dirpath)
{
	unsigned int before = files_in_index;

	open_fds_from_path(dirpath);

	if (files_in_index > before && num_pools < MAX_PATHNAME_POOLS) {
		pools[num_pools].start = before;
		pools[num_pools].count = files_in_index - before;
		num_pools++;
	}
}

void generate_filelist(void)
{
	/* Only generate once — multiple providers may call this. */
	if (fileindex != NULL)
		return;

	names = zmalloc(sizeof(struct namelist));
	INIT_LIST_HEAD(&names->list);

	output(1, "Generating file descriptors\n");

	num_pools = 0;

	if (nr_victim_paths > 0) {
		unsigned int i;
		for (i = 0; i < nr_victim_paths; i++)
			add_pool(victim_paths[i]);
	} else {
		add_pool("/dev");
		add_pool("/proc");
		add_pool("/sys");
	}

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		return;

	if (files_in_index == 0) {
		output(1, "Didn't add any files!!\n");
		return;
	}
	fileindex = list_to_index(names);
}

const char * get_filename(void)
{
	struct pathname_pool *pool;

	if (files_in_index == 0)	/* This can happen if we run with -n. Should we do something else ? */
		return NULL;

	/* Pick a pool first so /dev gets equal probability with /proc and /sys
	 * despite having far fewer files. */
	if (num_pools > 1) {
		pool = &pools[rand() % num_pools];
		return fileindex[pool->start + rand() % pool->count];
	}

	return fileindex[rand() % files_in_index];
}

const char * get_filename_for_pool(unsigned int pool_id)
{
	struct pathname_pool *pool;

	if (pool_id >= num_pools)
		return NULL;

	pool = &pools[pool_id];
	if (pool->count == 0)
		return NULL;

	return fileindex[pool->start + rand() % pool->count];
}

unsigned int get_pool_file_count(unsigned int pool_id)
{
	if (pool_id >= num_pools)
		return 0;
	return pools[pool_id].count;
}

/* Return a random path from the startup-walked pool, or NULL if empty. */
const char * get_random_walked_pathname(void)
{
	return get_filename();
}

const char * generate_pathname(void)
{
	const char *pathname;
	char *newpath;
	unsigned int len;

	/*
	 * WALKED_PATH_RATIO percent of the time, draw from the startup-walked
	 * pool of real filesystem paths (/dev, /proc, /sys).  The rest of the
	 * time, pick from a small hardcoded list of paths that are guaranteed
	 * to exist and are known to exercise interesting kernel code paths.
	 * This ensures some coverage even in container environments where the
	 * walk yields few or no readable entries.
	 */
	if (files_in_index > 0 && (int)(rand() % 100) < WALKED_PATH_RATIO) {
		pathname = get_filename();
	} else {
		unsigned int n;

		for (n = 0; interesting_paths[n] != NULL; n++)
			;
		pathname = interesting_paths[rand() % n];
	}

	if (pathname == NULL)
		return NULL;

	newpath = zmalloc(MAX_PATH_LEN);

	len = strlen(pathname);

	/* 90% chance of returning an unmangled filename. */
	if (!ONE_IN(10)) {
		memcpy(newpath, pathname, len + 1);
		return newpath;
	}

	/* Create a bogus filename. */

	if (RAND_BOOL())
		(void) memcpy(newpath, pathname, len);
	else {
		if (len < MAX_PATH_LEN - 2) {
			/* make it look relative to cwd */
			newpath[0] = '.';
			newpath[1] = '/';
			(void) memcpy(newpath + 2, pathname, len);
			len += 2;
		}
	}

	/* 50/50 chance of making it look like a dir */
	if (RAND_BOOL()) {
		if (len <= MAX_PATH_LEN - 2) {
			newpath[len] = '/';
			newpath[len + 1] = 0;
		}
	}

	return newpath;
}
