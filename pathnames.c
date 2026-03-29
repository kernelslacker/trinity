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

unsigned int files_in_index = 0;
const char **fileindex;

#define MAX_PATHNAME_POOLS 4

struct pathname_pool {
	unsigned int start;	/* index into fileindex[] */
	unsigned int count;
};

static struct pathname_pool pools[MAX_PATHNAME_POOLS];
static unsigned int num_pools;

struct namelist {
	struct list_head list;
	const char *name;
};

static struct namelist *names = NULL;

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

	/* By default, don't follow symlinks so we only get each file once.
	 * But, if we do something like -V /lib, then follow it
	 *
	 * I'm not sure about this, might remove later.
	 */
	if (nr_victim_paths == 0)
		flags |= FTW_PHYS;

	ret = nftw(dirpath, file_tree_callback, 32, flags);
	if (ret != 0) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != EXIT_SIGINT)
			output(0, "Something went wrong during nftw(%s). (%d:%s)\n",
				dirpath, ret, strerror(errno));
		return;
	}

	output(0, "Added %d filenames from %s\n", files_in_index - before, dirpath);
}

/* Generate an index of pointers to the filenames */
static const char ** list_to_index(struct namelist *namelist)
{
	struct list_head *node, *tmp;
	struct namelist *nl;
	const char **findex;
	unsigned int i = 0;

	findex = zmalloc(sizeof(char *) * files_in_index);

	list_for_each_safe(node, tmp, &namelist->list) {
		nl = (struct namelist *) node;
		findex[i++] = nl->name;

		/* Destroy the list head, but keep the ->name alloc because
		 * now the index points to it.
		 */
		list_del(&nl->list);
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

const char * generate_pathname(void)
{
	const char *pathname = get_filename();
	char *newpath;
	unsigned int len;

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
