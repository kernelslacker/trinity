#include <ftw.h>
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

struct namelist {
	struct list_head list;
	const char *name;
};

static struct namelist *names = NULL;

static int ignore_files(const char *path)
{
	unsigned int i, j;
	unsigned int pathlen, offset = 0;

	/* These are exact matches. */
	const char *ignored_paths[] = {
		".", "..",

		/* dangerous/noisy/annoying stuff in /proc */
		"/proc/sysrq-trigger", "/proc/kmem", "/proc/kcore",

		/* dangerous/noisy/annoying stuff in /dev */
		"/dev/log", "/dev/mem", "/dev/kmsg", "/dev/kmem",
		NULL
	};

	/* Partial matches. */	//FIXME: This whole function should just use globs to pattern match.
	const char *ignored_patterns[] = {

		/* dangerous/noisy/annoying per-process stuff. */
		"coredump_filter", "make-it-fail", "oom_adj", "oom_score_adj",
		NULL
	};

	pathlen = strlen(path);

	/* First do the exact matches */
	for (i = 0; ignored_paths[i]; i++) {
		if (strlen(ignored_paths[i]) != pathlen) {
			continue;
		}

		if (!strcmp(path, ignored_paths[i])) {
			debugf("Skipping %s\n", path);
			return 1;
		}
	}

	/* Now make sure none of the patterns match the end of the pathname */
	for (j = 0; j < pathlen; j++) {
		if (path[j] == '/')
			offset = j;
	}
	offset++;

	if (offset == 1)
		return 0;

	for (i = 0; ignored_patterns[i]; i++) {
		if (!strcmp(path + offset, ignored_patterns[i])) {
			debugf("Skipping pattern %s\n", path);
			return 1;
		}
	}

	/* special case to match tty* until I do globbing */
	if (!strncmp(path + offset, "tty", 3)) {
		debugf("Skipping %s\n", path);
		return 1;
	}

	/* seriously though, I should add globbing */
	if (!strncmp(path + offset, "sd", 2)) {
		debugf("Skipping %s\n", path);
		return 1;
	}

	return 0;
}

static void add_to_namelist(const char *name)
{
	struct namelist *newnode;

	newnode = zmalloc(sizeof(struct namelist));
	newnode->name = strdup(name);
	INIT_LIST_HEAD(&newnode->list);
	list_add_tail(&newnode->list, &names->list);
}

int check_stat_file(const struct stat *sb)
{
	int openflag = 0;
	bool set_read = FALSE;
	bool set_write = FALSE;
	uid_t target_uid = orig_uid;
	gid_t target_gid = orig_gid;

	if (dropprivs == TRUE) {
		target_uid = nobody_uid;
		target_gid = nobody_gid;
	}

	if (S_ISLNK(sb->st_mode))
		return -1;

	if (sb->st_uid == target_uid) {
		if (sb->st_mode & S_IRUSR)
			set_read = TRUE;
		if (sb->st_mode & S_IWUSR)
			set_write = TRUE;
	}

	if (sb->st_gid == target_gid) {
		if (sb->st_mode & S_IRGRP)
			set_read = TRUE;
		if (sb->st_mode & S_IWGRP)
			set_write = TRUE;
	}

	if (sb->st_mode & S_IROTH)
		set_read = TRUE;
	if (sb->st_mode & S_IWOTH)
		set_write = TRUE;


	if (set_read == 0 && set_write == 0)
		return -1;

	if (set_read == TRUE)
		openflag = O_RDONLY;
	if (set_write == TRUE)
		openflag = O_WRONLY;
	if ((set_read == TRUE) && (set_write == TRUE))
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

	// Check we can read it.
	if (check_stat_file(sb) == -1)
		return FTW_CONTINUE;

	if (shm->exit_reason != STILL_RUNNING)
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
	if (victim_path == NULL)
		flags |= FTW_PHYS;

	ret = nftw(dirpath, file_tree_callback, 32, flags);
	if (ret != 0) {
		if (shm->exit_reason != EXIT_SIGINT)
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

void generate_filelist(void)
{
	names = zmalloc(sizeof(struct namelist));
	INIT_LIST_HEAD(&names->list);

	output(1, "Generating file descriptors\n");

	if (victim_path != NULL) {
		open_fds_from_path(victim_path);
	} else {
		open_fds_from_path("/dev");
		open_fds_from_path("/proc");
		open_fds_from_path("/sys");
	}

	if (shm->exit_reason != STILL_RUNNING)
		return;

	if (files_in_index == 0) {
		output(1, "Didn't add any files!!\n");
		return;
	}
	fileindex = list_to_index(names);
}

const char * get_filename(void)
{
	if (files_in_index == 0)	/* This can happen if we run with -n. Should we do something else ? */
		return NULL;

	return fileindex[rnd() % files_in_index];
}

const char * generate_pathname(void)
{
	const char *pathname = get_filename();
	char *newpath;
	unsigned int len;

	if (pathname == NULL)
		return NULL;

	/* 90% chance of returning an unmangled filename */
	if (!ONE_IN(10))
		return strdup(pathname);

	/* Create a bogus filename. */
	newpath = zmalloc(MAX_PATH_LEN);

	len = strlen(pathname);

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
