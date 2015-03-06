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

#include "fd.h"
#include "files.h"
#include "list.h"
#include "log.h"
#include "maps.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "syscalls/syscalls.h"
#include "trinity.h"	// __unused__
#include "uid.h"
#include "utils.h"

unsigned int files_in_index = 0;
const char **fileindex;
unsigned int nr_file_fds = 0;

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
		"/dev/log", "/dev/mem", "/dev/kmsg",
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
	return 0;
}

static void add_to_namelist(const char *name)
{
	struct namelist *newnode;

	newnode = zmalloc(sizeof(struct namelist));
	newnode->name = strdup(name);
	list_add_tail(&newnode->list, &names->list);
}

static int check_stat_file(const struct stat *sb)
{
	int openflag;
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


	if ((set_read | set_write) == 0)
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

static void generate_filelist(void)
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

int open_with_fopen(const char *filename, int flags)
{
	FILE *file;
	int fd = -1;
	char mode[3]="   ";

	switch (flags) {
	case O_RDONLY:  mode[0] = 'r';
			mode[1] = 0;
			break;
	case O_WRONLY:  mode[0] = 'w';
			mode[1] = 0;
			break;
	case O_RDWR:    mode[0] = 'w';
			mode[1] = '+';
			mode[2] = 0;
			break;
	}

	file = fopen(filename, mode);
	if (file)
		fd = fileno(file);

	return fd;
}

static int open_file(void)
{
	const char *filename;
	const char *modestr;
	struct stat sb;
	int fd;
	int ret;
	int tries = 0;
	int fcntl_flags;
	int flags, randflags;
	bool opened_with_fopen = FALSE;

retry:
	filename = get_filename();
	ret = lstat(filename, &sb);
	if (ret == -1)
		goto retry;

	flags = check_stat_file(&sb);
	if (flags == -1)
		goto retry;

	/* OR in some random flags. */
retry_flags:

	if (RAND_BOOL()) {
		randflags = get_o_flags();
		fd = open(filename, flags | randflags | O_NONBLOCK);
	} else {
		fd = open_with_fopen(filename, flags);
		fcntl_flags = random_fcntl_setfl_flags();
		fcntl(fd, F_SETFL, fcntl_flags);
		opened_with_fopen = TRUE;
	}

	if (fd < 0) {
		/*
		 * if we failed to open the file, retry with different flags.
		 * we should eventually succeed, but set an arbitary upper limit of
		 * 50 tries before just giving up.
		 */
		tries++;
		if (tries == 50) {
			output(2, "Couldn't open %s : %s\n", filename, strerror(errno));
			return fd;
		}
		goto retry_flags;
	}

	switch (flags) {
	case O_RDONLY:  modestr = "read-only";  break;
	case O_WRONLY:  modestr = "write-only"; break;
	case O_RDWR:    modestr = "read-write"; break;
	default: modestr = "unknown"; break;
	}
	if (opened_with_fopen == FALSE)
		output(2, "fd[%i] = open %s (%s) flags:%x\n", fd, filename, modestr, flags | randflags);
	else
		output(2, "fd[%i] = fopen %s (%s) flags:%x fcntl_flags:%x\n",
				fd, filename, modestr, flags, fcntl_flags);
	return fd;
}

static int open_files(void)
{
	unsigned int i, nr_to_open;

	generate_filelist();

	if (files_in_index == 0) {
		/* Something bad happened. Crappy -V maybe? */
		panic(EXIT_NO_FILES);
		return FALSE;
	}

	nr_to_open = min(files_in_index, NR_FILE_FDS);

	if (fileindex == NULL)	/* this can happen if we ctrl-c'd */
		return FALSE;

	for (i = 0; i < nr_to_open; i++) {
		int fd;

		fd = open_file();

		shm->file_fds[i] = fd;
		nr_file_fds++;
	}
	return TRUE;
}

const char * get_filename(void)
{
	if (files_in_index == 0)	/* This can happen if we run with -n. Should we do something else ? */
		return NULL;

	return fileindex[rand() % files_in_index];
}

static int get_rand_file_fd(void)
{
	unsigned int fd_index;

	if (nr_file_fds == 0)
		return -1;

	fd_index = rand() % nr_file_fds;
	return shm->file_fds[fd_index];
}

const struct fd_provider file_fd_provider = {
	.name = "pseudo",	// FIXME: Use separate providers for dev/sysfs/procfs
	.enabled = TRUE,
	.open = &open_files,
	.get = &get_rand_file_fd,
};
