#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "files.h"
#include "shm.h"
#include "log.h"
#include "sanitise.h"
#include "constants.h"

static int files_added = 0;
char **fileindex;
unsigned int files_in_index = 0;

struct namelist {
	struct namelist *prev;
	struct namelist *next;
	char *name;
};

static struct namelist *names = NULL;

static uid_t my_uid;
static gid_t my_gid;

static int ignore_files(char *file)
{
	int i;
	const char *ignored_files[] = {".", "..",
		/* boring stuff in /dev */
		"dmmidi0", "dmmidi1","dmmidi2","dmmidi3",
		"midi00", "midi01","midi02","midi03",
		".udev", "log",
		/* Ignore per-process stuff. */
		"keycreate", "sockcreate", "fscreate", "exec",
		"current", "coredump_filter", "make-it-fail",
		"oom_adj", "oom_score_adj",
		"clear_refs", "loginuid", "sched", "comm", "mem",
		"task", "autogroup",
		/* ignore cgroup stuff*/
		"cgroup",
		NULL};

	for(i = 0; ignored_files[i]; i++) {
		if (!strcmp(file, ignored_files[i]))
			return 1;
	}
	if (!strncmp(file, "tty", 3))
		return 1;
	return 0;
}

static struct namelist *list_alloc(void)
{
	struct namelist *node;

	node = malloc(sizeof(struct namelist));
	if (node == NULL)
		exit(EXIT_FAILURE);
	memset(node, 0, sizeof(struct namelist));
	return node;
}

static void __list_add(struct namelist *new, struct namelist *prev, struct namelist *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static void list_add(struct namelist *list, char *name)
{
	struct namelist *newnode;

	newnode = list_alloc();

	if (list == NULL) {
		list = names = newnode;
		list->next = list;
		list->prev = list;
	}
	newnode->name = strdup(name);

	__list_add(newnode, list, list->next);
}

static void add_file_to_list(struct stat buf, char *path)
{
	int set_read = FALSE, set_write = FALSE;

	if (buf.st_uid == my_uid) {
		if (buf.st_mode & S_IRUSR)
			set_read = TRUE;
		if (buf.st_mode & S_IWUSR)
			set_write = TRUE;

	} else if (buf.st_gid == my_gid) {
		if (buf.st_mode & S_IRGRP)
			set_read = TRUE;
		if (buf.st_mode & S_IWGRP)
			set_write = TRUE;

	} else {
		if ((buf.st_mode & S_IROTH))
			set_read = TRUE;
		if (buf.st_mode & S_IWOTH)
			set_write = TRUE;
	}

	if ((set_read | set_write) == 0)
		return;

	list_add(names, path);
	files_added++;
}


static void __open_fds(const char *dir)
{
	char path[4096];
	int r;
	DIR *d;
	struct dirent *de;
	struct stat buf;
	char is_dir = FALSE;

	d = opendir(dir);
	if (!d) {
		printf("can't open %s\n", dir);
		return;
	}
	while ((de = readdir(d))) {

		if (shm->exit_reason != STILL_RUNNING)
			return;

		memset(&buf, 0, sizeof(struct stat));
		memset(&path, 0, 4096);
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (ignore_files(de->d_name))
			continue; /*".", "..", everything that's not a regular file or directory !*/

		r = lstat(path, &buf);
		if (r == -1)
			continue;

		if (S_ISLNK(buf.st_mode))
			continue;
		if (S_ISFIFO(buf.st_mode))
			continue;

		if (S_ISDIR(buf.st_mode)) {
			is_dir = TRUE;

			if (buf.st_uid != my_uid) {
				/* We don't own the dir, is it group/other readable ? */
				if (buf.st_mode & (S_IRGRP|S_IROTH)) {
					__open_fds(path);
					goto openit;
				}
				continue;
			} else {
				/* We own this dir. */
				__open_fds(path);
				goto openit;
			}

		} else {
			is_dir = FALSE;
		}

openit:
		if (is_dir == FALSE)
			add_file_to_list(buf, path);

	}
	closedir(d);
}

static void open_fds(const char *dir)
{
	int before = files_added;
	__open_fds(dir);
	output(0, "Added %d filenames from %s\n", files_added - before, dir);
}

void generate_filelist(void)
{
	unsigned int i = 0;
	struct namelist *node;
	struct stat statbuf;
	int r;

	my_uid = getuid();
	my_gid = getgid();

	output(1, "Generating file descriptors\n");

	if (victim_path != NULL) {
		r = lstat(victim_path, &statbuf);
		if (r == -1) {
			output(1, "Couldn't stat %s\n", victim_path);
			return;
		}
		if (S_ISDIR(statbuf.st_mode))
			open_fds(victim_path);
		else {
			add_file_to_list(statbuf, victim_path);
		}
	} else {
		open_fds("/dev");
		open_fds("/proc");
		open_fds("/sys");
	}

	if (files_added == 0) {
		output(1, "Didn't add any files!!\n");
		return;
	}

	if (shm->exit_reason != STILL_RUNNING)
		return;

	/*
	 * Generate an index of pointers to the filenames
	 */
	fileindex = malloc(sizeof(void *) * files_added);

	node = names;
	do {
		fileindex[i++] = node->name;
		node = node->next;
	} while (node->next != names);
	files_in_index = i;
}

static int stat_file(char *filename)
{
	struct stat buf;
	int ret;
	int openflag;
	bool set_read = FALSE;
	bool set_write = FALSE;

	memset(&buf, 0, sizeof(struct stat));
	ret = lstat(filename, &buf);
	if (ret == -1)
		return -1;

	if (buf.st_uid == my_uid) {
		if (buf.st_mode & S_IRUSR)
			set_read = TRUE;
		if (buf.st_mode & S_IWUSR)
			set_write = TRUE;

	} else if (buf.st_gid == my_gid) {
		if (buf.st_mode & S_IRGRP)
			set_read = TRUE;
		if (buf.st_mode & S_IWGRP)
			set_write = TRUE;

	} else {
		if ((buf.st_mode & S_IROTH))
			set_read = TRUE;
		if (buf.st_mode & S_IWOTH)
			set_write = TRUE;
	}

	if ((set_read | set_write) == 0)
		return -1;

	if (set_read == TRUE)
		openflag = O_RDONLY;
	if (set_write == TRUE)
		openflag = O_WRONLY;
	if ((set_read == TRUE) && (set_write == TRUE))
		openflag = O_RDWR;

	return openflag;
}

static int open_file(void)
{
	int fd;
	char *filename;
	int flags;
	const char *modestr;

retry:
	filename = get_filename();
	flags = stat_file(filename);
	if (flags == -1)
		goto retry;

	fd = open(filename, flags | O_NONBLOCK);

	switch (flags) {
	case O_RDONLY:  modestr = "read-only";  break;
	case O_WRONLY:  modestr = "write-only"; break;
	case O_RDWR:    modestr = "read-write"; break;
	default: break;
	}
	output(2, "[%d] fd[%i] = %s (%s)\n",
		getpid(), fd, filename, modestr);
	return fd;
}

void open_files(void)
{
	unsigned int i, nr_to_open;
	int fd;

	if (files_in_index < NR_FILE_FDS)
		nr_to_open = files_in_index;
	else
		nr_to_open = NR_FILE_FDS;

	if (fileindex == NULL)	/* this can happen if we ctrl-c'd */
		return;

	for (i = 0; i < nr_to_open; i++) {
		fd = open_file();

		shm->file_fds[i] = fd;
		nr_file_fds++;
	}
}

void close_files(void)
{
	unsigned int i;
	int fd;

	shm->current_fd = 0;
	shm->fd_lifetime = 0;

	// FIXME: Does this need locking? At the least, check for NULL fd's
	for (i = 0; i < nr_file_fds; i++) {
		fd = shm->file_fds[i];
		shm->file_fds[i] = 0;
		if (fd != 0)
			close(fd);
	}

	nr_file_fds = 0;
}
