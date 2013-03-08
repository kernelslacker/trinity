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
#include <linux/kdev_t.h>

#include "trinity.h"	// __unused__
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

static int ignore_files(const char *file)
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

	//FIXME: Broken, 'file' is now a full pathname.

	for(i = 0; ignored_files[i]; i++) {
		if (!strcmp(file, ignored_files[i])) {
			//printf("Skipping %s\n", fpath);
			return 1;
		}
	}
	if (!strncmp(file, "tty", 3)) {
		//printf("Skipping %s\n", fpath);
		return 1;
	}
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

static void list_add(struct namelist *list, const char *name)
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

static int check_stat_file(const struct stat *sb)
{
	int openflag;
	bool set_read = FALSE;
	bool set_write = FALSE;

	if (S_ISLNK(sb->st_mode))
		return -1;

	if (sb->st_uid == my_uid) {
		if (sb->st_mode & S_IRUSR)
			set_read = TRUE;
		if (sb->st_mode & S_IWUSR)
			set_write = TRUE;

	} else if (sb->st_gid == my_gid) {
		if (sb->st_mode & S_IRGRP)
			set_read = TRUE;
		if (sb->st_mode & S_IWGRP)
			set_write = TRUE;

	} else {
		if ((sb->st_mode & S_IROTH))
			set_read = TRUE;
		if (sb->st_mode & S_IWOTH)
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

	if (S_ISDIR(sb->st_mode))
		openflag = O_RDONLY;

	return openflag;
}

static int file_tree_callback(const char *fpath, const struct stat *sb, __unused__ int typeflag, __unused__ struct FTW *ftwbuf)
{

	if (ignore_files(fpath)) {
		return FTW_SKIP_SUBTREE;
	}

	// Check we can read it.
	if (check_stat_file(sb) == -1)
		return FTW_CONTINUE;

	if (shm->exit_reason != STILL_RUNNING)
		return FTW_STOP;

	list_add(names, fpath);
	//printf("Adding %s\n", fpath);
	files_added++;

	return FTW_CONTINUE;
}


static void open_fds(const char *dirpath)
{
	int before = files_added;
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
		output(0, "Something went wrong during nftw(). Returned %d\n", ret);
		return;
	}

	output(0, "Added %d filenames from %s\n", files_added - before, dirpath);
}

void generate_filelist(void)
{
	unsigned int i = 0;
	struct namelist *node;

	my_uid = getuid();
	my_gid = getgid();

	output(1, "Generating file descriptors\n");

	if (victim_path != NULL) {
		open_fds(victim_path);
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

static int open_file(void)
{
	int fd;
	int ret;
	char *filename;
	int flags;
	const char *modestr;
	struct stat sb;

retry:
	filename = get_filename();
	ret = lstat(filename, &sb);
	if (ret == -1)
		goto retry;

	flags = check_stat_file(&sb);
	if (flags == -1)
		goto retry;

	fd = open(filename, flags | O_NONBLOCK);
	if (fd < 0) {
		output(2, "Couldn't open %s : %s\n", filename, strerror(errno));
		return fd;
	}

	switch (flags) {
	case O_RDONLY:  modestr = "read-only";  break;
	case O_WRONLY:  modestr = "write-only"; break;
	case O_RDWR:    modestr = "read-write"; break;
	default: modestr = "unknown"; break;
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

char * get_filename(void)
{
	return fileindex[rand() % files_in_index];
}


static struct {
	int major;
	int minor;
	char *name;
} *block_devs, *char_devs, *misc_devs;

static size_t bldevs, chrdevs, miscdevs;

static void parse_proc_devices(void)
{
	FILE *fp;
	char *name, *line = NULL;
	size_t n = 0;
	int block, major;
	void *new;

	fp = fopen("/proc/devices", "r");
	if (!fp)
		return;

	block = 0;

	while (getline(&line, &n, fp) >= 0) {
		if (strcmp("Block devices:\n", line) == 0)
			block = 1;
		else if (sscanf(line, "%d %as", &major, &name) == 2) {
			if (block) {
				new = realloc(block_devs, (bldevs+1)*sizeof(*block_devs));
				if (!new) {
					free(name);
					continue;
				}
				block_devs = new;
				block_devs[bldevs].major = major;
				block_devs[bldevs].minor = 0;
				block_devs[bldevs].name = name;
				bldevs++;
			} else {
				new = realloc(char_devs, (chrdevs+1)*sizeof(*char_devs));
				if (!new) {
					free(name);
					continue;
				}
				char_devs = new;
				char_devs[chrdevs].major = major;
				char_devs[chrdevs].minor = 0;
				char_devs[chrdevs].name = name;
				chrdevs++;
			}
		}
	}

	fclose(fp);
	free(line);
}

static void parse_proc_misc(void)
{
	FILE *fp;
	char *name;
	int minor;
	void *new;

	fp = fopen("/proc/misc", "r");
	if (!fp)
		return;

	while (fscanf(fp, "%d %as", &minor, &name) == 2) {
		new = realloc(misc_devs, (miscdevs+1)*sizeof(*misc_devs));
		if (!new) {
			free(name);
			continue;
		}
		misc_devs = new;
		misc_devs[miscdevs].major = 0;
		misc_devs[miscdevs].minor = minor;
		misc_devs[miscdevs].name = name;
		miscdevs++;
	}

	fclose(fp);
}

void parse_devices(void)
{
	parse_proc_devices();
	parse_proc_misc();

	output(2, "Parsed %zu char devices, %zu block devices, %zu misc devices.\n",
			chrdevs, bldevs, miscdevs);
}

const char *map_dev(dev_t st_rdev, mode_t st_mode)
{
	int major, minor;
	size_t i, j;

	major = MAJOR(st_rdev);
	minor = MINOR(st_rdev);

	if (S_ISCHR(st_mode))
		for (i=0; i < chrdevs; ++i)
			if (char_devs[i].major == major) {
				if (strcmp(char_devs[i].name, "misc") == 0) {
					for (j=0; j < miscdevs; ++j)
						if (misc_devs[j].minor == minor)
							return misc_devs[j].name;
				} else
					return char_devs[i].name;
			}
	else if (S_ISBLK(st_mode))
		for (i=0; i < bldevs; ++i)
			if (block_devs[i].major == major)
				return block_devs[i].name;

	return NULL;
}
