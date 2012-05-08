#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trinity.h"
#include "shm.h"
#include "constants.h"

static int ignore_files(char *file)
{
	int i;
	const char *ignored_files[] = {".", "..",
		/* boring stuff in /dev */
		"dmmidi0", "dmmidi1","dmmidi2","dmmidi3",
		"midi00", "midi01","midi02","midi03",
		".udev",
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

char *pathnames[NR_PATHNAMES];
unsigned int pathname_idx = 0;

static int add_fd(unsigned int chance, char *pathname, int flags)
{
	int fd = -1;

	if ((unsigned int)(rand() % 5000) < chance)
		if (pathname_idx < NR_PATHNAMES)
			pathnames[pathname_idx++] = strdup(pathname);

	if ((unsigned int)(rand() % 5000) < chance) {
		fd = open(pathname, flags | O_NONBLOCK);
		if (fd < 0)
			return -1;
//		printf("Added: %s\n", pathname);
	}
	return fd;
}

void open_fds(const char *dir)
{
	char b[4096];
	int openflag, fd, r;
	DIR *d = opendir(dir);
	struct dirent *de;
	struct stat buf;
	const char *modestr;
	unsigned int chance;

	if (!d) {
		printf("can't open %s\n", dir);
		return;
	}
	while ((de = readdir(d))) {

		memset(&buf, 0, sizeof(struct stat));
		snprintf(b, sizeof(b), "%s/%s", dir, de->d_name);
		if (ignore_files(de->d_name))
			continue; /*".", "..", everything that's not a regular file or directory !*/
		r = lstat(b,&buf);
		if (r == -1)
			continue;
		openflag = 0;
		if (S_ISLNK(buf.st_mode))
			continue;
		if (S_ISFIFO(buf.st_mode))
			continue;
		//if (S_ISREG(buf.st_mode))
		//	continue;
		if (S_ISDIR(buf.st_mode)) {
			/* probability of adding a directory to the list. */
			chance = 5;
			openflag = O_RDONLY;
			if (buf.st_uid != getuid()) {
				/* We don't own the dir, is it group/other readable ? */
				if (buf.st_mode & (S_IRGRP|S_IROTH)) {
					open_fds(b);
					goto openit;
				}
			} else {
				/* We own this dir. */
				open_fds(b);
				goto openit;
			}
		} else {
			int mode_was_set = 0;

			/* if we own the file, unlikely, since you should NOT run this thing as root */
			if (buf.st_uid == getuid()) {
				if (buf.st_mode & S_IRUSR) {
					openflag &= O_RDONLY;
					mode_was_set = 1;
				}
				if (buf.st_mode & S_IWUSR) {
					openflag |= O_WRONLY;
					mode_was_set = 1;
				}
			} else if (buf.st_gid == getgid()) {
				if (buf.st_mode & S_IRGRP) {
					openflag &= O_RDONLY;
					mode_was_set = 1;
				}
				if (buf.st_mode & S_IWGRP) {
					openflag |= O_WRONLY;
					mode_was_set = 1;
				}
			} else {
				if (buf.st_mode & S_IROTH) {
					openflag &= O_RDONLY;
					mode_was_set = 1;
				}
				if (buf.st_mode & S_IWOTH) {
					openflag |= O_WRONLY;
					mode_was_set = 1;
				}
			}
			//if (strcmp(de->d_name, "sr0") == 0) {
			//	printf("sr0 mode = %o\n", buf.st_mode);
			//}

			if (!mode_was_set) {
				//printf("couldn't find a mode to open %s\n", b);
				continue;
			}

			if ((openflag & O_RDONLY) && (openflag & O_WRONLY))
				openflag = O_RDWR;

			/* files have a higher probability of success than directories
			 * also, writable files are probably more 'fun' */
			switch (openflag) {
			case O_RDONLY:	chance = 10; break;
			case O_WRONLY:	chance = 100; break;
			case O_RDWR:	chance = 100; break;
			default: break;
			}
openit:
			if (fds_left_to_create == 0)
				break;

			fd = add_fd(chance, b, openflag);
			if (fd == -1)
				continue;

			switch (openflag) {
			case O_RDONLY:	modestr = "read-only";	break;
			case O_WRONLY:	modestr = "write-only";	break;
			case O_RDWR:	modestr = "read-write";	break;
			default: break;
			}
			output("fd[%i] = %s (%s)\n", fd, b, modestr);
			shm->fds[fd_idx++] = fd;
			fds_left_to_create--;
		}
	}
	closedir(d);
}

void open_files()
{
more:
	open_fds("/sys/kernel/debug");
	open_fds("/dev");
	open_fds("/proc");
	open_fds("/sys");
	if (fds_left_to_create > 0)
		goto more;
}

void close_files()
{
	unsigned int i;

	for (i = 0; i < fd_idx; i++) {
		close(shm->fds[i]);
		shm->fds[i] = 0;
		fds_left_to_create++;
	}
	fd_idx = 0;
}
