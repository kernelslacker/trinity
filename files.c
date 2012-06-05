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

char *pathnames[NR_PATHNAMES];
unsigned int pathname_idx = 0;

#define FD_LIKELYHOOD 5000

static int add_fd(unsigned int chance, const char *pathname, int flags, unsigned char is_dir)
{
	int fd = -1;
	DIR *d = NULL;

	if ((unsigned int)(rand() % FD_LIKELYHOOD) < chance) {
		/* Add it to the list of filenames */
		if (pathname_idx != NR_PATHNAMES) {

			if (pathnames[pathname_idx] != NULL)
				free(pathnames[pathname_idx]);

			pathnames[pathname_idx++] = strdup(pathname);
		}

		/* Add it to the list of fd's */
		if (is_dir == TRUE) {
			d = opendir(pathname);
			if (d != NULL)
				fd = dirfd(d);
		} else {
			fd = open(pathname, flags | O_NONBLOCK);
		}

		if (fd < 0) {
			//printf("Couldn't open %s : %s\n", pathname, strerror(errno));
			return -1;
		}
//		printf("Added: %s\n", pathname);
	}
	return fd;
}

void open_fds(const char *dir, unsigned char add_all)
{
	char b[4096];
	int openflag, fd, r;
	DIR *d = opendir(dir);
	struct dirent *de;
	struct stat buf;
	const char *modestr;
	unsigned int chance = 0;
	int set_read;
	int set_write;
	unsigned char is_dir = FALSE;


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

		if (S_ISDIR(buf.st_mode)) {
			is_dir = TRUE;

			/* probability of adding a directory to the list. */
			chance = 5;

			if (buf.st_uid != getuid()) {
				/* We don't own the dir, is it group/other readable ? */
				if (buf.st_mode & (S_IRGRP|S_IROTH)) {
					open_fds(b, add_all);
					goto openit;
				}
				continue;
			} else {
				/* We own this dir. */
				open_fds(b, add_all);
				goto openit;
			}
			// unreachable.
		} else {
			is_dir = FALSE;
		}

openit:
		set_read = FALSE;
		set_write = FALSE;

		/* if we own the file, unlikely, since you should NOT run this thing as root */
		if (buf.st_uid == getuid()) {
			if (buf.st_mode & S_IRUSR)
				set_read = TRUE;
			if (buf.st_mode & S_IWUSR)
				set_write = TRUE;

		} else if (buf.st_gid == getgid()) {
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
			continue;

		if (set_read == 1)
			openflag = O_RDONLY;
		if (set_write == 1)
			openflag = O_WRONLY;
		if ((set_read == 1) && (set_write == 1))
			openflag = O_RDWR;

		if (!S_ISDIR(buf.st_mode)) {
			/* files have a higher probability of success than directories
			 * also, writable files are probably more 'fun' */
			switch (openflag) {
			case O_RDONLY:	chance = 10;
					break;
			case O_WRONLY:
			case O_RDWR:	chance = 100;
					break;
			default: break;
			}
		}

		if (fds_left_to_create == 0)
			break;

		/* This is used just for the victim files */
		if (add_all == TRUE)
			chance = FD_LIKELYHOOD;

		fd = add_fd(chance, b, openflag, is_dir);
		if (fd == -1)
			continue;

		switch (openflag) {
		case O_RDONLY:	modestr = "read-only";	break;
		case O_WRONLY:	modestr = "write-only";	break;
		case O_RDWR:	modestr = "read-write";	break;
		default: break;
		}
		output("fd[%i] = %s (%s)", fd, b, modestr);
		if (is_dir == TRUE)
			output(" [dir]");
		output("\n");
		shm->fds[fd_idx++] = fd;
		fds_left_to_create--;
	}
	closedir(d);
}

void open_files()
{
	const char dir1[]="/";
	const char dir2[]=".";
	const char dir3[]="..";
	const char dir4[]="";

	while (fds_left_to_create > 0) {

		(void)add_fd(-1, dir1, O_RDONLY, TRUE);
		(void)add_fd(-1, dir2, O_RDWR, TRUE);
		(void)add_fd(-1, dir3, O_RDWR, TRUE);
		(void)add_fd(-1, dir4, O_RDWR, TRUE);

		if (victim_path != NULL)
			open_fds(victim_path, TRUE);

		open_fds("/sys/kernel/debug", FALSE);
		open_fds("/dev", FALSE);
		open_fds("/proc", FALSE);
		open_fds("/sys", FALSE);
	}
}

void close_files()
{
	unsigned int i;
	int fd;

	for (i = 0; i < fd_idx; i++) {
		fd = shm->fds[i];
		shm->fds[i] = 0;
		close(fd);
		fds_left_to_create++;
	}
	fd_idx = 0;
}

void regenerate_fds(void)
{
	close_files();
	pathname_idx = 0;
	open_files();
}
