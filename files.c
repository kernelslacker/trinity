#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

static int fds[1024];
static int fd_idx;

static int ignore_files(char *file)
{
	int i;
	char *ignored_files[] = {".", "..",
		/* boring stuff in /dev */
		"dmmidi0", "dmmidi1","dmmidi2","dmmidi3",
		"midi00", "midi01","midi02","midi03",
		/* Ignore per-process stuff. */
		"keycreate", "sockcreate", "fscreate", "exec",
		"current", "coredump_filter", "make-it-fail",
		"oom_adj", "oom_score_adj",
		"clear_refs", "loginuid", "sched", "comm", "mem",
		"task",
		NULL};

	for(i = 0; ignored_files[i]; i++) {
		if (!strcmp(file, ignored_files[i]))
			return 1;
	}
	if (!strncmp(file, "tty", 3))
		return 1;
	return 0;
}

static void open_fds(char *dir)
{
	char b[4096];
	int openflag, fd, r;
	DIR *d = opendir(dir);
	struct dirent *de;
	struct stat buf;

	if (!d) {
		printf("cant open %s\n", dir);
		return;
	}
	while ((de = readdir(d))) {
		snprintf(b, sizeof(b), "%s/%s", dir, de->d_name);
		if (ignore_files(de->d_name))
			continue; /*".", "..", everything that's not a regular file or directory !*/
		r = lstat(b,&buf);
		if (r == -1)
			continue;
		openflag = 0;
		if (S_ISLNK(buf.st_mode))
			continue;
		//if (S_ISREG(buf.st_mode))
		//	continue;
		if (S_ISDIR(buf.st_mode)) {
			if (buf.st_uid != getuid()) {
				/* We don't own the dir, is it group/other readable ? */
				if (buf.st_mode & (S_IRGRP|S_IROTH))
					open_fds(b);
			} else {
				/* We own this dir. */
				open_fds(b);
			}
		} else {
			/* if we own the file, unlikely, since you should NOT run this thing as root */
			if (buf.st_uid == getuid()) {
				if (buf.st_mode & S_IRUSR) openflag |= O_RDONLY;
				if (buf.st_mode & S_IWUSR) openflag |= O_WRONLY;
			} else if (buf.st_gid == getgid()) {
				if (buf.st_mode & S_IRGRP) openflag |= O_RDONLY;
				if (buf.st_mode & S_IWGRP) openflag |= O_WRONLY;
			} else {
				if (buf.st_mode & S_IROTH) openflag |= O_RDONLY;
				if (buf.st_mode & S_IWOTH) openflag |= O_WRONLY;
			}
			if (!openflag)
				continue;
			if ((openflag & O_RDONLY) && (openflag & O_WRONLY))
				openflag = O_RDWR;
			printf("%s/%s\n", dir, de->d_name);
			fd = open(b, openflag);
			if (fd < 0)
				continue;
			fds[fd_idx++] = fd;
		}
	}
	closedir(d);
}

#define TYPE_MAX 128
#define PROTO_MAX 256
static void open_sockets()
{
	int fd;
	int socks=0;

	printf("Creating sockets.\n");

	while (socks < 500) {
		fd = socket(rand() % PF_MAX, rand() % TYPE_MAX, rand() % PROTO_MAX);
		if (fd > -1) {
			fds[fd_idx++] = fd;
			socks++;
			printf("(%d sockets created)\r", socks);
			fflush(stdout);
		}
	}
	printf("\ncreated %d sockets\n", socks);
}


void setup_fds(void)
{
	fd_idx = 0;

	printf("Opening fds\n");
	open_fds("/dev");
	open_fds("/sys");
	open_fds("/proc");
	open_sockets();

	printf("done getting fds [idx:%d]\n", fd_idx);
	if (!fd_idx) {
		printf("couldn't open any files\n");
		exit(0);
	}
}


int get_random_fd(void)
{
	return fds[rand() % fd_idx];
}
