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

#include "trinity.h"

#define MAX_FDS 750

static unsigned int fds[1024];
static unsigned int socket_fds[MAX_FDS];
static unsigned int fd_idx;
static unsigned int socks=0;

static int ignore_files(char *file)
{
	int i;
	char *ignored_files[] = {".", "..",
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

static int add_fd(unsigned int chance, char *b, int flags)
{
	int fd = -1;

	if ((unsigned int)(rand() % 100) < chance) {
		fd = open(b, flags | O_NONBLOCK);
		if (fd < 0)
			return -1;
//		printf("Added: %s\n", b);
	}
	return fd;
}

static void open_fds(char *dir)
{
	char b[4096];
	int openflag, fd, r;
	DIR *d = opendir(dir);
	struct dirent *de;
	struct stat buf;
	char *modestr;
	unsigned int chance;

	if (!d) {
		printf("cant open %s\n", dir);
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
			chance = 30;
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
			// for files, increase the probability of success
			chance = 40;
openit:
			fd = add_fd(chance, b, openflag);
			if (fd == -1)
				continue;

			switch (openflag) {
			case O_RDONLY:	modestr = "read-only";	break;
			case O_WRONLY:	modestr = "write-only";	break;
			case O_RDWR:	modestr = "read-write";	break;
			}
			printf("%s/%s (%s)\n", dir, de->d_name, modestr);
			writelog("fd[%i] = %s (%s)\n", fd_idx, b, modestr);
			fds[fd_idx++] = fd;
		}
		if (fd_idx > (MAX_FDS / 2))
			break;
	}
	closedir(d);
}

static int spin=0;
static char spinner[]="-\\|/";

static char *cachefilename="trinity.socketcache";

#define TYPE_MAX 128
#define PROTO_MAX 256
static void generate_sockets(unsigned int nr_to_create)
{
	int fd;
	int cachefile;

	unsigned int domain, type, protocol;
	unsigned int buffer[3];

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile < 0) {
		printf("Couldn't open cachefile for writing! (%s)\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (socks < nr_to_create) {
		domain = rand() % PF_MAX;
		type = rand() % TYPE_MAX;
		protocol = rand() % PROTO_MAX;

		printf("%c (%d sockets created. needed:%d) [domain:%d type:%d proto:%d]    \r",
			spinner[spin++], socks, nr_to_create-socks,
			domain, type, protocol);
		if (spin == 4)
			spin = 0;
		fd = socket(domain, type, protocol);
		if (fd > -1) {
			socket_fds[socks] = fd;
			writelog_nosync("fd[%i] = domain:%i type:%i protocol:%i\n",
				fd, domain, type, protocol);
			socks++;

			buffer[0] = domain;
			buffer[1] = type;
			buffer[2] = protocol;
			write(cachefile, &buffer, sizeof(int) * 3);

			if (socks == nr_to_create)
				goto done;
		}
	}

done:
	close(cachefile);
	printf("\ncreated %d sockets\n", socks);
	writelog("created %d sockets\n\n", socks);
}

static void open_sockets()
{
	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
	int bytesread=-1;
	int fd;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0) {
		printf("Couldn't find socket cachefile. Regenerating.\n");
		generate_sockets(MAX_FDS/2);
		return;
	}

	while (bytesread != 0) {
		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0)
			break;

		domain = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		fd = socket(domain, type, protocol);
		if (fd < 0) {
			printf("Cachefile is stale. Need to regenerate.\n");
			unlink(cachefilename);
			generate_sockets(MAX_FDS/2);
		}
		socket_fds[socks] = fd;
		writelog_nosync("fd[%i] = domain:%i type:%i protocol:%i\n",
			socks+fd_idx, domain, type, protocol);
		socks++;
	}
	printf("(%d sockets created based on info from socket cachefile.)\n", socks);
	synclog();

	close(cachefile);
}

static int pipes[2];

void setup_fds(void)
{
	fd_idx = 0;

	printf("Creating pipes\n");
	if (pipe(pipes) < 0) {
		perror("pipe fail.\n");
		exit(EXIT_FAILURE);
	}
	fds[0] = pipes[0];
	fds[1] = pipes[1];
	fd_idx += 2;
	writelog("fd[0] = pipe\n");
	writelog("fd[1] = pipe\n");

	printf("Opening fds\n");
	open_sockets();
	open_fds("/dev");
	open_fds("/sys");
	open_fds("/proc");

	printf("done getting fds [idx:%d]\n", fd_idx);
	if (!fd_idx) {
		printf("couldn't open any files\n");
		exit(0);
	}
}


int get_random_fd(void)
{
	int i;

	i = rand() % 2;
	if (i == 0)
		return fds[rand() % fd_idx];
	if (i == 1)
		return socket_fds[rand() % socks];

	// should never get here.
	printf("oops! %s:%d\n", __FILE__, __LINE__);
	exit(EXIT_FAILURE);
}
