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

#include "scrashme.h"

static int fds[1024];
static int socket_fds[500];
static int fd_idx;
static int socks=0;

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
			writelog("fd[%i] = %s\n", fd_idx, b);
			fds[fd_idx++] = fd;
		}
	}
	closedir(d);
}

static int spin=0;
static char spinner[]="-\\|/";

static char *cachefilename="scrashme.socketcache";

#define TYPE_MAX 128
#define PROTO_MAX 256
static void generate_sockets()
{
	int fd;
	int cachefile;
	int nr_to_create = 500;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];

	if (fd_idx < 500)
		nr_to_create = fd_idx;
	if (nr_to_create < 100)
		nr_to_create = 100;

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile < 0) {
		printf("Couldn't open cachefile for writing! (%s)\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (domain = 0; domain < PF_MAX; domain++) {
		for (type = 0; type < TYPE_MAX; type++) {
			for (protocol = 0; protocol < PROTO_MAX; protocol++) {
				printf("%c (%d sockets created. needed:%d) [domain:%d type:%d proto:%d]    \r",
					spinner[spin++], socks, nr_to_create-socks,
					domain, type, protocol);
				if (spin == 4)
					spin = 0;
				fd = socket(domain, type, protocol);
				if (fd > -1) {
					socket_fds[socks] = fd;
					writelog_nosync("fd[%i] = domain:%i type:%i protocol:%i\n",
						socks+fd_idx, domain, type, protocol);
					socks++;

					buffer[0] = domain;
					buffer[1] = type;
					buffer[2] = protocol;
					write(cachefile, &buffer, sizeof(int) * 3);

					if (socks == nr_to_create)
						goto done;
				}
			}
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
		generate_sockets();
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
			generate_sockets();
		}
		socket_fds[socks] = fd;
		writelog_nosync("fd[%i] = domain:%i type:%i protocol:%i\n",
			socks+fd_idx, domain, type, protocol);
		socks++;
	}
	printf("(%d sockets created based on info from socket cachefile.)\n", socks);

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
