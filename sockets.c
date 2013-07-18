#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "trinity.h"
#include "constants.h"
#include "shm.h"
#include "net.h"
#include "log.h"
#include "params.h"	// victim_path, verbose, do_specific_proto
#include "random.h"

unsigned int nr_sockets = 0;

static const char *cachefilename="trinity.socketcache";

#define MAX_PER_DOMAIN 5
#define MAX_TRIES_PER_DOMAIN 10

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	int fd;
	struct sockaddr sa;
	socklen_t salen;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		return fd;

	shm->socket_fds[nr_sockets] = fd;

	output(2, "fd[%i] = domain:%i (%s) type:0x%x protocol:%i\n",
		fd, domain, get_proto_name(domain), type, protocol);

	nr_sockets++;

	/* Sometimes, listen on created sockets. */
	if (rand_bool()) {
		__unused__ int ret;

		/* fake a sockaddr. */
		generate_sockaddr((unsigned long *) &sa, (unsigned long *) &salen, domain);

		ret = bind(fd, &sa, salen);
/*		if (ret == -1)
			printf("bind: %s\n", strerror(errno));
		else
			printf("bind: success!\n");
*/
		ret = listen(fd, (rand() % 2) + 1);
/*		if (ret == -1)
			printf("listen: %s\n", strerror(errno));
		else
			printf("listen: success!\n");
*/
	}

	return fd;
}

static void generate_sockets(void)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	int fd, n;
	int cachefile;
	unsigned int nr_to_create = NR_SOCKET_FDS;
	unsigned int buffer[3];

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile < 0) {
		printf("Couldn't open cachefile for writing! (%s)\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (verbose)
		output(2, "taking writer lock for cachefile\n");
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_WRLCK F_SETLKW");
		exit(EXIT_FAILURE);
	}

	if (verbose)
		output(2, "took writer lock for cachefile\n");

	while (nr_to_create > 0) {

		struct socket_triplet st;

		if (shm->exit_reason != STILL_RUNNING) {
			close(cachefile);
			return;
		}

		gen_socket_args(&st);

		fd = open_socket(st.family, st.type, st.protocol);
		if (fd > -1) {
			nr_to_create--;

			buffer[0] = st.family;
			buffer[1] = st.type;
			buffer[2] = st.protocol;
			n = write(cachefile, &buffer, sizeof(int) * 3);
			if (n == -1) {
				printf("something went wrong writing the cachefile!\n");
				exit(EXIT_FAILURE);
			}

			if (nr_to_create == 0)
				goto done;
		}

		/* check for ctrl-c */
		if (shm->exit_reason != STILL_RUNNING)
			return;

		//FIXME: If we've passed -P and we're spinning here without making progress
		// then we should abort after a few hundred loops.
	}

done:
	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_SETLK");
		exit(1);
	}

	if (verbose)
		output(2, "dropped writer lock for cachefile\n");
	output(1, "created %d sockets\n", nr_sockets);

	close(cachefile);
}


static void close_sockets(void)
{
	unsigned int i;
	int fd;

	for (i = 0; i < nr_sockets; i++) {
		fd = shm->socket_fds[i];
		shm->socket_fds[i] = 0;
		if (close(fd) != 0) {
			printf("failed to close socket.(%s)\n", strerror(errno));
		}
	}

	nr_sockets = 0;
}

void open_sockets(void)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
	int bytesread=-1;
	int fd;

	/* If we have victim files, don't worry about sockets. */
	if (victim_path != NULL)
		return;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0) {
		printf("Couldn't find socket cachefile. Regenerating.\n");
		generate_sockets();
		return;
	}

	if (verbose)
		output(2, "taking reader lock for cachefile\n");
	fl.l_pid = getpid();
	fl.l_type = F_RDLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_RDLCK F_SETLKW");
		exit(1);
	}
	if (verbose)
		output(2, "took reader lock for cachefile\n");

	while (bytesread != 0) {
		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0)
			break;

		domain = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		if (do_specific_proto == TRUE) {
			if (domain != specific_proto) {
				printf("ignoring socket cachefile due to specific protocol request, and stale data in cachefile.\n");
				generate_sockets();
				close(cachefile);
				return;
			}
		}

		fd = open_socket(domain, type, protocol);
		if (fd < 0) {
			printf("Cachefile is stale. Need to regenerate.\n");
regenerate:
			close(cachefile);
			unlink(cachefilename);

			close_sockets();

			generate_sockets();
			return;
		}

		/* check for ctrl-c */
		if (shm->exit_reason != STILL_RUNNING) {
			close(cachefile);
			return;
		}
	}

	if (nr_sockets < NR_SOCKET_FDS) {
		printf("Insufficient sockets in cachefile (%d). Regenerating.\n", nr_sockets);
		goto regenerate;
	}

	output(1, "%d sockets created based on info from socket cachefile.\n", nr_sockets);

	fl.l_pid = getpid();
	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_UNLCK F_SETLK ");
		exit(1);
	}

	if (verbose)
		output(2, "dropped reader lock for cachefile\n");
	close(cachefile);
}
