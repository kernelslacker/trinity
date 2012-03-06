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
#include "sanitise.h"

unsigned int socket_fds[MAX_FDS/2];
unsigned int socks=0;

static int spin=0;
static char spinner[]="-\\|/";

static char *cachefilename="trinity.socketcache";

#define MAX_PER_DOMAIN 5
#define MAX_TRIES_PER_DOMAIN 10
static char sockarray[PF_MAX];

void generate_sockets(unsigned int nr_to_create)
{
	struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0 };
	int fd, n;
	unsigned int i, tries;
	int cachefile;

	unsigned long domain, type, protocol;
	unsigned int buffer[3];

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile < 0) {
		printf("Couldn't open cachefile for writing! (%s)\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	output("taking writer lock for cachefile\n");
	fl.l_pid = getpid();
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_SETLKW");
		exit(EXIT_FAILURE);
	}

	output("took writer lock for cachefile\n");

	while (nr_to_create > 0) {
		for (i = 0; i < PF_MAX; i++)
			sockarray[i] = 0;

		for (i = 0; i < PF_MAX; i++) {
			tries = 0;

			if (sockarray[i] == MAX_PER_DOMAIN)
				break;

			sanitise_socket(&domain, &type, &protocol, NULL, NULL, NULL);

			if (do_specific_proto == 1)
				domain = specific_proto;
			else
				domain = i;

			output("%c (%d sockets created. needed:%d) [domain:%d type:0x%x proto:%d]    \r",
				spinner[spin++], socks, nr_to_create,
				domain, type, protocol);
			if (spin == 4)
				spin = 0;

			fd = socket(domain, type, protocol);
			if (fd > -1) {
				socket_fds[socks] = fd;

				output("fd[%i] = domain:%i type:0x%x protocol:%i\n",
					fd, domain, type, protocol);

				sockarray[i]++;
				socks++;
				fds_left_to_create--;
				nr_to_create--;

				buffer[0] = domain;
				buffer[1] = type;
				buffer[2] = protocol;
				n = write(cachefile, &buffer, sizeof(int) * 3);
				if (n == -1) {
					printf("something went wrong writing the cachefile!\n");
					exit(EXIT_FAILURE);
				}

				if (nr_to_create == 0)
					goto done;
			} else {
				tries++;
			}
			if (tries == MAX_TRIES_PER_DOMAIN)
				break;
		}
	}

done:
	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_SETLK");
		exit(1);
	}

	output("dropped writer lock for cachefile\n");
	close(cachefile);

	output("\ncreated %d sockets\n", socks);
	synclog();
}

void open_sockets()
{
	struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0 };
	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
	unsigned int i;
	int bytesread=-1;
	int fd;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0) {
		printf("Couldn't find socket cachefile. Regenerating.\n");
		generate_sockets(fds_left_to_create/2);
		return;
	}

	output("taking reader lock for cachefile\n");
	fl.l_pid = getpid();
	fl.l_type = F_RDLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl reader F_SETLKW");
		exit(1);
	}
	output("took reader lock for cachefile\n");

	while (bytesread != 0) {
		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0)
			break;

		domain = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		if (do_specific_proto == 1) {
			if (domain != specific_proto) {
				printf("ignoring socket cachefile due to specific protocol request, and stale data in cachefile.\n");
				generate_sockets(fds_left_to_create/2);
				return;
			}
		}

		fd = socket(domain, type, protocol);
		if (fd < 0) {
			printf("Cachefile is stale. Need to regenerate.\n");
regenerate:
			close(cachefile);
			unlink(cachefilename);

			for (i = 0; i < socks; i++) {
				close(socket_fds[i]);
				socket_fds[i] = 0;
				fds_left_to_create++;
			}
			socks = 0;

			generate_sockets(fds_left_to_create/2);
			return;
		}
		socket_fds[socks] = fd;
		output("fd[%i] = domain:%i type:0x%x protocol:%i\n",
			fd, domain, type, protocol);
		socks++;
		fds_left_to_create--;
	}
	synclog();

	if (socks < fds_left_to_create/2) {
		printf("Insufficient sockets in cachefile (%d). Regenerating.\n", socks);
		goto regenerate;
	}

	output("(%d sockets created based on info from socket cachefile.)\n", socks);

	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl reader F_SETLK ");
		exit(1);
	}

	output("dropped reader lock for cachefile\n");
	close(cachefile);
}
