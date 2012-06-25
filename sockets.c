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
#include "constants.h"
#include "shm.h"

unsigned int socks=0;

static const char *cachefilename="trinity.socketcache";

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
	fl.l_type = F_WRLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_WRLCK F_SETLKW");
		exit(EXIT_FAILURE);
	}

	output("took writer lock for cachefile\n");

	while (nr_to_create > 0) {

		if (shm->exit_now == TRUE)
			return;

		for (i = 0; i < PF_MAX; i++)
			sockarray[i] = 0;

		for (i = 0; i < PF_MAX; i++) {
			tries = 0;

			if (sockarray[i] == MAX_PER_DOMAIN)
				break;

			/* Pretend we're child 0 and we've called sys_socket */
			sanitise_socket(0);
			domain = shm->a1[0];
			type = shm->a2[0];
			protocol = shm->a3[0];

			if (do_specific_proto == TRUE)
				domain = specific_proto;
			else
				domain = i;

			fd = socket(domain, type, protocol);
			if (fd > -1) {
				shm->socket_fds[socks] = fd;

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
}


static void close_sockets(void)
{
	unsigned int i;
	int fd;

	for (i = 0; i < socks; i++) {
		fd = shm->socket_fds[i];
		shm->socket_fds[i] = 0;
		if (close(fd) == 0) {
			socks--;
			fds_left_to_create++;
		} else {
			printf("failed to close socket.(%s)\n", strerror(errno));
		}
	}
}

void open_sockets()
{
	struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0 };
	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
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
		perror("fcntl F_RDLCK F_SETLKW");
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

		if (do_specific_proto == TRUE) {
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

			close_sockets();

			generate_sockets(fds_left_to_create/2);
			return;
		}
		shm->socket_fds[socks] = fd;
		output("fd[%i] = domain:%i type:0x%x protocol:%i\n",
			fd, domain, type, protocol);
		socks++;
		fds_left_to_create--;
	}

	if (socks < fds_left_to_create/2) {
		printf("Insufficient sockets in cachefile (%d). Regenerating.\n", socks);
		goto regenerate;
	}

	output("(%d sockets created based on info from socket cachefile.)\n", socks);

	fl.l_pid = getpid();
	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_UNLCK F_SETLK ");
		exit(1);
	}

	output("dropped reader lock for cachefile\n");
	close(cachefile);
}

struct protocol {
	const char *name;
	unsigned int proto;
};

static struct protocol protocols[] = {
	{ "PF_UNSPEC",       0 },
	{ "PF_LOCAL",        1 },
	{ "PF_UNIX",         PF_LOCAL },
	{ "PF_FILE",         PF_LOCAL },
	{ "PF_INET",         2 },
	{ "PF_AX25",         3 },
	{ "PF_IPX",          4 },
	{ "PF_APPLETALK",    5 },
	{ "PF_NETROM",       6 },
	{ "PF_BRIDGE",       7 },
	{ "PF_ATMPVC",       8 },
	{ "PF_X25",          9 },
	{ "PF_INET6",        10 },
	{ "PF_ROSE",         11 },
	{ "PF_DECnet",       12 },
	{ "PF_NETBEUI",      13 },
	{ "PF_SECURITY",     14 },
	{ "PF_KEY",          15 },
	{ "PF_NETLINK",      16 },
	{ "PF_ROUTE",        PF_NETLINK },
	{ "PF_PACKET",       17 },
	{ "PF_ASH",          18 },
	{ "PF_ECONET",       19 },
	{ "PF_ATMSVC",       20 },
	{ "PF_RDS",          21 },
	{ "PF_SNA",          22 },
	{ "PF_IRDA",         23 },
	{ "PF_PPPOX",        24 },
	{ "PF_WANPIPE",      25 },
	{ "PF_LLC",          26 },
	{ "PF_CAN",          29 },
	{ "PF_TIPC",         30 },
	{ "PF_BLUETOOTH",    31 },
	{ "PF_IUCV",         32 },
	{ "PF_RXRPC",        33 },
	{ "PF_ISDN",         34 },
	{ "PF_PHONET",       35 },
	{ "PF_IEEE802154",   36 },
	{ "PF_CAIF",         37 },
	{ "PF_ALG",          38 },
	{ "PF_NFC",          39 },
};

void find_specific_proto(char *protoarg)
{
	unsigned int i;
	struct protocol *p = protocols;

	if (specific_proto == 0) {
		/* we were passed a string */
		for (i = 0; i < (sizeof(protocols) / sizeof(struct protocol)); i++) {
			if (strcmp(protoarg, p[i].name) == 0) {
				specific_proto = p[i].proto;
				break;
			}
		}
	} else {
		/* we were passed a numeric arg. */
		for (i = 0; i < PF_MAX; i++) {
			if (specific_proto == p[i].proto)
				break;
		}
	}

	if (i > PF_MAX) {
		printf("Protocol unknown. Pass a numeric value [0-%d] or one of ", PF_MAX);
		for (i = 0; i < (sizeof(protocols) / sizeof(struct protocol)); i++)
			printf("%s ", p[i].name);
		printf("\n");

		exit(EXIT_FAILURE);
	}

	printf("Using protocol %s (%u) for all sockets\n", p[i].name, p[i].proto);
	return;
}
