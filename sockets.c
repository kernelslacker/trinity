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

	output(2, "fd[%i] = domain:%i type:0x%x protocol:%i\n",
		fd, domain, type, protocol);

	nr_sockets++;

	/* Sometimes, listen on created sockets. */
	if (rand() % 2) {
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

void generate_sockets(void)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	int fd, n;
	int cachefile;
	unsigned int nr_to_create = NR_SOCKET_FDS;

	unsigned long domain, type, protocol;
	unsigned int buffer[3];

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile < 0) {
		printf("Couldn't open cachefile for writing! (%s)\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	output(2, "taking writer lock for cachefile\n");
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_WRLCK F_SETLKW");
		exit(EXIT_FAILURE);
	}

	output(2, "took writer lock for cachefile\n");

	while (nr_to_create > 0) {

		if (shm->exit_reason != STILL_RUNNING)
			return;

		/* Pretend we're child 0 and we've called sys_socket */
		sanitise_socket(0);

		//FIXME: If we passed a specific domain, we want to sanitise
		//  the proto/type fields.  Split it out of sanitise_socket()

		if (do_specific_proto == TRUE)
			domain = specific_proto;
		else
			domain = shm->a1[0];

		type = shm->a2[0];
		protocol = shm->a3[0];

		fd = open_socket(domain, type, protocol);
		if (fd > -1) {
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
		}

		/* check for ctrl-c */
		if (shm->exit_reason != STILL_RUNNING)
			return;
	}

done:
	fl.l_type = F_UNLCK;
	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_SETLK");
		exit(1);
	}

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
		if (close(fd) == 0) {
			nr_sockets--;
		} else {
			printf("failed to close socket.(%s)\n", strerror(errno));
		}
	}
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

	output(2, "taking reader lock for cachefile\n");
	fl.l_pid = getpid();
	fl.l_type = F_RDLCK;
	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_RDLCK F_SETLKW");
		exit(1);
	}
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
		if (shm->exit_reason != STILL_RUNNING)
			return;

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

	output(2, "dropped reader lock for cachefile\n");
	close(cachefile);
}

struct protocol {
	const char *name;
	unsigned int proto;
};

static const struct protocol protocols[] = {
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

void find_specific_proto(const char *protoarg)
{
	unsigned int i;

	if (specific_proto == 0) {
		/* we were passed a string */
		for (i = 0; i < ARRAY_SIZE(protocols); i++) {
			if (strcmp(protoarg, protocols[i].name) == 0) {
				specific_proto = protocols[i].proto;
				break;
			}
		}
	} else {
		/* we were passed a numeric arg. */
		for (i = 0; i < PF_MAX; i++) {
			if (specific_proto == protocols[i].proto)
				break;
		}
	}

	if (i > PF_MAX) {
		printf("Protocol unknown. Pass a numeric value [0-%d] or one of ", PF_MAX);
		for (i = 0; i < ARRAY_SIZE(protocols); i++)
			printf("%s ", protocols[i].name);
		printf("\n");

		exit(EXIT_FAILURE);
	}

	printf("Using protocol %s (%u) for all sockets\n", protocols[i].name, protocols[i].proto);
}
