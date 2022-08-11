#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "debug.h"
#include "domains.h"
#include "net.h"
#include "objects.h"
#include "params.h"	// verbose, do_specific_domain
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

unsigned int nr_sockets = 0;

static const char *cachefilename="trinity.socketcache";
static int cachefile;

static void sso_socket(struct socket_triplet *triplet, struct sockopt *so, int fd)
{
	int ret;
	unsigned int tries = 0;

	/* skip over bluetooth due to weird linger bug */
	if (triplet->family == PF_BLUETOOTH)
		return;

	so->optval = 0;

retry:
	if (so->optval != 0) {
		free((void *) so->optval);
		so->optval = 0;
	}

	do_setsockopt(so, triplet);

	ret = setsockopt(fd, so->level, so->optname, (void *)so->optval, so->optlen);
	if (ret == 0) {
		output(2, "setsockopt(%u 0x%lx 0x%lx 0x%lx) on fd %u [%u:%u:%u]\n",
			so->level, so->optname, so->optval, so->optlen, fd,
			triplet->family, triplet->type, triplet->protocol);
	} else {
		tries++;
		if (tries != 100)
			goto retry;
	}

	if (so->optval != 0)
		free((void *) so->optval);
}

static struct object * add_socket(int fd, unsigned int domain, unsigned int type, unsigned int protocol)
{
	struct object *obj;

	obj = alloc_object();

	obj->sockinfo.fd = fd;
	obj->sockinfo.triplet.family = domain;
	obj->sockinfo.triplet.type = type;
	obj->sockinfo.triplet.protocol = protocol;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_SOCKET);

	return obj;
}

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	struct object *obj;
	struct sockaddr *sa = NULL;
	const struct netproto *proto;
	socklen_t salen;
	struct sockopt so = { 0, 0, 0, 0 };
	int fd;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		return fd;

	obj = add_socket(fd, domain, type, protocol);

	proto = net_protocols[domain].proto;
	if (proto != NULL)
		if (proto->socket_setup != NULL)
			proto->socket_setup(fd);

	// FIXME:
	// All of this needs to be broken out into child ops instead of
	// special casing it all at creation time.

	/* Set some random socket options. */
	sso_socket(&obj->sockinfo.triplet, &so, fd);

	nr_sockets++;

	/* Sometimes, listen on created sockets. */
	if (RAND_BOOL()) {
		int ret, one = 1;

		/* fake a sockaddr. */
		generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, domain);

		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (ret != -1)
			goto skip_bind;

		ret = bind(fd, sa, salen);
		if (ret != -1)
			(void) listen(fd, RAND_RANGE(1, 128));

//		ret = accept4(fd, sa, &salen, SOCK_NONBLOCK);
//		if (ret != -1) {
//			obj = add_socket(ret, domain, type, protocol);
//			nr_sockets++;
//		}
	}

skip_bind:
	if (sa != NULL)
		free(sa);

	return fd;
}

static void lock_cachefile(int type)
{
	struct flock fl = {
		.l_len = 0,
		.l_start = 0,
		.l_whence = SEEK_SET,
	};

	fl.l_pid = getpid();
	fl.l_type = type;

	if (verbose)
		output(2, "waiting on lock for cachefile\n");

	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_SETLKW");
		return;
	}

	if (verbose)
		output(2, "took lock for cachefile\n");
}

static void unlock_cachefile(void)
{
	struct flock fl = {
		.l_len = 0,
		.l_start = 0,
		.l_whence = SEEK_SET,
	};

	fl.l_pid = getpid();
	fl.l_type = F_UNLCK;

	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_UNLCK F_SETLK ");
		return;
	}

	if (verbose)
		output(2, "dropped lock for cachefile\n");
}

static unsigned int valid_proto(unsigned int family)
{
	const char *famstr;

	famstr = get_domain_name(family);

	/* Not used for creating sockets. */
	if (strncmp(famstr, "UNSPEC", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "BRIDGE", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "SECURITY", 11) == 0)
		return FALSE;

	/* Not actually implemented (or now removed). */
	if (strncmp(famstr, "NETBEUI", 10) == 0)
		return FALSE;
	if (strncmp(famstr, "ASH", 6) == 0)
		return FALSE;
	if (strncmp(famstr, "ECONET", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "SNA", 6) == 0)
		return FALSE;
	if (strncmp(famstr, "WANPIPE", 10) == 0)
		return FALSE;

	/* Needs root. */
	if (orig_uid != 0) {
		if (strncmp(famstr, "KEY", 6) == 0)
			return FALSE;
		if (strncmp(famstr, "PACKET", 9) == 0)
			return FALSE;
		if (strncmp(famstr, "LLC", 6) == 0)
			return FALSE;
	}

	return TRUE;
}

static bool write_socket_to_cache(struct socket_triplet *st)
{
	unsigned int buffer[3];
	int n;

	if (cachefile == -1)
		return FALSE;

	buffer[0] = st->family;
	buffer[1] = st->type;
	buffer[2] = st->protocol;
	n = write(cachefile, &buffer, sizeof(int) * 3);
	if (n == -1) {
		outputerr("something went wrong writing the cachefile! : %s\n", strerror(errno));
		return FALSE;
	}
	return TRUE;
}

static bool generate_socket(unsigned int family, unsigned int protocol, unsigned int type)
{
	struct socket_triplet st;
	int fd;

	st.family = family;
	st.type = type;
	st.protocol = protocol;

	fd = open_socket(st.family, st.type, st.protocol);
	if (fd > -1) {
		write_socket_to_cache(&st);
		return TRUE;
	}
	output(2, "Couldn't open socket %u:%u:%u. %s\n", family, type, protocol, strerror(errno));
	return FALSE;
}

static bool generate_specific_socket(int family)
{
	struct socket_triplet st;
	int fd;

	st.family = family;

	BUG_ON(st.family >= ARRAY_SIZE(no_domains));
	if (no_domains[st.family])
		return FALSE;

	if (get_domain_name(st.family) == NULL)
		return FALSE;

	if (valid_proto(st.family) == FALSE) {
		outputerr("Can't do protocol %s\n", get_domain_name(st.family));
		return FALSE;
	}

	st.protocol = rnd() % 256;

	if (sanitise_socket_triplet(&st) == -1)
		rand_proto_type(&st);

	fd = open_socket(st.family, st.type, st.protocol);
	if (fd == -1) {
		output(0, "Couldn't open socket (%u:%u:%u). %s\n",
				st.family, st.type, st.protocol,
				strerror(errno));
		return FALSE;
	}

	return write_socket_to_cache(&st);
}

#define NR_SOCKET_FDS 50

static bool generate_sockets(void)
{
	int i, r, ret = FALSE;
	bool domains_disabled = FALSE;

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile == -1) {
		outputerr("Couldn't open cachefile for writing! (%s)\n", strerror(errno));
		return FALSE;
	}
	lock_cachefile(F_WRLCK);

	if (do_specific_domain == TRUE) {
		while (nr_sockets < NR_SOCKET_FDS) {
			ret = generate_specific_socket(specific_domain);

			if (ret == FALSE)
				return FALSE;
		}
		goto out_unlock;
	}

	/*
	 * check if all domains are disabled.
	 */
	for (i = 0; i < (int)ARRAY_SIZE(no_domains); i++) {
		if (no_domains[i] == FALSE) {
			domains_disabled = FALSE;
			break;
		} else {
			domains_disabled = TRUE;
		}
	}

	if (domains_disabled == TRUE) {
		output(0, "All domains disabled!\n");
		goto out_unlock;
	}

	for (i = 0; i < TRINITY_PF_MAX; i++) {
		const struct netproto *proto = net_protocols[i].proto;
		struct socket_triplet *triplets;
		unsigned int j;

		if (no_domains[i] == TRUE)
			continue;

		/* check for ctrl-c again. */
		if (shm->exit_reason != STILL_RUNNING)
			goto out_unlock;

		if (proto == NULL)
			continue;
		if (proto->nr_triplets == 0)
			continue;

		triplets = proto->valid_triplets;
		for (j = 0; j < proto->nr_triplets; j++)
			ret |= generate_socket(triplets[j].family, triplets[j].protocol, triplets[j].type);

		if (proto->nr_privileged_triplets == 0)
			continue;

		if (orig_uid != 0)
			continue;

		triplets = proto->valid_privileged_triplets;
		for (j = 0; j < proto->nr_privileged_triplets; j++)
			ret |= generate_socket(triplets[j].family, triplets[j].protocol, triplets[j].type);
	}

	/* This is here temporarily until we have sufficient ->valid_proto's */
	while (nr_sockets < NR_SOCKET_FDS) {
		r = rnd() % TRINITY_PF_MAX;
		for (i = 0; i < 10; i++)
			if (generate_specific_socket(r) == FALSE)
				break;
	}

out_unlock:
	if (cachefile != -1) {
		unlock_cachefile();
		close(cachefile);
	}

	return ret;
}

static void socket_destructor(struct object *obj)
{
	struct socketinfo *si = &obj->sockinfo;
	struct linger ling = { .l_onoff = FALSE, .l_linger = 0 };
	int fd;

	//FIXME: This is a workaround for a weird bug where we hang forevre
	// waiting for bluetooth sockets when we setsockopt.
	// Hopefully at some point we can remove this when someone figures out what's going on.
	if (si->triplet.family == PF_BLUETOOTH)
		return;

	/* Grab an fd, and nuke it before someone else uses it. */
	fd = si->fd;
	si->fd = 0;

	/* disable linger */
	(void) setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));

	(void) shutdown(fd, SHUT_RDWR);

	if (close(fd) != 0)
		output(1, "failed to close socket [%u:%u:%u].(%s)\n",
			si->triplet.family,
			si->triplet.type,
			si->triplet.protocol,
			strerror(errno));
}

static void socket_dump(struct object *obj, bool global)
{
	struct socketinfo *si = &obj->sockinfo;

	output(2, "socket fd:%u domain:%u (%s) type:0x%u protocol:%u global:%d\n",
		si->fd, si->triplet.family, get_domain_name(si->triplet.family),
		si->triplet.type, si->triplet.protocol,
		global);
}

static int open_sockets(void)
{
	struct objhead *head;
	int bytesread = -1;
	int ret;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);
	head->destroy = &socket_destructor;
	head->dump = &socket_dump;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0) {
		output(1, "Couldn't find socket cachefile. Regenerating.\n");
		ret = generate_sockets();
		output(1, "created %u sockets\n", nr_sockets);
		return ret;
	}

	lock_cachefile(F_RDLCK);

	while (bytesread != 0) {
		unsigned int domain, type, protocol;
		unsigned int buffer[3];
		int fd;

		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0) {
			if (nr_sockets == 0)
				goto regenerate;
			break;
		}

		domain = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		if (domain >= TRINITY_PF_MAX) {
			output(1, "cachefile contained invalid domain %u\n", domain);
			goto regenerate;
		}

		if ((do_specific_domain == TRUE && domain != specific_domain) ||
		    (no_domains[domain] == TRUE)) {
			output(1, "ignoring socket cachefile due to specific "
			       "protocol request (or protocol disabled), "
			       "and stale data in cachefile.\n");
regenerate:
				unlock_cachefile();	/* drop the reader lock. */
				close(cachefile);
				unlink(cachefilename);

				ret = generate_sockets();
				return ret;
		}

		fd = open_socket(domain, type, protocol);
		if (fd < 0) {
			output(1, "Cachefile is stale. Need to regenerate.\n");
			goto regenerate;
		}

		/* check for ctrl-c */
		if (shm->exit_reason != STILL_RUNNING) {
			close(cachefile);
			return FALSE;
		}
	}

	output(1, "%u sockets created based on info from socket cachefile.\n", nr_sockets);

	unlock_cachefile();
	close(cachefile);

	return TRUE;
}

struct socketinfo * get_rand_socketinfo(void)
{
	struct object *obj;

	/* When using victim files, sockets can be 0. */
	if (objects_empty(OBJ_FD_SOCKET) == TRUE)
		return NULL;

	obj = get_random_object(OBJ_FD_SOCKET, OBJ_GLOBAL);
	return &obj->sockinfo;
}

static int get_rand_socket_fd(void)
{
	struct socketinfo *sockinfo;

	sockinfo = get_rand_socketinfo();
	if (sockinfo == NULL)
		return -1;

	return sockinfo->fd;
}

int fd_from_socketinfo(struct socketinfo *si)
{
	if (si != NULL) {
		if (!(ONE_IN(1000)))
			return si->fd;
	}
	return get_random_fd();
}

static const struct fd_provider socket_fd_provider = {
	.name = "sockets",
	.enabled = TRUE,
	.open = &open_sockets,
	.get = &get_rand_socket_fd,
};

REG_FD_PROV(socket_fd_provider);
