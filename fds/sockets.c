#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "child.h"
#include "debug.h"
#include "domains.h"
#include "fd-event.h"
#include "list.h"
#include "net.h"
#include "objects.h"
#include "params.h"	// verbosity, do_specific_domain
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

unsigned int nr_sockets = 0;


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

struct object * add_socket(int fd, unsigned int domain, unsigned int type, unsigned int protocol)
{
	struct object *obj;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return NULL;
	}
	INIT_LIST_HEAD(&obj->list);

	obj->sockinfo.fd = fd;
	obj->sockinfo.triplet.family = domain;
	obj->sockinfo.triplet.type = type;
	obj->sockinfo.triplet.protocol = protocol;
	obj->sockinfo.needs_setup = true;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_SOCKET);

	/* add_object frees obj and returns without inserting when called
	 * from a child process (OBJ_GLOBAL from non-mainpid).  Signal
	 * failure by returning NULL so callers can close the fd. */
	if (getpid() != mainpid)
		return NULL;

	return obj;
}

/*
 * Perform deferred per-protocol socket setup.
 * Called lazily when a child first uses the socket.
 * Random setsockopt is handled separately in socket_child_ops().
 */
static void socket_setup_lazy(struct socketinfo *si)
{
	const struct netproto *proto;
	int fd = si->fd;

	si->needs_setup = false;

	proto = net_protocols[si->triplet.family].proto;
	if (proto != NULL)
		if (proto->socket_setup != NULL)
			proto->socket_setup(fd);
}

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	int fd;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		return fd;

	add_socket(fd, domain, type, protocol);

	nr_sockets++;

	return fd;
}

static unsigned int valid_proto(unsigned int family)
{
	const char *famstr;

	famstr = get_domain_name(family);

	/* Not used for creating sockets. */
	if (strncmp(famstr, "UNSPEC", 7) == 0)
		return false;
	if (strncmp(famstr, "BRIDGE", 7) == 0)
		return false;
	if (strncmp(famstr, "SECURITY", 9) == 0)
		return false;

	/* Not actually implemented (or now removed). */
	if (strncmp(famstr, "NETBEUI", 8) == 0)
		return false;
	if (strncmp(famstr, "ASH", 4) == 0)
		return false;
	if (strncmp(famstr, "SNA", 4) == 0)
		return false;
	if (strncmp(famstr, "WANPIPE", 8) == 0)
		return false;

	/* Needs root. */
	if (orig_uid != 0) {
		if (strncmp(famstr, "KEY", 4) == 0)
			return false;
		if (strncmp(famstr, "PACKET", 7) == 0)
			return false;
		if (strncmp(famstr, "LLC", 4) == 0)
			return false;
	}

	return true;
}

static bool generate_socket(unsigned int family, unsigned int protocol, unsigned int type)
{
	int fd;

	fd = open_socket(family, type, protocol);
	if (fd > -1)
		return true;
	output(2, "Couldn't open socket %u:%u:%u. %s\n", family, type, protocol, strerror(errno));
	return false;
}

static unsigned int rand_proto_for_family(unsigned int family)
{
	static const unsigned int inet_protos[] = {
		IPPROTO_IP, IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_IPIP,
		IPPROTO_TCP, IPPROTO_EGP, IPPROTO_PUP, IPPROTO_UDP,
		IPPROTO_IDP, IPPROTO_TP, IPPROTO_DCCP, IPPROTO_IPV6,
		IPPROTO_RSVP, IPPROTO_GRE, IPPROTO_ESP, IPPROTO_AH,
		IPPROTO_MTP, IPPROTO_BEETPH, IPPROTO_ENCAP, IPPROTO_PIM,
		IPPROTO_COMP, IPPROTO_SCTP, IPPROTO_UDPLITE, IPPROTO_MPLS,
		IPPROTO_RAW,
	};

	switch (family) {
	case PF_INET:
	case PF_INET6:
		return RAND_ARRAY(inet_protos);
	case PF_UNIX:
		return 0;
	default:
		return rand() % 16;
	}
}

static bool generate_specific_socket(int family)
{
	struct socket_triplet st;
	int fd;

	st.family = family;

	BUG_ON(st.family >= ARRAY_SIZE(no_domains));
	if (no_domains[st.family])
		return false;

	if (get_domain_name(st.family) == NULL)
		return false;

	if (valid_proto(st.family) == false)
		return false;

	st.protocol = rand_proto_for_family(st.family);

	if (sanitise_socket_triplet(&st) == -1)
		rand_proto_type(&st);

	fd = open_socket(st.family, st.type, st.protocol);
	if (fd == -1) {
		output(2, "Couldn't open socket (%u:%u:%u). %s\n",
				st.family, st.type, st.protocol,
				strerror(errno));
		return false;
	}

	return true;
}

#define NR_SOCKET_FDS 50

static bool generate_sockets(void)
{
	int i, r, ret = false;
	bool domains_disabled = false;

	if (do_specific_domain == true) {
		while (nr_sockets < NR_SOCKET_FDS) {
			ret = generate_specific_socket(specific_domain);

			if (ret == false)
				return ret;
		}
		return ret;
	}

	/*
	 * check if all domains are disabled.
	 */
	for (i = 0; i < (int)ARRAY_SIZE(no_domains); i++) {
		if (no_domains[i] == false) {
			domains_disabled = false;
			break;
		} else {
			domains_disabled = true;
		}
	}

	if (domains_disabled == true) {
		output(0, "All domains disabled!\n");
		return ret;
	}

	for (i = 0; i < TRINITY_PF_MAX; i++) {
		const struct netproto *proto = net_protocols[i].proto;
		struct socket_triplet *triplets;
		unsigned int j;

		if (no_domains[i] == true)
			continue;

		/* check for ctrl-c again. */
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			return ret;

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

	while (nr_sockets < NR_SOCKET_FDS) {
		r = rand() % TRINITY_PF_MAX;
		for (i = 0; i < 10; i++)
			if (generate_specific_socket(r) == false)
				break;
	}

	return ret;
}

static void socket_destructor(struct object *obj)
{
	struct socketinfo *si = &obj->sockinfo;
	struct linger ling = { .l_onoff = false, .l_linger = 0 };
	int fd;

	/* Grab an fd, and nuke it before someone else uses it. */
	fd = si->fd;
	si->fd = -1;

	/*
	 * Skip setsockopt/shutdown for bluetooth sockets —
	 * setsockopt(SO_LINGER) on PF_BLUETOOTH can hang forever
	 * in the kernel.  See also the matching skip in sso_socket().
	 * But we must still close the fd or it leaks.
	 */
	if (si->triplet.family == PF_BLUETOOTH)
		goto do_close;

	/* disable linger */
	(void) setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));

	(void) shutdown(fd, SHUT_RDWR);

do_close:
	if (close(fd) != 0)
		output(1, "failed to close socket [%u:%u:%u].(%s)\n",
			si->triplet.family,
			si->triplet.type,
			si->triplet.protocol,
			strerror(errno));
}

static void socket_dump(struct object *obj, enum obj_scope scope)
{
	struct socketinfo *si = &obj->sockinfo;

	output(2, "socket fd:%u domain:%u (%s) type:0x%u protocol:%u scope:%d\n",
		si->fd, si->triplet.family, get_domain_name(si->triplet.family),
		si->triplet.type, si->triplet.protocol,
		scope);
}

/*
 * Child operation: randomly set socket options, bind, listen, and
 * accept4 on a socket.  Called periodically during child fuzzing so
 * sockets get random configurations and children exercise the
 * setsockopt/bind/listen/accept paths as fuzzing ops.
 */
static void socket_child_ops(void)
{
	struct socketinfo *si;
	struct sockaddr *sa = NULL;
	socklen_t salen;
	struct sockopt so = { 0, 0, 0, 0 };
	int fd, ret, one = 1, flags, afd;

	si = get_rand_socketinfo();
	if (si == NULL)
		return;

	fd = si->fd;

	/* Set random socket options — moved here from socket_setup_lazy()
	 * so each child exercises setsockopt at runtime rather than
	 * doing a one-shot setup at first touch. */
	sso_socket(&si->triplet, &so, fd);

	generate_sockaddr((struct sockaddr **) &sa, &salen, si->triplet.family);

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret == -1)
		goto out;

	ret = bind(fd, sa, salen);
	if (ret == -1)
		goto out;

	ret = listen(fd, RAND_RANGE(1, 128));
	if (ret == -1)
		goto out;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags != -1)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	afd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (afd != -1) {
		struct childdata *child = this_child();

		if (child == NULL || child->fd_event_ring == NULL ||
		    !fd_event_enqueue(child->fd_event_ring, FD_EVENT_NEWSOCK,
				      afd, (int)si->triplet.family, 0,
				      si->triplet.type, si->triplet.protocol))
			close(afd);
	}

out:
	free(sa);
}

static int open_sockets(void)
{
	struct objhead *head;
	int ret;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);
	head->destroy = &socket_destructor;
	head->dump = &socket_dump;
	/*
	 * Route obj structs for this provider through the shared obj
	 * heap.  Sockets is the largest fan-in of the remaining shared-
	 * heap holdouts: add_socket() is the single allocation site but
	 * is reached from three runtime contexts that all need the obj
	 * to land in shm:
	 *
	 *   - generate_sockets() at init: the per-protocol valid-triplet
	 *     fan-out (and the random-fill loop that brings nr_sockets
	 *     up to NR_SOCKET_FDS).  Pre-fork in the parent.
	 *
	 *   - open_socket_fd(): the .open hook fired by try_regenerate_
	 *     fd() when the pool drops below threshold.  Picks a random
	 *     family/type/protocol triplet and opens a fresh socket.
	 *     Runs in the parent post-fork — exactly the case the
	 *     shared obj heap exists to serve.
	 *
	 *   - fd-event.c FD_EVENT_NEWSOCK drain: a child that
	 *     successfully accept4()s an inbound connection in
	 *     socket_child_ops() enqueues the new fd plus the parent
	 *     family/type/protocol scalars; the parent's event drain
	 *     calls add_socket() with those, transferring the fd into
	 *     the global pool.  Runs in the parent post-fork on every
	 *     drained event, so the obj must land somewhere children
	 *     can see — same structural property as the regen path.
	 *
	 * struct socketinfo carries no pointer fields (triplet is three
	 * ints, fd is an int, needs_setup is a bool), so this is an obj-
	 * struct-only conversion — no companion alloc_shared_str() calls
	 * for heap-allocated members.  The transient sockaddr buffer
	 * built by generate_sockaddr() inside socket_child_ops() lives
	 * for the duration of one accept4() attempt and is freed in the
	 * same function via free(sa); it is not attached to the obj and
	 * therefore stays on the private heap.
	 */
	head->shared_alloc = true;

	ret = generate_sockets();
	output(1, "created %u sockets\n", nr_sockets);
	return ret;
}

struct socketinfo * get_rand_socketinfo(void)
{
	struct object *obj;

	/* When using victim files, sockets can be 0. */
	if (objects_empty(OBJ_FD_SOCKET) == true)
		return NULL;

	obj = get_random_object(OBJ_FD_SOCKET, OBJ_GLOBAL);
	if (obj == NULL)
		return NULL;

	if (obj->sockinfo.needs_setup)
		socket_setup_lazy(&obj->sockinfo);

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
		if (si->needs_setup)
			socket_setup_lazy(si);

		if (!(ONE_IN(1000)))
			return si->fd;
	}
	return get_random_fd();
}

static int open_socket_fd(void)
{
	struct socket_triplet st;
	int r, fd;

	r = rand() % TRINITY_PF_MAX;
	st.family = r;

	if (st.family >= ARRAY_SIZE(no_domains))
		return false;
	if (no_domains[st.family])
		return false;
	if (get_domain_name(st.family) == NULL)
		return false;
	if (valid_proto(st.family) == false)
		return false;

	st.protocol = rand_proto_for_family(st.family);
	if (sanitise_socket_triplet(&st) == -1)
		rand_proto_type(&st);

	fd = open_socket(st.family, st.type, st.protocol);
	if (fd < 0)
		return false;

	return true;
}

static const struct fd_provider socket_fd_provider = {
	.name = "sockets",
	.objtype = OBJ_FD_SOCKET,
	.enabled = true,
	.init = &open_sockets,
	.get = &get_rand_socket_fd,
	.open = &open_socket_fd,
	.child_ops = &socket_child_ops,
};

REG_FD_PROV(socket_fd_provider);
