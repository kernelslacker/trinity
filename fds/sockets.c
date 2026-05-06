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
#include "net.h"
#include "objects.h"
#include "proto-alg-dict.h"
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
	const struct netproto *proto;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return NULL;
	}

	obj->sockinfo.fd = fd;
	obj->sockinfo.triplet.family = domain;
	obj->sockinfo.triplet.type = type;
	obj->sockinfo.triplet.protocol = protocol;

	/* Run per-protocol socket setup eagerly, before the obj is
	 * published into the global pool.  The shared obj heap is
	 * mprotected READ-ONLY post-init (commit fbce60744dfb), so any
	 * deferred write to obj->sockinfo from a child SEGVs. */
	proto = net_protocols[domain].proto;
	if (proto != NULL && proto->socket_setup != NULL)
		proto->socket_setup(fd);

	add_object(obj, OBJ_GLOBAL, OBJ_FD_SOCKET);

	/* add_object frees obj and returns without inserting when called
	 * from a child process (OBJ_GLOBAL from non-mainpid).  Signal
	 * failure by returning NULL so callers can close the fd. */
	if (getpid() != mainpid)
		return NULL;

	return obj;
}

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	struct object *obj;
	int fd;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		return fd;

	/* add_socket() owns the fd on failure: on shared-heap exhaustion
	 * it close()s the fd before returning NULL, and on the non-mainpid
	 * path it frees the obj after add_object() drops it.  Either way
	 * the fd is not safe to publish, so don't bump nr_sockets. */
	obj = add_socket(fd, domain, type, protocol);
	if (obj == NULL)
		return -1;

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

	/* Set random socket options at runtime so each child exercises
	 * setsockopt rather than doing a one-shot setup at add time. */
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

/*
 * Probe each socket family the random-syscall picker might select and
 * latch off the ones the running kernel can't open at all.  gen_socket_args
 * (syscalls/socket.c) consults no_domains[] before every random socket()
 * pick; without this auto-skip, a kernel built without CONFIG_BT / CONFIG_X25
 * / CONFIG_TIPC / CONFIG_PHONET / CONFIG_ATM / CONFIG_NFC / CONFIG_INFINIBAND
 * / CONFIG_SMC etc. burns one random-syscall slot per cycle on a
 * guaranteed-EAFNOSUPPORT call.  Only mark when both SOCK_STREAM and
 * SOCK_DGRAM probes return EAFNOSUPPORT or EPROTONOSUPPORT — anything else
 * (EACCES, EPERM, success) means the family is reachable and policy / type
 * mismatches are not our concern here.  The grammar code stays in tree;
 * users on a kernel with the family present probe-pass and fuzz normally.
 */
static void probe_unsupported_pf_families(void)
{
	unsigned int pf;

	for (pf = 0; pf < TRINITY_PF_MAX; pf++) {
		int fd, e_stream, e_dgram;

		if (no_domains[pf])
			continue;

		fd = socket(pf, SOCK_STREAM, 0);
		if (fd >= 0) {
			close(fd);
			continue;
		}
		e_stream = errno;

		fd = socket(pf, SOCK_DGRAM, 0);
		if (fd >= 0) {
			close(fd);
			continue;
		}
		e_dgram = errno;

		if ((e_stream != EAFNOSUPPORT && e_stream != EPROTONOSUPPORT) ||
		    (e_dgram != EAFNOSUPPORT && e_dgram != EPROTONOSUPPORT))
			continue;

		no_domains[pf] = true;
		__atomic_add_fetch(&shm->stats.no_domains_runtime_skipped,
				   1, __ATOMIC_RELAXED);
		output(1, "auto-disabled socket family %u (%s): probe returned "
			  "%s/%s\n",
		       pf, get_domain_name(pf) ? get_domain_name(pf) : "?",
		       strerror(e_stream), strerror(e_dgram));
	}
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
	 * ints, fd is an int), so this is an obj-struct-only conversion
	 * — no companion alloc_shared_str() calls for heap-allocated
	 * members.  The transient sockaddr buffer
	 * built by generate_sockaddr() inside socket_child_ops() lives
	 * for the duration of one accept4() attempt and is freed in the
	 * same function via free(sa); it is not attached to the obj and
	 * therefore stays on the private heap.
	 */
	head->shared_alloc = true;

#ifdef USE_IF_ALG
	/* Build the AF_ALG algorithm dictionary in the parent before any
	 * socket setup runs.  generate_sockets() below calls into
	 * proto_alg.socket_setup() which consumes the dict; children
	 * inherit the populated tables via COW. */
	init_alg_template_dict();
#endif

	probe_unsupported_pf_families();

	ret = generate_sockets();
	output(1, "created %u sockets\n", nr_sockets);
	return ret;
}

struct socketinfo * get_rand_socketinfo(void)
{
	/* When using victim files, sockets can be 0. */
	if (objects_empty(OBJ_FD_SOCKET) == true)
		return NULL;

	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		struct socketinfo *si;

		/*
		 * Use the versioned API so we can re-validate the slot
		 * right before handing &obj->sockinfo back to the caller.
		 * The lockless OBJ_GLOBAL reader race that surfaced the
		 * +0x1ded78 SEGV cluster (sanitise-hook-audit rows 1-4 —
		 * sanitise_recv/sendmsg/mmsg, setsockopt, getsockopt) is
		 * the same shape get_map() already defends against:
		 * the parent destroys the obj between the lockless pick
		 * and the consumer's later deref of si->triplet.family /
		 * si->fd, and free_shared_obj() routes the chunk back to
		 * the shared-heap freelist where a concurrent
		 * alloc_shared_obj() recycles it underneath us.  The
		 * version snapshot below + validate_object_handle() just
		 * before return narrows that window to a few cycles.
		 */
		obj = get_random_object_versioned(OBJ_FD_SOCKET, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		/*
		 * Defend against stale or corrupted slot pointers leaking
		 * out of the OBJ_FD_SOCKET pool.  Heap pointers land at
		 * >= 0x10000 and below the 47-bit user/kernel boundary;
		 * any obj pointer outside that window can't be a real obj
		 * struct, and dereferencing &obj->sockinfo then si->fd or
		 * si->triplet.family scribbles garbage into whatever
		 * sanitise_* hook is consuming the socketinfo (recvmsg's
		 * msg_name, setsockopt's level/optname dispatch).
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_socketinfo: bogus obj %p in "
				  "OBJ_FD_SOCKET pool\n", obj);
			continue;
		}

		si = &obj->sockinfo;

		/*
		 * Even when the obj pointer is sane, the socketinfo may
		 * have been stomped by a stray syscall write — leaving a
		 * believable obj address but wildly wrong fd/family.
		 * Legitimate sockets always have fd >= 0 (set by
		 * add_socket() before publish) and family < TRINITY_PF_MAX
		 * (the same bound syscalls/socket.c:133 and
		 * syscalls/socketcall.c:199 enforce on the dispatch path).
		 * Reject anything outside those bounds rather than feed it
		 * into rand_proto_for_family() / get_domain_name() etc.
		 */
		if (si->fd < 0 || si->triplet.family >= TRINITY_PF_MAX) {
			outputerr("get_rand_socketinfo: bogus sockinfo "
				  "(fd=%d family=%u) for obj %p\n",
				  si->fd, si->triplet.family, obj);
			continue;
		}

		/*
		 * Last-line check: if the parent destroyed/replaced this
		 * slot between get_random_object_versioned() and now, the
		 * version no longer matches and obj is unsafe to deref.
		 * Drop it and pick again rather than handing &obj->sockinfo
		 * to the caller.
		 */
		if (!validate_object_handle(OBJ_FD_SOCKET, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		return si;
	}

	return NULL;
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
