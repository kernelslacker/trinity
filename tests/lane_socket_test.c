/*
 * Self-check for lane_netlink_socketinfo(): a child in the userns-admin
 * lane sends netlink, seven draws in eight, on a socket of the drawn
 * protocol that it opened itself and keeps in its OBJ_LOCAL pool, and
 * opens another once that one is retired.  Outside the lane, for another
 * family, for a protocol whose kernel side lives in init_net alone, or for
 * one socket() has refused for good, the drawn socket stays.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "child-api.h"		/* child_userns_lane_is_active */
#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "net.h"		/* lane_netlink_socketinfo */
#include "objects.h"
#include "socketinfo.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);
extern int (*fake_netlink_socket)(int type, int protocol);	/* fake_net.c */

/* Enough draws that a swap and a keep both turn up: that none of them
 * keeps the drawn socket has odds of (7/8)^256, about 1e-15, and that a
 * quarter of them do, about 5e-10. */
#define DRAWS		256
#define POOL_CAP	8

/* Also set by userns_lane_test.c. */
bool fake_lane_active;

/* What child-init-sandbox.c answers in a run. */
bool child_userns_lane_is_active(void)
{
	return fake_lane_active;
}

static struct objhead local_sockets;
static struct object *local_array[POOL_CAP];
/* add_object()'s stamp, which, like a pool's, never repeats. */
static unsigned int last_slot_version;

static struct objhead *pool_head(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_LOCAL && type == OBJ_FD_SOCKET)
		return &local_sockets;
	return NULL;
}

static struct object *pool_alloc_object(void)
{
	struct object *obj = calloc(1, sizeof(*obj));

	if (obj == NULL)
		BUG("lane socket: out of memory");
	return obj;
}

static struct object *no_object(void)
{
	return NULL;
}

/* Files the object as the real add_object() does, its type and slot
 * version stamped. */
static void pool_add_object(struct object *obj, enum obj_scope scope,
			    enum objecttype type)
{
	if (scope != OBJ_LOCAL || type != OBJ_FD_SOCKET)
		BUG("lane socket: a socket went to another pool");
	if (local_sockets.num_entries == POOL_CAP)
		BUG("lane socket: the pool is full");
	obj->obj_type = type;
	obj->slot_version = ++last_slot_version;
	local_sockets.array[local_sockets.num_entries++] = obj;
}

/* A netlink socket already in the child's pool that it did not open in
 * the lane, such as a dup of one of the parent's. */
static struct object *pooled(unsigned int protocol, int fd)
{
	struct object *obj = pool_alloc_object();

	obj->sockinfo.fd = fd;
	obj->sockinfo.triplet.family = PF_NETLINK;
	obj->sockinfo.triplet.type = SOCK_DGRAM;
	obj->sockinfo.triplet.protocol = protocol;
	pool_add_object(obj, OBJ_LOCAL, OBJ_FD_SOCKET);
	return obj;
}

static unsigned int socket_calls;
static int socket_type, socket_protocol, socket_fd = -1;
static int socket_errno;	/* non-zero: socket() fails with it */

/* /dev/null stands in for the netlink socket: nothing is sent on it. */
static int lane_socket(int type, int protocol)
{
	socket_calls++;
	socket_type = type;
	socket_protocol = protocol;
	if (socket_errno != 0) {
		errno = socket_errno;
		return -1;
	}
	socket_fd = open("/dev/null", O_RDONLY);
	if (socket_fd < 0)
		BUG("lane socket: cannot open /dev/null");
	return socket_fd;
}

/* Empties the pool, as a close() of each socket in it retires them. */
static void retire_all(void)
{
	unsigned int i;

	for (i = 0; i < local_sockets.num_entries; i++)
		free(local_sockets.array[i]);
	local_sockets.num_entries = 0;
	if (socket_fd >= 0)
		close(socket_fd);
	socket_fd = -1;
}

static void reset(void)
{
	retire_all();
	socket_calls = 0;
	socket_errno = 0;
	fake_lane_active = true;
}

/* Draws @si DRAWS times, each answer @si itself or @own; counts the
 * swaps to @own. */
static unsigned int swaps_to(struct socketinfo *si, const struct socketinfo *own)
{
	unsigned int i, swaps = 0;

	for (i = 0; i < DRAWS; i++) {
		struct socketinfo *got = lane_netlink_socketinfo(si);

		if (got == si)
			continue;
		if (own == NULL || got != own)
			BUG("lane socket: a swap to a socket it should not use");
		swaps++;
	}
	return swaps;
}

/* Draws @si until the first swap, which must be to a socket that has
 * just been opened for its protocol and pooled, and returns it. */
static struct socketinfo *first_swap(struct socketinfo *si)
{
	unsigned int i, calls = socket_calls;

	for (i = 0; i < DRAWS; i++) {
		struct socketinfo *got = lane_netlink_socketinfo(si);
		struct object *last;

		if (got == si)
			continue;
		last = local_sockets.array[local_sockets.num_entries - 1];
		if (socket_calls != calls + 1 || got != &last->sockinfo)
			BUG("lane socket: the first swap is not to a socket opened for it");
		return got;
	}
	BUG("lane socket: no draw swapped");
	return NULL;
}

/* The lane decides. */
static void outside_the_lane_the_drawn_socket_stays(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE }, .fd = 100,
	};

	reset();
	fake_lane_active = false;
	if (swaps_to(&si, NULL) != 0 || socket_calls != 0)
		BUG("lane socket: swapped outside the lane");
}

/* Only netlink is swapped. */
static void another_family_stays(void)
{
	struct socketinfo si = {
		.triplet = { PF_INET, SOCK_DGRAM, 0 }, .fd = 100,
	};

	reset();
	if (swaps_to(&si, NULL) != 0 || socket_calls != 0)
		BUG("lane socket: swapped a socket that is not netlink");
}

/* An empty pool gets one socket, of the drawn type and protocol, which
 * every later swap reuses; a minority of draws keep the drawn socket. */
static void opens_one_socket_then_reuses_it(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE }, .fd = 100,
	};
	struct socketinfo *own = NULL;
	unsigned int i, kept = 0, swaps = 0;

	reset();
	for (i = 0; i < DRAWS; i++) {
		struct socketinfo *got = lane_netlink_socketinfo(&si);

		if (got == &si) {
			kept++;
			continue;
		}
		if (own == NULL)
			own = got;
		if (got != own)
			BUG("lane socket: two sockets for one protocol");
		swaps++;
	}
	if (kept == 0 || swaps == 0)
		BUG("lane socket: every draw went the same way");
	if (kept > DRAWS / 4)
		BUG("lane socket: most draws kept the parent's socket");
	if (socket_calls != 1 || socket_type != SOCK_DGRAM ||
	    socket_protocol != NETLINK_ROUTE)
		BUG("lane socket: not one socket() of the drawn type and protocol");
	if (local_sockets.num_entries != 1 ||
	    own != &local_sockets.array[0]->sockinfo)
		BUG("lane socket: the socket sent on is not the pooled one");
	if (own->fd != socket_fd || own->triplet.family != PF_NETLINK ||
	    own->triplet.type != SOCK_DGRAM ||
	    own->triplet.protocol != NETLINK_ROUTE)
		BUG("lane socket: the pooled socket misstates what it is");
}

/* A pooled netlink socket of the protocol that the lane did not open,
 * such as a dup of the parent's, sits in the parent's netns: the child
 * opens its own instead and never sends on the copy. */
static void takes_no_pooled_copy_of_a_parent_socket(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_XFRM }, .fd = 100,
	};
	struct socketinfo *own;

	reset();
	pooled(NETLINK_XFRM, 200);
	own = first_swap(&si);
	swaps_to(&si, own);
	if (socket_calls != 1)
		BUG("lane socket: opened more than one socket for one protocol");
}

/* Once the pool retires the child's socket, the next swap opens another
 * rather than sending on the gone one's number. */
static void a_retired_socket_is_replaced(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG }, .fd = 100,
	};
	struct socketinfo *own;

	reset();
	first_swap(&si);
	retire_all();
	own = first_swap(&si);
	swaps_to(&si, own);
	if (socket_calls != 2)
		BUG("lane socket: a retired socket was not replaced once");
}

/* A protocol the kernel lacks costs one socket() per child, not one per
 * draw. */
static void a_missing_protocol_is_not_retried(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER }, .fd = 100,
	};

	reset();
	socket_errno = EPROTONOSUPPORT;
	if (swaps_to(&si, NULL) != 0)
		BUG("lane socket: swapped to a socket it could not open");
	if (socket_calls != 1)
		BUG("lane socket: retried a protocol the kernel lacks");
}

/* Running out of fds says nothing about the protocol: the next swap
 * tries again, and gets its socket once one can be had. */
static void a_transient_failure_is_retried(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC }, .fd = 100,
	};

	reset();
	socket_errno = EMFILE;
	if (swaps_to(&si, NULL) != 0)
		BUG("lane socket: swapped to a socket it could not open");
	if (socket_calls < 2)
		BUG("lane socket: gave up on a protocol after EMFILE");

	socket_errno = 0;
	first_swap(&si);
}

/* A lane socket of a protocol whose kernel socket lives in init_net
 * alone would have no peer, so the drawn socket stays. */
static void an_init_net_only_protocol_stays(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR }, .fd = 100,
	};

	reset();
	if (swaps_to(&si, NULL) != 0 || socket_calls != 0)
		BUG("lane socket: swapped an init_net-only protocol");
}

/* A protocol past the kernel's table is never opened. */
static void an_out_of_range_protocol_stays(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, MAX_LINKS }, .fd = 100,
	};

	reset();
	if (swaps_to(&si, NULL) != 0 || socket_calls != 0)
		BUG("lane socket: tried a protocol past MAX_LINKS");
}

/* With no object to pool it in, the socket just opened is closed and the
 * drawn one stays. */
static void a_socket_with_no_object_is_closed(void)
{
	struct socketinfo si = {
		.triplet = { PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT },
		.fd = 100,
	};
	unsigned int i;

	reset();
	fake_alloc_object = no_object;
	for (i = 0; i < DRAWS && socket_calls == 0; i++) {
		if (lane_netlink_socketinfo(&si) != &si)
			BUG("lane socket: swapped to a socket it had no object for");
	}
	fake_alloc_object = pool_alloc_object;
	if (socket_calls != 1)
		BUG("lane socket: never opened a socket to close");
	if (fcntl(socket_fd, F_GETFD) != -1 || errno != EBADF)
		BUG("lane socket: a socket with no object was left open");
	socket_fd = -1;
}

void lane_socket_self_check(void);
void lane_socket_self_check(void)
{
	struct objhead *(*saved_hook)(enum obj_scope, enum objecttype) =
		fake_get_objhead;

	local_sockets.array = local_array;
	fake_get_objhead = pool_head;
	fake_alloc_object = pool_alloc_object;
	fake_add_object = pool_add_object;
	fake_netlink_socket = lane_socket;

	/* The helper's state lasts the process, so each case that can
	 * open a socket takes a protocol of its own. */
	outside_the_lane_the_drawn_socket_stays();
	another_family_stays();
	opens_one_socket_then_reuses_it();
	takes_no_pooled_copy_of_a_parent_socket();
	a_retired_socket_is_replaced();
	a_missing_protocol_is_not_retried();
	a_transient_failure_is_retried();
	an_init_net_only_protocol_stays();
	an_out_of_range_protocol_stays();
	a_socket_with_no_object_is_closed();
	reset();

	fake_netlink_socket = NULL;
	fake_add_object = NULL;
	fake_alloc_object = NULL;
	fake_get_objhead = saved_hook;
	fake_lane_active = false;
}
