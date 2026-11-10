/*
 * Self-check for get_rand_socket_fd_of_triplet() (fds/sockets-pick.c): a
 * pick hands out only sockets of the shapes it names, reading socket()'s
 * type flags and an inet protocol of 0 as the kernel does, each of the
 * child's matching sockets in turn, and one of the parent's only while
 * the child holds none; a closed socket never.  The pools come through
 * fake_objects.c's get_objhead() hook, and the picker is reached through
 * __real_, past the fake_fds.c stand-in.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "kernel/in.h"		/* IPPROTO_L2TP */
#include "net.h"
#include "objects.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

int __real_get_rand_socket_fd_of_triplet(const struct socket_triplet *triplets,
					 unsigned int n_triplets);

/* Picks per check: one of two sockets sits out all of them 2^-63 of the
 * time. */
#define PICKS	64

/* What l2tp_validate_socket() takes. */
static const struct socket_triplet l2tp_shapes[] = {
	{ PF_INET,  SOCK_DGRAM, IPPROTO_UDP },
	{ PF_INET6, SOCK_DGRAM, IPPROTO_UDP },
	{ PF_INET,  SOCK_DGRAM, IPPROTO_L2TP },
	{ PF_INET6, SOCK_DGRAM, IPPROTO_L2TP },
};

/* The child's sockets as socket() records them: 40 and 41 are of the
 * shapes, the others not. */
static const struct socketinfo local_socks[] = {
	/* An inet datagram socket of protocol 0 is UDP. */
	{ .triplet = { PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0 }, .fd = 40 },
	{ .triplet = { PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_L2TP },
	  .fd = 41 },
	/* A raw socket of protocol UDP is not a datagram socket. */
	{ .triplet = { PF_INET, SOCK_RAW, IPPROTO_UDP }, .fd = 42 },
	/* An inet stream socket of protocol 0 is TCP. */
	{ .triplet = { PF_INET6, SOCK_STREAM, 0 }, .fd = 43 },
	/* A unix socket's 0 is no inet protocol. */
	{ .triplet = { PF_UNIX, SOCK_DGRAM, 0 }, .fd = 44 },
	/* Closed. */
	{ .triplet = { PF_INET, SOCK_DGRAM, IPPROTO_UDP }, .fd = -1 },
};

static struct objhead local_head, global_head;
static struct object local_objs[ARRAY_SIZE(local_socks)];
static struct object *local_array[ARRAY_SIZE(local_socks)];
static struct object global_obj;
static struct object *global_array[1];

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void)type;
	return scope == OBJ_LOCAL ? &local_head : &global_head;
}

/* The child's sockets from the first'th on, and the parent's UDP socket,
 * fd 50. */
static void fill_pools(unsigned int first)
{
	unsigned int i;

	memset(local_objs, 0, sizeof(local_objs));
	for (i = first; i < ARRAY_SIZE(local_socks); i++) {
		local_objs[i].obj_type = OBJ_FD_SOCKET;
		local_objs[i].sockinfo = local_socks[i];
		local_array[i - first] = &local_objs[i];
	}
	local_head.array = local_array;
	local_head.num_entries = ARRAY_SIZE(local_socks) - first;

	memset(&global_obj, 0, sizeof(global_obj));
	global_obj.obj_type = OBJ_FD_SOCKET;
	global_obj.sockinfo.triplet = (struct socket_triplet) {
		PF_INET, SOCK_DGRAM, IPPROTO_UDP };
	global_obj.sockinfo.fd = 50;
	global_array[0] = &global_obj;
	global_head.array = global_array;
	global_head.num_entries = 1;
}

/* Every pick is one of the n fds in want, and each comes up. */
static void expect_picks(const int *want, unsigned int n, const char *what)
{
	unsigned int seen = 0, i, k;

	for (k = 0; k < PICKS; k++) {
		int fd = __real_get_rand_socket_fd_of_triplet(l2tp_shapes,
							      ARRAY_SIZE(l2tp_shapes));

		for (i = 0; i < n && want[i] != fd; i++)
			;
		if (i == n) {
			fprintf(stderr, "socket pick: %s: pick %u gave fd %d\n",
				what, k, fd);
			BUG("socket pick: a pick gave a socket it should not");
		}
		seen |= 1U << i;
	}
	if (seen != (1U << n) - 1) {
		fprintf(stderr, "socket pick: %s: picks gave the fds %#x of %u\n",
			what, seen, n);
		BUG("socket pick: a pick passed over a socket of its shapes");
	}
}

void socket_pick_self_check(void);
void socket_pick_self_check(void)
{
	static const int child_own[] = { 40, 41 };
	static const int parent_own[] = { 50 };
	static const int none[] = { -1 };

	fake_get_objhead = head_hook;

	fill_pools(0);
	expect_picks(child_own, ARRAY_SIZE(child_own), "the child's sockets");

	fill_pools(2);
	expect_picks(parent_own, ARRAY_SIZE(parent_own),
		     "the child's of other shapes");

	global_head.num_entries = 0;
	expect_picks(none, ARRAY_SIZE(none), "none of the shapes");

	fake_get_objhead = NULL;
	memset(&local_head, 0, sizeof(local_head));
	memset(&global_head, 0, sizeof(global_head));
}
