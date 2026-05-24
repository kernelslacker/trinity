/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Shape buckets for the (upeer_sockaddr, upeer_addrlen) pair.
 *
 * The kernel accepts five distinct argument shapes here, and each one
 * traverses a different patch of the accept(2) -> move_addr_to_user()
 * path.  The pre-bucket sanitiser only ever published shape (a) (full
 * sockaddr_storage out + *lenp = sizeof(struct sockaddr_storage)), so
 * the truncation oracle inside move_addr_to_user() and the explicit
 * "peer-not-wanted" NULL/NULL arm never fired.
 *
 *  (a) full sockaddr_storage out + *lenp = full capacity.
 *  (b) addr == NULL && addrlen == NULL -- caller doesn't want the peer
 *      address back.  The kernel requires the pair to be BOTH NULL or
 *      BOTH non-NULL; a mixed pair is -EFAULT.
 *  (c) addr non-NULL, *lenp = 0 -- kernel writes nothing but reports
 *      the full needed length in *lenp via the value-result writeback.
 *  (d) addr non-NULL, *lenp = sizeof(struct sockaddr) -- canonical
 *      truncation oracle: kernel writes a truncated address and
 *      reports the full needed length back.
 *  (e) addr non-NULL, *lenp = small non-zero value -- exercises the
 *      move_addr_to_user() length-writeback path with a variety of
 *      undersized buffer claims.
 */
static void sanitise_accept_addrlen(struct syscallrecord *rec)
{
	static const socklen_t undersized_lens[] = { 1, 2, 4, 8, 12 };
	socklen_t *lenp;
	unsigned int bucket = rnd_modulo_u32(100);

	if (bucket < 20) {
		/* (b) Both slots must be NULL together; mixed pair EFAULTs. */
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sockaddr_storage));

	lenp = zmalloc(sizeof(*lenp));
	if (bucket < 50) {
		/* (a) full sockaddr_storage capacity. */
		*lenp = sizeof(struct sockaddr_storage);
	} else if (bucket < 65) {
		/* (c) zero-length writeback oracle. */
		*lenp = 0;
	} else if (bucket < 85) {
		/* (d) canonical truncation length. */
		*lenp = sizeof(struct sockaddr);
	} else {
		/* (e) miscellaneous undersized lengths. */
		*lenp = RAND_ARRAY(undersized_lens);
	}

	rec->a3 = (unsigned long) lenp;
	/*
	 * upeer_addrlen is value-result.  Use _inout (not _out) so the
	 * init value survives any heap-overlap relocation: the kernel
	 * reads *lenp as max_addrlen BEFORE writing the actual length
	 * back.  Mirrors getsockopt.c:73-101.
	 */
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));
}

static void sanitise_accept(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	sanitise_accept_addrlen(rec);
}

static void post_accept(struct syscallrecord *rec)
{
	struct fd_hash_entry *listen_entry;
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	new->sockinfo.fd = fd;

	/* Inherit triplet from the listening socket. */
	listen_entry = fd_hash_lookup(rec->a1);
	if (listen_entry != NULL && listen_entry->type == OBJ_FD_SOCKET) {
		new->sockinfo.triplet = listen_entry->obj->sockinfo.triplet;
	}

	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

struct syscallentry syscall_accept = {
	.name = "accept",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "upeer_sockaddr", [2] = "upeer_addrlen" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SOCKET,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_accept,
	.post = post_accept,
};

/*
 * SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
	 int __user *, upeer_addrlen, int, flags)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 *
 */

static unsigned long accept4_flags[] = {
	SOCK_NONBLOCK, SOCK_CLOEXEC,
};

static void sanitise_accept4(struct syscallrecord *rec)
{
	socklen_t *lenp;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sockaddr_storage));

	/* See sanitise_accept above for the value-result socklen_t* rationale. */
	lenp = zmalloc(sizeof(*lenp));
	*lenp = sizeof(struct sockaddr_storage);
	rec->a3 = (unsigned long) lenp;
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));
}

struct syscallentry syscall_accept4 = {
	.name = "accept4",
	.num_args = 4,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "upeer_sockaddr", [2] = "upeer_addrlen", [3] = "flags" },
	.arg_params[3].list = ARGLIST(accept4_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SOCKET,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_accept4,
	.post = post_accept,
};
