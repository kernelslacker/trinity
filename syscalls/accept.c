/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include "net.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "unblocker.h"
#include "utils.h"

#include "kernel/socket.h"
/*
 * Shape buckets for the (upeer_sockaddr, upeer_addrlen) pair.
 *
 * move_addr_to_user() splits three ways on the caller's *lenp against
 * the real sockaddr length: full-capacity (no truncation), undersized
 * (truncated copy, real length written back), and oversized (kernel
 * clamps *lenp writeback to the real length).  The out buffer itself
 * is always sized to struct sockaddr_storage via avoid_shared_buffer_out()
 * -- only the *lenp VALUE varies -- so an oversized *lenp cannot make
 * the kernel overrun the out buffer.
 *
 *  (a) full sockaddr_storage out + *lenp = full capacity -- no
 *      truncation, no clamp.
 *  (b) addr == NULL && addrlen == NULL -- caller doesn't want the peer
 *      address back.  The kernel requires the pair to be BOTH NULL or
 *      BOTH non-NULL; a mixed pair is -EFAULT.
 *  (c) addr non-NULL, *lenp = 0 -- degenerate undersized: kernel writes
 *      nothing but reports the full needed length in *lenp via the
 *      value-result writeback.
 *  (d) addr non-NULL, *lenp = sizeof(struct sockaddr) -- canonical
 *      truncation oracle: kernel writes a truncated address and
 *      reports the full needed length back.
 *  (e) addr non-NULL, *lenp = a value straddling the real per-family
 *      sockaddr sizes (16 for AF_INET, 28 for AF_INET6) -- exercises
 *      the undersized-buffer arm of move_addr_to_user() at the
 *      boundaries where truncation flips.
 *  (f) addr non-NULL, *lenp > sizeof(struct sockaddr_storage) --
 *      exercises the oversized/clamp arm: the kernel copies at most
 *      the real sockaddr and clamps the *lenp writeback back down.
 */
static void sanitise_accept_addrlen(struct syscallrecord *rec)
{
	static const socklen_t undersized_lens[] = {
		sizeof(struct sockaddr) - 1,
		sizeof(struct sockaddr_in) - 1,
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6) - 1,
		sizeof(struct sockaddr_in6),
	};
	static const socklen_t oversized_lens[] = {
		sizeof(struct sockaddr_storage) + 1,
		sizeof(struct sockaddr_storage) * 2,
		4096,
	};
	socklen_t *lenp;
	unsigned int bucket = rnd_modulo_u32(100);

	if (bucket < 20) {
		/* (b) Both slots must be NULL together; mixed pair EFAULTs. */
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sockaddr_storage));

	/*
	 * Source the value-result socklen_t slot from
	 * get_writable_address() rather than bare zmalloc().  The
	 * original zmalloc() result was untracked (no deferred_alloc_track)
	 * AND the .post handler made no attempt to free it, so every
	 * accept call leaked an 8-byte libc-heap chunk -- 5-second runs
	 * showed thousands of these accumulating per child.  Pool-owned
	 * memory has no free obligation, mirrors the pipe/socketpair fix
	 * shape, and the slot lives outside the libc brk arena so the
	 * kernel-side writeback of the actual length can't trip glibc
	 * malloc consistency checks on adjacent chunks.
	 *
	 * On pool exhaustion fall back to the NULL/NULL pair shape (b)
	 * so the kernel EFAULTs cleanly instead of writing the result
	 * length into a leftover slot from a previous iteration.
	 */
	lenp = (socklen_t *) get_writable_address(sizeof(*lenp));
	if (lenp == NULL) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	if (bucket < 45) {
		/* (a) full sockaddr_storage capacity. */
		*lenp = sizeof(struct sockaddr_storage);
	} else if (bucket < 60) {
		/* (c) zero-length writeback oracle. */
		*lenp = 0;
	} else if (bucket < 75) {
		/* (d) canonical truncation length. */
		*lenp = sizeof(struct sockaddr);
	} else if (bucket < 90) {
		/* (e) undersized lengths straddling per-family sockaddr sizes. */
		*lenp = RAND_ARRAY(undersized_lens);
	} else {
		/* (f) oversized -- kernel clamps the writeback. */
		*lenp = RAND_ARRAY(oversized_lens);
	}

	rec->a3 = (unsigned long) lenp;
}

/*
 * On-demand accept-unblocker.  Immediately before the kernel-side
 * accept() runs, fire a loopback connect at the very fd this call is
 * about to use so the backlog is non-empty by the time accept enters
 * inet_csk_accept's wait loop.  Removes the blocking window for this
 * specific call rather than relying on the periodic baseline in
 * socket_child_ops().
 *
 * rec->a1 arrives as a struct socketinfo * from ARG_SOCKETINFO and is
 * overwritten with the int fd by fd_from_socketinfo() below.  Grab
 * the cached listener metadata off the socketinfo first; the
 * connector then prefers cache->local over a lazy probe.
 *
 * fd_from_socketinfo() carries a 1/1000 random-fd substitution; on
 * that arm rec->a1 ends up pointing at an arbitrary fd, the connector
 * lazy-probes that, and a non-listener is a hard no-op.
 */
static void sanitise_accept(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	int fd;

	rec->a1 = fd_from_socketinfo(si);
	fd = (int) rec->a1;

	accept_unblocker_fire(fd, si);

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

/*
 * accept4_flags[] is still wired up to ARG_LIST so the argument
 * generator has a default to publish; sanitise_accept4_flags()
 * overrides rec->a4 below with an explicit bucket draw.  ARG_LIST's
 * bitmask path would never reach the zero-flags or full-combo arms
 * on its own, and never test the invalid-high-bit reject path.
 */
static unsigned long accept4_flags[] = {
	SOCK_NONBLOCK, SOCK_CLOEXEC,
};

static unsigned long sanitise_accept4_flags(void)
{
	unsigned int pick = rnd_modulo_u32(10);

	switch (pick) {
	case 0:
	case 1:
		return 0;
	case 2:
	case 3:
	case 4:
		return SOCK_NONBLOCK;
	case 5:
	case 6:
	case 7:
		return SOCK_CLOEXEC;
	case 8:
		return SOCK_NONBLOCK | SOCK_CLOEXEC;
	default:
		/* Invalid high bit -- kernel reject path. */
		return 0x80000000UL;
	}
}

static void sanitise_accept4(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	int fd;

	rec->a1 = fd_from_socketinfo(si);
	fd = (int) rec->a1;

	accept_unblocker_fire(fd, si);

	sanitise_accept_addrlen(rec);

	rec->a4 = sanitise_accept4_flags();
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
