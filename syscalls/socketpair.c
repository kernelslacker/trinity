/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * gen_socket_args() randomises (family, type, protocol) across the
 * full kernel socket matrix.  On stock kernels only AF_UNIX (plus a
 * very narrow AF_TIPC slice) reliably produces a connected fd pair
 * from socketpair(2); the AF_INET / AF_INET6 / PF_NETLINK / PF_VSOCK
 * draws either fail in socket_setup() before publishing the fd pair
 * or hit -EOPNOTSUPP, so the post handler's register_socketpair_fd()
 * publish almost never runs and the consumer pool starves.
 *
 * Bias 60% of calls to (AF_UNIX, {SOCK_STREAM|SOCK_DGRAM|SOCK_SEQPACKET}, 0)
 * so the success-publish path runs reliably, keep 40% on the wide
 * gen_socket_args() draw so the other-AF reject paths stay exercised.
 * Going 100% AF_UNIX would crater coverage of those reject paths.
 */
static const unsigned long af_unix_types[] = {
	SOCK_STREAM,
	SOCK_DGRAM,
	SOCK_SEQPACKET,
};

static void register_socketpair_fd(int fd, struct syscallrecord *rec)
{
	struct object *new;

	if (fd <= 2 || fd >= (1 << 20))
		return;
	if (find_local_object_by_fd(OBJ_FD_SOCKET, fd) != NULL)
		return;

	new = alloc_object();
	new->sockinfo.fd = fd;
	new->sockinfo.triplet.family = rec->a1;
	new->sockinfo.triplet.type = rec->a2;
	new->sockinfo.triplet.protocol = rec->a3;
	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

/*
 * Snapshot for the post handler.  Three-leg hardening, mirroring the
 * shape that landed for pipe/timer_create/io_setup:
 *
 *   1. The int[2] output buffer is sourced from get_writable_address()
 *      rather than zmalloc() + avoid_shared_buffer_out().  The arena
 *      is mmap-backed, far from the libc brk region where glibc malloc
 *      consistency checks fire, so a wild kernel write into this slot
 *      can no longer surface as a SIGABRT cluster at __libc_message
 *      raise IP.  Pool-owned -- no deferred_free needed for the buffer.
 *
 *   2. The snap struct carries a magic cookie that the post handler
 *      checks before dereferencing *get_arg_snapshot(rec, 4).  A
 *      sibling scribble of rec->post_state with a heap-shaped pointer
 *      to a foreign chunk survives looks_like_corrupted_ptr() but
 *      fails the cookie gate.
 *
 *   3. The snap pointer is registered in the post-state ownership table
 *      at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check; the ownership table closes
 *      that gap.
 *
 * The OUT-pointer (a4 / usockvec) defence is now generic:
 * .arg_snapshot_mask opts a4 into the dispatch-time arg_shadow capture
 * (snapshotted inside __do_syscall() after the final
 * blanket_address_scrub, from the locals about to enter the kernel),
 * and the post handler reads it via get_arg_snapshot(rec, 4).  A
 * sibling scribble of rec->a4 between dispatch and post bumps the
 * generic arg_shadow_stomp tripwire from inside the accessor; the
 * returned value is the kernel-visible address, so the fd-pair deref
 * still hits the buffer the kernel actually wrote.  The previous
 * snap->usockvec vs rec->a4 identity check was a false-positive source:
 * a4 is ARG_ADDRESS, so the dispatcher's blanket_address_scrub
 * benignly relocates the pointer between sanitise and dispatch and
 * the divergence is expected, not a corruption signal.
 */
#define SOCKETPAIR_POST_STATE_MAGIC	0x534F434B5F4D4147UL	/* "SOCK_MAG" */
struct socketpair_post_state {
	unsigned long magic;
};

static void sanitise_socketpair(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };
	int *usockvec;
	struct socketpair_post_state *snap;

	if (rnd_modulo_u32(5) < 3) {
		/* 60%: force the AF_UNIX success-publish arm. */
		st.family = AF_UNIX;
		st.type = RAND_ARRAY(af_unix_types);
		st.protocol = 0;
	} else {
		/* 40%: retain wide kernel reject coverage. */
		gen_socket_args(&st);
	}

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;

	usockvec = (int *) get_writable_address(sizeof(int) * 2);
	if (usockvec == NULL) {
		/*
		 * Pool exhaustion / mincore failure.  Leaving a leftover
		 * pointer from a previous iteration in rec->a4 would let the
		 * kernel write the fd pair into whatever sits there now.
		 * Force NULL so the kernel returns -EFAULT cleanly.
		 */
		rec->a4 = 0;
		return;
	}
	rec->a4 = (unsigned long) usockvec;

	/* magic-cookie / private post_state: see post_state_register().
	 * The OUT-pointer is defended via .arg_snapshot_mask + the
	 * dispatch-time arg_shadow capture, not a snap field. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SOCKETPAIR_POST_STATE_MAGIC;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  Runs ahead of post_socketpair(), which
 * clears rec->post_state during cleanup; reading the snap from a
 * .post hook after that point would see zero.  Does its own shape +
 * magic + ownership validation and reads the OUT-pointer via the
 * generic arg_shadow accessor before deref so a sibling-stomped
 * post_state or rec->a4 doesn't drive register_socketpair_fd() with
 * foreign bytes -- corruption attribution for the snap-struct gates
 * stays in post_socketpair() below; out-pointer corruption is bumped
 * generically by arg_shadow_stomp from inside get_arg_snapshot().
 */
static void post_socketpair_record_fds(struct syscallrecord *rec)
{
	struct socketpair_post_state *snap =
		(struct socketpair_post_state *) rec->post_state;
	int *usockvec;

	if ((long) rec->retval != 0)
		return;

	if (snap == NULL || looks_like_corrupted_ptr(rec, snap))
		return;

	if (!post_state_is_owned(snap))
		return;

	if (snap->magic != SOCKETPAIR_POST_STATE_MAGIC)
		return;

	/*
	 * The OUT-pointer (a4 / usockvec) is read via the generic arg_shadow
	 * accessor: it returns the kernel-visible address snapshotted in
	 * __do_syscall() after the final blanket_address_scrub.  A sibling
	 * stomp of rec->a4 between dispatch and here bumps arg_shadow_stomp
	 * from inside the accessor and the post handler still sees the
	 * address the kernel actually wrote.
	 */
	usockvec = (int *) get_arg_snapshot(rec, 4);
	if (usockvec == NULL || looks_like_corrupted_ptr(rec, usockvec))
		return;

	register_socketpair_fd(usockvec[0], rec);
	register_socketpair_fd(usockvec[1], rec);
}

static void post_socketpair(struct syscallrecord *rec)
{
	struct socketpair_post_state *snap =
		(struct socketpair_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_socketpair: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (another
	 * in-flight socketpair child's snap, or a stale snap a sibling
	 * stomp resurrected by redirecting rec->post_state at it), in
	 * which case reading snap->magic touches the wrong struct.  Reject
	 * before deferred_freeptr() hands a foreign pointer to the
	 * deferred-free ring.  Mirrors prctl.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_socketpair: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: ownership table confirmed this is our snap,
	 * so reading snap->magic is now safe.  A mismatch here means the
	 * snapshot itself was wholesale-scribbled in place.
	 */
	if (snap->magic != SOCKETPAIR_POST_STATE_MAGIC) {
		outputerr("post_socketpair: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a4 = 0;
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_socketpair = {
	.name = "socketpair",
	.num_args = 4,
	.argtype = { [3] = ARG_ADDRESS },
	.argname = { [0] = "family", [1] = "type", [2] = "protocol", [3] = "usockvec" },
	.group = GROUP_NET,
	.sanitise = sanitise_socketpair,
	.post = post_socketpair,
	.ret_objtype_via_post = post_socketpair_record_fds,
	.rettype = RET_ZERO_SUCCESS,
	/* a4 (usockvec) is the kernel's OUT-pointer; both post handlers
	 * deref through it.  Shadow it so a sibling stomp between
	 * dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handlers still see the address the
	 * kernel actually wrote, not the stomped value. */
	.arg_snapshot_mask = (1u << 3),
};
