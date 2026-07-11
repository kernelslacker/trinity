/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <fcntl.h>
#include "objects.h"
#include "output-poison.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
static void register_pipe_fd(int fd, bool reader)
{
	struct object *new;

	if (fd <= 2 || fd >= (1 << 20))
		return;
	if (find_local_object_by_fd(OBJ_FD_PIPE, fd) != NULL)
		return;

	new = alloc_object();
	new->pipeobj.fd = fd;
	new->pipeobj.reader = reader;
	add_object(new, OBJ_LOCAL, OBJ_FD_PIPE);
}

/*
 * Snapshot for the post handler.  Three-leg hardening, mirroring the
 * shape that landed for getsockname/getpeername:
 *
 *   1. The int[2] output buffer is sourced from get_writable_address()
 *      rather than zmalloc() + avoid_shared_buffer_out().  The arena
 *      is mmap-backed, far from the libc brk region where glibc malloc
 *      consistency checks fire, so a wild kernel write into this slot
 *      can no longer surface as a SIGABRT cluster at __libc_message
 *      raise IP.  Pool-owned -- no deferred_free needed for the buffer.
 *
 *   2. The snap struct carries a magic cookie that the post handler
 *      checks before dereferencing *get_arg_snapshot(rec, 1).  A
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
 * The OUT-pointer (a1 / fildes) defence is now generic:
 * .arg_snapshot_mask opts a1 into the dispatch-time arg_shadow capture
 * (snapshotted inside __do_syscall() after the final
 * blanket_address_scrub, from the locals about to enter the kernel),
 * and the post handler reads it via get_arg_snapshot(rec, 1).  A
 * sibling scribble of rec->a1 between dispatch and post bumps the
 * generic arg_shadow_stomp tripwire from inside the accessor; the
 * returned value is the kernel-visible address, so the fd-pair deref
 * still hits the buffer the kernel actually wrote.
 */
#define PIPE_POST_STATE_MAGIC	0x504950455F4D4147UL	/* "PIPE_MAG" */
struct pipe_post_state {
	unsigned long magic;
	/*
	 * Seed for the poison pattern stamped into the fildes[2] output
	 * buffer at sanitise time.  Returned by poison_output_struct() and
	 * fed back into check_output_struct() in the post handler so an
	 * intact pattern after a success return flags the kernel having
	 * skipped copy_to_user() on the fd pair entirely.  A seed of 0
	 * means sanitise did not stamp poison for this call (pool-
	 * exhaustion early return) and the post handler no-ops the check.
	 */
	uint64_t poison_seed;
};

static void sanitise_pipe(struct syscallrecord *rec)
{
	int *fildes;
	struct pipe_post_state *snap;

	fildes = (int *) get_writable_address(sizeof(int) * 2);
	if (fildes == NULL) {
		/*
		 * Pool exhaustion / mincore failure.  Leaving a leftover
		 * pointer from a previous iteration in rec->a1 would let the
		 * kernel write the fd pair into whatever sits there now.
		 * Force NULL so the kernel returns -EFAULT cleanly.
		 */
		rec->a1 = 0;
		return;
	}
	rec->a1 = (unsigned long) fildes;

	/* magic-cookie / private post_state: see post_state_register().
	 * The OUT-pointer is defended via .arg_snapshot_mask + the
	 * dispatch-time arg_shadow capture, not a snap field. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	/*
	 * Stamp a per-call poison pattern into the fd-pair buffer the
	 * kernel is about to fill.  The post handler feeds the seed back
	 * into check_output_struct(); a byte-identical poison after a 0
	 * retval means the kernel skipped copy_to_user() entirely.  The
	 * two written fd ints fully clobber the 8-byte seed on a real
	 * write, so no coincidental-match risk.
	 */
	snap->poison_seed = poison_output_struct(fildes, sizeof(int) * 2, 0);
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  Runs ahead of post_pipe(), which clears
 * rec->post_state during its cleanup pass; reading the snap from a
 * .post hook after that point would see zero.  Does its own shape +
 * magic + ownership validation and reads the OUT-pointer via the
 * generic arg_shadow accessor before deref so a sibling-stomped
 * post_state or rec->a1 doesn't drive register_pipe_fd() with foreign
 * bytes -- corruption attribution for the snap-struct gates stays in
 * post_pipe() below; out-pointer corruption is bumped generically by
 * arg_shadow_stomp from inside get_arg_snapshot().
 */
static void post_pipe_record_fds(struct syscallrecord *rec)
{
	struct pipe_post_state *snap =
		(struct pipe_post_state *) rec->post_state;
	int *fildes;

	if ((long) rec->retval != 0)
		return;

	if (snap == NULL || looks_like_corrupted_ptr(rec, snap))
		return;

	if (!post_state_is_owned(snap))
		return;

	if (snap->magic != PIPE_POST_STATE_MAGIC)
		return;

	/*
	 * The OUT-pointer (a1 / fildes) is read via the generic arg_shadow
	 * accessor: it returns the kernel-visible address snapshotted in
	 * __do_syscall() after the final blanket_address_scrub.  A sibling
	 * stomp of rec->a1 between dispatch and here bumps arg_shadow_stomp
	 * from inside the accessor and the post handler still sees the
	 * address the kernel actually wrote.
	 */
	fildes = (int *) get_arg_snapshot(rec, 1);
	if (fildes == NULL || looks_like_corrupted_ptr(rec, fildes))
		return;

	register_pipe_fd(fildes[0], true);
	register_pipe_fd(fildes[1], false);
}

static void post_pipe(struct syscallrecord *rec)
{
	struct pipe_post_state *snap =
		(struct pipe_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_pipe: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (another
	 * in-flight pipe child's snap, or a stale snap a sibling stomp
	 * resurrected by redirecting rec->post_state at it), in which case
	 * reading snap->magic touches the wrong struct.  Reject before
	 * deferred_freeptr() hands a foreign pointer to the deferred-free
	 * ring.  Mirrors prctl.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_pipe: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: ownership table confirmed this is our snap,
	 * so reading snap->magic is now safe.  A mismatch here means the
	 * snapshot itself was wholesale-scribbled in place.  Mirrors
	 * recv.c:212.
	 */
	if (snap->magic != PIPE_POST_STATE_MAGIC) {
		outputerr("post_pipe: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Untouched-out-buf poison check: on a success return, ask
	 * check_output_struct() whether the sanitise-time poison pattern
	 * survived intact in the fildes[2] buffer.  Intact poison after
	 * a 0 retval means the kernel reported success but never wrote
	 * the fd pair -- bump the shared post_handler_untouched_out_buf
	 * counter.  Recover the OUT pointer via the arg_shadow accessor
	 * (matches post_pipe_record_fds) so a sibling stomp of rec->a1
	 * between dispatch and now bumps arg_shadow_stomp from inside
	 * the accessor rather than steering the check at foreign bytes.
	 * A seed of 0 means sanitise did not stamp poison for this call
	 * (mirrors sysinfo.c) -- skip so "we couldn't poison" is not
	 * confused with "kernel didn't write".
	 */
	if ((long) rec->retval == 0 && snap->poison_seed != 0) {
		int *fildes = (int *) get_arg_snapshot(rec, 1);

		if (fildes != NULL &&
		    !looks_like_corrupted_ptr(rec, fildes) &&
		    check_output_struct(fildes, sizeof(int) * 2,
					snap->poison_seed))
			__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
					   1, __ATOMIC_RELAXED);
	}

	rec->a1 = 0;
	post_state_release(rec, snap);
}

struct syscallentry syscall_pipe = {
	.name = "pipe",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "fildes" },
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe,
	.post = post_pipe,
	.ret_objtype_via_post = post_pipe_record_fds,
	.rettype = RET_ZERO_SUCCESS,
	/* a1 (fildes) is the kernel's OUT-pointer; the post handler
	 * derefs through it.  Shadow it so a sibling stomp between
	 * dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handler still sees the address the
	 * kernel actually wrote, not the stomped value. */
	.arg_snapshot_mask = (1u << 0),
};

/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE	O_EXCL
#endif

static unsigned long pipe2_flags[] = {
	O_CLOEXEC, O_NONBLOCK, O_DIRECT, O_NOTIFICATION_PIPE,
};

/*
 * pipe2_flags[] is still wired up to ARG_LIST so the argument
 * generator has a default to publish; sanitise_pipe2 overrides
 * rec->a2 below with an explicit bucket draw.  ARG_LIST's single-bit
 * pick never reaches the zero-flags arm, the canonical CLOEXEC|
 * NONBLOCK pair, or the invalid-high-bit reject path.  Buckets are
 * biased toward success-path shapes so post_pipe keeps registering
 * fds.
 */
static unsigned long sanitise_pipe2_flags(void)
{
	unsigned int pick = rnd_modulo_u32(12);

	switch (pick) {
	case 0:
	case 1:
		/* (a) 0 -- behaves like pipe(). */
		return 0;
	case 2:
	case 3:
		/* (b) O_CLOEXEC. */
		return O_CLOEXEC;
	case 4:
		/* (c) O_NONBLOCK. */
		return O_NONBLOCK;
	case 5:
		/* (d) O_DIRECT -- packet-mode. */
		return O_DIRECT;
	case 6:
		/* (e) O_NOTIFICATION_PIPE. */
		return O_NOTIFICATION_PIPE;
	case 7:
	case 8:
		/* (f) canonical CLOEXEC|NONBLOCK pair. */
		return O_CLOEXEC | O_NONBLOCK;
	case 9:
	case 10:
		/* (g) all-on combo. */
		return O_CLOEXEC | O_DIRECT | O_NONBLOCK;
	default:
		/* (h) invalid high bit -- kernel reject path. */
		return 0x80000000UL;
	}
}

static void sanitise_pipe2(struct syscallrecord *rec)
{
	int *fildes;
	struct pipe_post_state *snap;

	fildes = (int *) get_writable_address(sizeof(int) * 2);
	if (fildes == NULL) {
		rec->a1 = 0;
		rec->a2 = sanitise_pipe2_flags();
		return;
	}
	rec->a1 = (unsigned long) fildes;

	/* magic-cookie / private post_state: see post_state_register().
	 * The OUT-pointer is defended via .arg_snapshot_mask + the
	 * dispatch-time arg_shadow capture, not a snap field. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	/*
	 * Stamp a per-call poison pattern into the fd-pair buffer the
	 * kernel is about to fill; see sanitise_pipe() for the rationale.
	 */
	snap->poison_seed = poison_output_struct(fildes, sizeof(int) * 2, 0);
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);

	rec->a2 = sanitise_pipe2_flags();
}

struct syscallentry syscall_pipe2 = {
	.name = "pipe2",
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LIST },
	.argname = { [0] = "fildes", [1] = "flags" },
	.arg_params[1].list = ARGLIST(pipe2_flags),
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe2,
	.post = post_pipe,
	.ret_objtype_via_post = post_pipe_record_fds,
	.rettype = RET_ZERO_SUCCESS,
	/* a1 (fildes) is the kernel's OUT-pointer; the post handler
	 * derefs through it.  Shadow it so a sibling stomp between
	 * dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handler still sees the address the
	 * kernel actually wrote, not the stomped value. */
	.arg_snapshot_mask = (1u << 0),
};
