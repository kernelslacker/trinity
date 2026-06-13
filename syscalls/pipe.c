/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "objects.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

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
 *      checks before dereferencing snap->fildes.  A sibling scribble of
 *      rec->post_state with a heap-shaped pointer to a foreign chunk
 *      survives looks_like_corrupted_ptr() but fails the cookie gate.
 *
 *   3. The snap pointer is registered in the post-state ownership table
 *      at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check; the ownership table closes
 *      that gap.
 *
 * Only the writable-arena buffer pointer needs storing -- there is no
 * second pointer to free because get_writable_address() returns
 * pool-managed memory.
 */
#define PIPE_POST_STATE_MAGIC	0x504950455F4D4147UL	/* "PIPE_MAG" */
struct pipe_post_state {
	unsigned long magic;
	int *fildes;
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

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	snap->fildes = fildes;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  Runs ahead of post_pipe(), which clears
 * rec->post_state during its cleanup pass; reading the snap from a
 * .post hook after that point would see zero.  Does its own shape +
 * magic + ownership validation before deref so a sibling-stomped
 * post_state doesn't drive register_pipe_fd() with foreign bytes --
 * corruption attribution stays in post_pipe() below, which repeats
 * the same checks and owns the post_handler_corrupt_ptr_bump()
 * accounting.
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

	fildes = snap->fildes;
	if (fildes == NULL || looks_like_corrupted_ptr(rec, fildes))
		return;

	/*
	 * Identity check: snap->fildes was set to rec->a1 at sanitise
	 * time -- both slots hold the same get_writable_address() return.
	 * looks_like_corrupted_ptr() above is shape-only: a sibling stomp
	 * that left a heap-shaped value in either slot survives the
	 * shape gate and the fd-pair deref below would read either the
	 * kernel's writes into a foreign address (snap->fildes intact,
	 * rec->a1 stomped pre-syscall) or foreign memory the kernel
	 * never touched (snap->fildes stomped, rec->a1 intact).  The
	 * snap struct already cleared the magic + ownership gates, so a
	 * snap->fildes != rec->a1 divergence narrows the scribble to one
	 * of those two vectors.  Bail before register_pipe_fd() sees fd
	 * values read from the wrong buffer.
	 */
	if ((unsigned long) fildes != rec->a1) {
		__atomic_add_fetch(&shm->stats.pipe_inner_ptr_mismatch,
				   1, __ATOMIC_RELAXED);
		return;
	}

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

	rec->a1 = 0;
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
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

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	snap->fildes = fildes;
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
};
