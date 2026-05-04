/*
 *   SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode, void __user *, arg, unsigned int, nr_args)
 */
#include <limits.h>
#include <string.h>
#include <linux/io_uring.h>
#include "arch.h"
#include "deferred-free.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Opcodes added after our system headers — guard with #ifndef. */
#ifndef IORING_REGISTER_PBUF_STATUS
#define IORING_REGISTER_PBUF_STATUS	26
#endif
#ifndef IORING_REGISTER_NAPI
#define IORING_REGISTER_NAPI		27
#endif
#ifndef IORING_UNREGISTER_NAPI
#define IORING_UNREGISTER_NAPI		28
#endif
#ifndef IORING_REGISTER_CLOCK
#define IORING_REGISTER_CLOCK		29
#endif
#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS	30
#endif
#ifndef IORING_REGISTER_SEND_MSG_RING
#define IORING_REGISTER_SEND_MSG_RING	31
#endif
#ifndef IORING_REGISTER_ZCRX_IFQ
#define IORING_REGISTER_ZCRX_IFQ	32
#endif
#ifndef IORING_REGISTER_RESIZE_RINGS
#define IORING_REGISTER_RESIZE_RINGS	33
#endif
#ifndef IORING_REGISTER_MEM_REGION
#define IORING_REGISTER_MEM_REGION	34
#endif
#ifndef IORING_REGISTER_QUERY
#define IORING_REGISTER_QUERY		35
#endif
#ifndef IORING_REGISTER_ZCRX_CTRL
#define IORING_REGISTER_ZCRX_CTRL	36
#endif
#ifndef IORING_REGISTER_BPF_FILTER
#define IORING_REGISTER_BPF_FILTER	37
#endif
#ifndef IORING_REGISTER_USE_REGISTERED_RING
#define IORING_REGISTER_USE_REGISTERED_RING	(1U << 31)
#endif

static unsigned long io_uring_register_opcodes[] = {
	IORING_REGISTER_BUFFERS,
	IORING_UNREGISTER_BUFFERS,
	IORING_REGISTER_FILES,
	IORING_UNREGISTER_FILES,
	IORING_REGISTER_EVENTFD,
	IORING_UNREGISTER_EVENTFD,
	IORING_REGISTER_FILES_UPDATE,
	IORING_REGISTER_EVENTFD_ASYNC,
	IORING_REGISTER_PROBE,
	IORING_REGISTER_PERSONALITY,
	IORING_UNREGISTER_PERSONALITY,
	IORING_REGISTER_RESTRICTIONS,
	IORING_REGISTER_ENABLE_RINGS,
	IORING_REGISTER_FILES2,
	IORING_REGISTER_FILES_UPDATE2,
	IORING_REGISTER_BUFFERS2,
	IORING_REGISTER_BUFFERS_UPDATE,
	IORING_REGISTER_IOWQ_AFF,
	IORING_UNREGISTER_IOWQ_AFF,
	IORING_REGISTER_IOWQ_MAX_WORKERS,
	IORING_REGISTER_RING_FDS,
	IORING_UNREGISTER_RING_FDS,
	IORING_REGISTER_PBUF_RING,
	IORING_UNREGISTER_PBUF_RING,
	IORING_REGISTER_SYNC_CANCEL,
	IORING_REGISTER_FILE_ALLOC_RANGE,
	IORING_REGISTER_PBUF_STATUS,
	IORING_REGISTER_NAPI,
	IORING_UNREGISTER_NAPI,
	IORING_REGISTER_CLOCK,
	IORING_REGISTER_CLONE_BUFFERS,
	IORING_REGISTER_SEND_MSG_RING,
	IORING_REGISTER_ZCRX_IFQ,
	IORING_REGISTER_RESIZE_RINGS,
	IORING_REGISTER_MEM_REGION,
	IORING_REGISTER_QUERY,
	IORING_REGISTER_ZCRX_CTRL,
	IORING_REGISTER_BPF_FILTER,
	/*
	 * Modifier bit OR'd onto the request opcode that tells the kernel
	 * to treat fd as a registered-ring index rather than a real fd.
	 * Listing it as a pool value exercises the masking path (low bits
	 * are zero, so the kernel decodes it as opcode 0 via the registered
	 * ring) -- a corner ARG_OP would not otherwise reach.
	 */
	IORING_REGISTER_USE_REGISTERED_RING,
};

/*
 * Snapshot of the opcode-gated heap allocation sanitise hands to the
 * kernel via rec->a3, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so the post path is immune to a sibling syscall scribbling
 * rec->a2 or rec->a3 between the syscall returning and the post handler
 * running.
 *
 * Per-op allocation matrix.  Of the ~38 IORING_REGISTER_* opcodes this
 * generator emits, only one allocates a heap buffer that the post
 * handler has to free:
 *
 *   IORING_REGISTER_BUFFERS -> struct iovec * (alloc_iovec)
 *
 * The other opcodes feed rec->a3 with non-heap values -- get_writable_
 * struct() / get_writable_address() pool pointers, or zero -- and leave
 * heap_buf NULL.  The post handler dispatches off the snapshot's
 * opcode, not rec->a2, so a sibling scribble of the opcode also cannot
 * redirect the free into a non-heap rec->a3 (which would UAF the
 * OBJ_MMAP pool).
 */
struct io_uring_register_post_state {
	unsigned int opcode;
	void *heap_buf;
};

static void sanitise_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap;
	struct io_uringobj *ring;
	unsigned int opcode;
	unsigned int nr;
	void *buf;

	ring = get_io_uring_ring();
	if (ring != NULL)
		rec->a1 = ring->fd;

	opcode = rec->a2;

	switch (opcode) {
	/* Opcodes that take no arg — clear both to avoid early EFAULT. */
	case IORING_UNREGISTER_BUFFERS:
	case IORING_UNREGISTER_FILES:
	case IORING_UNREGISTER_EVENTFD:
	case IORING_REGISTER_ENABLE_RINGS:
	case IORING_REGISTER_PERSONALITY:
	case IORING_UNREGISTER_PERSONALITY:
	case IORING_UNREGISTER_IOWQ_AFF:
		rec->a3 = 0;
		rec->a4 = 0;
		break;

	/*
	 * IORING_REGISTER_BUFFERS: arg = struct iovec[], nr_args = count.
	 * Kernel iterates the array copying each iovec from userspace.
	 */
	case IORING_REGISTER_BUFFERS:
		nr = 1 + (rand() % 8);
		rec->a3 = (unsigned long) alloc_iovec(nr);
		rec->a4 = nr;
		break;

	/*
	 * IORING_REGISTER_FILES: arg = int[] of fds, nr_args = count.
	 * Use -1 as placeholder; kernel accepts sparse sets with -1 holes.
	 */
	case IORING_REGISTER_FILES:
		nr = 1 + (rand() % 16);
		buf = get_writable_struct(nr * sizeof(int));
		if (buf)
			memset(buf, 0xff, nr * sizeof(int));  /* fill with -1 */
		rec->a3 = (unsigned long) buf;
		rec->a4 = nr;
		break;

	/*
	 * IORING_REGISTER_PROBE: arg = struct io_uring_probe with trailing
	 * ops[], nr_args = number of op slots.
	 */
	case IORING_REGISTER_PROBE: {
		struct io_uring_probe *probe;
		nr = IORING_OP_LAST;
		probe = (struct io_uring_probe *)
			get_writable_struct(sizeof(*probe) +
					    nr * sizeof(probe->ops[0]));
		if (probe)
			memset(probe, 0, sizeof(*probe) + nr * sizeof(probe->ops[0]));
		rec->a3 = (unsigned long) probe;
		rec->a4 = nr;
		break;
	}

	/*
	 * IORING_REGISTER_IOWQ_MAX_WORKERS: arg = uint[2] (bounded/unbounded),
	 * nr_args = 2.
	 */
	case IORING_REGISTER_IOWQ_MAX_WORKERS:
		buf = get_writable_struct(2 * sizeof(unsigned int));
		rec->a3 = (unsigned long) buf;
		rec->a4 = 2;
		break;

	/*
	 * For opcodes with struct args we don't model in detail, provide a
	 * zeroed page so the kernel reaches argument parsing rather than
	 * faulting immediately on a garbage pointer.
	 */
	default:
		buf = get_writable_address(page_size);
		if (buf)
			memset(buf, 0, page_size);
		rec->a3 = (unsigned long) buf;
		rec->a4 = 1;
		break;
	}

	/*
	 * Several opcodes above (PROBE, IOWQ_MAX_WORKERS, the default
	 * catch-all) hand the kernel a get_writable_address()-derived
	 * pointer as a writeback target.  get_writable_address() pulls
	 * from the OBJ_MMAP pool which is structurally distinct from the
	 * alloc_shared() regions, but a VA-space alias is not impossible
	 * and the kernel writeback into a stomped shared region produces
	 * exactly the silent-corruption symptom we just chased through
	 * init_child_mappings.  Mirror the defensive scrub
	 * pick_random_ioctl() runs after ioctl_arg_for_request() — same
	 * reasoning, same shape, same negligible cost.
	 */
	avoid_shared_buffer(&rec->a3, page_size);

	/*
	 * Snapshot the opcode and the (possibly heap) pointer for the
	 * post handler.  A sibling syscall can scribble rec->a3 between
	 * the syscall returning and the post handler running, leaving a
	 * real-but-wrong heap pointer that looks_like_corrupted_ptr()
	 * cannot distinguish from the original; the old post handler
	 * then hands the wrong allocation to free, leaking ours and
	 * corrupting another sanitise routine's live buffer.  A scribble
	 * of rec->a2 is just as dangerous -- flipping the opcode from
	 * any non-allocating value to IORING_REGISTER_BUFFERS would
	 * redirect the old opcode-gated dispatch into a non-heap rec->a3
	 * (a get_writable_address / get_writable_struct pool pointer)
	 * and UAF the OBJ_MMAP pool.  rec->post_state is private to the
	 * post handler, so the scribblers have nothing to scribble there.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->opcode = opcode;
	snap->heap_buf = (opcode == IORING_REGISTER_BUFFERS) ?
		(void *)(unsigned long) rec->a3 : NULL;
	rec->post_state = (unsigned long) snap;
}

/*
 * IORING_REGISTER_BUFFERS is the only opcode whose sanitise path
 * allocates memory (via alloc_iovec()) into rec->a3.  Other opcodes
 * use pool-managed pointers (get_writable_address / get_writable_struct)
 * that must not be free()d.  Gate the deferred free on the snapshot's
 * opcode -- not rec->a2 -- so a sibling scribble of either rec->a2 or
 * rec->a3 cannot redirect or misdirect the free.
 */
static void post_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap =
		(struct io_uring_register_post_state *) rec->post_state;
	unsigned long ret = rec->retval;

	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_io_uring_register: rejected suspicious "
			  "post_state=%p (pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Per-opcode STRONG-VAL.  io_uring_register(2) is a multiplexer;
	 * each opcode has its own retval shape but every opcode shares the
	 * same -1UL failure return via the syscall return path.  On a
	 * non-failure return, three families of shape exist:
	 *
	 *   IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS: kernel
	 *     loops over the user-supplied ring-fd array in
	 *     fs/io_uring/register.c::io_ringfd_register /
	 *     io_ringfd_unregister and returns the loop count, bounded by
	 *     nr_args (rec->a4).  Anything > nr_args is a structural
	 *     regression: torn write of the count or -errno leaking through
	 *     the success return slot.
	 *
	 *   IORING_REGISTER_PERSONALITY: kernel allocates a personality id
	 *     via xa_alloc_cyclic() with XA_LIMIT(1, INT_MAX) and returns
	 *     the new id.  0 or any value > INT_MAX would be a structural
	 *     regression -- xa_alloc_cyclic() never returns 0 with that
	 *     limit, and ids do not legitimately span the high half of an
	 *     unsigned long.
	 *
	 *   All other emitted opcodes (BUFFERS / FILES / EVENTFD /
	 *     EVENTFD_ASYNC / FILES_UPDATE / BUFFERS_UPDATE / IOWQ_AFF /
	 *     IOWQ_MAX_WORKERS / FILE_ALLOC_RANGE / SYNC_CANCEL / NAPI /
	 *     PROBE / RESTRICTIONS / ENABLE_RINGS / *_UPDATE / etc.):
	 *     kernel returns 0 on success.  Any non-zero, non-(-1UL) value
	 *     is a sign-extension tear at the syscall ABI boundary or
	 *     -errno leaking through the success slot.  This default is
	 *     fail-soft for any future opcode the kernel adds: legitimate
	 *     0/-1UL still passes; only a spurious mid-range retval trips.
	 *
	 * Validate using the snapshot's opcode (not rec->a2) so a sibling
	 * scribble of rec->a2 cannot misroute the dispatch.  -1UL fall-
	 * through is intentional -- every opcode's documented failure path
	 * lands there.  The buffer cleanup tail below runs unchanged on
	 * every retval shape so heap allocations are released either way.
	 */
	if (ret != (unsigned long)-1L) {
		switch (snap->opcode) {
		case IORING_REGISTER_RING_FDS:
		case IORING_UNREGISTER_RING_FDS:
			if (ret > rec->a4) {
				outputerr("post_io_uring_register: opcode=%u rejected count retval=0x%lx > nr_args=%lu\n",
					  snap->opcode, ret, rec->a4);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		case IORING_REGISTER_PERSONALITY:
			if (ret < 1 || ret > (unsigned long) INT_MAX) {
				outputerr("post_io_uring_register: opcode=PERSONALITY rejected id retval=0x%lx outside [1, INT_MAX]\n",
					  ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		default:
			if (ret != 0) {
				outputerr("post_io_uring_register: opcode=%u rejected RZS retval=0x%lx (expected 0 or -1UL)\n",
					  snap->opcode, ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		}
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointer may no longer reference our heap allocation.
	 * NULL is a legitimate value here (most opcodes do not allocate),
	 * so only flag a non-NULL value that fails the heuristic.  Leak
	 * rather than hand garbage to free().
	 */
	if (snap->heap_buf != NULL && looks_like_corrupted_ptr(rec, snap->heap_buf)) {
		outputerr("post_io_uring_register: rejected suspicious snap "
			  "heap_buf=%p (post_state-scribbled?)\n", snap->heap_buf);
		deferred_freeptr(&rec->post_state);
		return;
	}

	/*
	 * Belt-and-suspenders: only release if both the snapshot's
	 * opcode says we allocated and we actually have a non-NULL heap
	 * pointer to release.  deferred_free_enqueue() (not
	 * deferred_freeptr) so concurrent observers that grabbed the
	 * address from rec->a3 before a scribble do not UAF.
	 */
	if (snap->heap_buf != NULL && snap->opcode == IORING_REGISTER_BUFFERS)
		deferred_free_enqueue(snap->heap_buf, NULL);

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_io_uring_register = {
	.name = "io_uring_register",
	.group = GROUP_IO_URING,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_IO_URING, [1] = ARG_OP, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "opcode", [2] = "arg", [3] = "nr_args" },
	.arg_params[1].list = ARGLIST(io_uring_register_opcodes),
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_uring_register,
	.post = post_io_uring_register,
	.rettype = RET_ZERO_SUCCESS,
};
