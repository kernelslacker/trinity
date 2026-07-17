/*
 *   SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode, void __user *, arg, unsigned int, nr_args)
 */
#include <limits.h>
#include <sched.h>
#include "arch.h"
#include "kernel/io_uring.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "io_uring_register-internal.h"

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
 * Stratified opcode picker.  Uniform sampling across the 38-entry
 * io_uring_register_opcodes[] table under-exercises the rarer kernel
 * paths because the list mixes a small set of common multi-purpose
 * opcodes (BUFFERS/FILES/EVENTFD/PROBE/PERSONALITY/IOWQ_MAX_WORKERS)
 * with newer narrowly-targeted ones (zcrx, mem_region, query,
 * bpf_filter, clock, resize_rings, ...).  Bias the picker so the rare
 * paths get hit ~50% of the time, and ~10% of the time OR the
 * IORING_REGISTER_USE_REGISTERED_RING modifier bit onto a re-rolled
 * base opcode to exercise the masking path that decodes fd as a
 * registered-ring index rather than a real fd.
 */
static const unsigned long io_uring_register_opcodes_common[] = {
	IORING_REGISTER_BUFFERS,
	IORING_REGISTER_FILES,
	IORING_REGISTER_EVENTFD,
	IORING_REGISTER_PROBE,
	IORING_REGISTER_PERSONALITY,
	IORING_REGISTER_IOWQ_MAX_WORKERS,
};

static const unsigned long io_uring_register_opcodes_rare[] = {
	IORING_REGISTER_RESIZE_RINGS,
	IORING_REGISTER_CLONE_BUFFERS,
	IORING_REGISTER_ZCRX_IFQ,
	IORING_REGISTER_MEM_REGION,
	IORING_REGISTER_QUERY,
	IORING_REGISTER_ZCRX_CTRL,
	IORING_REGISTER_BPF_FILTER,
	IORING_REGISTER_CLOCK,
	IORING_REGISTER_NAPI,
	IORING_REGISTER_SEND_MSG_RING,
	IORING_REGISTER_RING_FDS,
	IORING_REGISTER_RESTRICTIONS,
	IORING_REGISTER_ENABLE_RINGS,
	IORING_REGISTER_SYNC_CANCEL,
	IORING_REGISTER_PBUF_RING,
	IORING_REGISTER_PBUF_STATUS,
};

static unsigned long pick_io_uring_register_opcode(void)
{
	unsigned int r = rnd_modulo_u32(100);
	unsigned long base;

	if (r < 40)
		return io_uring_register_opcodes_common[rnd_modulo_u32(ARRAY_SIZE(io_uring_register_opcodes_common))];
	if (r < 90)
		return io_uring_register_opcodes_rare[rnd_modulo_u32(ARRAY_SIZE(io_uring_register_opcodes_rare))];

	/*
	 * 10%: re-roll a base opcode (50/50 common vs rare) and OR in the
	 * IORING_REGISTER_USE_REGISTERED_RING modifier bit.  The kernel
	 * masks this bit off before dispatching, decoding fd as a
	 * registered-ring index rather than a real fd -- a path the bare
	 * opcode list never reaches when the modifier is listed alone as
	 * a pool value (it decodes there as opcode 0).
	 */
	if (rnd_modulo_u32(2))
		base = io_uring_register_opcodes_common[rnd_modulo_u32(ARRAY_SIZE(io_uring_register_opcodes_common))];
	else
		base = io_uring_register_opcodes_rare[rnd_modulo_u32(ARRAY_SIZE(io_uring_register_opcodes_rare))];
	return base | IORING_REGISTER_USE_REGISTERED_RING;
}

/*
 * Snapshot of the per-opcode state sanitise needs the post handler to
 * see.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so the post path is immune to a sibling syscall scribbling
 * rec->a2 or rec->a3 between the syscall returning and the post
 * handler running.
 *
 * Every IORING_REGISTER_* opcode this generator emits feeds rec->a3
 * with a non-heap value -- get_writable_struct() / get_writable_address()
 * pool pointers, alloc_iovec()'s writable-pool slot (see
 * rand/random-address.c), or zero.  Trinity never owns the memory
 * backing rec->a3, so the post handler has no free to perform.  The
 * post handler dispatches off the snapshot's opcode (not rec->a2) for
 * the per-op STRONG-VAL retval check below, so a sibling scribble of
 * rec->a2 cannot misroute that validation either.
 *
 * The magic cookie hardens the post handler against rec->post_state
 * being scribbled with a heap-shaped pointer to a foreign allocation --
 * a cookie mismatch rejects the forgery before any inner-field deref.
 */
#define IO_URING_REGISTER_POST_STATE_MAGIC	0x494F5F55524D4147UL	/* "IO_URMAG" */
struct io_uring_register_post_state {
	unsigned long magic;
	unsigned int opcode;
	/*
	 * Per-opcode length of the user buffer at rec->a3.  Set in the
	 * dispatch switch alongside the buffer allocation, then handed to
	 * avoid_shared_buffer_inout() as the relocation length.
	 * arg_len == 0 means the opcode takes no arg and the relocation
	 * call is skipped entirely.
	 */
	unsigned long arg_len;
};

static void sanitise_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap;
	struct ioring_register_payload p;
	struct io_uringobj *ring;
	unsigned int opcode;
	/*
	 * Per-opcode user-buffer length at rec->a3, set in the dispatch
	 * switch below.  0 means the opcode takes no arg and the trailing
	 * avoid_shared_buffer_inout() relocation is skipped.  Opcodes whose
	 * exact size is not modelled fall through to page_size, mirroring
	 * the previous unconditional behaviour but only for the modeled-
	 * unknown fallback.
	 */
	unsigned long arg_len = 0;

	rec->a2 = pick_io_uring_register_opcode();

	ring = get_io_uring_ring();
	if (ring != NULL)
		rec->a1 = ring->fd;

	/*
	 * 15% of the time, override into the kernel's blind fd == -1
	 * registration path (io_uring_register_blind).  Three opcodes are
	 * only reachable that way: SEND_MSG_RING, RESTRICTIONS (task-scoped
	 * via io_register_restrictions_task), BPF_FILTER (task-scoped via
	 * io_register_bpf_filter_task).  QUERY is also a blind opcode but
	 * is reachable via the real-fd path too, so it isn't in the pool.
	 * The override only fires when the real-fd path was actually in
	 * play (ring != NULL); the remaining 85% keep the existing
	 * real-fd dispatch intact.  Done as a re-roll after
	 * pick_io_uring_register_opcode() returns rather than a new picker
	 * entry so the override stays decoupled from the picker tables.
	 */
	if (ring != NULL && (rnd_modulo_u32(100)) < 15) {
		static const unsigned long blind_opcodes[] = {
			IORING_REGISTER_SEND_MSG_RING,
			IORING_REGISTER_RESTRICTIONS,
			IORING_REGISTER_BPF_FILTER,
		};
		rec->a1 = (unsigned long) -1U;
		rec->a2 = blind_opcodes[rnd_modulo_u32(ARRAY_SIZE(blind_opcodes))];
	}

	opcode = rec->a2;

	switch (opcode) {
	case IORING_REGISTER_BUFFERS:
	case IORING_UNREGISTER_BUFFERS:
		p = ioring_reg_buffers_payload(opcode);
		break;

	case IORING_REGISTER_FILES:
	case IORING_UNREGISTER_FILES:
		p = ioring_reg_files_payload(opcode);
		break;

	case IORING_REGISTER_EVENTFD:
	case IORING_REGISTER_EVENTFD_ASYNC:
	case IORING_UNREGISTER_EVENTFD:
		p = ioring_reg_eventfd_payload(opcode);
		break;

	case IORING_REGISTER_PROBE:
		p = ioring_reg_probe_payload();
		break;

	case IORING_REGISTER_PERSONALITY:
	case IORING_UNREGISTER_PERSONALITY:
		p = ioring_reg_personality_payload();
		break;

	case IORING_REGISTER_RESTRICTIONS:
		p = ioring_reg_restrictions_payload();
		break;

	case IORING_REGISTER_IOWQ_AFF:
	case IORING_UNREGISTER_IOWQ_AFF:
	case IORING_REGISTER_IOWQ_MAX_WORKERS:
		p = ioring_reg_iowq_payload(opcode);
		break;

	case IORING_REGISTER_NAPI:
	case IORING_UNREGISTER_NAPI:
		p = ioring_reg_napi_payload();
		break;

	/* IORING_REGISTER_ENABLE_RINGS: no arg. */
	case IORING_REGISTER_ENABLE_RINGS:
		p = (struct ioring_register_payload){ 0, 0, 0 };
		break;

	case IORING_REGISTER_FILE_ALLOC_RANGE:
		p = ioring_reg_file_alloc_range_payload();
		break;

	case IORING_REGISTER_CLOCK:
		p = ioring_reg_clock_payload();
		break;

	case IORING_REGISTER_RING_FDS:
	case IORING_UNREGISTER_RING_FDS:
		p = ioring_reg_ring_fds_payload();
		break;

	case IORING_REGISTER_PBUF_RING:
	case IORING_UNREGISTER_PBUF_RING:
		p = ioring_reg_pbuf_ring_payload();
		break;

	case IORING_REGISTER_PBUF_STATUS:
		p = ioring_reg_pbuf_status_payload();
		break;

	case IORING_REGISTER_ZCRX_IFQ:
		p = ioring_reg_zcrx_ifq_payload();
		break;

	case IORING_REGISTER_RESIZE_RINGS:
		p = ioring_reg_resize_rings_payload();
		break;

	case IORING_REGISTER_MEM_REGION:
		p = ioring_reg_mem_region_payload();
		break;

	case IORING_REGISTER_FILES2:
	case IORING_REGISTER_BUFFERS2:
		p = ioring_reg_rsrc_register_payload(opcode);
		break;

	case IORING_REGISTER_FILES_UPDATE2:
	case IORING_REGISTER_BUFFERS_UPDATE:
		p = ioring_reg_rsrc_update_payload(opcode);
		break;

	case IORING_REGISTER_QUERY:
		p = ioring_reg_query_payload();
		break;

	case IORING_REGISTER_ZCRX_CTRL:
		p = ioring_reg_zcrx_ctrl_payload();
		break;

	case IORING_REGISTER_CLONE_BUFFERS:
		p = ioring_reg_clone_buffers_payload(ring);
		break;

	case IORING_REGISTER_SYNC_CANCEL:
		p = ioring_reg_sync_cancel_payload();
		break;

	case IORING_REGISTER_SEND_MSG_RING:
		p = ioring_reg_send_msg_ring_payload();
		break;

	case IORING_REGISTER_BPF_FILTER:
		p = ioring_reg_bpf_filter_payload();
		break;

	default:
		p = ioring_reg_default_payload();
		break;
	}

	rec->a3 = p.arg;
	rec->a4 = p.nr;
	arg_len = p.len;

	/*
	 * Snapshot the opcode and the per-opcode user-buffer length for
	 * the post handler.  rec->post_state is private to the post path,
	 * so a sibling scribble of rec->a2 / rec->a3 between the syscall
	 * returning and the post handler running cannot misroute the
	 * snapshot's opcode-gated STRONG-VAL dispatch below.  Snap
	 * allocation is hoisted above avoid_shared_buffer_inout so the
	 * per-opcode arg_len can drive the relocation length.  No
	 * original_alloc capture: every opcode now feeds rec->a3 a
	 * pool-managed pointer (alloc_iovec migrated to writable-pool in
	 * the preceding commit), so there is nothing for the post handler
	 * to free.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = IO_URING_REGISTER_POST_STATE_MAGIC;
	snap->opcode = opcode & ~IORING_REGISTER_USE_REGISTERED_RING;
	snap->arg_len = arg_len;
	post_state_install(rec, snap);

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
	 *
	 * Use the per-opcode arg_len for the relocation length.  For
	 * IORING_REGISTER_BUFFERS the source allocation is
	 * nr * sizeof(struct iovec) (16..128 bytes), so a page_size memcpy
	 * would read past its end.  arg_len == 0 marks the no-arg opcodes
	 * (UNREGISTER_*, ENABLE_RINGS, PERSONALITY, etc.); skip the
	 * relocation entirely on those rather than relocate a NULL.
	 */
	if (snap->arg_len > 0)
		avoid_shared_buffer_inout(&rec->a3, snap->arg_len);
}

/*
 * Every IORING_REGISTER_* opcode this generator emits feeds rec->a3
 * with a pool-managed pointer (get_writable_address /
 * get_writable_struct, or the writable-pool result alloc_iovec now
 * returns).  Pool slots are never free()d by trinity, so the post
 * handler has no buffer cleanup to perform; it owns only the
 * post_state snapshot and the per-opcode STRONG-VAL retval check.
 */
static void post_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap;
	unsigned long ret = rec->retval;
	unsigned long a4 = get_arg_snapshot(rec, 4);

	rec->a3 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, IO_URING_REGISTER_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

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
			if (ret > a4) {
				outputerr("post_io_uring_register: opcode=%u rejected count retval=0x%lx > nr_args=%lu\n",
					  snap->opcode, ret, a4);
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

	post_state_release(rec, snap);
}

struct syscallentry syscall_io_uring_register = {
	.name = "io_uring_register",
	.group = GROUP_IO_URING,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_IO_URING, [1] = ARG_OP, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "opcode", [2] = "arg", [3] = "nr_args" },
	.arg_params[1].list = ARGLIST(io_uring_register_opcodes),
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_io_uring_register,
	.post = post_io_uring_register,
	/* a4 (nr_args) is the upper bound the post oracle compares retval
	 * against for IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS
	 * ("rejected count retval=... > nr_args=...").  The opcode itself
	 * is already snapshot-protected via the io_uring_register_post_state
	 * magic-cookie record, but the count operand a4 was left on the
	 * live cross-child shm slot -- a sibling stomp landing between the
	 * syscall returning and the post handler running could swing the
	 * bound and either spuriously flag a legitimate retval as a corrupt
	 * pointer or mask a real out-of-range return.  Shadow a4 so
	 * get_arg_snapshot(rec, 4) bumps arg_shadow_stomp on mismatch and
	 * the oracle validates against the count the kernel actually saw. */
	.arg_snapshot_mask = (1u << 3),
};
