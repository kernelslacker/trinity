#pragma once
/*
 * Shared io_uring SQ/CQ/SQE ring-setup helper.
 *
 * Every childop that opens a private io_uring ring drives the same
 * sequence: io_uring_setup, three IORING_OFF_* mmap regions (with the
 * SQ + CQ aliased into one mapping when IORING_FEAT_SINGLE_MMAP is
 * set), then snapshot the kernel-returned ring metadata.  The teardown
 * mirror unmaps the regions and closes the ring fd.
 *
 * Three things had to be uniform across childops and were not when each
 * carried its own copy:
 *
 *   - SINGLE_MMAP under-map.  The aliased mapping must cover
 *     max(sq_sz, cq_sz); the per-childop copies all mapped sq_sz only,
 *     so on kernels where cq_sz > sq_sz any later CQ-ring write walked
 *     past the mapping.
 *
 *   - Unchecked size math.  SQ/CQ/SQE sizes were computed with bare
 *     `+`/`*` on kernel-returned offsets and entry counts.  A fuzz-
 *     target kernel that hands back nonsense values could wrap the
 *     math and turn the kernel bug into a trinity self-crash.
 *
 *   - errno-after-cleanup.  On mmap failure the per-childop copies
 *     called close()/munmap() before the caller read errno to classify
 *     supported vs unsupported, and cleanup can clobber errno.  An
 *     unsupported env could be miscounted as transient (or vice
 *     versa).
 *
 * The helper covers all three: __builtin_*_overflow on the size math,
 * max(sq, cq) for the SINGLE_MMAP region, validate every kernel-
 * returned offset lands inside the mapped span, and save/restore errno
 * around every cleanup syscall.  The three-state status enum below
 * lets callers latch-off only on a real unsupported verdict, never on
 * a transient mmap blip.
 */

#include <stdbool.h>
#include <stddef.h>

struct io_uring_params;

/*
 * Classification of iour_ring_setup failures.
 *
 *   IOUR_SUPPORTED   -- ring stood up successfully; out is populated.
 *   IOUR_UNSUPPORTED -- the kernel won't ever support this ring on
 *                       this host (CONFIG_IO_URING off, io_uring
 *                       disabled by sysctl, flag combo permanently
 *                       rejected).  Caller should latch the childop
 *                       off for the life of the process.
 *   IOUR_TRANSIENT   -- a temporary failure (out of memory, fd
 *                       exhaustion, hostile kernel return value the
 *                       overflow / offset-validation guard caught).
 *                       Caller should skip the cycle but NOT latch
 *                       off -- the next attempt may well succeed.
 *
 * The setup-failure errno is captured before any cleanup syscall runs,
 * so the classification reflects the real failure cause regardless of
 * what close() / munmap() do to errno on the teardown path.
 */
enum iour_setup_status {
	IOUR_SUPPORTED,
	IOUR_UNSUPPORTED,
	IOUR_TRANSIENT,
};

/*
 * Populated ring state.  Each childop's per-iteration ctx used to
 * carry private copies of these fields; the helper now owns them.
 *
 * Sizes:
 *   sq_map_sz, cq_map_sz, sqe_map_sz are the actual mmap lengths
 *   passed to mmap (and to be passed to munmap).  When single_mmap is
 *   true the SQ and CQ rings share one mapping sized to
 *   max(sq_sz, cq_sz); sq_map_sz holds that mapped length and
 *   cq_map_sz is 0 (the cq_ring pointer aliases sq_ring and must NOT
 *   be munmap'd separately).
 *
 * Offsets:
 *   sq_off_* / cq_off_* are the kernel-returned ring-field offsets
 *   into the mapped regions, validated by iour_ring_setup to land
 *   inside [0, sq_map_sz) / [0, cq_map_sz_effective) before the call
 *   returns IOUR_SUPPORTED.
 */
struct iour_ring {
	int		fd;

	void		*sq_ring;
	void		*cq_ring;	/* aliases sq_ring when single_mmap */
	void		*sqes;

	size_t		sq_map_sz;
	size_t		cq_map_sz;	/* 0 when single_mmap */
	size_t		sqe_map_sz;
	bool		single_mmap;

	unsigned int	sq_entries;
	unsigned int	cq_entries;

	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

	unsigned int	cq_off_head;
	unsigned int	cq_off_tail;
	unsigned int	cq_off_mask;
	unsigned int	cq_off_cqes;
};

/*
 * Stand up a private io_uring ring.
 *
 * Inputs:
 *   p       -- caller-supplied io_uring_params.  The caller fills
 *              p->flags (and any other input-only fields it cares
 *              about) before the call; iour_ring_setup zeroes nothing.
 *              The kernel populates the output fields in place.
 *   entries -- entry count passed verbatim to io_uring_setup.  No
 *              RAND_NEGATIVE_OR substitution happens here -- callers
 *              that want edge-value injection apply it themselves
 *              before the call.
 *   out     -- ring state populated on IOUR_SUPPORTED.  Always zeroed
 *              on entry; left fully zeroed (with out->fd = -1) on
 *              IOUR_UNSUPPORTED / IOUR_TRANSIENT so an accidental
 *              teardown call no-ops.
 *
 * Errno classification on failure is read from io_uring_setup's
 * errno before any cleanup syscall runs:
 *   ENOSYS / EPERM / EOPNOTSUPP / ENOTSUP -> IOUR_UNSUPPORTED
 *   anything else (incl. ENOMEM / EMFILE / EAGAIN / EINVAL) ->
 *     IOUR_TRANSIENT
 * EINVAL is treated as transient because trinity routinely feeds
 * edge-value entry counts and flag combos that the kernel will
 * legitimately reject without that meaning io_uring as a whole is
 * unavailable.
 *
 * Post-setup failure modes (size overflow on a hostile kernel return,
 * an offset that lands outside the mapped span, an mmap that fails
 * after setup succeeded) tear the partial state down and return
 * IOUR_TRANSIENT -- io_uring_setup itself worked, so the support
 * verdict stays unchanged.
 */
enum iour_setup_status iour_ring_setup(struct io_uring_params *p,
				       unsigned int entries,
				       struct iour_ring *out);

/*
 * Release every resource owned by ring.  Idempotent: safe to call on
 * a zeroed / failed ring, where every sentinel check short-circuits.
 * errno is preserved across the call -- save/restore brackets the
 * munmap and close syscalls so a caller that latches off the setup
 * errno can still call teardown safely after the classification.
 */
void iour_ring_teardown(struct iour_ring *ring);
