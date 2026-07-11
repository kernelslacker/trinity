/*
 * Cross-arg lengths-match validator and repair pass.
 *
 * Some syscalls express a buffer with a (pointer, count) pair whose
 * kernel-side coherence the per-argument generators do not enforce.
 * The random walk therefore produces routine incoherence: a NULL base
 * with a positive length (the kernel rejects at its earliest EFAULT
 * step) or a length that overshoots the writable extent of the base
 * (the kernel rejects at copy_from_user()/import time before any
 * interesting syscall body runs).  Both burn a syscall round-trip and
 * a kcov enable/disable pair to rediscover the same import guard over
 * and over.
 *
 * The entry point runs after .sanitise and before dispatch, on the
 * final argument-slot values.  Two dispositions per detected pair:
 *
 *   - NULL base with a positive length -> synthesise the same early-
 *     EINVAL reject shape the epoll rule takes.  A NULL base cannot
 *     be made coherent, so REPAIR does not apply.
 *
 *   - Non-NULL base with length > writable_extent(base) ->
 *     probabilistically clamp the length down to the extent in place,
 *     reusing the shared_region_size_for() lookup the per-slot ARG_LEN
 *     generator uses for the adjacent case.  A fraction of over-extent
 *     shapes is intentionally left uncorrected so the kernel's own
 *     import guard stays on the coverage surface.
 *
 * Callers see three counters: STATS_FIELD_VALIDATOR_REJECTED (via the
 * -1 return), STATS_FIELD_ARG_CONSTRAINT_REPAIRED (per clamp), and
 * STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT (per skipped clamp).
 */
#include <sys/uio.h>

#include "arg_coupling.h"
#include "child.h"		/* this_child */
#include "random.h"		/* ONE_IN */
#include "sanitise.h"		/* get_argval */
#include "signals.h"		/* asb_copy_active, asb_copy_recover */
#include "stats_ring.h"		/* STATS_FIELD_*, stats_ring_enqueue */
#include "syscall.h"
#include "trinity.h"
#include "utils-mem.h"		/* range_in_tracked_shared, range_readable_user,
				 * shared_region_size_for */

/*
 * Reciprocal of the per-detection probability that an over-extent shape
 * is LEFT uncorrected.  A pure clamp policy would turn every guaranteed
 * copy-fault into a kernel-walked call, which is the shift this validator
 * exists to make -- but it would also erase the kernel's copy_from_user
 * / import_iovec rejection paths as a coverage target.  1-in-4 leaves
 * roughly 25% of over-extent shapes DOA so those import guards still
 * see traffic; tune from the arg_constraint_kept_incoherent /
 * arg_constraint_repaired ratio in the periodic dump.
 */
#define ARG_COUPLING_REPAIR_SKIP_ONE_IN 4

static void arg_coupling_bump(enum stats_field field)
{
	struct childdata *child = this_child();

	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring, field, 0, 1);
}

static void write_arg_slot(struct syscallrecord *rec, unsigned int slot,
			   unsigned long val)
{
	switch (slot) {
	case 1: rec->a1 = val; break;
	case 2: rec->a2 = val; break;
	case 3: rec->a3 = val; break;
	case 4: rec->a4 = val; break;
	case 5: rec->a5 = val; break;
	case 6: rec->a6 = val; break;
	}
}

/*
 * Locate the sole (address, length) coupled pair whose length was not
 * already capped at arg-generation time.  gen_arg_len() caps a length
 * by shared_region_size_for(base) ONLY when the ARG_ADDRESS immediately
 * precedes the ARG_LEN, so pairs the syscall lays out with the length
 * in some other slot survive into dispatch uncapped.
 *
 * All three constraints below are load-bearing:
 *   - exactly one ARG_ADDRESS(-family) slot: multiple bases leave the
 *     pairing ambiguous, and a wrong pairing would corrupt an unrelated
 *     arg's length.
 *   - exactly one ARG_LEN slot: same argument in reverse.
 *   - len slot is not the slot immediately after the addr slot: the
 *     adjacent case is already handled by gen_arg_len().
 * Slots are 1-based.
 */
static bool find_coupled_addr_len(const struct syscallentry *entry,
				  unsigned int *addr_slot_out,
				  unsigned int *len_slot_out)
{
	unsigned int addr_slot = 0, len_slot = 0;
	unsigned int nargs = entry->num_args;
	unsigned int i;

	if (nargs > 6)
		nargs = 6;

	for (i = 0; i < nargs; i++) {
		enum argtype t = entry->argtype[i];

		if (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS) {
			if (addr_slot != 0)
				return false;
			addr_slot = i + 1;
		} else if (t == ARG_LEN) {
			if (len_slot != 0)
				return false;
			len_slot = i + 1;
		}
	}
	if (addr_slot == 0 || len_slot == 0)
		return false;
	if (len_slot == addr_slot + 1)
		return false;

	*addr_slot_out = addr_slot;
	*len_slot_out = len_slot;
	return true;
}

/*
 * Apply the DOA / over-extent rules to one (address, length) pair.
 * Returns -1 for the DOA shape (NULL base with a positive length) so
 * the caller can synthesise the shared early-EINVAL reject; returns 0
 * for the over-extent shape after either clamping the length or
 * skipping the clamp (each bumps its own disposition counter).  A base
 * that is not inside any tracked shared region (shared_region_size_for
 * returns 0) is left alone -- the size-agnostic case is the documented
 * fallback in gen_arg_len(), applied here on the same signal.
 */
static int reconcile_addr_len(struct syscallrecord *rec,
			      unsigned int addr_slot,
			      unsigned int len_slot)
{
	unsigned long addr = get_argval(rec, addr_slot);
	unsigned long len = get_argval(rec, len_slot);
	unsigned long extent;

	if (addr == 0) {
		if (len == 0)
			return 0;
		return -1;
	}

	extent = shared_region_size_for(addr);
	if (extent == 0 || len <= extent)
		return 0;

	if (ONE_IN(ARG_COUPLING_REPAIR_SKIP_ONE_IN)) {
		arg_coupling_bump(STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT);
		return 0;
	}
	write_arg_slot(rec, len_slot, extent);
	arg_coupling_bump(STATS_FIELD_ARG_CONSTRAINT_REPAIRED);
	return 0;
}

/*
 * Refuse to touch the iovec array unless it lies wholly within a
 * region trinity itself owns and knows is writable.  Between
 * srec_publish_end() and __do_syscall() a sibling can stomp rec->aN,
 * so the (iov, count) pair fetched from the record may redirect the
 * walk to unmapped, stale, read-only, or foreign memory.  Without a
 * gate, the iov_len writeback below would turn a validator meant to
 * REDUCE kernel EFAULTs into a trinity-side SIGSEGV source.
 *
 * range_readable_user() proves the count-entry span is mapped;
 * range_in_tracked_shared() then proves it belongs to one of the
 * mappings alloc_shared() created R/W for this run, so the writeback
 * cannot land on a foreign or read-only page.  Either failure => skip
 * silently, same disposition as the outer iov==NULL / count-out-of-
 * range early-continues (no bump).
 *
 * The walk itself is wrapped in the asb_copy_active / asb_copy_recover
 * sigsetjmp slot (see health/signals.c and post_snapshot_or_skip in
 * utils/post_snapshot.c) so a TOCTOU fault -- a sibling mprotect /
 * munmap in the window between the two proofs and the loads/stores
 * below -- unwinds to a skipped repair rather than a child SIGSEGV.
 * @j is volatile to silence -Wclobbered across the sigsetjmp edge.
 */
static void repair_iovec_extents_user(struct iovec *iov, unsigned long count)
{
	volatile unsigned long j;
	size_t bytes = count * sizeof(*iov);

	if (!range_readable_user(iov, bytes))
		return;
	if (!range_in_tracked_shared((unsigned long) iov, bytes))
		return;

	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return;
	}
	asb_copy_active = 1;

	for (j = 0; j < count; j++) {
		unsigned long base = (unsigned long) iov[j].iov_base;
		unsigned long ilen = (unsigned long) iov[j].iov_len;
		unsigned long extent;

		if (base == 0 || ilen == 0)
			continue;
		extent = shared_region_size_for(base);
		if (extent == 0 || ilen <= extent)
			continue;
		if (ONE_IN(ARG_COUPLING_REPAIR_SKIP_ONE_IN)) {
			arg_coupling_bump(STATS_FIELD_ARG_CONSTRAINT_KEPT_INCOHERENT);
			continue;
		}
		iov[j].iov_len = (size_t) extent;
		arg_coupling_bump(STATS_FIELD_ARG_CONSTRAINT_REPAIRED);
	}

	asb_copy_active = 0;
}

/*
 * Clamp each iovec entry's iov_len down to the writable extent of its
 * iov_base whenever it overshoots.  Same probabilistic partial-repair
 * gate as the addr/len rule so a fraction of over-extent entries
 * survive as import_iovec EFAULT coverage.
 *
 * Entries with iov_base == NULL, iov_len == 0, or an iov_base outside
 * every tracked shared region (SHAPE_INVALID and its 0xdeadbeef
 * sentinel among them) are left alone: the untracked case would need
 * a different oracle to distinguish "unmapped by design" from "clamp
 * target", and a NULL base with a zero length is a legal segment the
 * kernel accepts.  Bumps per-entry so the fanout across a wide iovec
 * is observable rather than collapsed into a per-syscall tick.
 */
static void repair_iovec_extents(struct syscallrecord *rec)
{
	const struct syscallentry *entry = rec->entry;
	unsigned int nargs = entry->num_args;
	unsigned int i;

	if (nargs > 6)
		nargs = 6;

	for (i = 0; i < nargs; i++) {
		enum argtype t = entry->argtype[i];
		struct iovec *iov;
		unsigned long count;

		if (t != ARG_IOVEC && t != ARG_IOVEC_IN)
			continue;
		if (i + 1 >= nargs || entry->argtype[i + 1] != ARG_IOVECLEN)
			continue;

		iov = (struct iovec *) get_argval(rec, i + 1);
		if (iov == NULL)
			continue;
		count = get_argval(rec, i + 2);
		if (count == 0 || count > UIO_MAXIOV)
			continue;

		repair_iovec_extents_user(iov, count);
	}
}

int validate_arg_coupling(struct syscallrecord *rec)
{
	const struct syscallentry *entry;
	unsigned int addr_slot, len_slot;

	if (rec == NULL)
		return 0;

	entry = rec->entry;
	if (entry == NULL || entry->name == NULL)
		return 0;

	/*
	 * epoll_wait / epoll_pwait / epoll_pwait2: the events output
	 * buffer (a2) must be non-NULL whenever maxevents (a3) is > 0.
	 * The kernel's ep_send_events() unconditionally dereferences the
	 * events pointer once maxevents is positive, so a NULL buffer
	 * with maxevents > 0 is rejected as EFAULT at copy_to_user time
	 * without exercising any interesting eventpoll path.  Skip the
	 * dispatch.  maxevents <= 0 is a legitimate sanitise bucket that
	 * exercises the early EINVAL reject; leave those alone.
	 *
	 * The family-membership test reads the cached is_epoll_wait_family
	 * byte stamped at table init.
	 */
	if (entry->is_epoll_wait_family) {
		if ((long) rec->a3 > 0 && rec->a2 == 0) {
			outputerr("arg-coupling: %s rejected: maxevents=%ld but events=NULL\n",
				  entry->name, (long) rec->a3);
			return -1;
		}
	}

	/*
	 * Non-adjacent (address, length) coupled pair: gen_arg_len()
	 * only caps a length by the writable extent when the ARG_ADDRESS
	 * immediately precedes the ARG_LEN, so any syscall whose length
	 * slot the kernel accepts elsewhere in the record survives into
	 * dispatch uncapped.  DOA rejects take the return -1 path;
	 * over-extent shapes are probabilistically clamped in place so
	 * the syscall walks real kernel code rather than copy-faulting
	 * at import.
	 */
	if (find_coupled_addr_len(entry, &addr_slot, &len_slot)) {
		if (reconcile_addr_len(rec, addr_slot, len_slot) < 0) {
			outputerr("arg-coupling: %s rejected: a%u=NULL but a%u=%lu\n",
				  entry->name, addr_slot, len_slot,
				  get_argval(rec, len_slot));
			return -1;
		}
	}

	/*
	 * Iovec entries whose iov_len overshoots the base allocation
	 * extent get the same probabilistic clamp treatment, per entry,
	 * independent of any outer addr/len pair the syscall carries.
	 */
	repair_iovec_extents(rec);

	return 0;
}
