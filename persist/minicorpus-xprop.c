/*
 * Cross-syscall value propagation for the mini-corpus mutator.
 *
 * Within-syscall splice shuffles values between arg slots of one
 * snapshot.  xprop extends the same idea across syscalls: with low
 * probability an arg of the target syscall is overridden with a value
 * pulled from a *different* syscall's corpus pool.  Most arg slots see
 * no benefit from foreign values -- the kernel cheaply rejects
 * type-incoherent garbage with -EINVAL and we burn iterations -- so the
 * initial whitelist is narrow: fd-consuming slots of the target draw
 * from fd-returning syscalls' pools.  That pairing has the highest
 * a-priori chance of producing a value that lands in a region of input
 * space the kernel will follow rather than reject outright.
 *
 * Built once from minicorpus_init() by walking the syscall table
 * (which select_syscall_tables() has already populated by the time
 * init_shm runs) and recording the nr of every syscall with
 * rettype == RET_FD whose argtype set is corpus-replayable.  Inherited
 * COW by every child fork.
 */

#include "minicorpus.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "minicorpus-internal.h"

#define XPROP_FD_SRC_MAX 64

static unsigned int xprop_fd_src_nrs[XPROP_FD_SRC_MAX];
static unsigned int xprop_n_fd_src;

static void xprop_consider_nr(unsigned int nr)
{
	struct syscallentry *e;

	if (xprop_n_fd_src >= XPROP_FD_SRC_MAX)
		return;
	e = get_syscall_entry(nr, false);
	if (e == NULL || e->rettype != RET_FD)
		return;
	if (!corpus_args_replayable(e))
		return;
	xprop_fd_src_nrs[xprop_n_fd_src++] = nr;
}

void xprop_build_whitelist(void)
{
	unsigned int nr;

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++)
		xprop_consider_nr(nr);

	output(0, "KCOV: mini-corpus xprop whitelist: %u fd-returning sources\n",
		xprop_n_fd_src);
}

/*
 * Pull a value from a different syscall's seen-arg pool for use as arg
 * @arg_atype of the target syscall @nr.  Returns true and writes the
 * picked value to *val on a hit; false leaves *val untouched.  Only
 * fd-typed target slots are eligible -- the whitelist source pool is
 * the fd-returning-syscall set built at init.  Self-pairs are filtered
 * (within-syscall shuffling is the splice op's job).
 */
bool minicorpus_pick_from_other_syscall(unsigned int nr,
					enum argtype arg_atype,
					unsigned long *val)
{
	struct corpus_ring *ring;
	unsigned int src_nr, slot, src_arg, num_args;
	unsigned int count, head;
	unsigned long picked;

	/* xprop attempt denominator.  Bumped once per
	 * entry regardless of outcome so the type-hit rate
	 * xprop_hits / xprop_attempts is directly readable, and
	 * the reject-cause breakdown below sums (with hits) to
	 * xprop_attempts minus the xprop_n_fd_src==0 early-out
	 * (the whitelist-uninitialised case, which is not a
	 * realised attempt). */
	if (xprop_n_fd_src == 0)
		return false;
	__atomic_fetch_add(&minicorpus_shm->xprop_attempts, 1UL,
			   __ATOMIC_RELAXED);
	if (!is_fdarg(arg_atype)) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_target_not_fdarg,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	src_nr = xprop_fd_src_nrs[rnd_modulo_u32(xprop_n_fd_src)];
	if (src_nr == nr) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_src_self,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	ring = &minicorpus_shm->rings[src_nr];

	/*
	 * Lockless reader.  Single slot, single arg, no joint snapshot
	 * across multiple entries -- drop ring->lock and synchronise on
	 * the writer's release-stores of count/head (see
	 * minicorpus_save_with_reason).  Writers still serialise on
	 * ring->lock; this reader just observes the published view.
	 *
	 * Ordering: the writer publishes count BEFORE head (the
	 * deliberate inversion vs chain_corpus_save documented at the
	 * publish site).  An acquire-load of count is the synchronisation
	 * edge -- it pairs with the writer's release-store of count and
	 * therefore makes the entry stores that preceded that store
	 * visible to us.  The head store happens *after* the count store
	 * in writer program order, so a count-acquire does not also
	 * synchronise the head bump; loading head relaxed can return a
	 * value one publish stale.  That is fine: a stale head still
	 * points one past a slot that was validly published in some
	 * earlier save, so we land on a legitimate xprop source -- "most
	 * recent" is a heuristic here, not a correctness invariant.
	 *
	 * Race tolerance: a concurrent minicorpus_save can overwrite the
	 * slot we are mid-read on.  num_args is validated in [1, 6] post-
	 * snapshot; a torn struct assignment that produces an out-of-
	 * range value just skips the pick, no retry -- same tolerance
	 * the fuzzer applies to the other 75%+ of mutated inputs.
	 * args[] is a fixed-size 6-element array, so reading
	 * args[src_arg] with src_arg < num_args <= 6 is memory-safe even
	 * if the underlying ulong was itself torn; the caller just gets
	 * a slightly-stale value, which is fuzz fodder either way.
	 */
	count = __atomic_load_n(&ring->count, __ATOMIC_ACQUIRE);
	if (count == 0) {
		__atomic_fetch_add(&minicorpus_shm->xprop_reject_src_empty,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}
	head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);

	/* Newest entry: head points one past the last write.  Adding
	 * CORPUS_RING_SIZE before the subtract keeps the unsigned modulo
	 * well-defined when head is 0 on a wrapped ring. */
	slot = (head + CORPUS_RING_SIZE - 1) % CORPUS_RING_SIZE;

	num_args = ring->entries[slot].num_args;
	if (num_args == 0 || num_args > 6) {
		__atomic_fetch_add(&minicorpus_shm->replay_torn_rejects,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}
	src_arg = rnd_modulo_u32(num_args);
	picked = ring->entries[slot].args[src_arg];

	*val = picked;
	__atomic_fetch_add(&minicorpus_shm->xprop_hits, 1UL,
			   __ATOMIC_RELAXED);
	return true;
}
