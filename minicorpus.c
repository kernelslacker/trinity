/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * Stores syscall argument snapshots that discovered new KCOV edges.
 * During future arg generation for the same syscall, a stored
 * snapshot may be replayed with per-argument mutations to explore
 * nearby input space.
 *
 * Syscalls with sanitise callbacks or with arg types that carry
 * heap pointers (ARG_IOVEC, ARG_PATHNAME, ARG_SOCKADDR, ARG_MMAP)
 * are excluded — those pointers become stale after deferred-free
 * eviction, causing UAF on replay.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "random.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

struct minicorpus_shared *minicorpus_shm = NULL;

void minicorpus_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Stays alloc_shared() rather than alloc_shared_global().
	 * Children are the producers for almost every field of the region:
	 *   - rings[nr].entries[]: minicorpus_save() writes saved arg
	 *     snapshots from child context after every coverage-positive
	 *     syscall, under the per-ring lock.
	 *   - rings[nr].lock: held by both child save and child replay.
	 *   - mut_trials[] / mut_wins[]: minicorpus_mut_attrib_commit()
	 *     atomically increments these from child context after every
	 *     non-cmp syscall.
	 *   - replay_count, splice_hits, splice_wins, replay_wins,
	 *     stack_depth_histogram[], chain_iter_count: bumped from
	 *     mutate_arg / minicorpus_mutate_args / chain replay paths,
	 *     all in child context.
	 * The only parent-side write is minicorpus_load_file (corpus
	 * warm-start) which runs strictly before fork_children() — pre-
	 * freeze, so it would be unaffected — but the post-fork paths
	 * dominate, and they need the region writable.  Cannot be
	 * mprotected without crippling per-call replay and the weighted
	 * mutator scheduler.
	 *
	 * Wild-write risk this leaves open: a child syscall buffer pointer
	 * aliasing into the corpus could corrupt a saved snapshot's args[]
	 * (the next replay feeds garbage to the kernel — at worst ENOSYS /
	 * EINVAL, not a parent crash) or stick a ring->lock byte (one
	 * syscall's saves/replays stall).  The mut_attrib counters can be
	 * skewed but the weight floor (MUT_WEIGHT_FLOOR=50) keeps the
	 * scheduler operational.  No parent crash surface.
	 */
	minicorpus_shm = alloc_shared(sizeof(struct minicorpus_shared));
	memset(minicorpus_shm, 0, sizeof(struct minicorpus_shared));
	output(0, "KCOV: mini-corpus allocated (%lu KB, %d entries/syscall)\n",
		(unsigned long) sizeof(struct minicorpus_shared) / 1024,
		CORPUS_RING_SIZE);
}

static void ring_lock(struct corpus_ring *ring)
{
	lock(&ring->lock);
}

static void ring_unlock(struct corpus_ring *ring)
{
	unlock(&ring->lock);
}

void minicorpus_save(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry *ent;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return;

	/* Reject syscalls whose args don't survive replay across runs.
	 *
	 *  - ARG_IOVEC / ARG_PATHNAME / ARG_SOCKADDR / ARG_MMAP: heap pointers
	 *    allocated by generic_sanitise().  After deferred-free eviction
	 *    they go stale and replaying them feeds freed memory to the kernel.
	 *
	 *  - ARG_PID: a pid valid in the saving run is meaningless in the
	 *    replaying run.  Worse, due to dense trinity pid allocation and
	 *    kernel pid recycling, a stale pid frequently HITS a current
	 *    trinity child or the parent — replay of kill/tkill/tgkill/
	 *    pidfd_send_signal/rt_sigqueueinfo entries cascade-SIGKILLs the
	 *    fleet.  Observed 2026-04-20 immediately after warm-start landed:
	 *    639-entry corpus → wave of "pid X has disappeared" reaps within
	 *    seconds of fork-out. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
		case ARG_PID:
			return;
		default:
			break;
		}
	}

	ring = &minicorpus_shm->rings[nr];

	ring_lock(ring);

	ent = &ring->entries[ring->head % CORPUS_RING_SIZE];
	ent->args[0] = rec->a1;
	ent->args[1] = rec->a2;
	ent->args[2] = rec->a3;
	ent->args[3] = rec->a4;
	ent->args[4] = rec->a5;
	ent->args[5] = rec->a6;
	ent->num_args = entry->num_args;

	/* Saved fd numbers are stale on replay — zero them out so mutate_arg
	 * gets a fresh fd rather than trying to reuse a closed one.  Same
	 * treatment for ARG_ADDRESS / ARG_NON_NULL_ADDRESS: raw user pointers
	 * from the saving run's address space are garbage in the replaying
	 * run, but the runtime can re-derive a valid writable page if the
	 * slot is zero. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]) ||
		    entry->argtype[i] == ARG_ADDRESS ||
		    entry->argtype[i] == ARG_NON_NULL_ADDRESS)
			ent->args[i] = 0;
	}

	ring->head++;
	if (ring->count < CORPUS_RING_SIZE)
		ring->count++;

	ring_unlock(ring);
}

/*
 * Per-process attribution stash for the weighted mutator scheduler.
 *
 * mutate_arg() bumps mut_attrib[op] every time it picks case `op`.  After
 * the syscall completes, the post-coverage path drains the stash via
 * minicorpus_mut_attrib_commit() (folding it into shm-wide trials/wins)
 * or minicorpus_mut_attrib_clear() (dropping it for cmp-mode calls).
 *
 * Process-local — children fork before any mutate_arg call, so each child
 * has its own copy.  No locking needed: a child runs single-threaded.
 */
static unsigned int mut_attrib[MUT_NUM_OPS];

/*
 * Process-local replay and splice attribution flags.
 *
 * Set by minicorpus_replay() when the respective event occurs; consumed
 * and cleared by minicorpus_mut_attrib_commit() / minicorpus_mut_attrib_clear()
 * to attribute wins without needing a second pass over the call path.
 * Per-process — same fork/single-threaded guarantee as mut_attrib[].
 */
static bool this_replay_ran;
static bool this_replay_spliced;

/*
 * Floor on the per-case weight in the weighted scheduler.
 *
 * Weights are scaled to [0, 1000] (see weighted_pick_case() comment).
 * A floor of 50 keeps even a thoroughly-failed case at ~5% of a winning
 * case's weight, so it still gets picked occasionally.  Without a floor,
 * a case that produced zero wins after many trials would asymptote to
 * weight 0 and never be retried — and kernel state changes underneath
 * us, so a previously-dead case can become productive later.
 */
#define MUT_WEIGHT_FLOOR 50

/*
 * Pick a mutator case 0..MUT_NUM_OPS-1 weighted by historical productivity.
 *
 * Each case's weight is the Beta(1,1)-prior posterior mean of its success
 * rate, scaled to [0, 1000]:
 *
 *     w[op] = max(MUT_WEIGHT_FLOOR, (wins[op] + 1) * 1000 / (trials[op] + 2))
 *
 * Why this formula:
 *
 *  - The Beta(1,1) prior (uniform) gives every case w=500 on cold start
 *    when trials=wins=0, so we degrade gracefully to uniform random pick
 *    until evidence accumulates.  No special-casing for the empty-stats
 *    state, no warm-up phase to misconfigure.
 *
 *  - Add-one (Laplace) smoothing in the numerator and add-two in the
 *    denominator keep the formula well-defined at trials=0 and prevent a
 *    single early success from pinning a case to weight 1000.  It's the
 *    closed-form posterior mean of a Beta-binomial, not an ad-hoc fudge.
 *
 *  - We use the posterior MEAN rather than full Thompson sampling
 *    (Beta-distribution sampling).  Thompson would also work and be
 *    technically more exploration-aware, but it requires a Gamma
 *    sampler in libc that doesn't exist; the floor + uniform-prior
 *    combination here gives most of the same exploration benefit with
 *    a few lines of integer arithmetic.
 *
 *  - The floor is on the absolute weight, not on relative pick probability.
 *    With six cases and one heavily winning, the floored cases share the
 *    remaining mass — never starved, never dominant.
 *
 * Called once per primitive mutation (not once per syscall): a 4-deep
 * stack consults the scheduler four times.  All loads are __atomic
 * RELAXED — slightly stale fleet-wide counts are fine, the scheduler
 * is statistical not exact.
 */
static unsigned int weighted_pick_case(enum argtype atype)
{
	unsigned int weights[MUT_NUM_OPS];
	unsigned int total = 0;
	unsigned int r, accum, i;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						  __ATOMIC_RELAXED);
		unsigned long s = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						  __ATOMIC_RELAXED);
		unsigned long w = ((s + 1) * 1000UL) / (t + 2UL);

		if (w < MUT_WEIGHT_FLOOR)
			w = MUT_WEIGHT_FLOOR;
		weights[i] = (unsigned int)w;
		total += weights[i];
	}

	/* Case 8 (fd-swap) only does anything useful on fd-typed slots —
	 * pulling a random pool fd into a non-fd arg would just look like
	 * a small-integer noise mutation.  Zero its weight for non-fd args
	 * so the scheduler doesn't waste pick budget on it (and so its
	 * trials/wins ratio stays a meaningful signal of fd-swap value). */
	if (!is_fdarg(atype)) {
		total -= weights[8];
		weights[8] = 0;
	}

	r = (unsigned int)(rand() % total);
	accum = 0;
	for (i = 0; i < MUT_NUM_OPS; i++) {
		accum += weights[i];
		if (r < accum)
			return i;
	}
	return MUT_NUM_OPS - 1;
}

void minicorpus_mut_attrib_commit(bool found_new)
{
	unsigned int i;

	if (minicorpus_shm == NULL)
		return;

	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned int picks = mut_attrib[i];

		if (picks == 0)
			continue;
		__atomic_fetch_add(&minicorpus_shm->mut_trials[i],
				   picks, __ATOMIC_RELAXED);
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->mut_wins[i],
					   picks, __ATOMIC_RELAXED);
		mut_attrib[i] = 0;
	}

	if (this_replay_ran) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->replay_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_ran = false;
	}

	if (this_replay_spliced) {
		if (found_new)
			__atomic_fetch_add(&minicorpus_shm->splice_wins,
					   1UL, __ATOMIC_RELAXED);
		this_replay_spliced = false;
	}
}

void minicorpus_mut_attrib_clear(void)
{
	memset(mut_attrib, 0, sizeof(mut_attrib));
	this_replay_ran = false;
	this_replay_spliced = false;
}

/*
 * Cross-arg splice ratio.  With probability 1/SPLICE_RATIO, an arg in
 * a replay starts from a sibling arg's snapshot value rather than its
 * own, before the per-arg mutator chain runs on it.
 *
 * Why splice within the same syscall (rather than across syscalls or
 * across snapshots): args within one syscall invocation share semantic
 * structure — flags fields tend to share bit-encodings, length fields
 * tend to share scale, fd fields tend to be related — and splicing
 * preserves that structure while shuffling which slot each value lands
 * in.  Cross-snapshot or cross-syscall splice would mostly produce
 * type-incoherent gibberish; intra-syscall keeps the splice on a chain
 * of values the kernel already validated together.
 *
 * 10% is conservative: too much splice and we lose the per-arg
 * locality the corpus is meant to preserve.  Tunable here without
 * touching call sites.
 */
#define SPLICE_RATIO 10

/*
 * Per-arg mutation stacking depth.
 *
 * Drawing inspiration from AFL's havoc stage, when we mutate an argument
 * we apply 1..STACK_MAX mutations in sequence rather than always exactly
 * one.  Stacking lets us reach states that no single mutator can produce
 * (e.g. bit-flip then add-delta then boundary-replace), which is where the
 * long-tail edges tend to live once the easy single-mutation neighbours
 * have been exhausted.
 *
 * STACK_MAX caps the chain so a single arg can't burn unbounded entropy
 * and so the mutated value keeps some relationship to the snapshot —
 * past ~4 mutations on a scalar the result is indistinguishable from a
 * fresh random value, at which point the corpus snapshot has stopped
 * doing useful guidance work.
 *
 * STACK_MAX is defined in minicorpus.h (shared with stats.c for the
 * stack_depth_histogram array bounds). */

/*
 * Apply a small mutation to a single argument value.
 * The mutations are designed to explore nearby input space:
 *   - bit flip: toggle a single random bit
 *   - add/sub:  adjust by a small delta (1..16)
 *   - boundary: replace with a boundary value (0, -1, page_size, etc.)
 *
 * Case selection is biased by historical productivity (see
 * weighted_pick_case()).  The selected case is recorded in mut_attrib[]
 * for post-syscall attribution by minicorpus_mut_attrib_commit().
 */
static unsigned long mutate_arg(unsigned long val, enum argtype atype)
{
	unsigned int op = weighted_pick_case(atype);

	mut_attrib[op]++;

	switch (op) {
	case 0:
		/* flip a random bit */
		val ^= 1UL << (rand() % (sizeof(unsigned long) * 8));
		break;
	case 1: {
		/* add small delta, saturate at ULONG_MAX */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = ((unsigned long)-1 - val < delta) ? (unsigned long)-1 : val + delta;
		break;
	}
	case 2: {
		/* subtract small delta, saturate at 0 */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = (val < delta) ? 0 : val - delta;
		break;
	}
	case 3:
		/* replace with boundary */
		val = get_boundary_value();
		break;
	case 4:
		/* byte-level shuffle: randomize one byte */
		{
			unsigned int byte_pos = rand() % sizeof(unsigned long);
			unsigned long mask = 0xffUL << (byte_pos * 8);
			val = (val & ~mask) | ((unsigned long) RAND_BYTE() << (byte_pos * 8));
		}
		break;
	case 5:
		/* keep original — sometimes the saved value is good as-is */
		break;
	case 6: {
		/* endian-aware add: byte-swap at a width chosen by 50/33/17
		 * bias toward 32/16/64-bit, add a small delta in network-order
		 * interpretation, swap back.  Hits arithmetic neighbours of BE
		 * fields (sockaddr ports/addrs, raw IP headers, netfilter
		 * rules, netlink BE attrs) that native-endian add/sub misses
		 * because the magnitude byte sits at the opposite end of the
		 * word.  Width bias matches the prevalence of __be32/__be16/
		 * __be64 in the kernel API surface. */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		unsigned int w = rand() % 6;
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v + (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v + (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) + delta);
		}
		break;
	}
	case 7: {
		/* endian-aware sub: mirror of case 6.  Subtracts in
		 * network-order interpretation; underflow wraps within the
		 * chosen width, which is fine — the resulting bit pattern is
		 * still an interesting boundary in the post-swap space. */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		unsigned int w = rand() % 6;
		if (w <= 2) {
			uint32_t v = __builtin_bswap32((uint32_t)val);
			val = (val & ~0xffffffffUL) |
			      __builtin_bswap32(v - (uint32_t)delta);
		} else if (w <= 4) {
			uint16_t v = __builtin_bswap16((uint16_t)val);
			val = (val & ~0xffffUL) |
			      __builtin_bswap16(v - (uint16_t)delta);
		} else {
			val = __builtin_bswap64(__builtin_bswap64(val) - delta);
		}
		break;
	}
	case 8: {
		/* fd-pool cross-pollination.  Picked only for fd-typed args
		 * (weighted_pick_case() zeros this case for non-fd slots).
		 * With ~50% probability replace val with a different live fd
		 * drawn from the global pool — get_random_fd() picks across
		 * any active fd provider, so an ARG_FD_PIPE slot can land on
		 * a socket / io_uring / memfd / etc., exercising kernel paths
		 * that mix fd flavours (vmsplice between odd pairs, io_uring
		 * registering odd fds, fcntl on weird types).
		 *
		 * The other ~50% applies a small integer add inline, matching
		 * case 1's semantics: fd slots still see arithmetic-neighbour
		 * exploration so we don't lose the "off-by-one fd index"
		 * coverage that case 1 normally provides on this slot.
		 *
		 * If get_random_fd() returns a sentinel (-1, no providers; or
		 * a stdio fd 0/1/2 that the fd-safety pass downstream would
		 * patch anyway), fall through to the integer path so the
		 * mutation isn't a no-op.  Counts as one case-8 trial in the
		 * scheduler regardless of which branch fired. */
		bool swapped = false;

		if (RAND_BOOL()) {
			int fd = get_random_fd();

			if (fd > 2) {
				val = (unsigned long)fd;
				swapped = true;
			}
		}
		if (!swapped) {
			unsigned long delta = 1 + (unsigned long)(rand() % 16);
			val = ((unsigned long)-1 - val < delta) ?
			      (unsigned long)-1 : val + delta;
		}
		break;
	}
	}
	return val;
}

/*
 * Pick a stacking depth in [1, STACK_MAX] using a capped geometric
 * distribution with rate 1/2: P(1)=1/2, P(2)=1/4, P(3)=1/8, P(4)=1/8
 * (the tail mass collapses into the cap).  The bias toward small N
 * keeps most replays close to the corpus snapshot — only a minority
 * get aggressively stacked into deeper exploration.
 */
static unsigned int pick_stack_depth(void)
{
	unsigned int n = 1;

	while (n < STACK_MAX && RAND_BOOL())
		n++;
	return n;
}

/*
 * Apply mutate_arg n_muts times in sequence.  The stack composes the
 * primitive mutations into a single transformation per call site.
 */
static unsigned long mutate_arg_stacked(unsigned long val, unsigned int n_muts,
					enum argtype atype)
{
	while (n_muts-- > 0)
		val = mutate_arg(val, atype);
	return val;
}

/*
 * Apply the per-arg mutator chain (cross-arg splice + weighted-stack
 * mutate + fd safety) to args[6] in place, using @entry's argtype[]
 * for splice eligibility and fd substitution.  Both the per-syscall
 * mini-corpus replay path and the chain-corpus replay path call this
 * so the mutation logic — and the splice/replay/mut_attrib telemetry
 * it bumps — is a single shared engine.
 *
 * Splice and mutate read from a local snapshot of the input so a
 * sibling arg's value used for splice is the original input, not an
 * already-mutated peer; matches the per-syscall behaviour.
 */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry)
{
	unsigned long snapshot[6];
	unsigned int i;

	if (entry == NULL || minicorpus_shm == NULL)
		return;

	memcpy(snapshot, args, sizeof(snapshot));

	for (i = 0; i < entry->num_args && i < 6; i++) {
		unsigned long val = snapshot[i];

		/* Cross-arg splice: with probability 1/SPLICE_RATIO, replace
		 * this arg's starting value with a sibling arg's value from
		 * the same snapshot.  Runs BEFORE the mutator chain so the
		 * spliced value gets mutated in place rather than passed
		 * straight through.  Requires num_args >= 2 (otherwise there
		 * is no other slot to splice from). */
		if (entry->num_args >= 2 && ONE_IN(SPLICE_RATIO)) {
			unsigned int offset = 1 +
				(unsigned int)(rand() % (entry->num_args - 1));
			unsigned int src = (i + offset) % entry->num_args;

			val = snapshot[src];
			__atomic_fetch_add(&minicorpus_shm->splice_hits,
					   1UL, __ATOMIC_RELAXED);
			this_replay_spliced = true;
		}

		/* ~25% chance to mutate each arg.  When we do mutate, apply
		 * a stack of 1..STACK_MAX primitive mutations (geometric,
		 * biased toward small N) rather than a single one. */
		if (ONE_IN(4)) {
			unsigned int depth = pick_stack_depth();

			__atomic_fetch_add(&minicorpus_shm->stack_depth_histogram[depth],
					   1UL, __ATOMIC_RELAXED);
			val = mutate_arg_stacked(val, depth, entry->argtype[i]);
		}

		/* Don't let fd args land on stdin/stdout/stderr. */
		if (is_fdarg(entry->argtype[i]) && val <= 2)
			val = (unsigned long) get_random_fd();

		args[i] = val;
	}

	__atomic_fetch_add(&minicorpus_shm->replay_count, 1UL, __ATOMIC_RELAXED);
	this_replay_ran = true;
}

bool minicorpus_replay(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry snapshot;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int slot;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	ring = &minicorpus_shm->rings[nr];

	/* No saved entries yet. */
	if (ring->count == 0)
		return false;

	/* ~25% chance to replay, 75% fresh generation. */
	if (!ONE_IN(4))
		return false;

	ring_lock(ring);

	if (ring->count == 0) {
		ring_unlock(ring);
		return false;
	}

	/* Pick a random entry from the ring. */
	slot = rand() % ring->count;
	/* The ring is written at head and wraps, so the oldest valid
	 * entry starts at (head - count) mod CORPUS_RING_SIZE. */
	slot = (ring->head - ring->count + slot) % CORPUS_RING_SIZE;
	snapshot = ring->entries[slot];

	ring_unlock(ring);

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return false;

	/* Don't replay into syscalls with pointer-bearing arg types.
	 * Same rationale as minicorpus_save(). */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
			return false;
		default:
			break;
		}
	}

	minicorpus_mutate_args(snapshot.args, entry);

	rec->a1 = snapshot.args[0];
	rec->a2 = snapshot.args[1];
	rec->a3 = snapshot.args[2];
	rec->a4 = snapshot.args[3];
	rec->a5 = snapshot.args[4];
	rec->a6 = snapshot.args[5];

	return true;
}

/*
 * On-disk corpus persistence (warm-start).
 *
 * The format is a fixed header followed by a stream of fixed-size
 * entries.  Header carries a magic, a format version, the running
 * kernel's major.minor, and the syscall-number space size.  Each
 * entry carries the syscall number, num_args, six argument values,
 * and a CRC32 covering only the entry payload — a corrupt entry is
 * dropped without taking down the whole file.
 *
 * The layout is intentionally architecture-specific: callers build
 * paths under a per-arch subdirectory.  Cross-arch reuse is unsafe
 * because syscall numbers don't agree.
 */

#define CORPUS_FILE_MAGIC	0x54524E43U	/* "TRNC" */
#define CORPUS_FILE_VERSION	3U

/* Linux utsname fields are __NEW_UTS_LEN+1 = 65 bytes including NUL. */
#define CORPUS_UTSNAME_LEN	65

struct corpus_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t kernel_major;	/* parsed from utsname.release, kept for diag */
	uint32_t kernel_minor;	/* same */
	uint32_t max_nr_syscall;
	uint32_t reserved;
	/* Full utsname.release and utsname.version strings.  release encodes
	 * the patch sublevel and any local version suffix (-rcN, -fbkN,
	 * vendor patches), version encodes the build timestamp + git hash
	 * for kernel builds that include them.  Strict equality on both
	 * means "same compiled kernel image" — the only safe granularity
	 * for replay, since e.g. 7.0 vs 7.0-rc1 can differ in syscall
	 * behavior despite matching major.minor. */
	char kernel_release[CORPUS_UTSNAME_LEN];
	char kernel_version[CORPUS_UTSNAME_LEN];
};

struct corpus_file_entry {
	uint32_t nr;
	uint32_t num_args;
	uint64_t args[6];
	uint32_t crc;
	uint32_t pad;
};

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Small, no deps. */
static uint32_t corpus_crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;
		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

static bool parse_kernel_version(const char *release,
		uint32_t *major, uint32_t *minor)
{
	unsigned long maj, min;
	char *end;

	errno = 0;
	maj = strtoul(release, &end, 10);
	if (end == release || *end != '.' || errno == ERANGE)
		return false;

	release = end + 1;
	errno = 0;
	min = strtoul(release, &end, 10);
	if (end == release || errno == ERANGE)
		return false;

	*major = (uint32_t)maj;
	*minor = (uint32_t)min;
	return true;
}

static bool current_kernel_version(uint32_t *major, uint32_t *minor)
{
	struct utsname u;

	if (uname(&u) != 0)
		return false;
	return parse_kernel_version(u.release, major, minor);
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

static ssize_t read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
}

bool minicorpus_save_file(const char *path)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	struct corpus_entry snapshot[CORPUS_RING_SIZE];
	char tmppath[PATH_MAX];
	int fd;
	unsigned int nr;
	int ret;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = CORPUS_FILE_MAGIC;
	hdr.version = CORPUS_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	if (!current_kernel_version(&hdr.kernel_major, &hdr.kernel_minor))
		return false;
	{
		struct utsname u;
		if (uname(&u) != 0)
			return false;
		strncpy(hdr.kernel_release, u.release, sizeof(hdr.kernel_release) - 1);
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		strncpy(hdr.kernel_version, u.version, sizeof(hdr.kernel_version) - 1);
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	}

	/* Per-pid tmp suffix so a periodic save and the on-shutdown save
	 * can't open the same .tmp file with O_TRUNC and interleave their
	 * writes into a corrupt blob.  The atomic rename still gives the
	 * final on-disk file all-or-nothing semantics. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		struct corpus_ring *ring = &minicorpus_shm->rings[nr];
		unsigned int snap_count, oldest, i;

		/* Lock briefly to copy the ring out into a local buffer, then
		 * release before the disk write.  Mid-run snapshots run while
		 * children are actively appending to rings; without the lock,
		 * head/count and entries[] can be read in inconsistent
		 * combinations.  Hold time is bounded by a memcpy of at most
		 * CORPUS_RING_SIZE entries (~1.8 KB), so per-ring writer stall
		 * is microseconds even under heavy contention. */
		ring_lock(ring);
		snap_count = ring->count;
		if (snap_count == 0) {
			ring_unlock(ring);
			continue;
		}
		oldest = (ring->head - snap_count) % CORPUS_RING_SIZE;
		for (i = 0; i < snap_count; i++) {
			unsigned int slot = (oldest + i) % CORPUS_RING_SIZE;
			snapshot[i] = ring->entries[slot];
		}
		ring_unlock(ring);

		for (i = 0; i < snap_count; i++) {
			struct corpus_entry *src = &snapshot[i];
			unsigned int j;

			memset(&ent, 0, sizeof(ent));
			ent.nr = nr;
			ent.num_args = src->num_args;
			for (j = 0; j < 6; j++)
				ent.args[j] = (uint64_t)src->args[j];

			ent.crc = corpus_crc32(&ent,
				offsetof(struct corpus_file_entry, crc));

			if (write_all(fd, &ent, sizeof(ent)) < 0)
				goto fail;
		}
	}

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		unlink(tmppath);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		unlink(tmppath);
		return false;
	}
	return true;

fail:
	close(fd);
	unlink(tmppath);
	return false;
}

bool minicorpus_load_file(const char *path,
		unsigned int *loaded, unsigned int *discarded)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	uint32_t cur_major, cur_minor;
	unsigned int nloaded = 0;
	unsigned int ndiscarded = 0;
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read_all(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
		close(fd);
		return false;
	}

	if (hdr.magic != CORPUS_FILE_MAGIC ||
	    hdr.version != CORPUS_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		close(fd);
		return false;
	}

	if (!current_kernel_version(&cur_major, &cur_minor) ||
	    hdr.kernel_major != cur_major ||
	    hdr.kernel_minor != cur_minor) {
		close(fd);
		return false;
	}

	{
		struct utsname u;
		if (uname(&u) != 0) {
			close(fd);
			return false;
		}
		/* Force NUL termination on the on-disk strings before strncmp,
		 * defensive against truncated/corrupt headers. */
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
		if (strncmp(hdr.kernel_release, u.release,
			    sizeof(hdr.kernel_release)) != 0 ||
		    strncmp(hdr.kernel_version, u.version,
			    sizeof(hdr.kernel_version)) != 0) {
			close(fd);
			return false;
		}
	}

	for (;;) {
		struct corpus_ring *ring;
		struct corpus_entry *dst;
		uint32_t want;
		ssize_t n;
		unsigned int j;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = corpus_crc32(&ent,
			offsetof(struct corpus_file_entry, crc));
		if (want != ent.crc || ent.nr >= MAX_NR_SYSCALL ||
		    ent.num_args > 6) {
			ndiscarded++;
			continue;
		}

		ring = &minicorpus_shm->rings[ent.nr];
		ring_lock(ring);
		dst = &ring->entries[ring->head % CORPUS_RING_SIZE];
		for (j = 0; j < 6; j++)
			dst->args[j] = (unsigned long)ent.args[j];
		dst->num_args = ent.num_args;
		ring->head++;
		if (ring->count < CORPUS_RING_SIZE)
			ring->count++;
		ring_unlock(ring);
		nloaded++;
	}

	close(fd);

	if (loaded)
		*loaded = nloaded;
	if (discarded)
		*discarded = ndiscarded;
	return nloaded > 0;
}

/*
 * Build a default per-arch corpus path under $XDG_CACHE_HOME (or
 * $HOME/.cache).  Creates the parent directory tree on demand.  The
 * returned pointer is owned by a static buffer.
 */
const char *minicorpus_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	int ret;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#elif defined(__powerpc64__)
	arch = "ppc64";
#elif defined(__powerpc__)
	arch = "ppc";
#elif defined(__s390x__)
	arch = "s390x";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__sparc__)
	arch = "sparc";
#elif defined(__riscv) || defined(__riscv__)
	arch = "riscv64";
#else
	arch = "unknown";
#endif

	if (xdg && xdg[0] == '/') {
		ret = snprintf(dir, sizeof(dir), "%s/trinity/corpus", xdg);
	} else if (home && home[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			"%s/.cache/trinity/corpus", home);
	} else {
		return NULL;
	}
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	/* mkdir -p the leaf directory.  We don't care about race losses
	 * (EEXIST is fine), only about the final dir actually existing. */
	{
		char *p;
		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			return NULL;
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, arch);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic mid-run snapshot trigger.
 *
 * The save path itself is set in the parent before fork via
 * minicorpus_enable_snapshots() and inherited COW by every child.  All
 * children call minicorpus_maybe_snapshot() after each kcov edge event;
 * the function early-returns cheaply unless the fleet-wide edge count
 * has advanced MINICORPUS_SNAPSHOT_EDGES past the last snapshot's
 * high-water-mark.  When the gap is reached, a single CAS on
 * minicorpus_shm->edges_at_last_snapshot picks one caller as the saver
 * — it runs minicorpus_save_file() while everyone else loses the CAS
 * and returns.  The next snapshot opportunity opens once the next
 * MINICORPUS_SNAPSHOT_EDGES window has accumulated.
 */
static char snapshot_path[PATH_MAX];
static bool snapshot_enabled;

void minicorpus_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(snapshot_path))
		return;
	memcpy(snapshot_path, path, len + 1);
	snapshot_enabled = true;
}

void minicorpus_maybe_snapshot(void)
{
	unsigned long edges_now, old;

	if (!snapshot_enabled || minicorpus_shm == NULL || kcov_shm == NULL)
		return;

	edges_now = __atomic_load_n(&kcov_shm->edges_found, __ATOMIC_RELAXED);
	old = __atomic_load_n(&minicorpus_shm->edges_at_last_snapshot,
			      __ATOMIC_RELAXED);

	if (edges_now < old + MINICORPUS_SNAPSHOT_EDGES)
		return;

	/* Race for the slot.  Whoever wins the CAS is responsible for the
	 * save; the others see the new high-water-mark on their next call
	 * and early-return.  RELAXED ordering is enough — the save itself
	 * is independently consistent (per-ring lock during read), and the
	 * counter is just gating who runs, not what they observe. */
	if (!__atomic_compare_exchange_n(&minicorpus_shm->edges_at_last_snapshot,
					 &old, edges_now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	minicorpus_save_file(snapshot_path);
}
