/*
 * KCOV hot-path collection: PC and CMP-record canonicalisation,
 * edge / transition hashing, per-child dedup, the kcov_collect and
 * kcov_collect_cmp entry points, and the syscall cold-skip policy.
 * Carved out of kcov.c last because many strategy and stat counters
 * converge here; the extern for kcov_covjump_breadcrumb_maybe (still
 * in kcov.c, moving in the next step) is the only cross-cluster call
 * this file makes beyond the public kcov / cmp_hints APIs.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "cmp_hints.h"
#include "kcov-internal.h"
#include "params.h"		/* kcov_trace_size */
#include "pids.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"		/* output, outputerr */
#include "utils.h"		/* log_self_corrupt_culprit */

/*
 * Strip the runtime KASLR base from a kernel PC so the bucket index for
 * a given instruction is invariant across reboots of the same kernel
 * build.  kcov_kaslr_base is populated by kcov_init_global from the
 * address of _text in /proc/kallsyms; on systems where that lookup
 * failed it stays zero and this is the identity transform (the run
 * then hashes raw PCs, matching the pre-canonicalisation behaviour).
 *
 * Single point of canonicalisation.  Callers route every PC that lands
 * in bucket_seen[] or the transition map through here exactly once at
 * the head of the kcov_collect() PC walk, then feed the canonical
 * value into pc_canon_to_edge() and pair_to_transition() without
 * re-canonicalising.  scripts/check-static/kcov-canonicalise-pcs.sh
 * enforces both halves of the rule: pc_canon_to_edge() must not call
 * kcov_canon_pc (would double-subtract the base), and any function in
 * kcov.c that calls pc_canon_to_edge() must also call kcov_canon_pc.
 */
static inline unsigned long kcov_canon_pc(unsigned long pc)
{
	return pc - (unsigned long)kcov_kaslr_base;
}

/*
 * Defence-in-depth against a sibling wild write that scribbled our
 * childdata->local_stats pointer.  The per-child freeze in init_child
 * mprotects childdata PROT_READ across siblings so a stray kernel-side
 * write traps at -EFAULT rather than reaching the pointer, but the
 * freeze is best-effort (mprotect can fail on VMA pressure, and the
 * bug that motivated this bracket -- an end-aligned childdata start
 * that EINVAL'd every sibling's mprotect -- proved silent freeze
 * failures are a real state).  The cheap userspace-VA bracket here
 * mirrors objpool_check()'s reject shape: a scribble that turned
 * local_stats into a low-VA / pid-encoded pointer is rejected before
 * the deref that would otherwise SIGSEGV in the syscall hot path.
 *
 * Called on every syscall in kcov_collect, so the check is a pair of
 * unsigned-integer comparisons and nothing else -- no atomics, no
 * bitmap walks.  Callers keep the existing NULL check redundant with
 * this predicate for readability at the guarded deref sites.
 */
static inline bool kcov_local_stats_plausible(const struct kcov_child_local_stats *ls)
{
	uintptr_t p = (uintptr_t)ls;

	return p >= 0x10000UL && p < 0x800000000000UL;
}

/*
 * KASLR-strip a kernel comparison-instruction address before it lands in
 * the cmp-hints bloom + per-syscall pool + persisted state file.  Same
 * transform as kcov_canon_pc -- both subtract the runtime _text base
 * resolved by kcov_get_kaslr_base -- but kept as a distinct entry point
 * for the cmp-hint side so cmp_hints.c has a single named ingress that
 * scripts/check-static/cmp-hints-canonicalise-cmp-ip.sh can enforce in
 * isolation from the PC-coverage canonicalisation rule.
 *
 * Without this, the cmp-hints pool indexed entries by the raw runtime
 * PC of the kernel comparison site; a KASLR reroll between save and
 * load shifted every cmp_ip by the difference in kernel-text bases, so
 * the kallsyms-fingerprint match said "same kernel" but the warm-loaded
 * pool aliased every constant to a different (cmp_ip, value, size) key.
 * Field-scoped scoring planned on top of cmp_ip would compound the
 * noise.  The persisted-file header now stamps kcov_kaslr_base alongside
 * the canonical cmp_ip values, and the load path rejects a canonical-vs-
 * raw mismatch the same way kcov_bitmap_file_header.kaslr_base does.
 */
unsigned long kcov_canon_cmp_ip(unsigned long ip)
{
	return ip - (unsigned long)kcov_kaslr_base;
}

/*
 * Hash an already-canonicalised PC into an edge index.
 *
 * The previous xor-shift mixed too few of the bits in a typical kernel PC.
 * Two PCs that landed within the same cacheline (low 6 bits identical) and
 * shared the same upper bits ended up hashed to indices differing only in
 * the low 7 bits, clustering thousands of distinct PCs into a tiny bitmap
 * range and triggering false coverage saturation.
 *
 * Murmur3's 64-bit finalizer mixes every input bit into every output bit
 * with a single multiply/xor pair per round, which is enough to avoid the
 * cacheline clustering without breaking the PC's locality for the rest of
 * the pipeline.
 */
static inline unsigned int pc_canon_to_edge(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc & (KCOV_NUM_EDGES - 1));
}

/*
 * Per-syscall/childop entry sentinel for the shadow transition map.
 * The transition hash needs a stable predecessor for the first PC of a
 * trace so two unrelated calls cannot accidentally join across the
 * boundary (call A's last PC feeding call B's first PC would
 * manufacture a transition that never executed).  The sentinel sets
 * bit 63 so it cannot alias any canonicalised kernel PC (after the
 * KASLR-base subtraction those occupy the low 4 GB), with the
 * (nr, do32) pair encoded below the marker so each call site gets its
 * own predecessor.  The do32 dimension matters because a 32-bit-compat
 * entry into the same syscall slot reaches different kernel entry
 * trampolines than the native path.
 */
static inline unsigned long kcov_entry_sentinel(unsigned int nr, bool do32)
{
	return (1UL << 63) | ((unsigned long)do32 << 32) | (unsigned long)nr;
}

/*
 * Hash a (prev_canon_pc, cur_canon_pc) pair into a transition slot
 * index.  Both inputs are already KASLR-canonicalised — the caller
 * (kcov_collect's PC walk) holds the canonical value for the current
 * PC so it can be threaded into both pc_canon_to_edge() and here
 * without re-running kcov_canon_pc.  Rotates cur left by 1 before
 * xoring so the pair (a, b) hashes differently from (b, a) — a
 * forward and a backward edge through the same two basic blocks are
 * distinct transitions.
 */
static inline unsigned int pair_to_transition(unsigned long prev,
					      unsigned long cur)
{
	unsigned long h = prev * 0x9E3779B97F4A7C15UL;

	h ^= (cur << 1) | (cur >> 63);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdUL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53UL;
	h ^= h >> 33;
	return (unsigned int)(h & (KCOV_NUM_TRANSITIONS - 1));
}

/*
 * AFL-style hit-count classification.  Returns the bucket index 0..7 for
 * a count >= 1.  Counts of 1, 2, 3 each get their own bucket (loops with
 * very small iteration counts are common and worth distinguishing); larger
 * counts collapse into geometric ranges so a 100-iteration loop and a
 * 90-iteration loop don't fight over distinct novelty events.
 */
static unsigned int bucket_for_count(unsigned int n)
{
	if (n <= 1)
		return 0;
	if (n == 2)
		return 1;
	if (n == 3)
		return 2;
	if (n <= 7)
		return 3;
	if (n <= 15)
		return 4;
	if (n <= 31)
		return 5;
	if (n <= 127)
		return 6;
	return 7;
}

/*
 * Publish a new maximum probe distance to the shared counter.  The
 * probe==0 fast path (edge found on first probe) is the dominant case
 * and can never raise the max, so skip the shared-cacheline load there.
 */
static void kcov_note_max_probe(unsigned long probe)
{
	unsigned long cur;

	if (probe == 0)
		return;
	cur = __atomic_load_n(&kcov_shm->dedup.dedup_max_probe_seen,
		__ATOMIC_RELAXED);
	while (probe > cur) {
		if (__atomic_compare_exchange_n(&kcov_shm->dedup.dedup_max_probe_seen,
				&cur, probe,
				false,
				__ATOMIC_RELAXED,
				__ATOMIC_RELAXED))
			break;
	}
}

/*
 * Per-call dedup: count how many times this trace has hit a given edge.
 * Returns the updated count (1 on first sight, ++count on repeat).  On
 * probe overflow returns 1, which makes the caller register the hit in
 * bucket 0 — graceful degradation to old "any-hit" semantics for the
 * pathological edge in the pathological call.
 *
 * A slot is treated as empty when its generation field doesn't match the
 * caller's current generation; this lets kcov_collect() invalidate the
 * entire table by bumping a single counter instead of zeroing it per call.
 */
static unsigned int dedup_inc(struct kcov_dedup_slot *dedup, unsigned int edge,
	uint64_t generation, unsigned int nr, bool do32)
{
	unsigned int slot = (edge * 0x9E3779B1U) & KCOV_DEDUP_MASK;
	unsigned int probe;

	for (probe = 0; probe < KCOV_DEDUP_MAX_PROBE; probe++) {
		struct kcov_dedup_slot *s = &dedup[slot];

		if (s->generation != generation) {
			kcov_note_max_probe(probe);
			s->generation = generation;
			s->edge_idx = edge;
			s->count = 1;
			return 1;
		}
		if (s->edge_idx == edge) {
			kcov_note_max_probe(probe);
			s->count++;
			return s->count;
		}
		slot = (slot + 1) & KCOV_DEDUP_MASK;
	}
	__atomic_fetch_add(&kcov_shm->dedup.dedup_probe_overflow,
		1, __ATOMIC_RELAXED);
	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].dedup_probe_overflow,
			1, __ATOMIC_RELAXED);
	return 1;
}

bool kcov_collect(struct kcov_child *kc, unsigned int nr, bool do32,
		  unsigned long *new_edge_count,
		  struct kcov_pc_result *result)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	unsigned long edges_this_call = 0;
	unsigned long distinct_edges_this_call = 0;
	unsigned long local_distinct_pcs = 0;
	unsigned long transitions_this_call = 0;
	bool found_new = false;
	/* Snapshot the mode once: a mid-loop flip from SHADOW to OFF (no
	 * runtime path does this today, but be explicit) cannot leave the
	 * loop body straddling the gate. */
	enum kcov_transition_coverage_mode tcov_mode =
		__atomic_load_n(&kcov_transition_coverage_mode, __ATOMIC_RELAXED);
	/* Seed prev_canon_pc with the per-syscall entry sentinel so the
	 * first PC in this trace has a stable predecessor.  Remote-mode
	 * traces merge coverage copied from remote contexts into the same
	 * buffer; the ordering quality of that merge
	 * is unverified, so transition records from remote-mode calls are
	 * treated as shadow-only by virtue of the whole feature being
	 * shadow-only — no separate gate is needed yet. */
	unsigned long prev_canon_pc = kcov_entry_sentinel(nr, do32);

	if (new_edge_count != NULL)
		*new_edge_count = 0;
	if (result != NULL) {
		result->bucket_bits = 0;
		result->distinct_edges = 0;
		result->local_distinct_pcs = 0;
		result->transition_edges_real_local = 0;
		result->trace_size = 0;
	}

	if (!kc->active)
		return false;

	/* kcov_shm->coverage.total_calls is bumped solely for its stamp role:
	 * the returned call_nr is stored into kcov_shm->per_syscall.last_edge_at[nr]
	 * on the found-new-edge branch below and read by the cold-skip
	 * gap denominator in kcov_syscall_cold_skip_pct() / by the
	 * last_efault_at[] stamp in syscall.c.  The dump-side accounting
	 * (post-mortem, stats.c JSON + Scuba rows, strategy snapshots)
	 * reads parent_stats.total_calls, drained from the per-child
	 * kcov_child_local_stats staging counter bumped below. */
	call_nr = __atomic_fetch_add(&kcov_shm->coverage.total_calls,
		1, __ATOMIC_RELAXED);

	/* Per-child staging bumps for the dump-side total_calls /
	 * remote_calls accounting.  Lives on childdata->local_stats so
	 * the hot kcov_shm cacheline does not take a relaxed atomic
	 * bump per call for dump accounting -- the per-child staging
	 * is authoritative for that path.  this_child() is NULL only
	 * in parent context, which kcov_collect()'s callers do not
	 * reach -- guard anyway so a future caller cannot crash the
	 * parent on a stray invocation.  kcov_shm->coverage.remote_calls is
	 * not bumped: no stamp-role consumer references the shm
	 * field, so the staged delta is authoritative. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL) {
			if (kcov_local_stats_plausible(cc->local_stats)) {
				cc->local_stats->total_calls++;
				if (kc->remote_mode)
					cc->local_stats->remote_calls++;
				cc->local_stats->local_syscalls_since_flush++;
			} else {
				log_self_corrupt_culprit(
					"kcov:local_stats:calls",
					(unsigned long)cc->local_stats,
					&cc->syscall);
			}
		}
	}

	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count >= (unsigned long)kcov_trace_size - 1) {
		/* Kernel wanted to record more PCs than the buffer holds; the
		 * tail of this call's coverage was dropped.  Bump a counter so
		 * the post-mortem can show whether kcov_trace_size needs to
		 * grow again (raise it via --kcov-trace-size; the compile-time
		 * KCOV_TRACE_SIZE is just the default). */
		__atomic_fetch_add(&kcov_shm->coverage.trace_truncated, 1,
			__ATOMIC_RELAXED);
		if (nr < MAX_NR_SYSCALL) {
			__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].trace_truncated,
				1, __ATOMIC_RELAXED);
		} else if (nr >= CHILDOP_KCOV_NR_BASE) {
			unsigned long op = nr - CHILDOP_KCOV_NR_BASE;
			if (op < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
					&kcov_shm->childop_kcov.childop_kcov_trace_truncated[op],
					1, __ATOMIC_RELAXED);
		}
		count = (unsigned long)kcov_trace_size - 1;
	}

	/* CAS-loop-up the per-syscall trace-size high-water mark using the
	 * post-cap count.  Same shape as the dedup_max_probe_seen update
	 * inside dedup_inc(): read, attempt cmpxchg, retry on lost race. */
	if (nr < MAX_NR_SYSCALL) {
		uint32_t observed = (uint32_t)count;
		uint32_t cur = __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][do32].max_trace_size,
			__ATOMIC_RELAXED);
		while (observed > cur) {
			if (__atomic_compare_exchange_n(
					&kcov_shm->per_syscall_diag[nr][do32].max_trace_size,
					&cur, observed,
					false,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED))
				break;
		}
	}

	/* Reset the recover-on-EBADF attempt counter only when this call
	 * actually harvested PCs.  A successful KCOV_ENABLE that lands on
	 * a syscall hitting zero kernel code (count == 0) is a no-op
	 * recovery -- forgiving the attempt would let the close-race
	 * chain re-burn the budget every iteration without ever making
	 * progress.  See edge case 3 in the recovery design doc. */
	if (count > 0 && kc->recovery_attempts != 0)
		kc->recovery_attempts = 0;

	/*
	 * Invalidate the dedup table by bumping the generation counter — every
	 * slot whose generation doesn't match is implicitly empty.  Counter is
	 * uint64_t so wraparound is unreachable in any plausible run; the
	 * defensive wipe-and-restart-at-1 below stays as a backstop for any
	 * future logic that resets the counter through zero.
	 */
	kc->current_generation++;
	if (kc->current_generation == 0) {
		memset(kc->dedup, 0, KCOV_DEDUP_SIZE * sizeof(*kc->dedup));
		kc->current_generation = 1;
	}

	/* Cache the bucket from the previous loop iteration so a run of
	 * repeat hits on the same edge (common: a tight kernel loop dumps
	 * the same PC dozens of times into the trace buffer) doesn't have
	 * to recompute bucket_for_count() for the prior count.  prev_edge
	 * is set to an unreachable sentinel so the first iteration always
	 * misses the cache and falls back to the explicit recomputation. */
	unsigned int prev_edge = (unsigned int)-1;
	unsigned int prev_bucket = 0;

	for (idx = 0; idx < count; idx++) {
		unsigned long pc_val = __atomic_load_n(&kc->trace_buf[idx + 1],
			__ATOMIC_RELAXED);
		/* Canonicalise once per PC and drive both pc_canon_to_edge
		 * (for the existing PC bitmap) and pair_to_transition (for
		 * the shadow transition map) off the same value.  Routing
		 * through pc_to_edge() instead would re-run kcov_canon_pc on
		 * every PC. */
		unsigned long canon_pc = kcov_canon_pc(pc_val);
		unsigned int edge = pc_canon_to_edge(canon_pc);
		unsigned int local_count = dedup_inc(kc->dedup, edge,
			kc->current_generation, nr, do32);
		unsigned int bucket = bucket_for_count(local_count);
		unsigned char mask, old;

		if (local_count == 1)
			local_distinct_pcs++;

		/* Shadow transition coverage: hash the (prev_canon_pc,
		 * canon_pc) pair into the transition map and bump the
		 * counters on the 0 -> 1 slot transition.  Done before the
		 * bucket-bit short-circuits below so a re-hit of a known PC
		 * still contributes a transition record for the new
		 * predecessor — that is the whole point of the signal (new
		 * route through warm code). */
		if (tcov_mode != KCOV_TRANSITION_COVERAGE_OFF) {
			unsigned int tslot = pair_to_transition(prev_canon_pc,
								canon_pc);
			unsigned char tseen;

			tseen = __atomic_load_n(&kcov_shm->transition_seen[tslot],
				__ATOMIC_RELAXED);
			if (!(tseen & 0x1U)) {
				unsigned char told;

				told = __atomic_fetch_or(
					&kcov_shm->transition_seen[tslot],
					0x1U, __ATOMIC_RELAXED);
				if (!(told & 0x1U)) {
					__atomic_fetch_add(
						&kcov_shm->transition_edges_found,
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->transition_distinct_edges,
						1, __ATOMIC_RELAXED);
					transitions_this_call++;
				}
			}
		}
		prev_canon_pc = canon_pc;

		/* Skip the atomic OR when this hit kept us inside the same
		 * bucket as the previous hit on this edge — there is no
		 * possible new bit to set, so the global write is wasted. */
		if (local_count > 1) {
			unsigned int last_bucket = (edge == prev_edge)
				? prev_bucket
				: bucket_for_count(local_count - 1);
			if (bucket == last_bucket) {
				prev_edge = edge;
				prev_bucket = bucket;
				continue;
			}
		}

		mask = (unsigned char)(1U << bucket);

		/* Relaxed-load short-circuit: in saturated runs the bit is
		 * already set the vast majority of the time, so the locked RMW
		 * below is wasted.  A racing peer that also sees clear hits the
		 * fetch_or path and the (!(old & mask)) gate still elects a
		 * single bucket-bit winner. */
		if (__atomic_load_n(&kcov_shm->bucket_seen[edge],
				    __ATOMIC_RELAXED) & mask)
			continue;

		old = __atomic_fetch_or(&kcov_shm->bucket_seen[edge],
			mask, __ATOMIC_RELAXED);

		if (!(old & mask)) {
			__atomic_fetch_add(&kcov_shm->coverage.edges_found,
				1, __ATOMIC_RELAXED);
			edges_this_call++;
			found_new = true;
			/* old == 0 means no bucket bit was previously set
			 * for this edge -- a true first sighting.  Bumping a
			 * separate distinct_edges counter only on this
			 * transition keeps the cardinality signal clean of
			 * the bucket-bit churn that drives edges_found, so
			 * the plateau detector can sample a delta that
			 * actually falls to zero on flat runs. */
			if (old == 0) {
				__atomic_fetch_add(&kcov_shm->coverage.distinct_edges,
					1, __ATOMIC_RELAXED);
				distinct_edges_this_call++;
			}
		}

		prev_edge = edge;
		prev_bucket = bucket;
	}

	/* Per-child staging bump for the dump-side total_pcs.  Same
	 * batched-flush model as total_calls / remote_calls above; the
	 * delta here is +count (PCs returned by the kernel for this
	 * syscall), already a batched value at this site.  No
	 * stamp-role consumer reads kcov_shm->coverage.total_pcs, so the
	 * staged per-child delta is the source of truth for the dump
	 * path -- the shm atomic is not bumped. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL) {
			if (kcov_local_stats_plausible(cc->local_stats))
				cc->local_stats->total_pcs += count;
			else
				log_self_corrupt_culprit(
					"kcov:local_stats:pcs",
					(unsigned long)cc->local_stats,
					&cc->syscall);
		}
	}

	if (nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall.per_syscall_calls[nr][do32 ? 1 : 0],
			1, __ATOMIC_RELAXED);
		/* per-syscall split of
		 * kcov_collect() activity by collection mode.  See the field
		 * comments in include/kcov.h: a remote-sampled syscall lands
		 * in KCOV_MODE_REMOTE and drops synchronous local PC, so a
		 * static remote sampling policy can spend half a syscall's
		 * samples on a mode with no annotated producer.  Bump every
		 * call into the mode-keyed slot so per-mode yield is
		 * measurable per syscall. */
		if (kc->remote_mode)
			__atomic_fetch_add(&kcov_shm->remote_pc_calls[nr],
				1, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->local_pc_calls[nr],
				1, __ATOMIC_RELAXED);
		if (found_new) {
			/* Mirror the per_syscall_edges call-count + raw-edge
			 * split above into the local/remote slots so the
			 * mode-keyed yield ratio (edge_calls / pc_calls and
			 * edge_count / pc_calls) is directly readable. */
			if (kc->remote_mode) {
				__atomic_fetch_add(
					&kcov_shm->remote_pc_edge_calls[nr],
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->remote_pc_edge_count[nr],
					edges_this_call, __ATOMIC_RELAXED);
			} else {
				__atomic_fetch_add(
					&kcov_shm->local_pc_edge_calls[nr],
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->local_pc_edge_count[nr],
					edges_this_call, __ATOMIC_RELAXED);
			}
			/* per_syscall_edges bumps by 1 (call-count semantics --
			 * see the comment on the field in include/kcov.h).  The
			 * real bucket-edge count is surfaced via the
			 * new_edge_count out-param below. */
			__atomic_fetch_add(&kcov_shm->per_syscall.per_syscall_edges[nr][do32 ? 1 : 0],
				1, __ATOMIC_RELAXED);
			/* SHADOW-only Phase-1 remote-context split of the clean
			 * per-thread signal above.  kcov_enable_remote()'s
			 * KCOV_REMOTE_ENABLE puts the task in KCOV_MODE_REMOTE and
			 * merges coverage copied from remote kernel contexts
			 * (kthreads / softirqs / threaded IRQ handlers) into this
			 * task's trace_buf; a found_new credited under remote_mode
			 * may therefore correspond to kernel work not causally
			 * bound to this syscall's own dispatch.  Recording the
			 * remote-mode subset here lets the attribution-confidence
			 * dump surface the local-only clean signal as
			 * (per_syscall_edges - per_syscall_edges_clean_remote)
			 * without changing any live selection or scoring code. */
			if (kc->remote_mode)
				__atomic_fetch_add(
					&kcov_shm->per_syscall.per_syscall_edges_clean_remote[nr],
					1, __ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->per_syscall.last_edge_at[nr],
				call_nr, __ATOMIC_RELAXED);
			/* if this call had a cmp_hint
			 * injected into its arg surface (latched in
			 * generate-args.c via credit_cmp_hint_injection),
			 * credit the resulting PC-edge win to the cmp-hint
			 * pipeline at the per-syscall granularity.  The
			 * cmp_hint_injected_this_call latch is owner-only
			 * written by the child generator path that ran just
			 * before this dispatch, so reading it here is a
			 * plain field access -- no atomics needed on the
			 * latch itself.  Parent-context this_child()==NULL
			 * is handled the same way the prior credit path is:
			 * the helper either set the flag (child) or did
			 * nothing (parent), and a NULL child here means no
			 * latch was set so no PC-win is credited. */
			{
				struct childdata *cc = this_child();

				if (cc != NULL &&
				    cc->cmp_hint_injected_this_call)
					__atomic_fetch_add(
						&kcov_shm->per_syscall_cmp_hint_pc_wins[nr],
						1, __ATOMIC_RELAXED);
			}
			/* Bump the per-syscall frontier-edge ring so the
			 * coverage-frontier picker (when active) can bias
			 * selection toward syscalls currently producing fresh
			 * coverage. */
			frontier_record_new_edge(nr);
		} else if (count > 0) {
			/* Kernel executed code for this syscall but every PC
			 * was already in bucket_seen[] (warm-loaded or
			 * earlier-this-run).  Track separately from
			 * per_syscall_edges so cold-skip / anti-prior / picker
			 * consumers can tell a quietly-exercised syscall from
			 * one that has never fired this run. */
			__atomic_fetch_add(
				&kcov_shm->per_syscall.per_syscall_warm_known_hits[nr], 1,
				__ATOMIC_RELAXED);
			/* Per-child staging bump for the dump-side run-wide
			 * warm-known-hits counter.  Same batched-flush model
			 * as total_calls / remote_calls / total_pcs above;
			 * no stamp-role consumer reads
			 * kcov_shm->per_syscall.total_warm_known_hits, so the staged
			 * per-child delta is authoritative for the dump path
			 * -- the shm atomic is not bumped.  The per-syscall
			 * split above stays on the shm atomic -- it's an nr-
			 * indexed array, not a cross-child cacheline-bounce
			 * scalar. */
			{
				struct childdata *cc = this_child();

				if (cc != NULL) {
					if (kcov_local_stats_plausible(
						    cc->local_stats))
						cc->local_stats->total_warm_known_hits++;
					else
						log_self_corrupt_culprit(
							"kcov:local_stats:warm",
							(unsigned long)cc->local_stats,
							&cc->syscall);
				}
			}
			/* Lazy-seed last_edge_at[nr] from the warm-known hit
			 * stream.  Without this seed, a syscall whose entire
			 * surface is warm-loaded looks indistinguishable from
			 * one that has never executed -- both have
			 * last_edge_at[nr] == 0 -- and the cold-skip /
			 * frontier consumers throttle accordingly.  Use a
			 * compare-exchange-loop-free pattern: read once, set
			 * if zero.  Races between concurrent first-warm-hits
			 * resolve harmlessly to whichever store wins -- both
			 * carry the same semantic "this syscall is alive". */
			if (__atomic_load_n(&kcov_shm->per_syscall.last_edge_at[nr],
					    __ATOMIC_RELAXED) == 0)
				__atomic_store_n(&kcov_shm->per_syscall.last_edge_at[nr],
						 call_nr, __ATOMIC_RELAXED);
		}
		/* Per-call totals into the (nr, do32)-indexed diag slot:
		 * bucket_bits_real mirrors edges_this_call, distinct_pcs is the
		 * count of dedup_inc() first-sight events.  Both are single
		 * relaxed atomics per call (zero-add suppressed) regardless of
		 * found_new — a warm-known call still has a distinct_pcs > 0
		 * contribution that the post-mortem wants visible. */
		if (edges_this_call > 0)
			__atomic_fetch_add(
				&kcov_shm->per_syscall_diag[nr][do32].bucket_bits_real,
				edges_this_call, __ATOMIC_RELAXED);
		if (local_distinct_pcs > 0)
			__atomic_fetch_add(
				&kcov_shm->per_syscall_diag[nr][do32].distinct_pcs,
				local_distinct_pcs, __ATOMIC_RELAXED);
		/* Shadow transition coverage per-syscall accounting.  The
		 * call-count counter (per_syscall_transition_edges) bumps by
		 * 1 for any call that produced ≥ 1 new transition slot — the
		 * top-N stats block uses its delta the same way the PC top-N
		 * uses per_syscall_edges.  The real counter
		 * (per_syscall_transition_edges_real) carries the raw flip
		 * count so a single call that opens a large new region is
		 * not flattened to the same weight as a call that flipped a
		 * single slot.
		 *
		 * per_syscall_transition_edges_real_local mirrors the _real
		 * counter restricted to local-mode kcov traces (remote-mode
		 * traces merge coverage copied from remote contexts whose PC
		 * ordering is not verified to preserve transition adjacency
		 * -- see the kcov_transition_reward_mode enum comment in
		 * include/kcov.h).  It is the local-only signal frontier_
		 * cold_weight() folds into its blend; the unfiltered _real
		 * counter stays the stats-dump observability signal so the
		 * top-N output keeps reflecting the full transition load.
		 * Gated additionally on kcov_transition_reward_mode != OFF
		 * so OFF mode pays zero per-call cost. */
		if (transitions_this_call > 0) {
			enum kcov_transition_reward_mode trew_mode =
				__atomic_load_n(&kcov_transition_reward_mode,
						__ATOMIC_RELAXED);

			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges[nr],
				1, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&kcov_shm->per_syscall_transition_edges_real[nr],
				transitions_this_call, __ATOMIC_RELAXED);
			if (!kc->remote_mode &&
			    trew_mode != KCOV_TRANSITION_REWARD_OFF)
				__atomic_fetch_add(
					&kcov_shm->per_syscall_transition_edges_real_local[nr],
					transitions_this_call,
					__ATOMIC_RELAXED);

			/* SHADOW-ONLY topology-pair sample, transition lane.
			 * Co-located with the
			 * unconditional per_syscall_transition_edges_real bump
			 * above so the topology aggregate's transition lane
			 * fires whenever a transition is discovered, regardless
			 * of the kcov_transition_reward_mode rollback knob or
			 * the local/remote split downstream gates apply.  The
			 * PC-edge sibling tail call in frontier_record_new_edge
			 * (below the found_new branch above) is similarly
			 * unconditional on mode -- this co-location keeps the
			 * PC and transition lanes drawing from the same child
			 * population for the per-setup_op comparison the shadow
			 * aggregator surfaces. */
			topo_pair_record_shadow(nr,
						TOPO_PAIR_REASON_TRANSITION);
		}
	} else if (nr >= CHILDOP_KCOV_NR_BASE) {
		/* per-childop mirror
		 * of the per-syscall local/remote PC split above.  Indexed
		 * by op = nr - CHILDOP_KCOV_NR_BASE; bounds-clamped against
		 * KCOV_CHILDOP_NR_MAX (the in-tree _Static_assert pins
		 * NR_CHILD_OP_TYPES below the bound, but the guard stays
		 * paranoid since nr is composed from a child_op_type value
		 * outside this file). */
		unsigned long op = nr - CHILDOP_KCOV_NR_BASE;

		if (op < KCOV_CHILDOP_NR_MAX) {
			if (kc->remote_mode)
				__atomic_fetch_add(
					&kcov_shm->childop_remote_pc_calls[op],
					1, __ATOMIC_RELAXED);
			else
				__atomic_fetch_add(
					&kcov_shm->childop_local_pc_calls[op],
					1, __ATOMIC_RELAXED);
			if (found_new) {
				if (kc->remote_mode) {
					__atomic_fetch_add(
						&kcov_shm->childop_remote_pc_edge_calls[op],
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->childop_remote_pc_edge_count[op],
						edges_this_call, __ATOMIC_RELAXED);
				} else {
					__atomic_fetch_add(
						&kcov_shm->childop_local_pc_edge_calls[op],
						1, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&kcov_shm->childop_local_pc_edge_count[op],
						edges_this_call, __ATOMIC_RELAXED);
				}
			}
		}
	}

	if (new_edge_count != NULL)
		*new_edge_count = edges_this_call;
	if (result != NULL) {
		result->bucket_bits = edges_this_call;
		result->distinct_edges = distinct_edges_this_call;
		result->local_distinct_pcs = local_distinct_pcs;
		/* Post-cap PC count from the trace header above (already
		 * clamped to kcov_trace_size - 1 when the buffer filled),
		 * surfaced so post-collect callers can recognise calls whose
		 * trace approached the buffer ceiling without re-reading
		 * trace_buf[0].  Same value the trace_truncated /
		 * max_trace_size accounting consumed; this is a single store
		 * with no new load. */
		result->trace_size = count;
		/* Zeroed for remote-mode traces (the live-reward path
		 * excludes them -- see the kcov_transition_reward_mode
		 * remote-mode contract in include/kcov.h) and for OFF mode
		 * (which never ran the inner tcov bump branch but the
		 * per-call counter would still be a valid local count;
		 * gating here keeps the caller-side accounting symmetric
		 * with the per_syscall_transition_edges_real_local gate
		 * above so OFF mode pays zero attribution cost). */
		if (!kc->remote_mode &&
		    __atomic_load_n(&kcov_transition_reward_mode,
				    __ATOMIC_RELAXED) !=
		    KCOV_TRANSITION_REWARD_OFF)
			result->transition_edges_real_local =
				transitions_this_call;
	}

	/* Drain the per-child kcov_child_local_stats staging counters
	 * into parent_stats via the stats_ring on either trigger:
	 *   (a) found_new -- a fresh edge already costs a dump-side
	 *       notification, fold the staged delta into the same drain;
	 *   (b) the syscalls-since-flush counter has reached the cadence
	 *       cap, so a long run of no-new-edge calls still publishes.
	 * The bumps above are gated on this_child() != NULL &&
	 * kcov_local_stats_plausible(cc->local_stats); mirror that gate
	 * here so a scribbled local_stats pointer is not followed on the
	 * cadence check either. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL) {
			if (kcov_local_stats_plausible(cc->local_stats)) {
				if (found_new ||
				    cc->local_stats->local_syscalls_since_flush >=
					    KCOV_LOCAL_STATS_FLUSH_SYSCALLS)
					kcov_child_flush_stats(cc);
			} else {
				log_self_corrupt_culprit(
					"kcov:local_stats:flush",
					(unsigned long)cc->local_stats,
					&cc->syscall);
			}
		}
	}

	/* Diagnostic coverage-jump breadcrumb -- pure observability, no
	 * behaviour gate.  See kcov_covjump_breadcrumb_maybe() for the
	 * contract; call_nr is the kcov_shm->coverage.total_calls stamp this
	 * call took at the top of kcov_collect(). */
	kcov_covjump_breadcrumb_maybe(call_nr);

	return found_new;
}

/*
 * Read-only snapshot of the child's current PC-trace write position.
 * Mirrors the count-load-and-cap sequence at the head of kcov_collect()
 * so callers get the same "how many PCs have landed so far" value the
 * collect path would see, but does not touch bucket_seen, dedup, or any
 * shm counter -- it is safe to call from inside an outer bracket
 * without perturbing the authoritative kcov_bracket_end harvest that
 * childop_edges_clean (and thus the child canary) reads.
 */
unsigned long kcov_trace_pos(struct kcov_child *kc)
{
	unsigned long count;

	if (kc == NULL || kc->trace_buf == NULL || !kc->active)
		return 0;
	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count >= (unsigned long)kcov_trace_size - 1)
		count = (unsigned long)kcov_trace_size - 1;
	return count;
}

/*
 * Read-only novelty probe over trace_buf[*cursor+1 .. trace_buf[0]].
 * Counts PCs whose canonicalised edge is currently unseen in
 * kcov_shm->bucket_seen[], then advances *cursor to the new trace end.
 * Intended for per-walk reward gates that live inside an outer
 * childop-attribution bracket: the outer kcov_bracket_end stays the
 * SOLE authoritative writer of bucket_seen, kc->dedup,
 * kc->current_generation, and kcov_shm->coverage.edges_found, so this probe
 * does not affect childop_edges_clean (the child canary signal) or
 * any dedup / generation state.  A brand-new edge that appears N
 * times in the sampled window contributes N to the returned count;
 * that hit-count weighting is accepted heuristic noise for the
 * reward path.
 */
unsigned long kcov_sample_new_edges(struct kcov_child *kc, unsigned long *cursor)
{
	unsigned long end, idx, start, n = 0;

	if (kc == NULL || cursor == NULL || kc->trace_buf == NULL || !kc->active)
		return 0;
	end = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (end >= (unsigned long)kcov_trace_size - 1)
		end = (unsigned long)kcov_trace_size - 1;
	start = *cursor;
	if (start > end)
		start = end;
	for (idx = start; idx < end; idx++) {
		unsigned long pc = __atomic_load_n(&kc->trace_buf[idx + 1],
						   __ATOMIC_RELAXED);
		unsigned int edge = pc_canon_to_edge(kcov_canon_pc(pc));

		if (__atomic_load_n(&kcov_shm->bucket_seen[edge],
				    __ATOMIC_RELAXED) == 0)
			n++;
	}
	*cursor = end;
	return n;
}

unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick)
{
	unsigned long count;
	unsigned long novel;

	if (kc == NULL || !kc->cmp_capable || kc->cmp_trace_buf == NULL)
		return 0;

	count = __atomic_load_n(&kc->cmp_trace_buf[0], __ATOMIC_RELAXED);
	if (count >= KCOV_CMP_RECORDS_MAX) {
		/* Kernel wanted to record more comparisons than the cmp
		 * buffer holds; the tail was dropped.  Mirrors the PC-side
		 * trace_truncated counter. */
		__atomic_fetch_add(&kcov_shm->cmp_records.cmp_trace_truncated, 1,
			__ATOMIC_RELAXED);
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->per_syscall_diag[nr][do32].cmp_trace_truncated,
				1, __ATOMIC_RELAXED);
		count = KCOV_CMP_RECORDS_MAX;
	}

	/* Reset the recover-on-EBADF attempt counter only when this call
	 * actually harvested cmp records.  Mirrors the PC-side reset in
	 * kcov_collect() -- a successful KCOV_ENABLE on cmp_fd that lands
	 * on a syscall harvesting zero records is a no-op recovery, and
	 * forgiving the attempt would let a close-race chain re-burn the
	 * budget every iteration without ever making progress. */
	if (count > 0 && kc->cmp_recovery_attempts != 0)
		kc->cmp_recovery_attempts = 0;

	if (count == 0)
		return 0;

	cmp_hints_collect(kc->cmp_trace_buf, nr, do32);
	novel = bandit_cmp_observe(kc->cmp_trace_buf, nr, do32,
				   is_explorer, strategy_at_pick);

	__atomic_fetch_add(&kcov_shm->cmp_records.cmp_records_collected, count,
		__ATOMIC_RELAXED);

	return novel;
}

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr)
{
	unsigned long edges, calls, edges_total, calls_total, gap;
	unsigned int pct;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	/* Fold warm-loaded priors into the per-syscall view so the
	 * saturation cap fires on cross-session evidence the cold-skip
	 * path otherwise has to re-accumulate from scratch every run.
	 * The _prior arrays are frozen at warm-start (see kcov.h) so a
	 * plain read is sufficient -- no atomic needed. */
	edges = per_syscall_edges_total(nr);
	calls = per_syscall_calls_total(nr);
	edges_total = edges + per_syscall_edges_prior_total(nr);
	calls_total = calls + per_syscall_calls_prior_total(nr);

	/* Saturation cap: confirmed dead-weight slot, short-circuit the
	 * graduated path below.  See KCOV_SAT_CAP_CALLS / RATIO comment
	 * in include/kcov.h for the two-branch productivity test. */
	if (edges_total == 0) {
		if (calls_total >= KCOV_SAT_CAP_CALLS)
			return KCOV_SAT_CAP_SKIP_PCT;
	} else if (calls_total / edges_total >= KCOV_SAT_CAP_RATIO) {
		return KCOV_SAT_CAP_SKIP_PCT;
	}

	if (edges == 0) {
		/* Never produced an edge in THIS run.  Until this syscall has
		 * had KCOV_COLD_THRESHOLD attempts of its own, leave it alone —
		 * total_calls grows from every other syscall too, so basing
		 * the cutoff on total_calls would prematurely retire any
		 * syscall that the dispatch loop happens to under-pick.
		 * Once it has clearly had a fair shot, skip aggressively. */
		gap = calls;
	} else {
		unsigned long total, last;

		total = __atomic_load_n(&kcov_shm->coverage.total_calls,
			__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->per_syscall.last_edge_at[nr],
			__ATOMIC_RELAXED);
		if (total <= last)
			return 0;
		gap = total - last;
	}

	if (gap <= KCOV_COLD_THRESHOLD)
		return 0;

	/* Graduated skip: the further past the threshold, the more we skip.
	 * Formula is a 50% base plus 10 percentage points per additional
	 * KCOV_COLD_THRESHOLD-sized step, capped at 90% so even the deadest
	 * syscall still gets called once every ~10 attempts in case kernel
	 * state changes underneath us. */
	pct = 50 + (unsigned int)((gap / KCOV_COLD_THRESHOLD) * 10);
	if (pct > 90)
		pct = 90;
	return pct;
}

bool kcov_syscall_is_cold(unsigned int nr)
{
	return kcov_syscall_cold_skip_pct(nr) > 0;
}
