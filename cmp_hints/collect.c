/*
 * KCOV comparison-trace collection.
 *
 * cmp_hints_collect() walks a CMP-mode trace buffer, extracts every
 * (cmp_ip, value, size) tuple worth remembering, and folds them into
 * the per-syscall pool via the batched dedup+flush path in
 * cmp_hints/pool.c.  The scan also drives the greedy RedQueen
 * attribution stash (pending re-exec buffer), the field-scoped
 * per-field attribution walker, and every per-record diagnostic
 * counter the reporters consume.
 *
 * The two peer helpers in this file -- cmp_hint_apply_transform()
 * and cmp_hints_stash_consumed() -- sit alongside the collector even
 * though the consumer picker calls them; both are the "how do we
 * shape and remember a served value" glue and stay in the same
 * translation unit as the collector that owns the batch discipline
 * they mirror.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"
#include "kcov.h"
#include "params.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "stats_ring.h"
#include "strategy.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* From uapi/linux/kcov.h.  KCOV_CMP_SIZE(n) packs the operand-width
 * index n in {0,1,2,3} into bits 1..2 of the type word; the actual
 * operand width in bytes is (1U << n). */
#define KCOV_CMP_CONST		(1U << 0)
#define KCOV_CMP_SIZE_SHIFT	1
#define KCOV_CMP_SIZE_MASK	3U

/* Words per comparison record in the trace buffer. */
#define WORDS_PER_CMP 4

/*
 * Read ts->tv_sec / ts->tv_nsec under a sigsetjmp recovery point and
 * report which (if either) matches @arg2.
 *
 * The caller has already proved @ts readable via range_readable_user()
 * -- but that gate consults cached VMA state (tracked shared regions
 * + heap snapshots), and a sibling raw munmap/mremap that bypasses
 * untrack_shared_region() can stale the cache between the gate and
 * this read.  The sigsetjmp slot lets child_fault_handler longjmp
 * back here when a SIGSEGV/SIGBUS fires inside the read window,
 * degrading the fault to a counted skip instead of killing the whole
 * child mid-CMP-harvest.
 *
 * Lives in its own function (not inlined into cmp_hints_collect)
 * because sigsetjmp forces -Wclobbered to flag every local of the
 * containing function -- cmp_hints_collect has many.  Marked
 * noinline so the compiler can't undo the isolation.
 *
 * Returns true on a successful read (*@out_kind set, possibly to
 * REEXEC_FIELD_NONE if neither field matched).  Returns false on a
 * recovered fault -- caller should bump the shared skip counter and
 * move to the next field.
 */
/*
 * Non-const relational shadow classifier.
 *
 * Per-record readout of a would-be relational-attribution lane sitting
 * next to today's !KCOV_CMP_CONST drop-site.  Runs BEFORE the drop and
 * leaves the live path (pool, bloom, reexec_pending, credit) byte-for-
 * byte unchanged; the returned counts only feed the flush-at-exit
 * accumulators in cmp_hints_collect() and the kcov_shm shadow
 * counters they in turn drain into.
 *
 * Gated by rec_num_args > 0 at the caller (dispatch-time snapshot
 * available); a zero-arg call returns the zero-init struct which
 * bumps nothing.  The population meaning of each field:
 *
 *   measured        -- non-const record where the shadow evaluated;
 *                      addressable denominator for the ratios below.
 *   arg1_unique     -- exactly one snapshot slot equals arg1.
 *   arg2_unique     -- exactly one snapshot slot equals arg2.
 *   both_match      -- at least one slot on each side (ambiguous).
 *   would_attribute -- clean case: one side uniquely ours, the other
 *                      not ours at all; a relational lane could act
 *                      on this record without ambiguity.
 */
struct cmp_nonconst_shadow_result {
	bool measured;
	bool arg1_unique;
	bool arg2_unique;
	bool both_match;
	bool would_attribute;
};

static struct cmp_nonconst_shadow_result
cmp_nonconst_shadow_classify(unsigned int rec_num_args,
			     const unsigned long *rec_args,
			     unsigned long arg1, unsigned long arg2)
{
	struct cmp_nonconst_shadow_result r = { 0 };
	unsigned int k;
	unsigned int n1 = 0;
	unsigned int n2 = 0;

	if (rec_num_args == 0)
		return r;

	r.measured = true;
	for (k = 0; k < rec_num_args; k++) {
		if (rec_args[k] == arg1)
			n1++;
		if (rec_args[k] == arg2)
			n2++;
	}
	r.arg1_unique     = (n1 == 1);
	r.arg2_unique     = (n2 == 1);
	r.both_match      = (n1 >= 1 && n2 >= 1);
	r.would_attribute = (n1 == 1 && n2 == 0) || (n2 == 1 && n1 == 0);

	return r;
}

static __attribute__((noinline)) bool
cmp_field_match_timespec(const struct timespec *ts, unsigned long arg2,
			 enum reexec_field_kind *out_kind)
{
	*out_kind = REEXEC_FIELD_NONE;

	if (sigsetjmp(cmp_field_recover, 1) != 0) {
		/*
		 * Clear the flag FIRST so any subsequent fault in this
		 * child takes the normal diagnostic + _exit path rather
		 * than silently recovering here.
		 */
		cmp_field_read_active = 0;
		return false;
	}

	cmp_field_read_active = 1;
	if ((unsigned long)ts->tv_sec == arg2)
		*out_kind = REEXEC_FIELD_TIMESPEC_SEC;
	else if ((unsigned long)ts->tv_nsec == arg2)
		*out_kind = REEXEC_FIELD_TIMESPEC_NSEC;
	cmp_field_read_active = 0;
	return true;
}

void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr, bool do32)
{
	unsigned long count;
	unsigned long i;
	unsigned long skipped = 0;
	unsigned long inserted = 0;
	/*
	 * Per-record diagnostic reject counters: accumulate locally in
	 * the hot loop and flush once at function exit (mirroring the
	 * skipped/inserted pattern below) so the per-record fast path
	 * stays free of shared atomic traffic.  All four are advisory
	 * stat counters consumed only by stats.c reporters; nothing in
	 * the collect/save path gates on them, so the per-record-versus-
	 * batched accumulation is observably identical at the consumer.
	 */
	unsigned long reject_nonconst = 0;
	unsigned long reject_uninteresting = 0;
	unsigned long reject_sentinel = 0;
	unsigned long boring_arm_b_drops = 0;
	/*
	 * Shadow measurement of the non-const relational drop-site.
	 * Per-record accumulators flushed once at function exit (same
	 * pattern as the reject_* counters above) so the hot loop stays
	 * free of shared atomic traffic.  Nothing in the collect / save /
	 * re-exec paths reads these -- they exist only to size the
	 * headroom of a potential future relational-attribution lane.
	 * See the matching struct-tail comment in include/kcov.h.
	 */
	unsigned long nonconst_arg1_unique = 0;
	unsigned long nonconst_arg2_unique = 0;
	unsigned long nonconst_both_match = 0;
	unsigned long nonconst_would_attribute = 0;
	unsigned long nonconst_measured = 0;
	/*
	 * Shadow measurement at the width-masked RedQueen pin site.  Live
	 * consumer overwrites the whole 64-bit slot with arg1; a high-bit-
	 * preserving splice would keep bits outside width_mask.  Size how
	 * often the splice would differ from today's overwrite.  Same per-
	 * record accumulator + function-exit flush pattern as above;
	 * nothing on the live path reads these.  See the matching struct-
	 * tail comment in include/kcov.h.
	 */
	unsigned long width_pin_total = 0;
	unsigned long width_pin_would_differ = 0;
	struct cmp_hint_pool *pool;
	struct cmp_hints_bloom *bloom = NULL;
	struct childdata *child;
	struct cmp_hints_pending batch[CMP_HINTS_PENDING_BATCH];
	unsigned int n_batch = 0;
	/*
	 * Per-call CMP RedQueen attribution scan state.  Snapshot the
	 * dispatching syscall's rec->aN values + num_args once on entry so
	 * the per-record inner loop avoids a per-record reload (and a
	 * per-record entry->num_args branch).  attribute_enabled folds the
	 * gates the inner loop would otherwise re-check on every record:
	 * the child must be runnable, opted into the re-exec, and NOT mid-
	 * re-exec (recursion guard; otherwise we'd self-reinforce a runaway
	 * loop).  num_args == 0 (parent-context or
	 * pre-dispatch rec) also gates off; an attribution scan over zero
	 * meaningful slots is pure cost.
	 */
	bool attribute_enabled = false;
	unsigned long rec_args[6] = { 0 };
	unsigned int rec_num_args = 0;
	/*
	 * Field-attribution scan state.  Independent gate from
	 * attribute_enabled above: field attribution is a recording-side
	 * accumulator that does NOT require the RedQueen cohort, only a
	 * live dispatched syscall (entry != NULL, dispatch_args_valid).
	 * srec_field / entry_field stay NULL when the call is parent-
	 * context or pre-dispatch and the per-record helper short-circuits.
	 */
	struct syscallrecord *srec_field = NULL;
	struct syscallentry *entry_field = NULL;
	/*
	 * Per-slot argtype snapshot + a cheap gate for the field-scoped
	 * RedQueen scan over the field-scoped pool.  field_scan_enabled
	 * stays false for the overwhelming majority of syscalls (no
	 * field-eligible arg), so the per-record field scan is skipped
	 * outright and the scalar fast-path pays nothing beyond one bool
	 * test.
	 */
	enum argtype rec_argtype[6] = { 0 };
	bool field_scan_enabled = false;

	if (cmp_hints_shm == NULL || trace_buf == NULL)
		return;

	if (nr >= MAX_NR_SYSCALL)
		return;

	/*
	 * Per-syscall CMP-collection strip: bypass the bloom + pool path
	 * entirely for syscalls whose comparisons fire on kernel-internal
	 * state (task_struct / cred / ucounts / aio-table) that no
	 * syscall arg can drive.  Count the trace-buffer record total at
	 * the same per-record granularity used by cmp_hints_bloom_skipped
	 * so the two skip-paths are directly comparable in stats output.
	 */
	if (cmp_hints_strip[do32 ? 1 : 0][nr]) {
		if (kcov_shm != NULL) {
			unsigned long n = __atomic_load_n(&trace_buf[0],
							  __ATOMIC_RELAXED);

			if (n > KCOV_CMP_RECORDS_MAX)
				n = KCOV_CMP_RECORDS_MAX;
			if (n != 0)
				__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_strip_skipped,
						   n, __ATOMIC_RELAXED);
		}
		return;
	}

	pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];

	/* Mirror cmp_hints_try_get_ex()'s latched-corrupted skip: once
	 * pool->corrupted is set, every bloom-miss this walk would stage
	 * is dropped by pool_add_locked()/cmp_hints_flush_pending() with
	 * zero state mutation, so the per-record loop and the per-batch
	 * lock-acquire path below are pure overhead on the hot cmp path.
	 * Steady-state cost on a latched pool is one relaxed load --
	 * cmp_hints_pool_corrupted()'s fast path returns on the latch
	 * read before touching observed_count. */
	{
		unsigned int pool_count =
			__atomic_load_n(&pool->count, __ATOMIC_RELAXED);
		if (cmp_hints_pool_corrupted(pool, pool_count))
			return;
	}

	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);

	/* Buffer is the per-child KCOV_TRACE_CMP mmap, sized off
	 * KCOV_CMP_BUFFER_SIZE u64 entries.  Truncation accounting lives
	 * in kcov_collect_cmp(); here we just clamp to be defensive. */
	if (count > KCOV_CMP_RECORDS_MAX)
		count = KCOV_CMP_RECORDS_MAX;

	if (count == 0)
		return;

	/* The bloom is per-child storage in struct childdata.  Parent-context
	 * callers (this_child() == NULL) bypass the bloom entirely and fall
	 * back to the original pool-only path; cmp_hints_collect() is only
	 * meant to be driven from kcov_collect_cmp() in the child, so the
	 * fallback is just belt-and-braces. */
	child = this_child();
	if (child != NULL) {
		bloom = &child->cmp_hints_seen[do32 ? 1 : 0];
		bloom->records += count;
		if (bloom->records >= CMP_HINTS_BLOOM_RESET) {
			memset(bloom->bits, 0, sizeof(bloom->bits));
			bloom->records = 0;
		}

		/*
		 * Pre-stage the RedQueen attribution scan inputs.  Snapshot
		 * num_args + the per-rec dispatch_args[] (populated in
		 * __do_syscall() from the dispatch-time locals a1..a6, after
		 * the second blanket_address_scrub and before kernel entry)
		 * into a small stack-resident array so the per-record inner
		 * loop avoids re-reading rec each iteration -- rec lives at
		 * the cold tail of childdata and the hot CMP loop should not
		 * drag those lines into L1 thousands of times.  Reading from
		 * dispatch_args[] rather than live rec->aN means a sibling
		 * stomp between dispatch and this scan can't redirect us at
		 * a post-call slot value the kernel never compared against;
		 * dispatch_args_valid gates the read so a rec that never
		 * went through __do_syscall() (zero-init / parent context)
		 * stays unattributed instead of feeding the scan a zeroed
		 * arg vector.  Drop the gate entirely on the in_reexec path
		 * so the re-exec's own CMP harvest cannot stage a second
		 * tier of attributions -- the per-call buffer stays drained
		 * around the dispatch and is read back by the dispatch_step
		 * tail.
		 */
		if (child->redqueen_enabled && !child->in_reexec &&
		    child->reexec_pending_count < MAX_REEXEC_PENDING) {
			struct syscallrecord *rec = &child->syscall;
			struct syscallentry *entry = rec->entry;

			if (entry != NULL && entry->num_args > 0 &&
			    rec->dispatch_args_valid) {
				unsigned int n = entry->num_args;
				unsigned int k;

				if (n > 6)
					n = 6;
				rec_num_args = n;
				rec_args[0] = rec->dispatch_args[0];
				rec_args[1] = rec->dispatch_args[1];
				rec_args[2] = rec->dispatch_args[2];
				rec_args[3] = rec->dispatch_args[3];
				rec_args[4] = rec->dispatch_args[4];
				rec_args[5] = rec->dispatch_args[5];
				/* Snapshot the argtypes so the per-record field
				 * scan can tell which slots carry a pointer to a
				 * field-eligible struct without re-reading entry;
				 * flag the cheap gate so non-timespec syscalls
				 * skip the scan entirely. */
				for (k = 0; k < n; k++) {
					rec_argtype[k] = entry->argtype[k];
					if (entry->argtype[k] == ARG_TIMESPEC)
						field_scan_enabled = true;
				}
				attribute_enabled = true;
				if (kcov_shm != NULL)
					__atomic_fetch_add(
						&kcov_shm->cmp_attribution_calls_eligible,
						1UL, __ATOMIC_RELAXED);
			} else if (kcov_shm != NULL &&
				   entry != NULL && entry->num_args > 0 &&
				   !rec->dispatch_args_valid) {
				/* Redqueen cohort gate cleared and the
				 * syscall has args worth scanning, but
				 * the dispatch_args[] snapshot feed is
				 * missing -- attribution correctly skips
				 * the call, surface the rate so the
				 * snapshot-feed health is not silently
				 * folded into the eligible cohort. */
				__atomic_fetch_add(
					&kcov_shm->cmp_attribution_snapshot_unavailable,
					1UL, __ATOMIC_RELAXED);
			}
		}

		/* Field-attribution gate is decoupled from the redqueen
		 * cohort: any dispatched syscall with a valid arg snapshot
		 * is a candidate for the recording-side field scan.  Held
		 * separately from rec_args[] / rec_num_args above so the
		 * scalar fast-path keeps its existing shape (and stays cheap
		 * for non-struct syscalls).  in_reexec calls are excluded
		 * for the same reason the scalar gate excludes them -- the
		 * re-exec's CMP harvest would self-reinforce records into
		 * the same field pool a parent dispatch just populated. */
		if (!child->in_reexec) {
			struct syscallrecord *rec = &child->syscall;
			struct syscallentry *entry = rec->entry;

			if (entry != NULL && entry->num_args > 0 &&
			    rec->dispatch_args_valid) {
				srec_field = rec;
				entry_field = entry;
			}
		}
	}

	/* Two-phase split: the per-child bloom is lock-free child-private
	 * storage, so the filter pass runs entirely outside pool->lock.
	 * Only confirmed bloom misses get staged into the batch and folded
	 * into the pool under a single (per-batch) lock acquisition --
	 * which is the point of the bloom in the first place: bloom-hit
	 * records skip the pool lock outright instead of serialising on it
	 * just to discover they had nothing new to add. */
	for (i = 0; i < count; i++) {
		unsigned long *rec = &trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long type = rec[0];
		unsigned long arg1 = rec[1];
		unsigned long arg2 = rec[2];
		/* Canonicalise the kernel comparison-instruction address
		 * against the runtime KASLR base before any downstream
		 * consumer (bloom, pool insert, RedQueen pending stamp,
		 * persisted file) sees it.  Single point of canonicalisation
		 * for cmp_ip in this file -- the bloom hash, the pool dedup
		 * key, and the on-disk record all index by the canonical
		 * value, so a KASLR reroll between save and warm-load no
		 * longer aliases every learned constant to a fresh
		 * (cmp_ip, value, size) tuple.  When kcov_kaslr_base
		 * stayed zero (kallsyms unreadable), kcov_canon_cmp_ip is
		 * the identity transform and this matches the prior
		 * raw-PC behaviour for that one run; the load path's
		 * canonical-vs-raw mismatch guard catches any cross-run
		 * mode change. */
		unsigned long ip   = kcov_canon_cmp_ip(rec[3]);
		unsigned int size  = 1U << ((type >> KCOV_CMP_SIZE_SHIFT)
					    & KCOV_CMP_SIZE_MASK);

		/* We only care about comparisons where one side is a
		 * compile-time constant — those reveal what the kernel
		 * actually checks for.  Non-CONST records are dropped
		 * entirely; both operands are runtime values and feeding
		 * them back would just recycle the fuzzer's own inputs. */
		if (!(type & KCOV_CMP_CONST)) {
			struct cmp_nonconst_shadow_result cls;

			reject_nonconst++;
			/*
			 * Shadow-measure the relational lane BEFORE the
			 * drop.  Live path is unchanged -- no pool insert,
			 * no bloom stamp, no reexec_pending mutation; we
			 * only tally what a future relational-attribution
			 * lane would see if it existed.  Gate strictly on
			 * rec_num_args > 0 (the dispatch-time snapshot is
			 * present); deliberately NOT on attribute_enabled
			 * -- that flips false under reexec_pending back-
			 * pressure and would hide the un-throttled headroom
			 * this readout is meant to expose.
			 */
			cls = cmp_nonconst_shadow_classify(rec_num_args,
							   rec_args,
							   arg1, arg2);
			if (cls.measured)
				nonconst_measured++;
			if (cls.arg1_unique)
				nonconst_arg1_unique++;
			if (cls.arg2_unique)
				nonconst_arg2_unique++;
			if (cls.both_match)
				nonconst_both_match++;
			if (cls.would_attribute)
				nonconst_would_attribute++;
			continue;
		}

		/*
		 * KCOV's __sanitizer_cov_trace_const_cmpN clang/gcc helpers
		 * always place the compile-time constant in arg1; arg2 holds
		 * the runtime (variable) operand the kernel compared it
		 * against.  Adding arg2 to the pool would feed trinity's own
		 * generated syscall values back as "hints", evicting genuine
		 * kernel constants from the now-16-slot pool, so only arg1
		 * is ingested.
		 *
		 * Filter out uninteresting constants inline so the compiler
		 * can fold the per-record check to a couple of branches:
		 * skip the low constants caught by the boring-mask going to
		 * zero and the all-ones sentinel.
		 *
		 * A/B-comparison on the drop band: Arm A keeps the
		 * historical ~3UL mask (drop 0/1/2/3); Arm B widens to ~7UL
		 * (also drop 4/5/6/7).  The widened band straddles common
		 * meaningful bounds (struct sizes, low flag bits) so the
		 * per-arm pool-novelty + downstream new-edge deltas show
		 * whether the dropped values were carrying signal.  Parent-
		 * context callers (child == NULL) fall through with the
		 * historical mask so the off-child path is unchanged.  The
		 * divergence counter (cmp_hints_boring_arm_b_drops) bumps
		 * once per record where arg1 is in [4,7] -- every record the
		 * two arms would decide differently on, regardless of which
		 * arm this child is on -- giving the raw rate at which the
		 * wider filter actually deviates from the narrower one.
		 */
		{
			unsigned long boring_mask =
				(child != NULL && child->boring_filter_arm_b) ?
					~7UL : ~3UL;

			if (arg1 >= 4 && arg1 <= 7)
				boring_arm_b_drops++;

			if ((arg1 & boring_mask) == 0) {
				reject_uninteresting++;
				continue;
			}
		}
		if (arg1 == (unsigned long) -1) {
			reject_sentinel++;
			continue;
		}

		/*
		 * RedQueen attribution scan against the dispatching syscall's
		 * dispatch-time arg snapshot (rec->dispatch_args[] staged into
		 * rec_args[] at the entry to this function).  Runs BEFORE the
		 * bloom-check + pool-insert path so a bloom-suppressed record
		 * still gets attribution: the constant being in the pool
		 * already from a prior call carries no signal about which slot
		 * THIS call's kernel comparison fired on.  Attribution is
		 * orthogonal to pool novelty -- the consumer side gates the
		 * actual re-exec dispatch on `new_cmp > 0` from the parent
		 * call separately.
		 *
		 * Two-pass match.  PRIMARY: exact full-width match
		 * (dispatch_args[k] == arg2).  Catches the dominant case
		 * where the kernel sees the argument's full 64-bit value
		 * (cmd codes, length args, flag bitmasks, struct sizes).
		 * Low-noise -- a 64-bit equality across six slots collides
		 * only on genuinely identical args -- so this is the path
		 * the consumer's lift accounting trusts.
		 *
		 * FALLBACK (only on a primary miss, only when the KCOV
		 * comparison size is narrower than a long): width-masked
		 * rescan masking both operands to the low `size`*8 bits.
		 * Catches the kernel comparing a `u8`/`u16`/`u32` derived
		 * from a long-sized arg slot when the high bits differ
		 * (cast/truncation/field extraction), which the exact pass
		 * would silently drop.  Accepted ONLY when EXACTLY ONE slot
		 * matches under the mask -- the masked predicate's higher
		 * hit rate makes first-match-wins unreliable, so any masked
		 * ambiguity is dropped rather than guessed.  Counted under
		 * the separate reexec_attribution_width_match counter so
		 * the exact-path numerator stays clean.
		 *
		 * Primary-path cardinality > 1 (the same constant appears in
		 * multiple slots): first-match-wins.  Slot order 1..6 biases
		 * toward lower slots, which tend to be the cmd-like /
		 * dispatching ones.  Bump reexec_attribution_ambiguous once
		 * per matched record where >1 slot matched so the rate is
		 * observable; if it climbs >10% the escalation
		 * options (skip-ambiguous or fan-out) become live.
		 */
		if (attribute_enabled &&
		    child->reexec_pending_count < MAX_REEXEC_PENDING) {
			unsigned int pending_before =
				child->reexec_pending_count;
			unsigned int first_match = 0;
			unsigned int match_count = 0;
			unsigned int k;

			for (k = 0; k < rec_num_args; k++) {
				if (rec_args[k] == arg2) {
					if (match_count == 0)
						first_match = k + 1;
					match_count++;
				}
			}

			if (match_count > 0) {
				struct reexec_pending *p =
					&child->reexec_pending[child->reexec_pending_count];

				p->cmp_ip = ip;
				p->value = arg1;
				p->size = size;
				p->slot = first_match;
				/* Scalar slot pin: the consumer overwrites
				 * rec->a<slot> outright.  Set explicitly --
				 * reexec_pending[] is reused scratch, so a stale
				 * field_kind from a prior call must not survive
				 * into a scalar stamp. */
				p->field_kind = REEXEC_FIELD_NONE;
				child->reexec_pending_count++;

				if (kcov_shm != NULL) {
					unsigned int op_type =
						(unsigned int)child->op_type;

					__atomic_fetch_add(
						&kcov_shm->reexec_flat.reexec_attribution_found,
						1UL, __ATOMIC_RELAXED);
					/* per-nr HEAD of the attribution
					 * funnel.  Sibling of the existing
					 * reexec_attempts_by_syscall and
					 * reexec_ambiguous_by_syscall: nr is
					 * gated to MAX_NR_SYSCALL at
					 * cmp_hints_collect() entry. */
					__atomic_fetch_add(
						&kcov_shm->reexec_attribution_found_by_syscall[nr],
						1UL, __ATOMIC_RELAXED);
					/* per-childop partition of the same
					 * HEAD counter, bounded by
					 * KCOV_CHILDOP_NR_MAX (the build-
					 * time sized container).  Lets a
					 * childop-driven syscall be told
					 * apart from the same nr dispatched
					 * from the default OP_SYSCALL flow. */
					if (op_type < KCOV_CHILDOP_NR_MAX)
						__atomic_fetch_add(
							&kcov_shm->reexec_attribution_found_by_childop[op_type],
							1UL, __ATOMIC_RELAXED);
					/* which arg slot
					 * (a1..a6) won the first-match-wins
					 * scan.  first_match is 1-based;
					 * convert to 0-based index and gate
					 * on the histogram bound -- a
					 * corrupted pending entry that
					 * survived the slot bound check at
					 * the consumer site is harmlessly
					 * dropped here. */
					if (first_match >= 1 &&
					    first_match <= CMP_REDQUEEN_SLOT_HIST_NR)
						__atomic_fetch_add(
							&kcov_shm->reexec_attribution_slot_hist[first_match - 1],
							1UL, __ATOMIC_RELAXED);
					if (match_count > 1) {
						__atomic_fetch_add(
							&kcov_shm->reexec_flat.reexec_attribution_ambiguous,
							1UL, __ATOMIC_RELAXED);
						/* per-nr
						 * partition of the ambiguity
						 * counter.  nr is gated to
						 * MAX_NR_SYSCALL at
						 * cmp_hints_collect() entry,
						 * matching the existing
						 * per_syscall_cmp_inserts[nr]
						 * bump below. */
						__atomic_fetch_add(
							&kcov_shm->reexec_ambiguous_by_syscall[nr],
							1UL, __ATOMIC_RELAXED);
						/* per-childop partition of
						 * the ambiguity counter,
						 * mirroring the per-syscall
						 * sibling above. */
						if (op_type < KCOV_CHILDOP_NR_MAX)
							__atomic_fetch_add(
								&kcov_shm->reexec_attribution_ambiguous_by_childop[op_type],
								1UL, __ATOMIC_RELAXED);
					}
				}

				/* Disable further per-record scans this call
				 * once the buffer fills; the per-call cap at
				 * the consumer side will drain only a subset
				 * anyway and the extra scan work is wasted.
				 *
				 * bump reexec_pending_dropped
				 * exactly once per parent call where the
				 * buffer fills, so the operator can read "how
				 * often did the attribution census get
				 * truncated".  Subsequent records on this same
				 * call hit the attribute_enabled-false guard
				 * above and skip silently; the per-record
				 * count of dropped tuples is intentionally not
				 * tracked (the relevant signal is "did we lose
				 * any", not "how many"). */
				if (child->reexec_pending_count >=
				    MAX_REEXEC_PENDING) {
					attribute_enabled = false;
					if (kcov_shm != NULL) {
						__atomic_fetch_add(
							&kcov_shm->reexec_pending_dropped,
							1UL, __ATOMIC_RELAXED);
						/* per-nr partition of the
						 * pending-overflow counter:
						 * identifies the hot
						 * attributing syscalls whose
						 * attribution census the
						 * MAX_REEXEC_PENDING cap is
						 * truncating. */
						__atomic_fetch_add(
							&kcov_shm->reexec_attribution_dropped_pending_by_syscall[nr],
							1UL, __ATOMIC_RELAXED);
					}
				}
			} else if (size > 0 && size < sizeof(unsigned long)) {
				/* Width-aware fallback: exact-pass missed and
				 * the kernel comparison was narrower than a
				 * long.  arg2 carries the post-narrowing value
				 * (KCOV publishes the compared u8/u16/u32 with
				 * the high bits zero); the matching arg slot
				 * still holds the full long.  Mask both to the
				 * low `size`*8 bits and rescan.  Accept ONLY a
				 * unique match -- the masked predicate's
				 * higher hit rate makes first-match-wins
				 * unreliable, so any masked ambiguity is
				 * dropped rather than guessed.  size <
				 * sizeof(unsigned long) so the shift is always
				 * in range; size > 0 belt-and-braces against
				 * a corrupted KCOV header. */
				unsigned long width_mask =
					(1UL << (size * 8U)) - 1UL;
				unsigned long arg2_masked = arg2 & width_mask;
				unsigned int width_first = 0;
				unsigned int width_count = 0;

				for (k = 0; k < rec_num_args; k++) {
					if ((rec_args[k] & width_mask) == arg2_masked) {
						if (width_count == 0)
							width_first = k + 1;
						width_count++;
						if (width_count > 1)
							break;
					}
				}

				if (width_count == 1) {
					struct reexec_pending *p =
						&child->reexec_pending[child->reexec_pending_count];
					/* Shadow measurement (see width_pin_*
					 * declarations at function top): compare
					 * the matched slot's full 64-bit value
					 * against arg1 outside width_mask.  A non-
					 * zero XOR there means a high-bit-
					 * preserving splice would produce a
					 * different pin than today's whole-slot
					 * overwrite.  width_first is 1-based; the
					 * outer loop's size > 0 && size <
					 * sizeof(unsigned long) bound guarantees
					 * ~width_mask is well-defined and non-
					 * zero.  Live pin below is unchanged. */
					unsigned long orig =
						rec_args[width_first - 1];

					width_pin_total++;
					if (((orig ^ arg1) & ~width_mask) != 0)
						width_pin_would_differ++;

					p->cmp_ip = ip;
					p->value = arg1;
					p->size = size;
					p->slot = width_first;
					/* Scalar slot pin (see the exact-match
					 * stamp above for why field_kind is set
					 * explicitly on this reused scratch). */
					p->field_kind = REEXEC_FIELD_NONE;
					child->reexec_pending_count++;

					if (kcov_shm != NULL)
						__atomic_fetch_add(
							&kcov_shm->reexec_flat.reexec_attribution_width_match,
							1UL, __ATOMIC_RELAXED);

					/* Same buffer-fill backstop as the
					 * exact path: once reexec_pending[]
					 * is full, disable further per-record
					 * scans for the remainder of this
					 * parent call and bump
					 * reexec_pending_dropped + the per-nr
					 * partition once.  Subsequent records
					 * skip silently via the
					 * attribute_enabled guard. */
					if (child->reexec_pending_count >=
					    MAX_REEXEC_PENDING) {
						attribute_enabled = false;
						if (kcov_shm != NULL) {
							__atomic_fetch_add(
								&kcov_shm->reexec_pending_dropped,
								1UL, __ATOMIC_RELAXED);
							__atomic_fetch_add(
								&kcov_shm->reexec_attribution_dropped_pending_by_syscall[nr],
								1UL, __ATOMIC_RELAXED);
						}
					}
				}
			}

			/*
			 * Field-scoped RedQueen fallback over the field-scoped
			 * pool.  Runs only when the scalar exact + width passes
			 * added NO pending for this record (count unchanged) AND
			 * the dispatching syscall actually carries a field-eligible
			 * arg -- so the scalar fast-path stays untouched and
			 * non-timespec syscalls pay nothing past one bool test.
			 *
			 * The kernel compares a struct field (here a timespec's
			 * tv_sec / tv_nsec) but the scalar scan only ever sees
			 * the pointer in rec->a<slot>, never the field value, so
			 * a field comparison is invisible to it.  Read the
			 * candidate fields out of the dispatch-time buffer and
			 * match the runtime operand (arg2) against them; on a
			 * hit stamp a field-kind pending so the consumer pins
			 * just that one field on re-exec rather than spraying
			 * the constant across the whole arg.  Exact full-width
			 * match only in this first patch (fixed-size structs);
			 * width-masked field matching and variable-length
			 * buffers land in the follow-up.
			 */
			if (field_scan_enabled &&
			    child->reexec_pending_count == pending_before &&
			    child->reexec_pending_count < MAX_REEXEC_PENDING) {
				unsigned int fk;

				for (fk = 0; fk < rec_num_args; fk++) {
					const struct timespec *ts;
					enum reexec_field_kind kind =
						REEXEC_FIELD_NONE;
					struct reexec_pending *p;

					if (rec_argtype[fk] != ARG_TIMESPEC)
						continue;
					/* NULL "no timeout" arm or an
					 * implausibly small value -- nothing
					 * safe to dereference. */
					if (rec_args[fk] < 4096)
						continue;

					ts = (const struct timespec *)
						rec_args[fk];
					/*
					 * Shape (>= 4096) does not prove the
					 * saved pointer is still mapped: CMP
					 * harvest runs post-dispatch and the
					 * dispatched syscall (or a sibling)
					 * may have freed / munmapped the
					 * timespec the arg-gen path handed
					 * the kernel.  Gate the deref on the
					 * same cached-VMA readability check
					 * that protects every other post-
					 * dispatch pointer read in trinity;
					 * a stale pointer would otherwise
					 * SIGSEGV the whole child here.
					 */
					if (!range_readable_user(ts,
								 sizeof(*ts))) {
						if (kcov_shm != NULL)
							__atomic_fetch_add(
								&kcov_shm->cmp_field_timespec_skipped_bad_ptr,
								1UL, __ATOMIC_RELAXED);
						continue;
					}
					/*
					 * range_readable_user() proves the
					 * pointer from cached VMA state, but
					 * a sibling raw munmap/mremap that
					 * bypasses untrack_shared_region() can
					 * stale the cache between the gate and
					 * the loads below.  Wrap the two field
					 * reads in sigsetjmp/siglongjmp (in a
					 * helper so the recovery slot does not
					 * force every local in this function
					 * volatile under -Wclobbered) so the
					 * fault degrades to a counted skip
					 * instead of killing the child.
					 * Counter is shared with the cached-
					 * state miss above -- both are "shape-
					 * valid but not safe to deref" skips
					 * and include/kcov.h's counter doc
					 * already names both pathways.
					 */
					if (!cmp_field_match_timespec(ts, arg2,
								      &kind)) {
						if (kcov_shm != NULL)
							__atomic_fetch_add(
								&kcov_shm->cmp_field_timespec_skipped_bad_ptr,
								1UL, __ATOMIC_RELAXED);
						continue;
					}
					if (kind == REEXEC_FIELD_NONE)
						continue;

					p = &child->reexec_pending[
						child->reexec_pending_count];
					p->cmp_ip = ip;
					p->value = arg1;
					p->size = size;
					p->slot = fk + 1;
					p->field_kind = kind;
					child->reexec_pending_count++;

					if (kcov_shm != NULL) {
						/* Field attributions share the
						 * scalar attribution counters in
						 * this first patch -- they too
						 * produce a reexec_pending entry;
						 * a dedicated field counter lands
						 * with the field-scoped CMP pool
						 * follow-up. */
						__atomic_fetch_add(
							&kcov_shm->reexec_flat.reexec_attribution_found,
							1UL, __ATOMIC_RELAXED);
						__atomic_fetch_add(
							&kcov_shm->reexec_attribution_found_by_syscall[nr],
							1UL, __ATOMIC_RELAXED);
						if (fk < CMP_REDQUEEN_SLOT_HIST_NR)
							__atomic_fetch_add(
								&kcov_shm->reexec_attribution_slot_hist[fk],
								1UL, __ATOMIC_RELAXED);
					}

					/* One field pin per CMP record; the
					 * buffer-fill backstop mirrors the
					 * scalar paths exactly. */
					if (child->reexec_pending_count >=
					    MAX_REEXEC_PENDING) {
						attribute_enabled = false;
						if (kcov_shm != NULL) {
							__atomic_fetch_add(
								&kcov_shm->reexec_pending_dropped,
								1UL, __ATOMIC_RELAXED);
							__atomic_fetch_add(
								&kcov_shm->reexec_attribution_dropped_pending_by_syscall[nr],
								1UL, __ATOMIC_RELAXED);
						}
					}
					break;
				}
			}
		}

		/* Field-attribution recording.  Decoupled from the scalar
		 * attribute_enabled / reexec_pending plumbing above: the
		 * field scan walks cataloged INPUT struct args looking for
		 * a field whose runtime value matches arg2 and routes the
		 * matching const to a (nr, do32, arg, desc, field, size)
		 * pool.  Independent counters keep the scalar fast-path's
		 * lift accounting unpolluted -- field attribution is
		 * recording-side only in this MVP; the consumer side that
		 * re-injects from these pools is a follow-up.  Runs only
		 * when the syscall actually has a dispatched-arg snapshot
		 * to read, so non-struct / parent-context calls cost a
		 * single NULL-test per record. */
		if (srec_field != NULL && entry_field != NULL)
			cmp_hints_field_scan_record(srec_field, entry_field,
						    nr, do32, arg1, arg2,
						    size, ip);

		if (bloom != NULL &&
		    cmp_hints_bloom_check_and_set(bloom, ip, arg1, size)) {
			skipped++;
			continue;
		}

		batch[n_batch].ip = ip;
		batch[n_batch].val = arg1;
		batch[n_batch].size = size;
		n_batch++;

		if (n_batch == CMP_HINTS_PENDING_BATCH) {
			inserted += cmp_hints_flush_pending(pool, nr, do32,
							    batch, n_batch);
			n_batch = 0;
		}
	}

	inserted += cmp_hints_flush_pending(pool, nr, do32, batch, n_batch);

	if (skipped != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_bloom_skipped, skipped,
				   __ATOMIC_RELAXED);

	if (inserted != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr],
				   inserted, __ATOMIC_RELAXED);

	if (kcov_shm != NULL) {
		if (reject_nonconst != 0)
			__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_nonconst,
					   reject_nonconst, __ATOMIC_RELAXED);
		if (reject_uninteresting != 0)
			__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_uninteresting,
					   reject_uninteresting, __ATOMIC_RELAXED);
		if (reject_sentinel != 0)
			__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_sentinel,
					   reject_sentinel, __ATOMIC_RELAXED);
		if (boring_arm_b_drops != 0)
			__atomic_fetch_add(&kcov_shm->cmp_hints_boring_arm_b_drops,
					   boring_arm_b_drops, __ATOMIC_RELAXED);
		if (nonconst_arg1_unique != 0)
			__atomic_fetch_add(&kcov_shm->cmp_nonconst_arg1_unique,
					   nonconst_arg1_unique, __ATOMIC_RELAXED);
		if (nonconst_arg2_unique != 0)
			__atomic_fetch_add(&kcov_shm->cmp_nonconst_arg2_unique,
					   nonconst_arg2_unique, __ATOMIC_RELAXED);
		if (nonconst_both_match != 0)
			__atomic_fetch_add(&kcov_shm->cmp_nonconst_both_match,
					   nonconst_both_match, __ATOMIC_RELAXED);
		if (nonconst_would_attribute != 0)
			__atomic_fetch_add(&kcov_shm->cmp_nonconst_would_attribute,
					   nonconst_would_attribute, __ATOMIC_RELAXED);
		if (nonconst_measured != 0)
			__atomic_fetch_add(&kcov_shm->cmp_nonconst_measured,
					   nonconst_measured, __ATOMIC_RELAXED);
		if (width_pin_total != 0)
			__atomic_fetch_add(&kcov_shm->cmp_width_pin_total,
					   width_pin_total, __ATOMIC_RELAXED);
		if (width_pin_would_differ != 0)
			__atomic_fetch_add(&kcov_shm->cmp_width_pin_would_differ,
					   width_pin_would_differ, __ATOMIC_RELAXED);
	}
}

/*
 * Per-use-case output transform applied after the pool entry is picked.
 * Factored out of the (formerly inline) try_get body so each transform
 * lives next to its own documentation; the four use cases map onto
 * three distinct rotations (EXACT and FIELD share the bare-C path
 * because both back equality-gated slots that need the recorded
 * constant unmolested).
 *
 * The transform does not consult the pool entry's recorded comparison
 * width: this split deliberately keeps every existing pull byte-for-byte
 * equivalent so the wrapper can land alongside the new API without
 * shifting any of the four generate-args.c consumers.  The width-aware
 * fourth transform family from the spec ships in a follow-up once a
 * callsite opts into it.
 */
unsigned long cmp_hint_apply_transform(unsigned long c,
				       enum cmp_hint_use use,
				       unsigned long old)
{
	switch (use) {
	case CMP_HINT_EXACT:
	case CMP_HINT_FIELD:
		/* Bare C.  Equality-gated slots (cmd codes, enum
		 * selectors, version magics) need the constant
		 * unmolested -- the boundary +/-1 below would silently
		 * miss every exact-equality kernel check.  FIELD shares
		 * this path for the same reason: a field-scoped pull
		 * also targets equality-gated struct fields, so the
		 * recorded constant must reach the kernel unmodified. */
		return c;
	case CMP_HINT_BOUNDARY:
		/*
		 * Rotate uniformly among {C-1, C, C+1}.
		 * KCOV's CMP record exposes operand width and the constant
		 * but NOT the comparison operator (==, !=, <, <=, >, >=),
		 * so a substituted value of bare C only satisfies the
		 * equality cases.  Range checks ("if (len > MAX_LEN)")
		 * stay unsatisfied unless the kernel separately compares
		 * the exact boundary constant at another site.  The +/-1
		 * triple converts every range check whose limit matches
		 * a harvested C, at the cost of a 2/3 reduction in
		 * equality-match yield -- the equality slot (C unchanged)
		 * is retained in the rotation, so the worst case is a 3x
		 * slowdown on a purely equality-dominated callsite, while
		 * length-/cap-/extent-dominated syscalls (network length
		 * validation, BPF program-size caps, filesystem extents)
		 * get the boundary edges they were missing.
		 *
		 * Unsigned wrap is intentional and deliberately unclamped:
		 *   C == 0          ->  C-1 == ULONG_MAX
		 *   C == ULONG_MAX  ->  C+1 == 0
		 * Both wrapped values are themselves useful probes -- the
		 * underflow exercises length-cap / overflow validators, the
		 * overflow exercises empty-input / zero-length rejection
		 * paths -- so clamping would throw away the most useful
		 * boundary on the rare-but-real wrap case.
		 */
		switch (rnd_modulo_u32(3)) {
		case 0:
			c -= 1;
			break;
		case 2:
			c += 1;
			break;
		/* case 1 (and default): C unchanged */
		}
		return c;
	case CMP_HINT_FLAG_MASK:
		/* No caller mask to mix with -- degrade to bare C.  A
		 * mask-mode consumer that has not built a running mask
		 * yet (first flag-pull on a fresh slot) is effectively
		 * asking for the constant unmodified; that matches the
		 * EXACT path. */
		if (old == 0)
			return c;
		/* Mix C into the caller's running mask.  Three mix
		 * choices exercise different validators: OR adds a
		 * (possibly undocumented) bit; AND-NOT clears it
		 * (probes "this bit must NOT be set" combinations);
		 * XOR toggles (probes pair-of-flag mutual-exclusion
		 * constraints). */
		switch (rnd_modulo_u32(3)) {
		case 0:
			return old | c;
		case 1:
			return old & ~c;
		default:
			return old ^ c;
		}
	}
	/* enum exhaustively handled above; the unreachable return keeps
	 * the build flag-clean if a future use case is added without a
	 * matching arm here. */
	return c;
}

/*
 * SHADOW per-entry feedback scoring for the score-based feedback loop.
 *
 * Push one stash entry on the per-child cmp_hints_consumed_stash for
 * the just-pulled hint.  The dispatch_step tail drains the ring via
 * cmp_hints_feedback_credit_pc() / cmp_hints_feedback_credit_cmp_novelty()
 * and resets it; generate_syscall_args() resets it at call start too
 * so a parent dispatch that bailed before the credit drain does not
 * leak its stash into the next call.
 *
 * No-op outside child context (parent calls into cmp_hints_try_get_ex
 * during init self-checks etc. -- the SHADOW score is a per-child
 * concept).  No-op when in_reexec is set: the re-exec rebuilds args
 * with the slot pinned, so any hint pulled during the inner generate
 * call belongs to the re-exec, not the original parent call we are
 * about to credit, and crediting it here would double-attribute.
 */
void cmp_hints_stash_consumed(unsigned int nr, bool do32,
			      enum cmp_hint_pool_kind pool_kind,
			      enum cmp_hint_callsite callsite,
			      unsigned long cmp_ip, unsigned long value,
			      unsigned int size, enum cmp_hint_use use,
			      unsigned int arg_idx,
			      unsigned int field_idx,
			      const struct struct_desc *desc,
			      bool served_from_recent,
			      uint8_t age_bucket,
			      bool hyp_injected,
			      bool served_from_shared)
{
	struct childdata *child = this_child();
	struct cmp_hint_consumed_entry *e;

	if (child == NULL || child->in_reexec)
		return;

	if (child->cmp_hints_consumed_count >= CMP_HINT_CONSUMED_STASH_MAX) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hint_stash_overflow,
					   1UL, __ATOMIC_RELAXED);
		return;
	}

	e = &child->cmp_hints_consumed_stash[child->cmp_hints_consumed_count++];
	e->cmp_ip = cmp_ip;
	e->value = value;
	e->desc = desc;
	e->nr = (uint16_t)nr;
	e->field_idx = (uint16_t)field_idx;
	e->do32 = do32 ? 1 : 0;
	e->pool_kind = (uint8_t)pool_kind;
	/* Callsite the caller identified when it invoked cmp_hints_try_get*().
	 * Clamped to the CMP_HINT_CALLSITE_NR sentinel when the caller has
	 * no argtype-handler callsite (field-pool pulls from
	 * cmp_hints_field_try_get) so the credit-drain by-callsite bump
	 * silently skips those entries rather than misattributing them to
	 * bucket 0 (ARG_OP).  Defensive against a caller bug that passes an
	 * out-of-range value; the enum only grows via explicit tail appends. */
	e->callsite = ((unsigned int)callsite < (unsigned int)CMP_HINT_CALLSITE_NR)
		      ? (uint8_t)callsite
		      : (uint8_t)CMP_HINT_CALLSITE_NR;
	e->size = (uint8_t)size;
	e->transform = (uint8_t)use;
	e->arg_idx = (uint8_t)arg_idx;
	e->served_from_recent = served_from_recent ? 1 : 0;
	/* Defensive clamp -- a caller bug that passes an out-of-range bucket
	 * would otherwise blow past the kcov_shm histogram array width.
	 * The arms in cmp_hint_age_bucket() are bounded by construction;
	 * this is belt-and-braces against a future caller. */
	e->age_bucket = (age_bucket < CMP_HINT_AGE_BUCKETS) ?
			age_bucket : (uint8_t)(CMP_HINT_AGE_BUCKETS - 1U);
	e->hyp_injected = hyp_injected ? 1 : 0;
	e->served_from_shared = served_from_shared ? 1 : 0;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hint_flat.cmp_hints_consumed, 1UL,
				   __ATOMIC_RELAXED);
		/* SHADOW old-flat-pool by-kind partition.  Bumped here next
		 * to the flat consumed counter so the per-pool denominator is
		 * tracked in lock-step with the global denominator the
		 * existing dump path already exposes.  pool_kind has already
		 * been clamped into enum range by the assignment above.
		 * Shared-served stash entries are stamped with the
		 * CMP_HINT_POOL_KIND_NR sentinel by their caller so this
		 * gate silently skips them -- the shared-tier bootstrap has
		 * its own denominator (cmp_shared_tier_serves) and must not
		 * pollute the native by-pool consumed distribution. */
		if ((unsigned int)pool_kind < CMP_HINT_POOL_KIND_NR)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_consumed_by_pool[pool_kind],
				1UL, __ATOMIC_RELAXED);
	}

	/* SHADOW hypothesis-layer consume credit.  Resolves the would-have-
	 * been-chosen hypothesis from the same (cmp_ip, value, size) tuple
	 * the per-entry pool credit drain will use later; bumps the typed
	 * consumed_count + flat cmp_hyp_consumed so the typed denominator
	 * tracks the per-pool denominator already established above.  No-op
	 * when no hypothesis explains the value -- the credit lands only
	 * where the parallel inference layer has standing.  Gated off for
	 * shared-served entries: the cmp_ip carried on the stash comes
	 * from another syscall's observation, so any hypothesis hit at
	 * (this nr, that cross-syscall cmp_ip) would be a coincidence
	 * indistinguishable from noise and would inflate the typed
	 * consume denominator with cross-nr chatter the shared-tier
	 * bootstrap is not authorised to spend against native credit. */
	if (!served_from_shared)
		cmp_hyp_credit_consume(nr, do32, cmp_ip, value, size);
}
