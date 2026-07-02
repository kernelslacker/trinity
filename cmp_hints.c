/*
 * KCOV comparison operand collection and hint pool management.
 *
 * Parses KCOV_TRACE_CMP trace buffers to extract constants that the
 * kernel compared syscall-derived values against. These constants
 * are stored in per-syscall in-memory pools and used during argument
 * generation to produce values more likely to pass kernel validation.
 *
 * Buffer format (each record is 4 x u64):
 *   [0] type  - KCOV_CMP_CONST | KCOV_CMP_SIZE(n)
 *   [1] arg1  - first comparison operand
 *   [2] arg2  - second comparison operand
 *   [3] ip    - instruction pointer of the comparison
 *
 * Pool entries are keyed by (cmp_ip, value, size).  Distinguishing on
 * cmp_ip means the same constant compared at two different kernel
 * sites occupies two slots rather than colliding -- the precision
 * matters once a downstream consumer wants to attribute which site a
 * hint came from.  cmp_ip is the canonical (KASLR-stripped) address
 * produced by kcov_canon_cmp_ip(), routed in at the top of the
 * cmp_hints_collect() per-record loop; the bloom hash, the pool dedup
 * key, and the persisted on-disk record all index by the same canonical
 * value, so a KASLR reroll between save and warm-load does not alias
 * every learned constant to a different (cmp_ip, value, size) tuple.
 *
 * When a pool fills, the entry with the lowest last_used generation
 * is evicted (least-recently-inserted), so a fresh constant displaces
 * stale long-tail noise instead of stomping a slot at random.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "kcov.h"
#include "params.h"
#include "persist-util.h"
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
#include "pids.h"

/* From uapi/linux/kcov.h.  KCOV_CMP_SIZE(n) packs the operand-width
 * index n in {0,1,2,3} into bits 1..2 of the type word; the actual
 * operand width in bytes is (1U << n). */
#define KCOV_CMP_CONST		(1U << 0)
#define KCOV_CMP_SIZE_SHIFT	1
#define KCOV_CMP_SIZE_MASK	3U

/* Words per comparison record in the trace buffer. */
#define WORDS_PER_CMP 4

struct cmp_hints_shared *cmp_hints_shm = NULL;

/*
 * Per-syscall CMP-collection strip flags.  When cmp_hints_strip[do32][nr]
 * is true, cmp_hints_collect() returns immediately after the nr range
 * check, bypassing the bloom + pool_add_locked path entirely for that
 * syscall number.  Indexed by [do32bit ? 1 : 0][nr] under biarch: a
 * 32-bit syscall and a 64-bit syscall can share the same numeric nr
 * but mean unrelated things, so a single-dimensional table would
 * collaterally strip whichever sibling happens to live at the same
 * slot.  Uniarch builds only ever touch the [0] row.  Targets are syscalls whose KCOV_TRACE_CMP records
 * fire on task_struct / cred / ucounts / aio-table internal state set
 * by prior syscalls or kernel init, not on values driven by the
 * current syscall's argument surface -- the resulting pool entries
 * are unreachable from any subsequent argument generator and only
 * displace genuinely useful constants from the LRU eviction order.
 *
 * Per-record bump of cmp_hints_strip_skipped (mirroring the
 * cmp_hints_bloom_skipped accounting) makes the avoided work
 * observable; the stripped syscalls' pool[nr] entries continue to be
 * served by cmp_hints_try_get() from anything they accumulated before
 * the strip flag was set, so there is no consumer-side hole.
 */
bool cmp_hints_strip[2][MAX_NR_SYSCALL];

/*
 * Chaos-mode toggle.  cmp_hints saturates after a warm-up period at
 * roughly the per-syscall cap across the syscalls the fuzzer
 * exercises, and substitutes kernel-blessed constants at the
 * gen_undefined_arg injection point at >99% of pulls.  Constants the
 * kernel CMP'd against by definition passed the kernel's validation
 * gates; the vast majority of WARN_ONs guard INVALID state (refcount
 * underflow, mutually-exclusive flag combinations, etc.) -- so a
 * hint-injected arg is biased AWAY from the args that trip WARNs.
 *
 * Periodically suppress hint injection so random-arg generation gets
 * a fair shot at the invalid-combination space.  Gate at the
 * cmp_hints_try_get layer -- when chaos is active the function
 * returns false (no hint), the caller falls through to its other
 * arg-generation paths.  Zero churn at the call site.
 *
 * Cadence: cmp_hints_chaos_tick() is called once per bandit window
 * rotation from maybe_rotate_strategy().  Every CHAOS_WINDOW_MODULO'th
 * window flips chaos_active for the duration of that window -- 1 in
 * every 8 windows in the current default (12.5% of windows).  Cheap:
 * tick path is one fetch_add and one atomic store; hot-path gate is
 * one atomic load.  Modulo-of-counter rather than RNG so the cadence
 * stays exactly predictable -- attribution work in follow-ups can
 * line up WARN-fire deltas against the chaos schedule without
 * sampling noise.
 */
#define CHAOS_WINDOW_MODULO 8

void cmp_hints_chaos_tick(void)
{
	unsigned long n;

	if (kcov_shm == NULL)
		return;

	n = __atomic_add_fetch(&kcov_shm->cmp_hints_chaos_window_count, 1UL,
			       __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->cmp_hints_chaos_active,
			 (n % CHAOS_WINDOW_MODULO) == 0 ? 1u : 0u,
			 __ATOMIC_RELAXED);
}

bool cmp_hints_chaos_query(void)
{
	if (kcov_shm == NULL)
		return false;
	return __atomic_load_n(&kcov_shm->cmp_hints_chaos_active,
			       __ATOMIC_RELAXED) != 0;
}

/*
 * Mark each named syscall as cmp-collection-stripped.  Names are
 * resolved via search_syscall_table() against the active table set;
 * under biarch both the 32-bit and 64-bit indices are flagged since
 * cmp_hints_collect()'s nr argument comes from rec->nr at the call
 * site (which uses whichever table the child ran against), and the
 * same syscall name occupies different slots in each table.
 *
 * Unknown names log a warning and are skipped: the strip list is
 * compiled in and a typo here would otherwise silently fail to take
 * effect.  NULL entries are tolerated so the strip-target array can
 * carry a sentinel before any targets are populated.
 */
static void cmp_hints_strip_install(const char * const names[], unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		const char *name = names[i];
		bool found = false;
		int nr;

		if (name == NULL)
			continue;

		if (biarch == true) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  name);
			if (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) {
				cmp_hints_strip[0][nr] = true;
				found = true;
			}

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  name);
			if (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) {
				cmp_hints_strip[1][nr] = true;
				found = true;
			}
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls, name);
			if (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) {
				cmp_hints_strip[0][nr] = true;
				found = true;
			}
		}

		if (found == true)
			output(0, "KCOV: CMP collection stripped for %s\n",
			       name);
		else
			output(0, "KCOV: cmp_hints strip target '%s' not found in syscall table\n",
			       name);
	}
}

/*
 * Compiled-in list of syscalls whose per-call CMP records are
 * dominated by kernel-internal state unreachable from the syscall
 * argument surface.  See the cmp_hints_strip[] comment above for the
 * semantics; per-target rationale follows.
 *
 *   prctl    -- the option dispatch reads task_struct / mm_struct /
 *               cred / signal_struct fields and compares them against
 *               compile-time constants in each PR_* arm.  The option
 *               selector is one of trinity's syscall args, but every
 *               downstream comparand is kernel-internal state set by
 *               prior syscalls (or process init); the option value
 *               itself only feeds the dispatch switch, not any
 *               KCOV_CMP_CONST record.
 *   unshare  -- the flags arg drives a switch over CLONE_* bits, but
 *               the comparisons KCOV traps fire inside the per-
 *               namespace clone paths against ucounts / user_ns /
 *               nsproxy state, none of which a single unshare() arg
 *               can move.
 *   io_setup -- the constants land on aio_ring_setup() validation of
 *               table state attached to the mm (existing ioctx count,
 *               pinned-page accounting), set by earlier io_setup /
 *               io_destroy calls on the same task; the nr_events arg
 *               only sizes the ring, it does not drive the compared
 *               fields.
 *
 * Each is a top-volume CMP-record producer whose entries can only
 * displace constants from edge-producing syscalls in the same
 * cmp_hints_try_get() namespace (per-nr pools, so no direct
 * cross-contamination, but the global LRU and the bloom-reset cadence
 * absorb the wasted work).
 */
static const char * const cmp_hints_strip_targets[] = {
	"prctl",
	"unshare",
	"io_setup",
};

/*
 * Auto-strip CMP collection for any syscall whose num_args == 0.  With
 * no syscall arguments at all, every KCOV_CMP record such a syscall
 * emits is by construction unreachable from cmp_hints_try_get() -- the
 * argument surface is empty, so no constant the kernel compares
 * against can ever be steered by a subsequent generated arg.  Pool
 * entries from these syscalls only displace constants from
 * arg-bearing syscalls in the LRU eviction order and waste
 * bloom-reset cycles.
 *
 * Run after cmp_hints_strip_install() so the explicit per-rationale
 * list above is in place first; the explicit set is independent (it
 * strips arg-bearing syscalls whose comparisons fire on
 * kernel-internal state) and is not a subset of this one.  Emits a
 * single count line rather than per-syscall output -- ~20+ matches
 * would be log spam at fleet scale.
 */
static void cmp_hints_strip_no_arg_syscalls(void)
{
	struct syscallentry *entry;
	unsigned int i;
	unsigned int count = 0;

	if (biarch == true) {
		for_each_64bit_syscall(i) {
			if (i >= MAX_NR_SYSCALL)
				break;
			entry = syscalls_64bit[i].entry;
			if (entry == NULL)
				continue;
			if (entry->num_args == 0 && !cmp_hints_strip[0][i]) {
				cmp_hints_strip[0][i] = true;
				count++;
			}
		}
		for_each_32bit_syscall(i) {
			if (i >= MAX_NR_SYSCALL)
				break;
			entry = syscalls_32bit[i].entry;
			if (entry == NULL)
				continue;
			if (entry->num_args == 0 && !cmp_hints_strip[1][i]) {
				cmp_hints_strip[1][i] = true;
				count++;
			}
		}
	} else {
		for_each_syscall(i) {
			if (i >= MAX_NR_SYSCALL)
				break;
			entry = syscalls[i].entry;
			if (entry == NULL)
				continue;
			if (entry->num_args == 0 && !cmp_hints_strip[0][i]) {
				cmp_hints_strip[0][i] = true;
				count++;
			}
		}
	}

	output(0, "KCOV: CMP collection auto-stripped for %u zero-arg syscalls\n",
	       count);
}

void cmp_hints_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Wild-write risk: a child syscall whose user-buffer arg aliases
	 * into a pool could let the kernel scribble into pool->entries[]
	 * (worst case: a duplicate slips past the linear-scan dedup, or a
	 * stale value is handed back as a hint -- not a crash) or into the
	 * lock byte (a stuck lock would deadlock subsequent
	 * cmp_hints_collect callers in that one syscall slot).
	 * Diagnostic-grade only.
	 */
	cmp_hints_shm = alloc_shared(sizeof(struct cmp_hints_shared));
	memset(cmp_hints_shm, 0, sizeof(struct cmp_hints_shared));
	/* Stamp the wild-write canaries flanking pool->entries[] in every
	 * (nr, arch) slot.  These are runtime-only -- cmp_hints_load_file
	 * writes count/generation/entries/last_used_stamp and never touches
	 * canary_pre/canary_post, so a single init pass before warm-start
	 * is sufficient for the lifetime of the SHM. */
	{
		unsigned int nr, a;
		for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
			for (a = 0; a < 2; a++) {
				struct cmp_hint_pool *pool =
					&cmp_hints_shm->pools[nr][a];
				pool->canary_lock_post = CMP_HINTS_POOL_CANARY;
				pool->canary_pre = CMP_HINTS_POOL_CANARY;
				pool->canary_post = CMP_HINTS_POOL_CANARY;
			}
		}
	}
	/* Field-pool canaries.  Same triplet (lock_post / pre / post) as the
	 * per-syscall pools so a wild-write into either family lands in the
	 * same channel-attributed sentinels. */
	{
		unsigned int i;
		for (i = 0; i < CMP_FIELD_POOL_BUCKETS; i++) {
			struct cmp_field_pool *pool =
				&cmp_hints_shm->field_pools[i];
			pool->canary_lock_post = CMP_HINTS_POOL_CANARY;
			pool->canary_pre = CMP_HINTS_POOL_CANARY;
			pool->canary_post = CMP_HINTS_POOL_CANARY;
		}
	}
	output(0, "KCOV: CMP hint pool allocated (%lu KB)\n",
		(unsigned long) sizeof(struct cmp_hints_shared) / 1024);

	cmp_hints_strip_install(cmp_hints_strip_targets,
				ARRAY_SIZE(cmp_hints_strip_targets));
	cmp_hints_strip_no_arg_syscalls();
	cmp_hints_field_record_self_check();
}



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
				__atomic_fetch_add(&kcov_shm->cmp_hints_strip_skipped,
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
			reject_nonconst++;
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
						&kcov_shm->reexec_attribution_found,
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
							&kcov_shm->reexec_attribution_ambiguous,
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
							&kcov_shm->reexec_attribution_width_match,
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
							&kcov_shm->reexec_attribution_found,
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
		__atomic_fetch_add(&kcov_shm->cmp_hints_bloom_skipped, skipped,
				   __ATOMIC_RELAXED);

	if (inserted != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->per_syscall_cmp_inserts[nr],
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
			      unsigned long cmp_ip, unsigned long value,
			      unsigned int size, enum cmp_hint_use use,
			      unsigned int arg_idx,
			      unsigned int field_idx,
			      const struct struct_desc *desc,
			      bool served_from_recent,
			      uint8_t age_bucket,
			      bool hyp_injected)
{
	struct childdata *child = this_child();
	struct cmp_hint_consumed_entry *e;

	if (child == NULL || child->in_reexec)
		return;

	if (child->cmp_hints_consumed_count >= CMP_HINT_CONSUMED_STASH_MAX) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hint_stash_overflow,
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

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_consumed, 1UL,
				   __ATOMIC_RELAXED);
		/* SHADOW old-flat-pool by-kind partition.  Bumped here next
		 * to the flat consumed counter so the per-pool denominator is
		 * tracked in lock-step with the global denominator the
		 * existing dump path already exposes.  pool_kind has already
		 * been clamped into enum range by the assignment above. */
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
	 * where the parallel inference layer has standing. */
	cmp_hyp_credit_consume(nr, do32, cmp_ip, value, size);
}

/*
 * Per-child A/B stamp + weighted draw for the cmp-hints live-pick
 * policy -- the header-anticipated follow-up to the SHADOW per-entry
 * feedback loop ("weighted live-pick policy" in include/cmp_hints.h).
 *
 * Arm A (false) keeps the historical uniform draw at the two pick
 * sites below; arm B (true) routes the same pick through
 * cmp_hint_weighted_pick(), weighting each entry by
 *
 *      weight = CMP_HINT_LIVEPICK_FLOOR + wins * 4 - misses
 *
 * clamped to >= CMP_HINT_LIVEPICK_FLOOR so a single bad miss cannot
 * extinguish a slot's exploration budget.  The SHADOW recording path
 * (stash + dispatch-tail credit + per-entry .wins/.misses bumps + the
 * flat cmp_hint_wins/cmp_hint_misses counters) is unmodified and
 * fires identically from both arms: arm A is the control whose pick
 * distribution stays uniform; arm B consumes the same fresh score
 * snapshot the SHADOW recorder is producing.
 *
 * Stamp discipline: lazy-stamped on first read inside the child via
 * ONE_IN(2).  The file-static lives in COW'd post-fork memory, so
 * each forked child sees its own copy and the stamp persists for the
 * life of that child process.  Parent context never reaches the pick
 * path (this_child() == NULL on the parent side), so no parent-side
 * stamp ever leaks into a freshly-forked child via COW.  Independent
 * of the other A/B axes (cmp_hint_inject_arm_b / boring_filter_arm_b
 * / frontier_blend_arm_b / ...) so the cohort comparison stays
 * un-confounded.
 *
 * Race tolerance on the weight read: .wins / .misses are RELAXED
 * uint16_t writes from the SHADOW credit drain; the weighted draw
 * loads them with __atomic_load_n RELAXED.  A torn view (a sibling's
 * mid-bump being half-visible) at worst nudges the draw by one weight
 * unit -- the same tolerance the uniform draw already extends to a
 * concurrent eviction of the picked triplet.  Hints are advisory; the
 * next pull resamples.
 */
#define CMP_HINT_LIVEPICK_FLOOR	1U

static bool cmp_hint_livepick_arm_stamped;
static bool cmp_hint_livepick_arm_b;

bool cmp_hint_livepick_arm_b_active(void)
{
	if (!cmp_hint_livepick_arm_stamped) {
		cmp_hint_livepick_arm_b = ONE_IN(2);
		cmp_hint_livepick_arm_stamped = true;
	}
	return cmp_hint_livepick_arm_b;
}

unsigned int cmp_hint_weighted_pick(struct cmp_hint_entry *entries,
					   unsigned int count)
{
	uint32_t weights[CMP_HINTS_PER_SYSCALL];
	uint64_t total = 0;
	uint64_t acc = 0;
	uint32_t draw;
	unsigned int i;

	/* Defensive clamp against a torn count snapshot reaching the
	 * helper: the caller already passes a cmp_hints_pool_corrupted-
	 * gated count, but bounding entries[] access here keeps the
	 * weighted path self-contained against a future caller that
	 * forgets the gate. */
	if (count > CMP_HINTS_PER_SYSCALL)
		count = CMP_HINTS_PER_SYSCALL;

	for (i = 0; i < count; i++) {
		uint16_t w_wins =
			__atomic_load_n(&entries[i].wins, __ATOMIC_RELAXED);
		uint16_t w_misses =
			__atomic_load_n(&entries[i].misses, __ATOMIC_RELAXED);
		int32_t w = (int32_t)CMP_HINT_LIVEPICK_FLOOR
			  + (int32_t)w_wins * 4
			  - (int32_t)w_misses;

		if (w < (int32_t)CMP_HINT_LIVEPICK_FLOOR)
			w = (int32_t)CMP_HINT_LIVEPICK_FLOOR;
		weights[i] = (uint32_t)w;
		total += weights[i];
	}

	/* total >= count * FLOOR > 0 for count > 0; bounded by
	 * CMP_HINTS_PER_SYSCALL * (FLOOR + UINT16_MAX * 4) well under
	 * 2^32 so the rnd_modulo_u32 cast is safe. */
	draw = rnd_modulo_u32((uint32_t)total);

	for (i = 0; i < count; i++) {
		acc += weights[i];
		if ((uint64_t)draw < acc)
			return i;
	}
	/* Unreachable: draw < total and acc accumulates to total above.
	 * Fall back to the last in-bounds slot if a future change drifts
	 * the invariant rather than silently indexing off the array. */
	return count - 1;
}

static bool cmp_try_get_durable_tier(unsigned int nr, bool do32,
				     enum cmp_hint_use use, unsigned long old,
				     bool allow_hyp_inject,
				     const struct cmp_accept_range *accept,
				     unsigned long *out)
{
	struct cmp_hint_pool *pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];
	struct cmp_hint_entry *picked;
	unsigned int count;
	unsigned long picked_value;
	unsigned long picked_cmp_ip;
	uint32_t picked_size;

	/*
	 * Lockless read.  Multiple children fuzzing the same syscall would
	 * otherwise serialize on pool->lock just to grab one hint.
	 *
	 * Tolerated race: a stale count snapshot still indexes a populated
	 * slot — count is monotonic up to the CMP_HINTS_PER_SYSCALL cap, and
	 * once full it stops moving (full-pool eviction overwrites in place).
	 * The per-entry .value field is a naturally-aligned unsigned long, so
	 * a concurrent eviction yields either the pre- or post-overwrite
	 * value at the hardware level; both are valid hints that lived in
	 * the pool.
	 *
	 * For fuzzer hints this is benign — values are direct unsigned longs
	 * substituted as syscall args, never dereferenced.  We do not refresh
	 * the entry's last_used field on lookup: the LRU stamp tracks
	 * insertion freshness from cmp_hints_collect(), which is what the
	 * dedup-vs-eviction policy is built around.
	 */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return false;
	/* Lockless gate: a kernel-side wild write through a syscall arg
	 * pointer can stomp pool->count, and rnd_modulo_u32(garbage) would
	 * then index off the 1.1 MB SHM into an unmapped page.  Hints are
	 * advisory -- skip is the safe response. */
	if (cmp_hints_pool_corrupted(pool, count))
		return false;

	/* A/B-gated live-pick policy.  Arm A (control) keeps the
	 * historical uniform draw; arm B routes the pick through the
	 * weighted draw on the per-entry .wins/.misses score the SHADOW
	 * credit drain maintains.  The stash + credit path below is
	 * unchanged and fires identically from both arms, so the SHADOW
	 * win/miss counters keep flowing as the cohort-rollup signal the
	 * weighted draw is measured against. */
	if (cmp_hint_livepick_arm_b_active())
		picked = &pool->entries[
			cmp_hint_weighted_pick(pool->entries, count)];
	else
		picked = &pool->entries[rnd_modulo_u32(count)];
	/* Snapshot the entry triplet BEFORE the transform so the stash
	 * carries the raw pool-entry identity (cmp_ip, value, size) -- the
	 * tuple the credit drain uses to re-find the same entry.  Reading
	 * each field once locally also avoids reading a torn (cmp_ip, value,
	 * size) triplet on a concurrent eviction: even if a sibling overwrites
	 * the slot between our load of value and load of cmp_ip, the credit
	 * drain just fails to re-find a matching entry and the per-entry score
	 * for that pull is lost (the flat counter still bumps). */
	picked_value = picked->value;
	picked_cmp_ip = picked->cmp_ip;
	picked_size = picked->size;
	/* Staleness sample for the freshness observability counters.
	 * Lock-free reads on the two stamp fields: a torn read (a sibling
	 * insert advancing pool->last_used_stamp between our two loads, or
	 * a concurrent eviction overwriting picked->last_used with a fresh
	 * stamp) at worst misbuckets a single sample, which is acceptable
	 * shadow accounting -- the next pull resamples.  Guard the
	 * unsigned subtraction against a torn read that would make the
	 * entry stamp appear larger than the pool stamp; clamp to 0 per
	 * the codified rule "ensure b <= a at the point of a - b". */
	{
		uint64_t cur_stamp = __atomic_load_n(&pool->last_used_stamp,
						     __ATOMIC_RELAXED);
		uint64_t entry_stamp = __atomic_load_n(&picked->last_used,
						       __ATOMIC_RELAXED);
		uint64_t age = (cur_stamp >= entry_stamp) ?
				(cur_stamp - entry_stamp) : 0;
		uint8_t bucket = cmp_hint_age_bucket(age);
		unsigned long stash_value = picked_value;
		bool hyp_injected = false;
		bool inject_gate_fired = false;
		uint8_t inject_kind = 0;

		/* LIVE typed-hypothesis inject arm.  Runs only for callers
		 * that opted in (the typed-safe argtype set).  When the
		 * conservative gate fires AND the typed store has a
		 * hypothesis at the same (cmp_ip, width) the raw pick just
		 * served, the raw value is replaced by a value derived from
		 * that hypothesis.  Bypasses cmp_hint_apply_transform so the
		 * derived constant reaches the kernel verbatim -- a +/-1
		 * BOUNDARY shift on top of the derived value would dodge the
		 * value-keyed credit re-resolution path in
		 * cmp_hyp_find_for_credit, silently dropping the conversion
		 * attribution this arm exists to measure.  Raw pool stays
		 * the fallback on any gate miss / empty resolver / derive
		 * bail.
		 *
		 * Per-pull inject counters (gate_passed, live_injected,
		 * live_injected_by_kind) are NOT bumped inside the helper:
		 * deferring them to the accept-gated commit point below
		 * keeps a hint the caller's accept range subsequently
		 * rejects from contaminating the denominator. */
		if (allow_hyp_inject) {
			unsigned long derived;

			if (cmp_hyp_try_live_inject(nr, do32, picked_cmp_ip,
						    picked_size, &derived,
						    &inject_kind,
						    &inject_gate_fired)) {
				*out = derived;
				stash_value = derived;
				hyp_injected = true;
			}
		}
		if (!hyp_injected)
			*out = cmp_hint_apply_transform(picked_value, use, old);

		/* Caller accept-range gate.  Miss-exit: NO consume-age
		 * bump, NO returned counters, NO gate_passed /
		 * live_injected denominator, NO stash, NO would_pick --
		 * the value never reached the consumer.  Without this gate
		 * a derived value the caller subsequently rejects (today
		 * ARG_RANGE; same shape for any future typed-safe consumer
		 * with a hard bound) was credited and counted as
		 * cmp_hyp_live_injected (+ stash-eligible for
		 * cmp_hyp_pc_wins) even though it never reached the
		 * kernel, biasing both arm-verdict numerator and
		 * denominator. */
		if (accept != NULL &&
		    (*out < accept->lo || *out > accept->hi)) {
			/* Additive reason-counter for the LIVE inject path:
			 * only bump when the rejected value came from the
			 * typed hypothesis (hyp_injected), so the per-reason
			 * partition matches the existing accept-gated denom
			 * (a raw-pool value getting accept-rejected belongs
			 * to a different cohort and is not counted here). */
			if (hyp_injected && kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT],
					1UL, __ATOMIC_RELAXED);
			return false;
		}

		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_durable_consumed_age[bucket],
					   1UL, __ATOMIC_RELAXED);

			/* Inject-arm denominator + per-kind partition,
			 * deferred from cmp_hyp_try_live_inject() to here so
			 * an accept-rejected derived value does not
			 * contaminate the counters.  gate_passed counts
			 * "dice gate fired AND value reached the consumer";
			 * live_injected counts "gate fired AND derive
			 * succeeded AND value reached the consumer".  The
			 * gate_passed - live_injected delta keeps the
			 * "gate fired but the typed store had nothing"
			 * observability the kcov_shm doc describes. */
			if (inject_gate_fired)
				__atomic_fetch_add(&kcov_shm->cmp_hyp_live_inject_gate_passed,
						   1UL, __ATOMIC_RELAXED);
			if (hyp_injected) {
				__atomic_fetch_add(&kcov_shm->cmp_hyp_live_injected,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_live_injected_by_kind[inject_kind],
					1UL, __ATOMIC_RELAXED);
			}

			/* Mirror of the attempts ring path above: both the
			 * scalar and per-nr returned counters drain into
			 * parent_stats via the per-child stats_ring. */
			{
				struct childdata *return_child = this_child();

				if (return_child != NULL) {
					(void) stats_ring_enqueue(return_child->stats_ring,
								  STATS_FIELD_CMP_HINTS_TRY_GET_RETURNED,
								  0, 1);
					/* per-nr partition of the producer-side
					 * pool-hit counter.  Same in-bounds guard
					 * reasoning as the attempts bump above. */
					(void) stats_ring_enqueue(return_child->stats_ring,
								  STATS_FIELD_PER_SYSCALL_CMP_RETURNED,
								  (uint16_t)nr, 1);
				}
			}
		}

		cmp_hints_stash_consumed(nr, do32, CMP_HINT_POOL_PER_SYSCALL,
					 picked_cmp_ip, stash_value, picked_size, use,
					 0, 0, NULL,
					 false, bucket, hyp_injected);
	}
	cmp_hyp_would_pick(nr, do32, picked_cmp_ip, picked_size, picked_value);
	return true;
}

/* enum cmp_tier_result moved to include/cmp_hints-internal.h. */

static enum cmp_tier_result cmp_try_get_recent_tier(unsigned int nr, bool do32,
						    enum cmp_hint_use use,
						    unsigned long old,
						    bool allow_hyp_inject,
						    const struct cmp_accept_range *accept,
						    unsigned long *out)
{
	/*
	 * Recent-pool sampling tier.
	 *
	 * The recent ring carries fresh constants the durable pool's
	 * saturated LRU floor would have dropped.  During a
	 * CMP_RISING_PC_FLAT plateau -- when the
	 * cmp_hints_save_reject_cap dominance signal says the durable
	 * pool is the bottleneck -- sample the recent ring first; this
	 * gives the consumer a window onto the late-run constant
	 * stream without competing with the durable pool's selection
	 * on the off-plateau steady state.  Typed-inject callsites are
	 * exempted (allow_hyp_inject) so they reach the inject arm on
	 * the durable path instead.
	 *
	 * cmp_recent_would_pick / cmp_recent_would_miss continue to
	 * bump on every plateau call so the recent-tier opportunity
	 * rate stays observable alongside the served rate.
	 * cmp_recent_live_picks bumps on a return actually served from
	 * the recent ring.
	 *
	 * Lockless reads with ACQUIRE on count + RELAXED on entries[]
	 * mirror the durable pool's lockless reader contract: torn
	 * cross-field reads are tolerated (hints are advisory), and a
	 * concurrent ring writer can only ever produce the pre- or
	 * post-overwrite triplet -- both lived in the ring.
	 */
	if (shm != NULL &&
	    __atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT) {
		struct cmp_recent_pool *rp =
			&cmp_hints_shm->recent_pools[nr][do32 ? 1 : 0];
		unsigned int rcount =
			__atomic_load_n(&rp->count, __ATOMIC_ACQUIRE);

		if (rcount > 0 && rcount <= CMP_RECENT_PER_SYSCALL) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_recent_would_pick,
						   1UL, __ATOMIC_RELAXED);
			/* Typed-inject callsites must reach the inject arm on
			 * the durable path, not be shadowed by the recent-first
			 * early-return.
			 */
			if (!allow_hyp_inject) {
				struct cmp_recent_entry *re =
					&rp->entries[rnd_modulo_u32(rcount)];
				unsigned long re_value = re->value;
				unsigned long re_cmp_ip = re->cmp_ip;
				uint32_t re_size = re->size;

				*out = cmp_hint_apply_transform(re_value,
								use, old);

				/* Caller accept-range gate.  Miss-exit:
				 * NO live_picks bump, NO stash, NO
				 * would_pick -- the value never reached
				 * the consumer so it must not show up
				 * in any per-pull counter or in the
				 * SHADOW would-pick resolver, which
				 * would otherwise re-credit a value the
				 * caller threw away. */
				if (accept != NULL &&
				    (*out < accept->lo ||
				     *out > accept->hi))
					return CMP_TIER_REJECTED;

				if (kcov_shm != NULL)
					__atomic_fetch_add(&kcov_shm->cmp_recent_live_picks,
							   1UL, __ATOMIC_RELAXED);

				/* Stash the recent-served pull under the
				 * per-syscall pool-kind: the feedback drain's
				 * per-entry credit path re-finds by (cmp_ip,
				 * value, size) in the durable pool and will
				 * harmlessly fail to find the recent-only
				 * tuple, while the flat cmp_hint_wins /
				 * cmp_hint_misses counters still bump -- the
				 * follow-up commit wires the recent-pool
				 * conversion credit + promotion.
				 *
				 * served_from_recent=1, age_bucket=0: the
				 * recent ring has no per-entry LRU stamp; its
				 * freshness story IS the tier itself.  The
				 * credit drain partitions PC-wins by tier so a
				 * recent-served stash entry rolls up under
				 * cmp_hint_tier_recent_wins / _misses; the
				 * age-bucketed durable counters skip it. */
				cmp_hints_stash_consumed(nr, do32,
							 CMP_HINT_POOL_PER_SYSCALL,
							 re_cmp_ip, re_value,
							 re_size, use,
							 0, 0, NULL,
							 true, 0, false);
				cmp_hyp_would_pick(nr, do32, re_cmp_ip,
						   re_size, re_value);
				return CMP_TIER_SERVED;
			}
		} else if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_recent_would_miss,
					   1UL, __ATOMIC_RELAXED);
		}
	}

	return CMP_TIER_MISS;
}

bool cmp_hints_try_get_ex(unsigned int nr, bool do32, enum cmp_hint_use use,
			  unsigned long old, bool allow_hyp_inject,
			  const struct cmp_accept_range *accept,
			  unsigned long *out)
{
	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	if (kcov_shm != NULL) {
		/* Scalar attempts counter now lives in parent_stats and is
		 * fed via the per-child stats_ring -- the kernel cannot
		 * scribble it through any fuzzed syscall arg because the
		 * authoritative copy is in MAP_PRIVATE parent memory.
		 * Direct +1 enqueue (no local staging like the kcov
		 * batched counters): cmp_hints_try_get fires at consumer
		 * cadence, well below the SPSC budget.  Ring-full drops
		 * fold into ring_overflow_total. */
		struct childdata *attempt_child = this_child();

		if (attempt_child != NULL) {
			(void) stats_ring_enqueue(attempt_child->stats_ring,
						  STATS_FIELD_CMP_HINTS_TRY_GET_ATTEMPTS,
						  0, 1);
			/* per-nr partition of the consumer-demand counter,
			 * drained into parent_stats.per_syscall_cmp_attempts[].
			 * The shm/nr guard above already pinned nr <
			 * MAX_NR_SYSCALL so aux is in-bounds at the drain. */
			(void) stats_ring_enqueue(attempt_child->stats_ring,
						  STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS,
						  (uint16_t)nr, 1);
		}
	}

	/* Chaos-mode gate.  Placed after the attempts bump so the consumer
	 * demand series stays comparable across chaos and non-chaos
	 * windows -- suppressed pulls remain visible as the
	 * attempts/returned gap, with cmp_hints_chaos_suppressed
	 * accounting for the difference.  Before the pool snapshot so the
	 * suppressed path skips the lockless load entirely. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->cmp_hints_chaos_active,
			    __ATOMIC_RELAXED)) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_chaos_suppressed,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	switch (cmp_try_get_recent_tier(nr, do32, use, old,
					allow_hyp_inject, accept, out)) {
	case CMP_TIER_SERVED:
		return true;
	case CMP_TIER_REJECTED:
		return false;
	case CMP_TIER_MISS:
		break;
	}

	return cmp_try_get_durable_tier(nr, do32, use, old,
				       allow_hyp_inject, accept, out);
}

bool cmp_hints_try_get(unsigned int nr, bool do32, unsigned long *out)
{
	return cmp_hints_try_get_ex(nr, do32, CMP_HINT_BOUNDARY, 0, false,
				    NULL, out);
}


/*
 * SHADOW per-entry feedback scoring -- credit drain.
 *
 * Three small helpers feed off the same per-child stash that
 * cmp_hints_try_get_ex pushed entries onto.  Exactly ONE of the three
 * runs per parent dispatch (PC-mode win / PC-mode miss / CMP-mode
 * novelty) -- the dispatch_step caller picks based on the same mode +
 * outcome signals it already computed for the other per-call counters.
 *
 * Saturating per-entry counters use a small CAS-saturate loop on the
 * matching pool entry's uint16_t wins/misses field: the common path
 * is one __atomic_compare_exchange_n on the not-yet-saturated counter
 * and short-circuits as soon as the field hits UINT16_MAX so a
 * pathologically hot tuple stops spending atomics once its score has
 * already conclusively dominated the population.  Lock-free scan
 * tolerates a concurrent eviction the same way cmp_hints_try_get does:
 * the picked entry may have been replaced by a sibling between consume
 * and credit, in which case the entries[] re-find at the saved
 * (cmp_ip, value, size) fails, the flat call-level counter still
 * bumps, and the per-entry score for that stash slot is forfeit -- a
 * shadow scoring loss bounded by pool churn.
 */
static void cmp_hint_entry_bump_sat(uint16_t *fld)
{
	uint16_t old;

	old = __atomic_load_n(fld, __ATOMIC_RELAXED);
	while (old < UINT16_MAX) {
		if (__atomic_compare_exchange_n(fld, &old, (uint16_t)(old + 1),
						true,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return;
	}
}

static void cmp_hint_credit_entry_per_syscall(unsigned int nr, bool do32,
					      unsigned long cmp_ip,
					      unsigned long value,
					      unsigned int size,
					      bool win)
{
	struct cmp_hint_pool *pool;
	unsigned int count;
	unsigned int i;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return;
	if (cmp_hints_pool_corrupted(pool, count))
		return;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value != value || e->cmp_ip != cmp_ip ||
		    e->size != size)
			continue;
		cmp_hint_entry_bump_sat(win ? &e->wins : &e->misses);
		return;
	}

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hint_credit_entry_evicted,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * Mirror of cmp_hint_credit_entry_per_syscall for the field-scoped pool.
 * Re-walks the bucket via the SAME cmp_field_pool_hash + ACQUIRE-load key
 * probe loop the recorder uses so the credit drain re-finds the entry the
 * pick path stashed -- modulo a concurrent eviction, which forfeits this
 * pull's per-entry score (the flat call-level counter still bumps via
 * cmp_hints_feedback_credit_pc).  Full-key match is required: a hash
 * collision on (desc, nr, do32, arg_idx, field_idx, size) where the live
 * occupant is a different key continues the probe walk.  Walks the same
 * CMP_FIELD_POOL_PROBE_MAX window the recorder bounded so a saturated
 * table whose late buckets are unrelated keys still terminates.
 */
static void cmp_hint_credit_entry_field(unsigned int nr, bool do32,
					unsigned int arg_idx,
					const struct struct_desc *desc,
					unsigned int field_idx,
					unsigned long cmp_ip,
					unsigned long value,
					unsigned int size,
					bool win)
{
	uint32_t h;
	unsigned int probe;
	unsigned int do32_idx = do32 ? 1U : 0U;

	if (cmp_hints_shm == NULL || desc == NULL)
		return;
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	h = cmp_field_pool_hash(desc, nr, do32_idx, arg_idx, field_idx, size);

	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		unsigned int idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		struct cmp_field_pool *pool = &cmp_hints_shm->field_pools[idx];
		const struct struct_desc *occ;
		unsigned int count;
		unsigned int i;

		occ = __atomic_load_n(&pool->key.desc, __ATOMIC_ACQUIRE);
		if (occ == NULL)
			return;
		if (occ != desc ||
		    pool->key.nr != (uint16_t) nr ||
		    pool->key.do32 != (uint8_t) do32_idx ||
		    pool->key.arg_idx != (uint8_t) arg_idx ||
		    pool->key.field_idx != (uint16_t) field_idx ||
		    pool->key.size != (uint8_t) size)
			continue;

		count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
		if (count == 0)
			return;
		if (cmp_field_pool_corrupted(pool, count))
			return;

		for (i = 0; i < count; i++) {
			struct cmp_hint_entry *e = &pool->entries[i];

			if (e->value != value || e->cmp_ip != cmp_ip ||
			    e->size != size)
				continue;
			cmp_hint_entry_bump_sat(win ? &e->wins : &e->misses);
			return;
		}

		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hint_credit_entry_evicted,
					   1UL, __ATOMIC_RELAXED);
		return;
	}
}

void cmp_hints_feedback_reset_stash(void)
{
	struct childdata *child = this_child();

	if (child == NULL)
		return;
	child->cmp_hints_consumed_count = 0;
}

void cmp_hints_feedback_credit_pc(bool outcome_win)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	if (kcov_shm != NULL) {
		if (outcome_win)
			__atomic_fetch_add(&kcov_shm->cmp_hint_wins, 1UL,
					   __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cmp_hint_misses, 1UL,
					   __ATOMIC_RELAXED);
	}

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		switch ((enum cmp_hint_pool_kind)e->pool_kind) {
		case CMP_HINT_POOL_PER_SYSCALL:
			cmp_hint_credit_entry_per_syscall(e->nr, e->do32 != 0,
							  e->cmp_ip, e->value,
							  e->size, outcome_win);
			break;
		case CMP_HINT_POOL_FIELD:
			cmp_hint_credit_entry_field(e->nr, e->do32 != 0,
						    e->arg_idx, e->desc,
						    e->field_idx, e->cmp_ip,
						    e->value, e->size,
						    outcome_win);
			break;
		case CMP_HINT_POOL_KIND_NR:
		default:
			break;
		}

		/* SHADOW old-flat-pool by-kind PC outcome partition.  Per-
		 * stash-entry bump (the flat cmp_hint_wins / cmp_hint_misses
		 * counters above bump once per parent dispatch) so a dispatch
		 * that stashed hints from both per-syscall and field pools
		 * lands its PC outcome on each kind's column.  Matches the
		 * per-tier discipline already used by cmp_hint_tier_*_wins. */
		if (kcov_shm != NULL &&
		    e->pool_kind < CMP_HINT_POOL_KIND_NR)
			__atomic_fetch_add(outcome_win ?
				&kcov_shm->cmp_hint_pc_wins_by_pool[e->pool_kind] :
				&kcov_shm->cmp_hint_misses_by_pool[e->pool_kind],
				1UL, __ATOMIC_RELAXED);

		/* Typed-hypothesis outcome credit, gated on hyp_injected.
		 *
		 * Before this gate the credit fired on every drained entry,
		 * which meant cmp_hyp_pc_wins counted raw-pool replays whose
		 * value coincidentally matched a stored hypothesis at the
		 * same (cmp_ip, width).  That coincidental credit conflated
		 * "the typed store would have steered toward a converting
		 * value" with "the raw pool happened to serve a value the
		 * typed store also knows about", erasing the signal the
		 * counter exists to surface.
		 *
		 * Under the live arm the gate restricts the credit to stash
		 * entries the inject arm produced.  cmp_hyp_pc_wins now
		 * counts converting calls whose served value was derived
		 * from a typed hypothesis (against the cmp_hyp_live_injected
		 * denominator), so the conversion ratio finally measures
		 * what the typed store earns over the raw replay baseline. */
		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       outcome_win ? CMP_HYP_OUTCOME_PC_WIN
							   : CMP_HYP_OUTCOME_MISS);

		/* Per-tier + per-age conversion partition.  The flat
		 * cmp_hint_wins / cmp_hint_misses counters above bump once
		 * per parent dispatch; the per-stash-entry partition here
		 * is what isolates the freshness signal -- a single
		 * dispatch may have stashed hints from multiple tiers /
		 * age buckets and each lands the outcome on its own
		 * sourcing channel.  Recent-served stash entries roll up
		 * under the recent tier counter and skip the age
		 * histogram (the ring has no per-entry LRU stamp).
		 * Durable-served stash entries (both per-syscall and
		 * field pools) roll up under the durable tier counter and
		 * bump the age-bucketed wins/misses indexed by the bucket
		 * stamped on the stash entry at pick time.  Defensive
		 * clamp on age_bucket mirrors the clamp in
		 * cmp_hints_stash_consumed for the same reason -- a
		 * corrupted stash entry that survived the in-stash clamp
		 * is harmlessly dropped onto the last bucket here. */
		if (kcov_shm == NULL)
			continue;
		if (e->served_from_recent) {
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->cmp_hint_tier_recent_wins :
					   &kcov_shm->cmp_hint_tier_recent_misses,
					   1UL, __ATOMIC_RELAXED);
		} else {
			uint8_t bucket = e->age_bucket;

			if (bucket >= CMP_HINT_AGE_BUCKETS)
				bucket = (uint8_t)(CMP_HINT_AGE_BUCKETS - 1U);
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->cmp_hint_tier_durable_wins :
					   &kcov_shm->cmp_hint_tier_durable_misses,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(outcome_win ?
					   &kcov_shm->cmp_hint_durable_age_wins[bucket] :
					   &kcov_shm->cmp_hint_durable_age_misses[bucket],
					   1UL, __ATOMIC_RELAXED);
		}
	}

	child->cmp_hints_consumed_count = 0;
}

void cmp_hints_feedback_credit_cmp_novelty(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hint_cmp_novelty_wins, 1UL,
				   __ATOMIC_RELAXED);

	/* Per spec: CMP-mode novelty is kept SEPARATE from PC-edge win
	 * credit so it cannot masquerade as PC-edge conversion.  Do NOT
	 * bump per-entry wins/misses here -- those are the PC-edge
	 * shadow score the follow-up live-pick will weigh by.  The flat
	 * cmp_hint_cmp_novelty_wins counter is the diagnostic channel
	 * for the CMP-mode signal.
	 *
	 * SHADOW hypothesis layer: credit CMP_NOVELTY against the would-
	 * have-been-chosen hypothesis for every stashed pull.  The typed
	 * cmp_novelty_wins is a peer of pc_wins in struct cmp_hypothesis
	 * for the same reason -- the consumer side must not collapse the
	 * two when ranking hypotheses.
	 */
	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		/* Same hyp_injected gate as the PC drain above: only stash
		 * entries the live inject arm produced credit the typed
		 * hypothesis layer, so cmp_hyp_cmp_novelty_wins measures
		 * typed-arm-driven CMP novelty rather than coincidental
		 * raw-replay overlap with the hypothesis store. */
		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_CMP_NOVELTY);

		/* SHADOW old-flat-pool by-kind CMP-novelty partition.  Kept
		 * SEPARATE from the PC-outcome partition above so harvested-
		 * but-flat novelty cannot masquerade as PC-edge conversion --
		 * mirrors the flat cmp_hint_cmp_novelty_wins vs cmp_hint_wins
		 * split and the typed cmp_hyp_cmp_novelty_wins discipline. */
		if (kcov_shm != NULL &&
		    e->pool_kind < CMP_HINT_POOL_KIND_NR)
			__atomic_fetch_add(
				&kcov_shm->cmp_hint_cmp_novelty_wins_by_pool[e->pool_kind],
				1UL, __ATOMIC_RELAXED);
	}

	child->cmp_hints_consumed_count = 0;
}

/*
 * Typed-hyp TRANSITION_WIN credit drain.  Walks the stash without
 * resetting it -- the single reset is owned by cmp_hints_feedback_
 * credit_pc() / _cmp_novelty() at end-of-dispatch.  Fires once per
 * hyp_injected stash entry so a parent that stashed two typed-arm
 * hints from different (cmp_ip, width) sites bumps both hypotheses'
 * transition_wins.  Same hyp_injected gate as the PC / CMP-novelty
 * credits: a raw-pool replay that happened to coincide with a stored
 * hypothesis at the served site does NOT bump TRANSITION_WIN.
 */
void cmp_hints_feedback_credit_transition(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_TRANSITION_WIN);
	}
}

/*
 * Typed-hyp CORPUS_SAVE credit drain.  Same shape as the transition
 * drain above -- walks the stash without resetting it, fires once
 * per hyp_injected entry.  Called from random-syscall.c when the
 * dispatch produced a novelty signal that minicorpus_save accepted,
 * so the credited hypothesis is one whose typed-arm value actually
 * earned its way into the persisted corpus.
 */
void cmp_hints_feedback_credit_corpus_save(void)
{
	struct childdata *child = this_child();
	unsigned int i, n;

	if (child == NULL)
		return;
	n = child->cmp_hints_consumed_count;
	if (n == 0)
		return;

	for (i = 0; i < n; i++) {
		const struct cmp_hint_consumed_entry *e =
			&child->cmp_hints_consumed_stash[i];

		if (e->hyp_injected)
			cmp_hyp_credit_outcome(e->nr, e->do32 != 0, e->cmp_ip,
					       e->value, e->size,
					       CMP_HYP_OUTCOME_CORPUS_SAVE);
	}
}

/*
 * Warm-start persistence.
 *
 * CMP records are expensive to gather -- each one requires the kernel
 * to actually execute a comparison against a syscall-derived input, so
 * the pool grows orders of magnitude slower than the kcov bitmap.  A
 * cold start throws away every learned constant and the first windows
 * after restart inject no hints at all.  Persisting the pool across
 * runs lets a long-running fuzz session reach steady state immediately
 * on restart instead of re-paying the warm-up cost every time.
 *
 * On-disk layout mirrors the in-memory shape: a fixed-size header
 * followed by MAX_NR_SYSCALL pool records, each a count + generation
 * + a fixed CMP_HINTS_PER_SYSCALL slice of explicitly-sized entries
 * (uint64 value, uint64 cmp_ip, uint32 size, uint32 pad, uint64 last_used).
 * Fixed layout keeps the load path a single contiguous read and the
 * CRC computation a single contiguous range, at the cost of some
 * zero-padded slots in syscalls whose pools are not full.
 *
 * Validity is gated on the kallsyms-sha256 fingerprint computed by
 * kcov_get_kernel_fp() -- the same fingerprint the kcov bitmap uses,
 * so a rebuilt kernel invalidates both files in lock-step.  IP-keyed
 * hints would otherwise be meaningless against a binary with a
 * different function layout.
 */
#define CMP_HINTS_FILE_MAGIC	0x4348505FU	/* "CHP_" */
/* Bumped to 2 when CMP_HINTS_PER_SYSCALL halved from 32 to 16: the on-
 * disk pool slice is a fixed CMP_HINTS_PER_SYSCALL-wide array, so the
 * payload layout is not backward-compatible.  The per_syscall mismatch
 * gate in cmp_hints_load_file would also catch this on its own, but a
 * version-level guard makes the cold-start reason explicit in the log
 * and leaves a hook for any future schema changes that don't ride on
 * top of a constant change. */
/* Bumped to 3 (2026-05-26): the per-entry last_used field widened
 * from uint32_t to uint64_t to match the in-memory pool clock that
 * no longer wraps on long-running fuzz sessions.  The on-disk struct
 * grew by 4 bytes, so the payload layout is not backward-compatible;
 * older snapshots are rejected via this version gate and trigger a
 * cold start (which the warm-start path treats as benign). */
/* Bumped to 4 (2026-05-30): the pool array gained an arch dimension
 * (pools[MAX_NR_SYSCALL][2]), so the payload now carries 2 * MAX_NR_SYSCALL
 * pool slots laid out as the natural interleaving of the 2D array
 * (pools[i][0] followed by pools[i][1] for each i).  Existing v3
 * snapshots are uniarch-shaped and are rejected via this version
 * gate; cold start is treated as benign by the warm-start path. */
/* Bumped to 5: per-entry cmp_ip is now canonicalised against the
 * runtime KASLR base (kcov_canon_cmp_ip) before pool insert, and the
 * header carries the writer's kcov_kaslr_base so the load path can
 * reject a canonical-vs-raw mismatch the way the kcov-bitmap header
 * does.  v4 files were keyed by raw PCs; warm-loading them against a
 * v5 binary would either read raw cmp_ip into a canonical pool or
 * vice versa, silently aliasing every learned constant.  The header
 * grew by 8 bytes (kaslr_base appended after kallsyms_sha256); the
 * payload layout (cmp_hints_pool_ondisk / cmp_hints_entry_ondisk) is
 * unchanged. */
#define CMP_HINTS_FILE_VERSION	5U

struct cmp_hints_entry_ondisk {
	uint64_t value;
	uint64_t cmp_ip;
	uint32_t size;
	uint32_t pad;
	uint64_t last_used;
};

struct cmp_hints_pool_ondisk {
	uint32_t count;
	uint32_t generation;
	struct cmp_hints_entry_ondisk entries[CMP_HINTS_PER_SYSCALL];
};

struct cmp_hints_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t max_syscall;		/* MAX_NR_SYSCALL at file-build time */
	uint32_t per_syscall;		/* CMP_HINTS_PER_SYSCALL at file-build time */
	uint32_t entry_size;		/* sizeof(struct cmp_hints_entry_ondisk) */
	uint32_t payload_crc32;
	uint64_t payload_bytes;		/* sizeof(struct cmp_hints_pool_ondisk) * max_syscall */
	uint8_t  kallsyms_sha256[32];
	uint64_t kaslr_base;		/* v5: runtime _text base at save time.
					 * Zero means the writer could not resolve
					 * the base and the persisted cmp_ip values
					 * are raw runtime PCs.  The load path
					 * rejects when (hdr.kaslr_base != 0) XOR
					 * (current kcov_kaslr_base != 0) -- a
					 * canonical-vs-raw mix would silently
					 * alias the warm-loaded (cmp_ip, value,
					 * size) keys against the live pool. */
};

unsigned long cmp_hints_load_rejected_entries;

/* Parent-private scratch buffer for the per-pool snapshot phase of
 * cmp_hints_serialise().  cmp_hints_save_file (the sole caller) only
 * runs in parent context -- from cmp_hints_maybe_snapshot()'s stats-tick
 * path and from the trinity.c shutdown save -- so a single static
 * buffer is safe and avoids a per-pool malloc on the snapshot path. */
static struct cmp_hint_pool cmp_hints_pool_scratch;

/* Serialise the live shm pools[] into a heap-allocated on-disk buffer.
 *
 * Per pool: lock, memcpy the raw struct into a parent-private scratch
 * copy, unlock, then do the on-disk format translation from the scratch
 * without any lock held.  Holding pool->lock only for the duration of a
 * fixed-size struct copy bounds the critical section to O(sizeof(pool))
 * memory traffic regardless of how full the pool is, instead of the old
 * O(count) field-by-field translation loop.
 *
 * Why this matters: if a child SIGSEGV/SIGABRTs while holding pool->lock
 * during cmp_hints_collect, the parent's snapshot path has to acquire
 * that lock -- and shorter windows mean exponentially fewer crash sites
 * land inside the locked region.  Does not eliminate the leaked-lock
 * race; the broader fix is a pid-owned-lock pattern landing separately. */
static struct cmp_hints_pool_ondisk *cmp_hints_serialise(void)
{
	struct cmp_hints_pool_ondisk *out;
	unsigned int i, a, j;

	/* Flat array of 2 * MAX_NR_SYSCALL slots indexed [i * 2 + a],
	 * matching the natural memory layout of pools[i][a]. */
	out = calloc((size_t)MAX_NR_SYSCALL * 2, sizeof(*out));
	if (out == NULL)
		return NULL;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			struct cmp_hint_pool *pool = &cmp_hints_shm->pools[i][a];
			struct cmp_hints_pool_ondisk *slot = &out[i * 2 + a];
			unsigned int count;

			pool_lock(pool);
			memcpy(&cmp_hints_pool_scratch, pool, sizeof(*pool));
			pool_unlock(pool);

			count = cmp_hints_pool_scratch.count;
			/* Route the count check through the gate so a stomped
			 * pool observed for the first time from the save path
			 * still records the channel (count_oob + canary
			 * counters) and latches pool->corrupted -- otherwise a
			 * stomp landing inside a save window leaves no trace
			 * and the bogus entries get serialised behind a count
			 * clamped down to the cap, surviving the loader's
			 * per-entry validator and reappearing on next start. */
			if (cmp_hints_pool_corrupted(pool, count)) {
				slot->count = 0;
				slot->generation = 0;
				continue;
			}
			slot->count = count;
			slot->generation = cmp_hints_pool_scratch.generation;
			for (j = 0; j < count; j++) {
				slot->entries[j].value     = cmp_hints_pool_scratch.entries[j].value;
				slot->entries[j].cmp_ip    = cmp_hints_pool_scratch.entries[j].cmp_ip;
				slot->entries[j].size      = cmp_hints_pool_scratch.entries[j].size;
				slot->entries[j].last_used = cmp_hints_pool_scratch.entries[j].last_used;
			}
		}
	}
	return out;
}

static unsigned long cmp_hints_total_generation(void);

/*
 * Dirty-bit proxy for cmp_hints_save_file().  cmp_hints_total_generation()
 * is the sum of pool->generation across all MAX_NR_SYSCALL pools;
 * pool->generation increments only when pool content actually changes
 * (fresh insert or evict-replace), NOT on a dedup-refresh that only
 * bumps an existing entry's last_used stamp.  The sum is therefore
 * monotonic and changes precisely when the on-disk payload would
 * differ from what was last written; when it equals the value at the
 * last successful save, no pool has been touched and the snapshot can
 * be skipped.
 *
 * Initialised to ULONG_MAX so the first save in a process always fires;
 * advanced on every successful save and seeded by the warm-start loader
 * (which restores pool->generation from disk) so the
 * load-then-immediate-exit cycle skips its end-of-run save.
 *
 * Parent-private: cmp_hints_maybe_snapshot() and the trinity.c shutdown
 * save are both parent-context callers; no race with children.
 */
static unsigned long cmp_hints_generation_at_last_save = ULONG_MAX;

bool cmp_hints_save_file(const char *path)
{
	struct cmp_hints_file_header hdr;
	struct cmp_hints_pool_ondisk *payload;
	char tmppath[PATH_MAX];
	size_t payload_bytes;
	unsigned long gen_now;
	unsigned long saved_entries;
	unsigned int populated_pools;
	unsigned int i;
	int fd;
	int ret;

	if (path == NULL || cmp_hints_shm == NULL)
		return false;

	gen_now = cmp_hints_total_generation();
	if (gen_now == cmp_hints_generation_at_last_save) {
		output(0, "cmp-hints: snapshot skipped, no pool changes since last save\n");
		return true;
	}

	memset(&hdr, 0, sizeof(hdr));
	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256))
		return false;

	payload = cmp_hints_serialise();
	if (payload == NULL)
		return false;

	/* Counted off the on-disk image so the success log mirrors what
	 * the warm-start loader will print on the next run.  Cheap relative
	 * to the fsync that follows.  Walk the full 2 * MAX_NR_SYSCALL slot
	 * count so the per-arch populated slots are surfaced individually
	 * rather than collapsed back to per-nr. */
	saved_entries = 0;
	populated_pools = 0;
	for (i = 0; i < MAX_NR_SYSCALL * 2; i++) {
		if (payload[i].count > 0) {
			saved_entries += payload[i].count;
			populated_pools++;
		}
	}

	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 * sizeof(*payload);

	hdr.magic = CMP_HINTS_FILE_MAGIC;
	hdr.version = CMP_HINTS_FILE_VERSION;
	hdr.max_syscall = MAX_NR_SYSCALL;
	hdr.per_syscall = CMP_HINTS_PER_SYSCALL;
	hdr.entry_size = (uint32_t)sizeof(struct cmp_hints_entry_ondisk);
	hdr.payload_bytes = payload_bytes;
	hdr.payload_crc32 = crc32(payload, payload_bytes);
	/* Mirror the kcov-bitmap header's kaslr_base contract.  Zero is the
	 * "raw cmp_ip values, KASLR base lookup failed at save time" sentinel;
	 * the load path uses the (!= 0) XOR check below to refuse a cross-
	 * mode warm-load.  Stamping the value (not just a flag) leaves the
	 * door open for an offline tool to spot a base shift even between
	 * two canonical-mode runs. */
	hdr.kaslr_base = kcov_kaslr_base_value();

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)mypid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(payload);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(payload);
		return false;
	}

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		free(payload);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (write_all(fd, payload, payload_bytes) < 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}
	free(payload);
	cmp_hints_generation_at_last_save = gen_now;
	output(0, "cmp-hints: snapshot saved (%lu entries across %u syscalls) to %s\n",
	       saved_entries, populated_pools, path);
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(payload);
	return false;
}

/* Per-entry sanity: a valid record has size in {1,2,4,8}, a non-zero
 * non-sentinel cmp_ip, and no all-ones sentinel value.  An invalid
 * slot is dropped and bumps cmp_hints_load_rejected_entries; the
 * surrounding pool keeps loading.  cmp_ip is permitted to be zero
 * only at offsets past the persisted count (i.e. the zero-padded
 * tail of the slice).  Under canonical mode (kcov_kaslr_base != 0
 * at save time) the on-disk cmp_ip is a small offset from the
 * runtime _text base, not a high-half kernel address; the zero /
 * all-ones gates here stay correct in either mode because they
 * reject the same two sentinels. */
static bool cmp_hints_entry_valid(const struct cmp_hints_entry_ondisk *e)
{
	if (e->size != 1 && e->size != 2 && e->size != 4 && e->size != 8)
		return false;
	if (e->cmp_ip == 0 || e->cmp_ip == (uint64_t)-1)
		return false;
	if (e->value == (uint64_t)-1)
		return false;
	return true;
}

/*
 * Phase 1 of cmp_hints_load_file(): the open + header-validation
 * gauntlet.  Performs the cheap preflight (null guards, stale-tmp
 * sweep, kallsyms fingerprint capture), opens the persisted state
 * file, reads the on-disk header, and checks every field against
 * the running build (magic, version, max_syscall, per_syscall,
 * entry_size, payload_bytes, and finally the SHA-256 of
 * /proc/kallsyms).  Each rejection emits the same diagnostic line
 * as the original inline code and trips a cold start.
 *
 * On success returns true with *hdr filled and *fd_out holding an
 * open file descriptor positioned just past the header (the caller
 * owns the fd and must close it as part of the payload phase).
 * On failure returns false with no resources held by the caller --
 * if the fd was opened the helper closed it before returning.
 */
static bool cmp_hints_load_file_header(const char *path,
				       struct cmp_hints_file_header *hdr,
				       int *fd_out)
{
	uint8_t cur_fp[32];
	size_t payload_bytes;
	ssize_t n;
	int fd;

	if (path == NULL || cmp_hints_shm == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	if (!kcov_get_kernel_fp(cur_fp)) {
		output(0, "cmp-hints: cannot fingerprint kernel (/proc/kallsyms unavailable) -- warm-start disabled this run\n");
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "cmp-hints: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "cmp-hints: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	n = read_all(fd, hdr, sizeof(*hdr));
	if (n != (ssize_t)sizeof(*hdr)) {
		output(0, "cmp-hints: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(*hdr));
		(void)close(fd);
		return false;
	}

	if (hdr->magic != CMP_HINTS_FILE_MAGIC) {
		output(0, "cmp-hints: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr->magic, CMP_HINTS_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr->version != CMP_HINTS_FILE_VERSION) {
		output(0, "cmp-hints: file version %u != expected %u at %s -- cold start\n",
		       hdr->version, CMP_HINTS_FILE_VERSION, path);
		(void)close(fd);
		return false;
	}
	if (hdr->max_syscall != MAX_NR_SYSCALL) {
		output(0, "cmp-hints: max_syscall %u != expected %u at %s (file built with a different MAX_NR_SYSCALL) -- cold start\n",
		       hdr->max_syscall, MAX_NR_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr->per_syscall != CMP_HINTS_PER_SYSCALL) {
		output(0, "cmp-hints: per_syscall %u != expected %u at %s (file built with a different CMP_HINTS_PER_SYSCALL) -- cold start\n",
		       hdr->per_syscall, CMP_HINTS_PER_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr->entry_size != (uint32_t)sizeof(struct cmp_hints_entry_ondisk)) {
		output(0, "cmp-hints: entry_size %u != expected %zu at %s (file built with a different on-disk record layout) -- cold start\n",
		       hdr->entry_size,
		       sizeof(struct cmp_hints_entry_ondisk), path);
		(void)close(fd);
		return false;
	}
	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 *
			sizeof(struct cmp_hints_pool_ondisk);
	if (hdr->payload_bytes != payload_bytes) {
		output(0, "cmp-hints: payload_bytes %llu != expected %zu at %s -- cold start\n",
		       (unsigned long long)hdr->payload_bytes, payload_bytes,
		       path);
		(void)close(fd);
		return false;
	}
	if (memcmp(hdr->kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "cmp-hints: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		(void)close(fd);
		return false;
	}
	/* Pool entries are keyed by canonical cmp_ip (raw runtime PC minus
	 * the writer's KASLR base) when hdr->kaslr_base != 0, and by raw
	 * PC otherwise.  This run's collector applies the same transform
	 * against the local kcov_kaslr_base, so the two must agree on
	 * whether canonicalisation is in effect at all -- any XOR mismatch
	 * means one side is canonical and the other raw, and the
	 * (cmp_ip, value, size) keys would silently disagree.  Both-
	 * canonical (regardless of which base each used) and both-raw are
	 * accepted; the cmp_ip keys line up because each side strips its
	 * own local base.  Mirrors the kcov-bitmap warm-start guard. */
	if ((hdr->kaslr_base != 0) != (kcov_kaslr_base_value() != 0)) {
		output(0, "cmp-hints: canonicalisation mismatch at %s (file kaslr_base=0x%llx, current=0x%llx) -- refusing stale pool, cold start\n",
		       path,
		       (unsigned long long)hdr->kaslr_base,
		       (unsigned long long)kcov_kaslr_base_value());
		(void)close(fd);
		return false;
	}

	*fd_out = fd;
	return true;
}

/*
 * Phase 2 of cmp_hints_load_file(): the payload allocation, read,
 * and CRC verification.  Takes ownership of the fd handed off by
 * cmp_hints_load_file_header() -- on every exit path the fd is
 * closed exactly once, matching the original inline lifecycle
 * (close after a successful read_all, close after the alloc-fail
 * / read-fail branches).  payload_bytes is recomputed locally
 * from MAX_NR_SYSCALL and the on-disk record size; the header
 * phase already validated hdr->payload_bytes against that same
 * expression, so the two values are equal by construction.
 *
 * On success returns true with *payload_out pointing at a
 * freshly malloc'd buffer the caller owns and must free.  On
 * failure returns false with no resources held by the caller --
 * any allocation made by the helper has already been free()d and
 * the fd is closed.
 */
static bool cmp_hints_load_file_payload(const char *path, int fd,
					const struct cmp_hints_file_header *hdr,
					struct cmp_hints_pool_ondisk **payload_out)
{
	struct cmp_hints_pool_ondisk *payload;
	size_t payload_bytes;
	uint32_t want_crc;
	ssize_t n;

	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 * sizeof(*payload);
	payload = malloc(payload_bytes);
	if (payload == NULL) {
		output(0, "cmp-hints: payload alloc fail (%zu bytes) -- cold start\n",
		       payload_bytes);
		(void)close(fd);
		return false;
	}
	n = read_all(fd, payload, payload_bytes);
	if (n != (ssize_t)payload_bytes) {
		output(0, "cmp-hints: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, payload_bytes);
		free(payload);
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = crc32(payload, payload_bytes);
	if (want_crc != hdr->payload_crc32) {
		output(0, "cmp-hints: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(payload);
		return false;
	}

	*payload_out = payload;
	return true;
}

/*
 * Phase 3 of cmp_hints_load_file(): copy the validated payload
 * into the in-memory shm pools.  Past the header / fingerprint /
 * CRC gates the payload is considered authoritative against the
 * running kernel; this loop still skips any individual slot that
 * fails the per-entry bounds check so a single bit-rotted record
 * doesn't sink the whole warm-start.  The payload is a flat
 * array of 2 * MAX_NR_SYSCALL slots laid out as [i * 2 + a]
 * matching the memory layout of pools[i][a]; the inner do32
 * dimension is folded into a flat walk here for symmetry with
 * the serialise path.
 *
 * Counters are returned via out-params: loaded_entries is the
 * sum of successfully copied slots, populated_pools is the
 * number of pools that received at least one entry, and rejected
 * accumulates both whole-pool drops (src_count past the cap) and
 * per-slot validation failures.
 */
static void cmp_hints_load_file_restore_pools(const struct cmp_hints_pool_ondisk *payload,
					      unsigned long *loaded_entries_out,
					      unsigned int *populated_pools_out,
					      unsigned long *rejected_out)
{
	unsigned long loaded_entries = 0;
	unsigned long rejected = 0;
	unsigned int populated_pools = 0;
	unsigned int i, j;

	for (i = 0; i < MAX_NR_SYSCALL * 2; i++) {
		unsigned int nr = i / 2;
		unsigned int a = i & 1;
		struct cmp_hint_pool *pool = &cmp_hints_shm->pools[nr][a];
		const struct cmp_hints_pool_ondisk *src = &payload[i];
		unsigned int src_count = src->count;
		unsigned int dst_count = 0;
		uint64_t max_stamp = 0;

		if (src_count > CMP_HINTS_PER_SYSCALL) {
			rejected += src_count;
			continue;
		}
		if (src_count == 0)
			continue;

		pool_lock(pool);
		for (j = 0; j < src_count; j++) {
			if (!cmp_hints_entry_valid(&src->entries[j])) {
				rejected++;
				continue;
			}
			pool->entries[dst_count].value     = src->entries[j].value;
			pool->entries[dst_count].cmp_ip    = src->entries[j].cmp_ip;
			pool->entries[dst_count].size      = src->entries[j].size;
			pool->entries[dst_count].last_used = src->entries[j].last_used;
			if (src->entries[j].last_used > max_stamp)
				max_stamp = src->entries[j].last_used;
			dst_count++;
		}
		__atomic_store_n(&pool->generation, src->generation,
				 __ATOMIC_RELAXED);
		/* Seed the per-pool LRU clock to the max last_used we just loaded
		 * so fresh inserts after warm-start get strictly larger stamps
		 * and don't appear LRU-older than the warm-started entries (which
		 * would invert the eviction order and let new traffic immediately
		 * evict the just-loaded pool). */
		pool->last_used_stamp = max_stamp;
		__atomic_store_n(&pool->count, dst_count, __ATOMIC_RELEASE);
		pool_unlock(pool);

		if (dst_count > 0) {
			loaded_entries += dst_count;
			populated_pools++;
		}
	}

	*loaded_entries_out = loaded_entries;
	*populated_pools_out = populated_pools;
	*rejected_out = rejected;
}

/*
 * Phase 4 of cmp_hints_load_file(): post-restore bookkeeping and
 * the operator-facing summary lines.  Stamps the global
 * rejected-entries counter with whatever the restore loop
 * accumulated, seeds the dirty-bit baseline so a
 * load-then-immediate-exit cycle skips the redundant end-of-run
 * save (the restore loop already populated each
 * pool->generation from disk, so the live sum exactly reflects
 * the just-loaded state), and emits the one-line summary plus
 * the optional second line that fires only when at least one
 * record was rejected.  The payload buffer is freed by the
 * orchestrator before this helper runs so the success path
 * holds no transient allocations during the output() calls.
 */
static void cmp_hints_load_file_finalize(const char *path,
					 unsigned long loaded_entries,
					 unsigned int populated_pools,
					 unsigned long rejected)
{
	cmp_hints_load_rejected_entries = rejected;
	cmp_hints_generation_at_last_save = cmp_hints_total_generation();
	output(0, "cmp-hints: loaded %lu entries across %u syscalls from %s%s\n",
	       loaded_entries, populated_pools, path,
	       rejected ? " (rejected entries on warm-start: see counter)" : "");
	if (rejected != 0)
		output(0, "cmp-hints: %lu on-disk entries rejected by per-slot validation\n",
		       rejected);
}

bool cmp_hints_load_file(const char *path)
{
	struct cmp_hints_file_header hdr;
	struct cmp_hints_pool_ondisk *payload = NULL;
	unsigned long rejected = 0;
	unsigned long loaded_entries = 0;
	unsigned int populated_pools = 0;
	int fd;

	if (!cmp_hints_load_file_header(path, &hdr, &fd))
		return false;

	if (!cmp_hints_load_file_payload(path, fd, &hdr, &payload))
		return false;

	cmp_hints_load_file_restore_pools(payload, &loaded_entries,
					  &populated_pools, &rejected);

	free(payload);
	cmp_hints_load_file_finalize(path, loaded_entries, populated_pools,
				     rejected);
	return true;
}

const char *cmp_hints_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	char release[256];
	int ret;
	int rfd;
	ssize_t rn;
	char *nl;

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

	rfd = open("/proc/sys/kernel/osrelease", O_RDONLY);
	if (rfd < 0)
		return NULL;
	rn = read(rfd, release, sizeof(release) - 1);
	(void)close(rfd);
	if (rn <= 0)
		return NULL;
	release[rn] = '\0';
	nl = strchr(release, '\n');
	if (nl != NULL)
		*nl = '\0';
	for (nl = release; *nl; nl++) {
		if (*nl == '/')
			*nl = '_';
	}

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/cmp-hints", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/cmp-hints", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

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

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
		       dir, arch, release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic mid-run snapshot trigger.  Called only from parent context
 * (main_loop's stats tick), so the snapshot state lives in parent-
 * private statics -- no CAS race with children to worry about.
 *
 * Cadence is driven off the sum of pool->generation across all
 * MAX_NR_SYSCALL pools.  generation increments only on real pool
 * content changes (insert or evict-replace) under pool->lock; summing
 * it gives a cheap monotonically-non-decreasing proxy for "how many
 * novel CMP records did the children fold into the pool since we last
 * snapshotted".  Recomputing the sum on every tick is
 * O(MAX_NR_SYSCALL) of plain unsigned-int reads, well below the tick
 * budget.
 */
static char cmp_hints_snapshot_path[PATH_MAX];
static bool cmp_hints_snapshot_enabled;
static unsigned long cmp_hints_generation_at_last_snapshot;
static time_t cmp_hints_last_snapshot_time;

static unsigned long cmp_hints_total_generation(void)
{
	unsigned long sum = 0;
	unsigned int i, a;

	if (cmp_hints_shm == NULL)
		return 0;
	for (i = 0; i < MAX_NR_SYSCALL; i++)
		for (a = 0; a < 2; a++)
			sum += __atomic_load_n(&cmp_hints_shm->pools[i][a].generation,
					       __ATOMIC_RELAXED);
	return sum;
}

void cmp_hints_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(cmp_hints_snapshot_path))
		return;
	memcpy(cmp_hints_snapshot_path, path, len + 1);
	cmp_hints_snapshot_enabled = true;
	cmp_hints_last_snapshot_time = time(NULL);
	cmp_hints_generation_at_last_snapshot = cmp_hints_total_generation();
}

void cmp_hints_maybe_snapshot(void)
{
	unsigned long gen_now;
	time_t now;

	if (!cmp_hints_snapshot_enabled || cmp_hints_shm == NULL)
		return;

	gen_now = cmp_hints_total_generation();
	now = time(NULL);

	/* Both gates must expire before a snapshot fires: enough generations
	 * (so we don't write a near-identical payload to disk) AND enough
	 * wall time (so a high-churn period doesn't trigger one save per
	 * second).  The original && meant either gate alone could fire;
	 * with generation now advancing only on real content changes the
	 * generation gate stays quiet once the pools saturate, but during
	 * the initial fill it would still over-fire without the time gate. */
	if (gen_now < cmp_hints_generation_at_last_snapshot
			+ CMP_HINTS_SNAPSHOT_NEW ||
	    now < cmp_hints_last_snapshot_time
			+ (time_t)CMP_HINTS_SNAPSHOT_INTERVAL_SEC)
		return;

	if (cmp_hints_save_file(cmp_hints_snapshot_path)) {
		cmp_hints_generation_at_last_snapshot = gen_now;
		cmp_hints_last_snapshot_time = now;
	}
}
