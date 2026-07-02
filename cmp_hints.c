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
static bool cmp_hints_strip[2][MAX_NR_SYSCALL];

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
 * SHADOW typed-hypothesis inference.
 *
 * Called from cmp_hints_flush_pending() once per fresh durable-pool
 * insert, still under that pool's lock -- so writes into
 * hyp_pools[nr][do32 ? 1 : 0] are serialised per-(nr, do32) without a
 * second lock of our own.  Every observation drives one or more typed
 * lanes (EXACT / BITMASK / ENUM_FAMILY / RANGE), subject to the
 * per-kind + per-syscall caps the skeleton reserved.  The resulting
 * hypotheses stay in CMP_HYP_STATE_OBSERVED: no consumer reads them
 * and no injection path substitutes a hypothesis-derived value -- the
 * candidate-API + feedback wiring lands in the follow-up units.
 */
static struct cmp_hypothesis *cmp_hyp_find(struct cmp_hyp_pool *pool,
					   enum cmp_hypothesis_kind kind,
					   unsigned long cmp_ip, uint8_t width)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == kind && h->cmp_ip == cmp_ip && h->width == width)
			return h;
	}
	return NULL;
}

static struct cmp_hypothesis *cmp_hyp_find_exact(struct cmp_hyp_pool *pool,
						 unsigned long cmp_ip,
						 uint8_t width, uint64_t value)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind == CMP_HYP_EXACT && h->cmp_ip == cmp_ip
		    && h->width == width && h->exemplar == value)
			return h;
	}
	return NULL;
}

/*
 * Infer the RANGE-identity discriminators (direction / signedness /
 * relation-class) from an ENUM_FAMILY cluster summary at the same
 * (cmp_ip, width).  KCOV does NOT expose the kernel-side compare
 * operator -- direction is APPROXIMATE.  The heuristic: if the
 * most-recent exemplar sits at the high end of the cluster, treat the
 * probe as ASCENDING (kernel keeps comparing against a rising bound);
 * at the low end, DESCENDING; otherwise UNKNOWN so an un-inferable
 * probe is bucketed honestly rather than force-fit to a guess.
 *
 * Signedness: a bound whose sign bit (relative to its width) is set
 * cannot legitimately share identity with an unsigned probe that
 * happens to have the same numeric value -- a u8 hi=0xFF and an s8
 * hi=-1 are different probes.  Conservative classifier: SIGNED if
 * either bound has the width's sign bit set, else UNSIGNED.
 *
 * Relation: only INSIDE is reachable from the observer side -- KCOV
 * gives us matching operand values, not edge-rejection events.  The
 * OUTSIDE / BOUND / WRAP buckets exist for the future consumer-side
 * probe ladder and stay zero here.
 */
static void cmp_hyp_range_identity_infer(uint64_t lo, uint64_t hi,
					 uint8_t width,
					 const struct cmp_hypothesis *src,
					 uint8_t *out_dir, uint8_t *out_sign,
					 uint8_t *out_rel)
{
	uint64_t sign_bit;

	if (src != NULL && src->seen_count >= 3 && hi > lo) {
		uint64_t ex = src->exemplar;

		if (ex == hi)
			*out_dir = CMP_RANGE_DIR_ASCENDING;
		else if (ex == lo)
			*out_dir = CMP_RANGE_DIR_DESCENDING;
		else
			*out_dir = CMP_RANGE_DIR_UNKNOWN;
	} else {
		*out_dir = CMP_RANGE_DIR_UNKNOWN;
	}

	sign_bit = 1ULL << (width * 8U - 1U);
	if ((lo & sign_bit) != 0 || (hi & sign_bit) != 0)
		*out_sign = CMP_RANGE_SIGN_SIGNED;
	else
		*out_sign = CMP_RANGE_SIGN_UNSIGNED;

	*out_rel = CMP_RANGE_REL_INSIDE;
}

/*
 * RANGE dedup by inferred identity, NOT cmp_ip: two comparison sites
 * that observe the same logical range probe (same bounds, same
 * inferred direction, same width / signedness / relation-class)
 * collapse to ONE entry, and value churn at a single site that does
 * not shift the bounds folds into the same slot.  Bounds are part of
 * identity rather than payload, so a probe whose bounds drift even
 * one step apart is keyed as a distinct hypothesis.
 */
static struct cmp_hypothesis *
cmp_hyp_find_range_by_identity(struct cmp_hyp_pool *pool, uint64_t lo,
			       uint64_t hi, uint8_t width, uint8_t dir,
			       uint8_t sign, uint8_t rel)
{
	unsigned int i, n = pool->count;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->kind != CMP_HYP_RANGE || h->width != width)
			continue;
		if (h->lo != lo || h->hi != hi)
			continue;
		if (h->range_direction != dir
		    || h->range_signedness != sign
		    || h->range_relation != rel)
			continue;
		return h;
	}
	return NULL;
}

/*
 * Allocate a fresh hypothesis slot honouring the per-kind sub-cap and
 * the per-syscall total cap.  Returns NULL when either is exhausted
 * and bumps the matching kcov_shm saturation counter so the rejection
 * is visible.  The slot is memset and pre-stamped with identity
 * fields the caller does not have to re-write.
 */
static struct cmp_hypothesis *cmp_hyp_alloc(struct cmp_hyp_pool *pool,
					    enum cmp_hypothesis_kind kind,
					    unsigned int nr, bool do32,
					    unsigned long cmp_ip, uint8_t width)
{
	struct cmp_hypothesis *h;

	if (pool->count >= CMP_HYP_PER_SYSCALL) {
		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_hyp_pool_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_pool_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		}
		return NULL;
	}
	if (pool->per_kind_count[kind] >= CMP_HYP_PER_KIND) {
		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_hyp_kind_full, 1UL,
					   __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->cmp_hyp_kind_full_by_kind[kind],
					   1UL, __ATOMIC_RELAXED);
		}
		return NULL;
	}

	h = &pool->entries[pool->count];
	memset(h, 0, sizeof(*h));
	h->nr = nr;
	h->do32 = do32;
	h->width = width;
	h->kind = (uint8_t)kind;
	h->state = CMP_HYP_STATE_OBSERVED;
	h->cmp_ip = (uint64_t)cmp_ip;
	pool->per_kind_count[kind]++;
	pool->count++;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hyp_inserted, 1UL,
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_hyp_inserted_by_kind[kind],
				   1UL, __ATOMIC_RELAXED);
	}
	return h;
}

void cmp_hyp_observe(unsigned int nr, bool do32, unsigned long cmp_ip,
		     unsigned long value, unsigned int size)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h, *e;
	uint64_t val = (uint64_t)value;
	uint64_t generation = 0;
	uint8_t width;
	bool single_bit;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_observations, 1UL,
				   __ATOMIC_RELAXED);

	/* Wild-write defence: a stomp past the per-syscall cap would let
	 * the find/alloc scans walk off entries[].  Bail and surface it on
	 * the sibling cmp_hyp_pool_overflow counter -- distinct from the
	 * cmp_hyp_pool_full saturation lane so a corruption channel cannot
	 * hide inside legitimate back-pressure. */
	if (pool->count > CMP_HYP_PER_SYSCALL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hyp_pool_overflow, 1UL,
					   __ATOMIC_RELAXED);
		return;
	}

	/* The durable pool's generation, advanced in lock-step with the
	 * insert that triggered this observation, is a stable monotonic
	 * clock to stamp last_used_generation against.  Same lock window,
	 * so a plain read is consistent. */
	generation = cmp_hints_shm->pools[nr][do32 ? 1 : 0].generation;

	/*
	 * EXACT lane: per-value identity.  A repeat observation refreshes
	 * seen_count + last_used_generation; a fresh value tries to take a
	 * slot (subject to the per-kind cap of 2).
	 */
	h = cmp_hyp_find_exact(pool, cmp_ip, width, val);
	if (h != NULL) {
		h->seen_count++;
		h->last_used_generation = generation;
	} else {
		h = cmp_hyp_alloc(pool, CMP_HYP_EXACT, nr, do32, cmp_ip, width);
		if (h != NULL) {
			h->exemplar = val;
			h->lo = val;
			h->hi = val;
			h->seen_count = 1;
			h->last_used_generation = generation;
		}
	}

	/* BITMASK lane: only single-bit observations contribute.  A zero
	 * carries no bit; a multi-bit value would conflate single-bit
	 * evidence with combined-flag exemplars -- those belong to ENUM_FAMILY
	 * below so the consumer side can keep the two scoring families
	 * separate (one-unknown-bit probes vs combination probes). */
	single_bit = (val != 0) && ((val & (val - 1)) == 0);
	if (single_bit) {
		h = cmp_hyp_find(pool, CMP_HYP_BITMASK, cmp_ip, width);
		if (h != NULL) {
			h->mask |= val;
			h->seen_count++;
			if (val < h->lo)
				h->lo = val;
			if (val > h->hi)
				h->hi = val;
			h->exemplar = val;
			h->last_used_generation = generation;
		} else {
			h = cmp_hyp_alloc(pool, CMP_HYP_BITMASK, nr, do32,
					  cmp_ip, width);
			if (h != NULL) {
				h->mask = val;
				h->lo = val;
				h->hi = val;
				h->exemplar = val;
				h->seen_count = 1;
				h->last_used_generation = generation;
			}
		}
	}

	/*
	 * ENUM_FAMILY lane: every observation at (cmp_ip, width) folds into
	 * the per-key cluster summary (lo/hi/mask/seen_count, exemplar =
	 * most-recent).  Distinct from EXACT (per-value dedup) and from
	 * BITMASK (single-bit-only), and deliberately NOT collapsed into
	 * RANGE -- {1, 2, 3} may be three independent modes, not an interval,
	 * so promotion is left to the feedback unit's outcome scoring.
	 */
	e = cmp_hyp_find(pool, CMP_HYP_ENUM_FAMILY, cmp_ip, width);
	if (e != NULL) {
		e->seen_count++;
		e->mask |= val;
		if (val < e->lo)
			e->lo = val;
		if (val > e->hi)
			e->hi = val;
		e->exemplar = val;
		e->last_used_generation = generation;
	} else {
		e = cmp_hyp_alloc(pool, CMP_HYP_ENUM_FAMILY, nr, do32,
				  cmp_ip, width);
		if (e != NULL) {
			e->lo = val;
			e->hi = val;
			e->mask = val;
			e->exemplar = val;
			e->seen_count = 1;
			e->last_used_generation = generation;
		}
	}

	/*
	 * RANGE lane: synthesised only once the ENUM_FAMILY summary at the
	 * same key has accumulated enough observations to suggest a dense
	 * small interval (>= 3 hits, span 2..32).  The entry stays in
	 * CMP_HYP_STATE_OBSERVED -- the spec's promotion trap requires an
	 * interior non-constant pass OR an outside-reject + multiple
	 * inside-passes, which only the outcome-credited feedback unit can
	 * supply.  The probe ladder (lo-1, lo, lo+1, midpoint, hi-1, hi,
	 * hi+1, plus exponential probing when the high side is unknown) is
	 * implicit in {lo, hi}; the consumer derives it at pick time so the
	 * shadow store does not need to materialise it.
	 *
	 * Dedup key is an inferred RANGE-IDENTITY tuple {lo, hi, direction,
	 * width, signedness, relation-class}, NOT cmp_ip.  Two comparison
	 * sites that produce the same logical range probe -- regardless of
	 * the literal constants the kernel happened to compare against --
	 * collapse to ONE entry.  Width and signedness are part of the
	 * identity (per the discriminated-arg discipline): a u32 range and
	 * a u64 range with the same numeric bounds are not the same probe.
	 * Direction is APPROXIMATE -- KCOV cannot recover the operator --
	 * and CMP_RANGE_DIR_UNKNOWN owns un-inferable probes so they are
	 * keyed honestly instead of force-fit to a guess.
	 *
	 * Bound math safety: the > 32 / <= early-bail above guarantees
	 * hi > lo at the subtraction site; the second-line check below
	 * defends against a torn read of an in-flight ENUM entry under
	 * the RELAXED reader discipline the rest of the shadow path uses.
	 */
	if (e == NULL || e->seen_count < 3 || e->hi <= e->lo
	    || (e->hi - e->lo) > 32) {
		goto boundary;
	}
	{
		uint64_t r_lo = e->lo, r_hi = e->hi;
		uint8_t dir, sign, rel;

		if (r_hi < r_lo)
			goto boundary;

		cmp_hyp_range_identity_infer(r_lo, r_hi, width, e,
					     &dir, &sign, &rel);
		h = cmp_hyp_find_range_by_identity(pool, r_lo, r_hi, width,
						   dir, sign, rel);
		if (h == NULL) {
			h = cmp_hyp_alloc(pool, CMP_HYP_RANGE, nr, do32,
					  cmp_ip, width);
			if (h != NULL) {
				h->range_direction = dir;
				h->range_signedness = sign;
				h->range_relation = rel;
				h->lo = r_lo;
				h->hi = r_hi;
			}
		}
		if (h != NULL) {
			h->exemplar = e->exemplar;
			h->seen_count = e->seen_count;
			h->last_used_generation = generation;
		}
	}

boundary:
	/*
	 * BOUNDARY lane: per-(cmp_ip, width) summary populated from a
	 * SINGLE const observation -- explicitly NOT gated on RANGE's
	 * seen_count >= 3 / span 2..32 rule, which is what starves the
	 * single-boundary inequality case (one inequality `x < N` at one
	 * site sees the same const N every fire -> span 0 -> RANGE never
	 * synthesises, even though N+/-1 is the value that passes).
	 * Shape mirrors ENUM_FAMILY's bookkeeping (exemplar = most-recent
	 * const, lo/hi = running min/max over consts seen at this key)
	 * but the BOUNDARY derive arm emits a neighbourhood ladder rather
	 * than interior members, hitting the strict-inequality boundary
	 * EXACT and RANGE both refuse to produce.
	 */
	{
		bool fresh_boundary = false;

		h = cmp_hyp_find(pool, CMP_HYP_BOUNDARY, cmp_ip, width);
		if (h == NULL) {
			h = cmp_hyp_alloc(pool, CMP_HYP_BOUNDARY, nr, do32,
					  cmp_ip, width);
			fresh_boundary = (h != NULL);
		}
		if (h != NULL) {
			if (fresh_boundary) {
				h->lo = val;
				h->hi = val;
				h->seen_count = 1;
			} else {
				if (val < h->lo)
					h->lo = val;
				if (val > h->hi)
					h->hi = val;
				h->seen_count++;
			}
			h->exemplar = val;
			h->last_used_generation = generation;
			if (fresh_boundary && kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_boundary_inserted,
					1UL, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Resolve the would-have-been-chosen hypothesis for a (cmp_ip, width,
 * value) tuple against the SHADOW hyp_pool at (nr, do32).  Walks the
 * pool once and returns the most-specific kind whose stored shape
 * explains the value: EXACT (exemplar == value) > ENUM_FAMILY (lo..hi
 * cluster containing value) > BITMASK (single-bit value set in mask)
 * > RANGE (lo..hi interval containing value).  Returns NULL if no
 * hypothesis at the matching (cmp_ip, width) explains the value -- the
 * picked constant pre-dates the inference layer or sits in a slot the
 * observer never fired, both of which are unobservable from the credit
 * side.  Same RELAXED-load discipline as the rest of the SHADOW reader
 * path: torn fields tolerate the consumer-side advisory contract.
 */
/*
 * BOUNDARY credit window: |value - exemplar| <= 2 explains values the
 * N-1 / N+1 / N+/-2 derive ladder produces.  The strict-inequality case
 * the lane is built for needs +/-1; the wider +/-2 slot covers the
 * sweep arm without inflating the window so far that an unrelated
 * value-near-N collision is plausibly attributable.  Matches the same
 * order of magnitude as the derive ladder.
 */
#define CMP_HYP_BOUNDARY_CREDIT_WINDOW 2U

static struct cmp_hypothesis *cmp_hyp_find_for_credit(struct cmp_hyp_pool *pool,
						      unsigned long cmp_ip,
						      uint8_t width,
						      uint64_t value)
{
	struct cmp_hypothesis *enum_match = NULL;
	struct cmp_hypothesis *bitmask_match = NULL;
	struct cmp_hypothesis *range_match = NULL;
	struct cmp_hypothesis *boundary_match = NULL;
	unsigned int i, n = pool->count;
	bool single_bit = (value != 0) && ((value & (value - 1)) == 0);

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];

		if (h->cmp_ip != (uint64_t)cmp_ip || h->width != width)
			continue;
		switch (h->kind) {
		case CMP_HYP_EXACT:
			if (h->exemplar == value)
				return h;
			break;
		case CMP_HYP_ENUM_FAMILY:
			if (value >= h->lo && value <= h->hi && enum_match == NULL)
				enum_match = h;
			break;
		case CMP_HYP_BITMASK:
			if (single_bit && (h->mask & value) != 0
			    && bitmask_match == NULL)
				bitmask_match = h;
			break;
		case CMP_HYP_RANGE:
			if (value >= h->lo && value <= h->hi && range_match == NULL)
				range_match = h;
			break;
		case CMP_HYP_BOUNDARY:
			if (boundary_match == NULL) {
				uint64_t ex = h->exemplar;
				uint64_t d = (value >= ex)
					? (value - ex)
					: (ex - value);

				if (d <= CMP_HYP_BOUNDARY_CREDIT_WINDOW)
					boundary_match = h;
			}
			break;
		default:
			break;
		}
	}
	if (enum_match != NULL)
		return enum_match;
	if (bitmask_match != NULL)
		return bitmask_match;
	if (range_match != NULL)
		return range_match;
	if (boundary_match != NULL && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_boundary_credit_window_hits,
				   1UL, __ATOMIC_RELAXED);
	return boundary_match;
}

/*
 * Per-outcome counter selector.  Returns the per-hypothesis u64 field
 * to bump for OUTCOME; a returned NULL means the outcome falls outside
 * the published menu (caller treats as a no-op so a future enumerator
 * addition that forgets a matching arm here surfaces as a quiet skip
 * rather than an out-of-bounds write).
 */
static uint64_t *cmp_hyp_outcome_field(struct cmp_hypothesis *h,
				       enum cmp_hyp_outcome outcome)
{
	switch (outcome) {
	case CMP_HYP_OUTCOME_PC_WIN:		return &h->pc_wins;
	case CMP_HYP_OUTCOME_TRANSITION_WIN:	return &h->transition_wins;
	case CMP_HYP_OUTCOME_CMP_NOVELTY:	return &h->cmp_novelty_wins;
	case CMP_HYP_OUTCOME_CORPUS_SAVE:	return &h->corpus_save_wins;
	case CMP_HYP_OUTCOME_MISS:		return &h->misses;
	case CMP_HYP_OUTCOME_DISABLED:		return &h->disabled_skips;
	case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:	return &h->destructive_skips;
	case CMP_HYP_OUTCOME_CONTEXT_SKIP:	return &h->context_skips;
	case CMP_HYP_OUTCOME_NR:
	default:
		return NULL;
	}
}

/*
 * Map an outcome onto the matching kcov_shm flat counter so the
 * fleet-level rollup tracks the per-hypothesis credit.
 */
static unsigned long *cmp_hyp_outcome_flat(enum cmp_hyp_outcome outcome)
{
	if (kcov_shm == NULL)
		return NULL;
	switch (outcome) {
	case CMP_HYP_OUTCOME_PC_WIN:		return &kcov_shm->cmp_hyp_pc_wins;
	case CMP_HYP_OUTCOME_TRANSITION_WIN:	return &kcov_shm->cmp_hyp_transition_wins;
	case CMP_HYP_OUTCOME_CMP_NOVELTY:	return &kcov_shm->cmp_hyp_cmp_novelty_wins;
	case CMP_HYP_OUTCOME_CORPUS_SAVE:	return &kcov_shm->cmp_hyp_corpus_save;
	case CMP_HYP_OUTCOME_MISS:		return &kcov_shm->cmp_hyp_misses;
	case CMP_HYP_OUTCOME_DISABLED:		return &kcov_shm->cmp_hyp_disabled_skips;
	case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:	return &kcov_shm->cmp_hyp_destructive;
	case CMP_HYP_OUTCOME_CONTEXT_SKIP:	return &kcov_shm->cmp_hyp_context_skip;
	default:
		return NULL;
	}
}

void cmp_hyp_credit_outcome(unsigned int nr, bool do32, unsigned long cmp_ip,
			    unsigned long value, unsigned int size,
			    enum cmp_hyp_outcome outcome)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h;
	uint64_t *field;
	unsigned long *flat;
	uint8_t width;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;
	if ((unsigned int)outcome >= CMP_HYP_OUTCOME_NR)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	/* Lock-free read against the parallel hyp_pool grid.  Writers
	 * (cmp_hyp_observe) run under the matching durable cmp_hint_pool
	 * lock so a torn count or a half-written entry is possible from
	 * this side; the find walk tolerates both -- a misread kind /
	 * exemplar at worst drops the credit, never indexes off the
	 * array thanks to the count > cap bail. */
	h = cmp_hyp_find_for_credit(pool, cmp_ip, width, (uint64_t)value);
	if (h == NULL)
		return;

	field = cmp_hyp_outcome_field(h, outcome);
	if (field == NULL)
		return;
	__atomic_fetch_add(field, 1UL, __ATOMIC_RELAXED);

	flat = cmp_hyp_outcome_flat(outcome);
	if (flat != NULL)
		__atomic_fetch_add(flat, 1UL, __ATOMIC_RELAXED);

	/*
	 * Per-syscall + per-kind outcome partition.  Strictly additive
	 * mirrors of the flat outcome counter just bumped above; the
	 * per-syscall arrays are paired with per_syscall_cmp_injected /
	 * per_syscall_cmp_hint_pc_wins so the cmp-frontier weight can
	 * route on a real conversion rate, and the per-kind arrays let
	 * the periodic dump answer "which kind is actually converting"
	 * without a separate hyp-pool walk.  Only the outcome channels
	 * that exist as per-syscall partitions today bump per-syscall;
	 * per-kind covers every kind-relevant outcome.
	 */
	if (kcov_shm != NULL) {
		unsigned long *per_nr_field = NULL;

		switch (outcome) {
		case CMP_HYP_OUTCOME_TRANSITION_WIN:
			per_nr_field = &kcov_shm->per_syscall_cmp_hint_transition_wins[nr];
			break;
		case CMP_HYP_OUTCOME_MISS:
			per_nr_field = &kcov_shm->per_syscall_cmp_hint_misses[nr];
			break;
		case CMP_HYP_OUTCOME_CORPUS_SAVE:
			per_nr_field = &kcov_shm->per_syscall_cmp_hint_corpus_saves[nr];
			break;
		case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:
			per_nr_field = &kcov_shm->per_syscall_cmp_hint_destructive_skips[nr];
			break;
		case CMP_HYP_OUTCOME_CMP_NOVELTY:
			per_nr_field = &kcov_shm->per_syscall_cmp_hint_cmp_novelty_wins[nr];
			break;
		default:
			break;
		}
		if (per_nr_field != NULL)
			__atomic_fetch_add(per_nr_field, 1UL, __ATOMIC_RELAXED);

		if (h->kind < CMP_HYP_KIND_NR) {
			unsigned long *per_kind_field = NULL;

			switch (outcome) {
			case CMP_HYP_OUTCOME_PC_WIN:
				per_kind_field = &kcov_shm->cmp_hyp_pc_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_TRANSITION_WIN:
				per_kind_field = &kcov_shm->cmp_hyp_transition_wins_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_MISS:
				per_kind_field = &kcov_shm->cmp_hyp_misses_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CORPUS_SAVE:
				per_kind_field = &kcov_shm->cmp_hyp_corpus_save_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_destructive_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CONTEXT_SKIP:
				per_kind_field = &kcov_shm->cmp_hyp_context_skip_by_kind[h->kind];
				break;
			case CMP_HYP_OUTCOME_CMP_NOVELTY:
				per_kind_field = &kcov_shm->cmp_hyp_cmp_novelty_wins_by_kind[h->kind];
				break;
			default:
				break;
			}
			if (per_kind_field != NULL)
				__atomic_fetch_add(per_kind_field, 1UL, __ATOMIC_RELAXED);
		}
	}

	/*
	 * SHADOW scoring pass.  Recompute h->score_bucket from the per-hyp
	 * evidence counters just bumped above, and evaluate the would-
	 * promote / would-demote predicate the live state machine will
	 * eventually own.  Pure observation: h->state is NOT mutated and
	 * remains CMP_HYP_STATE_OBSERVED for every entry.  The bucket
	 * write is u8 and never read by the pick/inject path; the kcov_shm
	 * arrays are SHADOW telemetry.
	 *
	 * Counters are loaded RELAXED -- they race with concurrent
	 * credit_outcome() calls on the same hyp from sibling children.
	 * A torn read at worst computes a slightly stale bucket / mis-
	 * attributes one promote-vs-demote bump; both lanes converge as
	 * subsequent credits land.
	 *
	 *   wins = pc_wins + transition_wins + corpus_save_wins
	 *   pen  = misses + disabled_skips + destructive_skips + context_skips
	 *
	 * cmp_novelty_wins is intentionally excluded from both sides per the
	 * [11-feedback-loop] discipline that keeps CMP-novelty separate from
	 * PC-edge conversion.
	 *
	 * Bucketing (8 bands, fits in u8):
	 *   0  idle  (wins == 0 && pen == 0)
	 *   1  penalty-only (wins == 0, pen >= 1)
	 *   2  heavy net-negative (pen >= wins + 4)
	 *   3  slight net-negative (wins < pen < wins + 4)
	 *   4  break-even (wins == pen, both >= 1)
	 *   5  small net-positive (1 <= wins - pen < 4)
	 *   6  moderate net-positive (4 <= wins - pen < 16)
	 *   7  strong net-positive (wins - pen >= 16)
	 *
	 * Underflow on `wins - pen` is guarded by the pen-side branches
	 * above it -- bands 5..7 only execute when wins > pen.
	 */
	{
		uint64_t pc = __atomic_load_n(&h->pc_wins, __ATOMIC_RELAXED);
		uint64_t tr = __atomic_load_n(&h->transition_wins,
					      __ATOMIC_RELAXED);
		uint64_t cs = __atomic_load_n(&h->corpus_save_wins,
					      __ATOMIC_RELAXED);
		uint64_t ms = __atomic_load_n(&h->misses, __ATOMIC_RELAXED);
		uint64_t ds = __atomic_load_n(&h->disabled_skips,
					      __ATOMIC_RELAXED);
		uint64_t xs = __atomic_load_n(&h->destructive_skips,
					      __ATOMIC_RELAXED);
		uint64_t ks = __atomic_load_n(&h->context_skips,
					      __ATOMIC_RELAXED);
		uint64_t wins = pc + tr + cs;
		uint64_t pen = ms + ds + xs + ks;
		uint8_t bucket;
		bool would_promote = (pc | tr | cs) != 0;
		bool would_demote = !would_promote && ms >= 8;

		if (wins == 0)
			bucket = (pen == 0) ? 0 : 1;
		else if (pen >= wins + 4)
			bucket = 2;
		else if (pen > wins)
			bucket = 3;
		else if (pen == wins)
			bucket = 4;
		else if (wins - pen < 4)
			bucket = 5;
		else if (wins - pen < 16)
			bucket = 6;
		else
			bucket = 7;
		__atomic_store_n(&h->score_bucket, bucket, __ATOMIC_RELAXED);

		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_score_bucket_census[bucket],
				1UL, __ATOMIC_RELAXED);

		if (kcov_shm != NULL && h->kind < CMP_HYP_KIND_NR) {
			if (would_promote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_would_promote_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
			else if (would_demote)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_would_demote_by_kind[h->kind],
					1UL, __ATOMIC_RELAXED);
		}

		/*
		 * Live h->state mutation.  The would_promote / would_demote
		 * predicates above were stranded telemetry until now; here
		 * we drive the real state-machine transition off them so
		 * the picker (next commit) can route on h->state.
		 *
		 *   OBSERVED + would_promote  -> PROMOTED  (first win)
		 *   DEMOTED  + would_promote  -> OBSERVED  (revive --
		 *                                earn promotion again)
		 *   OBSERVED + would_demote   -> DEMOTED
		 *   DEMOTED  + sustained miss -> RETIRED   (>= retire
		 *                                threshold misses, still
		 *                                no wins -- dead end)
		 *
		 * RELAXED load/store mirrors the score_bucket store
		 * directly above: concurrent credit_outcome calls on the
		 * same hypothesis from sibling children race; a torn
		 * write at worst mis-attributes a single transition;
		 * the state machine is monotonic in the long run and
		 * subsequent credits converge.  PROMOTED only reverts
		 * via DEMOTED (an explicit miss-stream); DEMOTED ->
		 * RETIRED is terminal.  TESTING is left as a future
		 * intermediate -- a per-pick mutation that does not fit
		 * the credit-side hook.
		 */
		{
			uint8_t old_state = __atomic_load_n(&h->state,
							    __ATOMIC_RELAXED);
			uint8_t new_state = old_state;

			if (would_promote && old_state == CMP_HYP_STATE_OBSERVED)
				new_state = CMP_HYP_STATE_PROMOTED;
			else if (would_promote && old_state == CMP_HYP_STATE_DEMOTED)
				new_state = CMP_HYP_STATE_OBSERVED;
			else if (would_demote && old_state == CMP_HYP_STATE_OBSERVED)
				new_state = CMP_HYP_STATE_DEMOTED;
			else if (old_state == CMP_HYP_STATE_DEMOTED &&
				 ms >= CMP_HYP_RETIRE_MISS_THRESHOLD &&
				 (pc | tr | cs) == 0)
				new_state = CMP_HYP_STATE_RETIRED;

			if (new_state != old_state) {
				__atomic_store_n(&h->state, new_state,
						 __ATOMIC_RELAXED);
				if (kcov_shm != NULL &&
				    old_state < CMP_HYP_STATE_NR &&
				    new_state < CMP_HYP_STATE_NR)
					__atomic_fetch_add(
						&kcov_shm->cmp_hyp_state_transitions[old_state][new_state],
						1UL, __ATOMIC_RELAXED);
			}
		}
	}
}

/*
 * SHADOW per-hypothesis credit at hint-pull (consume) time.  Resolved
 * via the same EXACT > ENUM_FAMILY > BITMASK > RANGE specificity
 * ladder as cmp_hyp_credit_outcome(); on a hit, bumps the per-
 * hypothesis consumed_count and the flat cmp_hyp_consumed kcov_shm
 * counter so the fleet sees the typed-consumer denominator the
 * follow-up live-pick will weigh outcomes against.
 */
static void cmp_hyp_credit_consume(unsigned int nr, bool do32,
				   unsigned long cmp_ip, unsigned long value,
				   unsigned int size)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *h;
	uint8_t width;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	h = cmp_hyp_find_for_credit(pool, cmp_ip, width, (uint64_t)value);
	if (h == NULL)
		return;

	__atomic_fetch_add(&h->consumed_count, 1UL, __ATOMIC_RELAXED);
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hyp_consumed, 1UL,
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_hyp_consumed_by_kind[h->kind],
				   1UL, __ATOMIC_RELAXED);
	}
}

/*
 * Picker reroll denominator for DEMOTED slots.  A DEMOTED slot is
 * normally invisible to the picker, but gets a 1-in-N chance to be
 * surfaced when no PROMOTED / OBSERVED slot exists for the same
 * (cmp_ip, width) at the given kind.  Keeps a path to revival open:
 * a re-rolled DEMOTED that earns a win flips back to OBSERVED via
 * cmp_hyp_credit_outcome's DEMOTED + would_promote transition. */
#define CMP_HYP_DEMOTED_RETRY_DENOM	64U

/*
 * Picker.  Walks the typed-hypothesis pool for (cmp_ip, width) -- no
 * value constraint, unlike cmp_hyp_find_for_credit which matches on
 * (cmp_ip, width, value).  Records per-ladder-kind presence as it
 * walks, then applies the SAME specificity ordering
 * cmp_hyp_find_for_credit uses (EXACT > ENUM_FAMILY > BITMASK >
 * RANGE) to choose the pick.  Within each kind, state-aware
 * preference is applied:
 *
 *   PROMOTED  -- first match wins, preferred over OBSERVED
 *   OBSERVED  -- fallback when no PROMOTED slot exists
 *   TESTING   -- treated as OBSERVED (per-pick waystation, no
 *                special handling on the credit-side hook)
 *   DEMOTED   -- surfaced only via the CMP_HYP_DEMOTED_RETRY_DENOM
 *                re-roll, and only when no PROMOTED / OBSERVED slot
 *                exists for this kind -- keeps revival reachable
 *                without polluting the steady-state pick stream
 *   RETIRED   -- never picked
 *
 * Returns the chosen hypothesis or NULL, and writes the per-kind
 * presence mask through *present_out.  Presence reflects what the
 * picker would actually CONSIDER -- RETIRED slots do not register
 * presence, so the per-kind miss attribution downstream is consistent
 * with the picker's view.  (Treating RETIRED as "present" would mark
 * a kind as covered while the picker walks past it, biasing the
 * would_miss telemetry.)
 *
 * Lock-free read against a parallel writer (cmp_hyp_observe under the
 * matching durable cmp_hint_pool lock): a torn count or half-written
 * entry tolerates the same way cmp_hyp_find_for_credit tolerates it --
 * the count > cap bail bounds the walk and a misread kind / cmp_ip at
 * worst drops the shadow attribution for one pull, never indexes off
 * the array.  h->state is read RELAXED -- the credit-side writer is
 * RELAXED too; a torn read at worst routes one pick under a stale
 * state, and the picker is non-mutating so the race is benign.
 */
static struct cmp_hypothesis *
cmp_hyp_would_pick_locked(struct cmp_hyp_pool *pool, unsigned long cmp_ip,
			  uint8_t width,
			  bool present_out[CMP_HYP_KIND_NR])
{
	struct cmp_hypothesis *exact_promoted = NULL, *exact_observed = NULL, *exact_demoted = NULL;
	struct cmp_hypothesis *enum_promoted = NULL, *enum_observed = NULL, *enum_demoted = NULL;
	struct cmp_hypothesis *bitmask_promoted = NULL, *bitmask_observed = NULL, *bitmask_demoted = NULL;
	struct cmp_hypothesis *range_promoted = NULL, *range_observed = NULL, *range_demoted = NULL;
	struct cmp_hypothesis *boundary_promoted = NULL, *boundary_observed = NULL, *boundary_demoted = NULL;
	unsigned int i, n = pool->count;
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++)
		present_out[k] = false;

	if (n > CMP_HYP_PER_SYSCALL)
		return NULL;
	for (i = 0; i < n; i++) {
		struct cmp_hypothesis *h = &pool->entries[i];
		uint8_t state;
		struct cmp_hypothesis **promoted_slot = NULL;
		struct cmp_hypothesis **observed_slot = NULL;
		struct cmp_hypothesis **demoted_slot = NULL;
		unsigned int present_idx;

		if (h->cmp_ip != (uint64_t)cmp_ip || h->width != width)
			continue;
		switch (h->kind) {
		case CMP_HYP_EXACT:
			promoted_slot = &exact_promoted;
			observed_slot = &exact_observed;
			demoted_slot = &exact_demoted;
			present_idx = CMP_HYP_EXACT;
			break;
		case CMP_HYP_ENUM_FAMILY:
			promoted_slot = &enum_promoted;
			observed_slot = &enum_observed;
			demoted_slot = &enum_demoted;
			present_idx = CMP_HYP_ENUM_FAMILY;
			break;
		case CMP_HYP_BITMASK:
			promoted_slot = &bitmask_promoted;
			observed_slot = &bitmask_observed;
			demoted_slot = &bitmask_demoted;
			present_idx = CMP_HYP_BITMASK;
			break;
		case CMP_HYP_RANGE:
			promoted_slot = &range_promoted;
			observed_slot = &range_observed;
			demoted_slot = &range_demoted;
			present_idx = CMP_HYP_RANGE;
			break;
		case CMP_HYP_BOUNDARY:
			promoted_slot = &boundary_promoted;
			observed_slot = &boundary_observed;
			demoted_slot = &boundary_demoted;
			present_idx = CMP_HYP_BOUNDARY;
			break;
		default:
			continue;
		}

		state = __atomic_load_n(&h->state, __ATOMIC_RELAXED);
		switch (state) {
		case CMP_HYP_STATE_PROMOTED:
			if (*promoted_slot == NULL)
				*promoted_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_OBSERVED:
		case CMP_HYP_STATE_TESTING:
			if (*observed_slot == NULL)
				*observed_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_DEMOTED:
			if (*demoted_slot == NULL)
				*demoted_slot = h;
			present_out[present_idx] = true;
			break;
		case CMP_HYP_STATE_RETIRED:
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_skipped_retired,
					1UL, __ATOMIC_RELAXED);
			break;
		default:
			break;
		}
	}

#define CMP_HYP_PICK_TIER(p, o, d) do {					\
		if ((p) != NULL) {					\
			if (kcov_shm != NULL)				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_PROMOTED], \
					1UL, __ATOMIC_RELAXED);		\
			return (p);					\
		}							\
		if ((o) != NULL) {					\
			if (kcov_shm != NULL)				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_OBSERVED], \
					1UL, __ATOMIC_RELAXED);		\
			return (o);					\
		}							\
		if ((d) != NULL && ONE_IN(CMP_HYP_DEMOTED_RETRY_DENOM)) { \
			if (kcov_shm != NULL) {				\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_picked_by_state[CMP_HYP_STATE_DEMOTED], \
					1UL, __ATOMIC_RELAXED);		\
				__atomic_fetch_add(			\
					&kcov_shm->cmp_hyp_demoted_reroll_picked, \
					1UL, __ATOMIC_RELAXED);		\
			}						\
			return (d);					\
		}							\
	} while (0)

	CMP_HYP_PICK_TIER(exact_promoted, exact_observed, exact_demoted);
	CMP_HYP_PICK_TIER(enum_promoted, enum_observed, enum_demoted);
	CMP_HYP_PICK_TIER(bitmask_promoted, bitmask_observed, bitmask_demoted);
	CMP_HYP_PICK_TIER(range_promoted, range_observed, range_demoted);
	CMP_HYP_PICK_TIER(boundary_promoted, boundary_observed, boundary_demoted);

#undef CMP_HYP_PICK_TIER
	return NULL;
}

/*
 * SHADOW would-pick wrapper invoked by cmp_hints_try_get_ex() on every
 * successful raw-pool pick.  Pure observation: bumps the would-pick /
 * would-miss / would-value-differs counters in kcov_shm and returns.
 * The live pick (the *out value cmp_hints_try_get_ex already wrote and
 * the bool true it is about to return) is byte-for-byte unchanged.
 */
static void cmp_hyp_would_pick(unsigned int nr, bool do32,
			       unsigned long cmp_ip, unsigned int size,
			       unsigned long live_value)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *picked;
	bool present[CMP_HYP_KIND_NR];
	uint8_t width;
	unsigned int k;
	static const uint8_t ladder_kinds[] = {
		CMP_HYP_EXACT, CMP_HYP_ENUM_FAMILY,
		CMP_HYP_BITMASK, CMP_HYP_RANGE,
		CMP_HYP_BOUNDARY,
	};

	if (kcov_shm == NULL || cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	picked = cmp_hyp_would_pick_locked(pool, cmp_ip, width, present);
	if (picked != NULL) {
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_would_pick_by_kind[picked->kind],
			1UL, __ATOMIC_RELAXED);
		if (picked->exemplar != (uint64_t)live_value)
			__atomic_fetch_add(&kcov_shm->cmp_hyp_would_value_differs,
					   1UL, __ATOMIC_RELAXED);
	}
	for (k = 0; k < ARRAY_SIZE(ladder_kinds); k++) {
		uint8_t lk = ladder_kinds[k];

		if (!present[lk])
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_would_miss_by_kind[lk],
				1UL, __ATOMIC_RELAXED);
	}
	/*
	 * Decoupled BOUNDARY availability census.  Bumped whenever a
	 * BOUNDARY entry is populated at the served (cmp_ip, width) AND
	 * the derive arm would not bail (the guards inside the BOUNDARY
	 * case of cmp_hyp_derive_value always succeed for a non-corrupted
	 * entry, so presence is the binding condition).  Independent of
	 * the EXACT > ENUM > BITMASK > RANGE > BOUNDARY precedence above:
	 * EXACT is populated at every observation and outranks BOUNDARY,
	 * so cmp_hyp_would_pick_by_kind[BOUNDARY] stays structurally near
	 * zero -- the counter below is the lane's headline shadow metric
	 * (how often BOUNDARY would have a neighbour to inject if the
	 * precedence let it through).
	 */
	if (present[CMP_HYP_BOUNDARY])
		__atomic_fetch_add(&kcov_shm->cmp_hyp_boundary_candidate_available,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * Conservative inject rate for the LIVE typed-hypothesis arm.  ~3 %
 * baseline, strictly more conservative than the raw cmp-hint baseline
 * (1/16) so a regression on the unproven typed arm cannot drown the
 * measured raw signal.  Lifts to the existing amplified denom (4) only
 * under the CMP_RISING_PC_FLAT plateau where the raw path is already
 * amplified -- the gate below couples the two so the arm only ever
 * fires alongside the raw amplification.
 */
#define CMP_HYP_LIVE_INJECT_DENOM	32U

/*
 * Bootstrap channel dice (channel B) for the LIVE typed-hypothesis arm.
 * Fires REGARDLESS of plateau so the inject pipeline can earn its first
 * PC wins on OBSERVED-state hypotheses before the plateau gate has ever
 * opened.  Sparse (~0.4 %) so it cannot drown the raw cmp-hint signal
 * even in the worst case; integrated over a multi-hour run this still
 * accumulates thousands of typed-arm firings, plenty to seed the
 * promotion ladder.  Resolves the circular dependency where
 * cmp_hyp_try_live_inject was gated on a plateau that only opens once
 * PROMOTED hypotheses exist, but PROMOTED hypotheses only appear after
 * cmp_hyp_try_live_inject has fired and earned wins.
 */
#define CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM	256U

/*
 * PROMOTED-bypass channel dice (channel C) for the LIVE typed-hypothesis
 * arm.  Cheaper than the bootstrap dice (~1.6 %) because the state
 * machine (cmp_hyp_credit_outcome's DEMOTE / RETIRE on losses, PROMOTE
 * on wins) has already done the throttling work that the plateau gate
 * was approximating: a PROMOTED entry has demonstrably produced a
 * coverage win, so re-firing it cheaply is the warranted bias.  Only
 * applies when cmp_hyp_would_pick_locked returns a PROMOTED entry at
 * the served (cmp_ip, width) -- if the picker returns OBSERVED or NULL,
 * channel C is treated as if its dice had not been rolled (account via
 * NO_MATCH downstream when picker == NULL, otherwise bail).
 */
#define CMP_HYP_LIVE_INJECT_PROMOTED_DENOM	64U

/*
 * Derive ONE candidate value from PICKED via the spec's ladder.  Every
 * derived value is constructed so cmp_hyp_find_for_credit() will
 * re-resolve back to a hypothesis at the same (cmp_ip, width) at
 * credit time -- either the SAME hypothesis (EXACT.exemplar matches
 * EXACT; ENUM_FAMILY exemplar / lo / hi all lie in [lo, hi]; BITMASK
 * single set-bit is single-bit AND set in mask; RANGE lo / hi /
 * midpoint all lie in [lo, hi]) or, for the EXACT +/-1 arms, the
 * co-populated BOUNDARY hypothesis at the same (cmp_ip, width) via
 * its +/-2 credit window.  For RANGE, boundary probes (lo-1, hi+1)
 * are deliberately NOT emitted -- they fall outside [lo, hi] and so
 * are unreachable by the value-keyed credit walk, which would
 * silently drop their attribution; that neighbourhood is instead the
 * BOUNDARY arm's job.  The EXACT arm's +/-1 rotation is safe because
 * BOUNDARY co-registers on every observation and its credit window
 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) is wide enough to cover the
 * shifted values.
 *
 * Bug-pattern rules applied:
 *   * midpoint computed as lo + ((hi - lo) >> 1) so (lo + hi) cannot
 *     overflow.
 *   * RANGE rejects hi < lo (a torn read of an in-flight RANGE entry
 *     would otherwise underflow).
 *   * BITMASK with mask == 0 falls back to exemplar so the
 *     popcount-walk loop is never entered with an empty mask.
 *   * popcount-walk bounds via __builtin_popcountll so the bit-pick
 *     index is in [0, popcount); the for-loop's bit shift terminates
 *     on the uint64_t high-bit wrap and the seen counter exits
 *     deterministically.
 */
static bool cmp_hyp_derive_value(const struct cmp_hypothesis *picked,
				 unsigned long *out)
{
	uint64_t lo, hi, mask;
	unsigned int popcount, pick, seen;
	uint64_t bit;
	enum cmp_hyp_probe_class cls;

	if (picked == NULL || out == NULL)
		return false;
	switch (picked->kind) {
	case CMP_HYP_EXACT: {
		/*
		 * Rotate uniformly among {N-1, N, N+1}, mirroring
		 * cmp_hint_apply_transform's CMP_HINT_BOUNDARY case.
		 * Before this rotation the derive always returned the
		 * exemplar unchanged -- the compile-time const the kernel
		 * had already observed -- so every LIVE typed EXACT inject
		 * re-fed the site the byte-identical value that got recorded
		 * there in the first place: the equality gate the const
		 * originally passed still passed, but strict-inequality
		 * gates ("x < N", "x > N", the pattern documented in the
		 * CMP_HYP_BOUNDARY block below and in include/kcov.h's
		 * cmp_hyp_boundary_* commentary) stayed unsatisfied and
		 * pc_wins was structurally starved on this arm.  The raw
		 * cmp-hint arm applies this same +/-1 rotation at the same
		 * callsites via cmp_hint_apply_transform's CMP_HINT_BOUNDARY
		 * case, so pre-rotation the LIVE typed EXACT arm was a
		 * strict downgrade of the raw arm's conversion (the raw
		 * arm's own comment at the transform notes "the equality
		 * slot -- C unchanged -- is retained in the rotation, so
		 * the worst case is a 3x slowdown on a purely
		 * equality-dominated callsite, while
		 * length-/cap-/extent-dominated syscalls ... get the
		 * boundary edges they were missing").  The rotation restores
		 * parity with the raw arm and lets the strict-inequality
		 * boundary gates convert on the typed arm too.
		 *
		 * Credit attribution: EXACT's find_for_credit arm demands
		 * exemplar == value, so the +/-1 probes do NOT re-resolve
		 * back to this EXACT hypothesis at credit time -- they fall
		 * through to the BOUNDARY arm's +/-2 credit window
		 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) and get attributed
		 * to whichever BOUNDARY entry the observe path registered
		 * at the same (cmp_ip, width).  Both EXACT and BOUNDARY
		 * co-populate on every observation (see cmp_hyp_observe),
		 * so a fired shifted probe has a home; if the BOUNDARY
		 * slot was reclaimed, per-hypothesis credit misses but the
		 * pc_win itself is still counted in the flat kcov_shm
		 * rollup.  The exemplar arm still re-resolves to this
		 * EXACT hypothesis exactly as before.
		 *
		 * Unsigned wrap at the extremes (N == 0 -> N-1 ==
		 * ULONG_MAX; N == ULONG_MAX -> N+1 == 0) is intentional
		 * and unclamped, matching the raw transform's rationale:
		 * both wrapped values are themselves useful probes
		 * (underflow exercises length-cap validators; overflow
		 * exercises zero-length rejection paths), and the
		 * downstream accept-range gate in cmp_hints_try_get_ex
		 * rejects any that overshoot the caller's bounds and
		 * counts them under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 *
		 * Probe-class histogram: the +/-1 arms bump the shared
		 * CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1 / _PLUS1 buckets by
		 * *probe shape* rather than by originating hypothesis --
		 * a "constant nudged down/up by 1" probe reached the
		 * kernel, which is what a downstream reader wants to
		 * measure.  Splitting these into dedicated
		 * EXACT_MINUS1 / _PLUS1 buckets would need an
		 * include/kcov.h enum extension deferred to a follow-up if
		 * the shared bucket becomes ambiguous in practice.
		 */
		uint64_t n = picked->exemplar;

		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)(n - 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
			goto out_bump;
		case 2:
			*out = (unsigned long)(n + 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
			goto out_bump;
		/* case 1 (and default): N unchanged.  Retains the exact
		 * equality-gate probe so equality-dominated callsites
		 * (cmd codes, enum selectors, version magics) keep
		 * converting on the typed arm. */
		default:
			*out = (unsigned long)n;
			cls = CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR;
			goto out_bump;
		}
	}
	case CMP_HYP_ENUM_FAMILY:
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR;
			goto out_bump;
		case 1:
			*out = (unsigned long)picked->lo;
			cls = CMP_HYP_PROBE_CLASS_ENUM_LO;
			goto out_bump;
		default:
			*out = (unsigned long)picked->hi;
			cls = CMP_HYP_PROBE_CLASS_ENUM_HI;
			goto out_bump;
		}
	case CMP_HYP_BITMASK:
		mask = picked->mask;
		if (mask == 0) {
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
			goto out_bump;
		}
		popcount = (unsigned int)__builtin_popcountll(mask);
		pick = rnd_modulo_u32(popcount);
		seen = 0;
		for (bit = 1; bit != 0; bit <<= 1) {
			if ((mask & bit) == 0)
				continue;
			if (seen == pick) {
				*out = (unsigned long)bit;
				cls = CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT;
				goto out_bump;
			}
			seen++;
		}
		/* Unreachable: popcount of a non-zero mask is in
		 * [1, 64], and pick < popcount.  Fall back to exemplar so
		 * a future bit-shape change cannot strand the inject. */
		*out = (unsigned long)picked->exemplar;
		cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
		goto out_bump;
	case CMP_HYP_RANGE:
		lo = picked->lo;
		hi = picked->hi;
		if (hi < lo)
			return false;
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)lo;
			cls = CMP_HYP_PROBE_CLASS_RANGE_LO;
			goto out_bump;
		case 1:
			*out = (unsigned long)hi;
			cls = CMP_HYP_PROBE_CLASS_RANGE_HI;
			goto out_bump;
		default:
			*out = (unsigned long)(lo + ((hi - lo) >> 1));
			cls = CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT;
			goto out_bump;
		}
	case CMP_HYP_BOUNDARY: {
		/*
		 * Neighbourhood ladder around the exemplar N: the strict-
		 * inequality boundary EXACT cannot pass (the passing value
		 * for `x < N` is N-1, for `x > N` is N+1) and RANGE refuses
		 * to emit (the comment at RANGE bans lo-1 / hi+1 because the
		 * value-keyed credit walk cannot re-resolve them; the lane
		 * here owns that emission and the BOUNDARY arm of
		 * cmp_hyp_find_for_credit() owns the matching credit walk).
		 *
		 * Bug-pattern guards from the audit batch:
		 *   * unsigned underflow: emit N-1 / N-2 only when N >= 1
		 *     / N >= 2; arg1 is u64, N=0 - 1 would otherwise land at
		 *     ULONG_MAX.
		 *   * width overflow: skip the + arms when N is at the
		 *     width's max (1 << (width*8) - 1) so a u8/u16 boundary
		 *     does not wrap to 0 (or, worse, leak high-bit garbage
		 *     past the operand width that the accept gate would then
		 *     reject anyway).
		 *   * mask the derived value to the operand width so an u8
		 *     boundary at value 255 with the +1 arm gated off still
		 *     yields a well-formed 8-bit value when the sweep arm
		 *     touches it.
		 * The accept-range gate in cmp_hints_try_get_ex (and the
		 * caller's own range check) is the second line of defence:
		 * a derived neighbour past the caller's bounds is rejected
		 * cleanly and counted under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 */
		uint64_t n = picked->exemplar;
		uint64_t width_mask = (picked->width >= 8)
			? ~(uint64_t)0
			: ((uint64_t)1 << (picked->width * 8)) - 1;
		uint64_t width_max = width_mask;
		uint64_t cand;
		bool have_cand = false;

		switch (rnd_modulo_u32(4)) {
		case 0:
			if (n >= 1) {
				cand = n - 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
				have_cand = true;
				break;
			}
			/* N=0: N-1 would underflow.  Fall through to the +1
			 * arm which is well-defined for N=0 at any width. */
			/* fallthrough */
		case 1:
			if (n < width_max) {
				cand = n + 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
				have_cand = true;
				break;
			}
			/* N == width_max: N+1 would overflow the operand
			 * width.  Fall through to the exemplar arm, which
			 * always fits. */
			/* fallthrough */
		case 2:
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		default:
			/* Widen-by-one sweep for off-by-one chains.  Random
			 * direction; the same underflow / overflow guards as
			 * the +/-1 arms apply at the wider step. */
			if (rnd_modulo_u32(2) == 0) {
				if (n >= 2) {
					cand = n - 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			} else {
				if (n + 2 > n && n + 2 <= width_max) {
					cand = n + 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			}
			/* Both sweep directions strand the value at this
			 * width.  Fall back to the exemplar so the lane never
			 * emits "no value" -- the find_for_credit BOUNDARY
			 * window covers exemplar matches too. */
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		}
		if (!have_cand)
			return false;
		*out = (unsigned long)(cand & width_mask);
		goto out_bump;
	}
	default:
		return false;
	}

out_bump:
	/* SHADOW: census which probe class the derivation just emitted.
	 * Pure observation -- *out is unchanged from the pre-census ladder,
	 * the live inject arm receives the same byte-identical value. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_probe_class_hist[cls],
				   1UL, __ATOMIC_RELAXED);
	return true;
}

/*
 * LIVE typed-hypothesis inject try.  Composes the conservative gate
 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(32)) with the shadow
 * resolver and the derive helper above.  On a fire the raw pool's
 * (cmp_ip, value, width) tuple the pick step computed is replaced by
 * (cmp_ip, derived, width) -- cmp_ip and width are unchanged because
 * the inject targets the SAME comparison site, just substituting a
 * typed-derived value for the raw replay.
 *
 * The caller (cmp_hints_try_get_ex) only invokes this on a typed-safe
 * argtype; gating that here would conflate the gate's "did not fire"
 * with the caller's "not eligible" cohort.
 *
 * Per-pull accounting is deferred to the caller's accept-gated commit
 * point so a hint the caller's accept range subsequently rejects does
 * not contaminate cmp_hyp_live_inject_gate_passed /
 * cmp_hyp_live_injected[/_by_kind].  This helper bumps nothing, and
 * signals back through two out-params:
 *
 *   *out_gate_fired -- the conservative gate passed (plateau + dice +
 *                      size + shm); the caller bumps gate_passed when
 *                      its accept gate also passes.  Preserves the
 *                      "gate fired but the typed store had nothing"
 *                      observability the gate_passed - live_injected
 *                      delta currently surfaces, just gated on the
 *                      value actually reaching the consumer.
 *   *out_kind       -- picked->kind, valid iff the function returns
 *                      true (i.e. picked != NULL AND derive
 *                      succeeded).  The caller bumps live_injected /
 *                      live_injected_by_kind[*out_kind] under the
 *                      same accept-gate.
 *
 * Both out-params are written on every entry: out_gate_fired starts
 * at false and only flips true once the gate passes, out_kind is left
 * at 0 unless the function returns true.  Callers can therefore key
 * their accounting off the bool return alone for live_injected and off
 * *out_gate_fired for gate_passed without re-checking helper inputs.
 */
static bool cmp_hyp_try_live_inject(unsigned int nr, bool do32,
				    unsigned long cmp_ip, unsigned int size,
				    unsigned long *out,
				    uint8_t *out_kind,
				    bool *out_gate_fired)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *picked;
	bool present[CMP_HYP_KIND_NR];
	uint8_t width;
	unsigned long derived;
	bool plateau_on;
	bool channel_a_fired;
	bool channel_b_fired = false;
	bool channel_c_dice_won = false;
	uint8_t picked_state;

	*out_gate_fired = false;
	*out_kind = 0;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return false;
	if (shm == NULL)
		return false;

	/*
	 * Three independent channels can open this gate:
	 *
	 *   A  plateau == CMP_RISING_PC_FLAT  AND  ONE_IN(LIVE_INJECT_DENOM)
	 *   B  ONE_IN(BOOTSTRAP_DENOM)                          (always-on)
	 *   C  ONE_IN(PROMOTED_DENOM)  AND  picker returns PROMOTED
	 *
	 * A is the historical plateau-amplified path; the bootstrap (B) and
	 * promoted-bypass (C) channels exist so PC wins can accumulate even
	 * when the plateau gate has never opened.  C's "picker returns
	 * PROMOTED" half is verified AFTER the pool walk further down -- we
	 * roll the dice here and consult the picker once, deferring channel
	 * attribution until we know whether C qualifies.
	 *
	 * Dice are rolled even when an earlier channel has already fired so
	 * the random stream stays callsite-deterministic across plateau
	 * transitions -- without this, flipping the plateau on / off would
	 * shift every downstream rnd_*() consumer's value.  Cost is two
	 * rnd_modulo_u32 calls in the rejected case, both off the hot raw
	 * cmp-hint path.
	 */
	plateau_on = (__atomic_load_n(&shm->plateau_current_hypothesis,
				      __ATOMIC_RELAXED) ==
		      (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT);
	channel_a_fired = plateau_on && ONE_IN(CMP_HYP_LIVE_INJECT_DENOM);
	if (ONE_IN(CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM))
		channel_b_fired = true;
	if (ONE_IN(CMP_HYP_LIVE_INJECT_PROMOTED_DENOM))
		channel_c_dice_won = true;

	if (!channel_a_fired && !channel_b_fired && !channel_c_dice_won) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[plateau_on
					? CMP_HYP_LIVE_INJECT_REASON_DICE_MISS
					: CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out_gate_fired = true;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	picked = cmp_hyp_would_pick_locked(pool, cmp_ip, width, present);
	if (picked == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	/*
	 * Channel attribution.  Priority C > B > A: PROMOTED_BYPASS is the
	 * most informative signal (state machine validated the hyp), so when
	 * channels overlap we credit the most specific one.  Channel A has
	 * no specific reason counter -- its firings are visible as
	 * cmp_hyp_live_inject_gate_passed minus the sum of the BOOTSTRAP and
	 * PROMOTED_BYPASS reason counters.
	 *
	 * The "channel C dice won but picked is not PROMOTED, and A/B both
	 * lost" branch bails via NO_MATCH: structurally there IS a
	 * hypothesis at the site (picker returned non-NULL), but no channel
	 * actually qualified to drive an inject -- C requires PROMOTED, B/A
	 * didn't roll.  Treating it as NO_MATCH keeps the per-reason
	 * partition closed (sum of head + downstream reasons + injected ==
	 * total entries past the size-class guard) without adding a third
	 * new enum value just for this one corner.
	 */
	picked_state = __atomic_load_n(&picked->state, __ATOMIC_RELAXED);
	if (channel_c_dice_won && picked_state == CMP_HYP_STATE_PROMOTED) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS],
				1UL, __ATOMIC_RELAXED);
	} else if (channel_b_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP],
				1UL, __ATOMIC_RELAXED);
	} else if (!channel_a_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	if (!cmp_hyp_derive_value(picked, &derived)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out = derived;
	*out_kind = picked->kind;
	return true;
}

static void pool_lock(struct cmp_hint_pool *pool)
{
	if (cmp_hints_shm != NULL)
		__atomic_fetch_add(&cmp_hints_shm->held_count, 1,
				__ATOMIC_RELAXED);
	lock(&pool->lock);
}

static void pool_unlock(struct cmp_hint_pool *pool)
{
	unlock(&pool->lock);
	if (cmp_hints_shm != NULL)
		__atomic_sub_fetch(&cmp_hints_shm->held_count, 1,
				__ATOMIC_RELAXED);
}

/*
 * Wild-write gate for the cmp_hints SHM pool.  Called by every reader
 * (try_get lockless, pool_add_locked under lock) immediately after the
 * count load.  Bumps three independent kcov_shm counters so the
 * post-mortem can attribute corruption to whichever channel hit:
 *
 *   - cmp_hints_count_oob:                pool->count exceeds the
 *                                         16-slot cap, the only sign
 *                                         visible from the read path
 *                                         itself.
 *   - cmp_hints_canary_lock_post_corrupt: the sentinel between lock
 *                                         and count has been
 *                                         overwritten -- a wide write
 *                                         landed in the lock/count
 *                                         seam.
 *   - cmp_hints_canary_pre_corrupt:       the sentinel between
 *                                         last_used_stamp and
 *                                         entries[] has been
 *                                         overwritten -- write
 *                                         reached the pool from the
 *                                         header side.
 *   - cmp_hints_canary_post_corrupt:      the sentinel after entries[]
 *                                         has been overwritten --
 *                                         write reached the pool
 *                                         from the tail side.
 *
 * A narrow stomp that lands exactly on count (or exactly on any
 * single header field) trips ONLY count_oob; the canaries flank the
 * data but cannot detect a write that fits entirely between them.
 * Non-zero canary deltas narrow the stomp's width and direction --
 * useful for forensics, not load-bearing for the corruption-present
 * decision.  Canary loads are gated on the count check so the
 * steady-state cost is one compare-against-16; the canary cache
 * lines are only touched once a stomp has already occurred.  Returns
 * true when corruption is present so callers can treat the pool as
 * advisory-empty.
 *
 * Per-pool latch (pool->corrupted) one-shots the counter bumps: the
 * first observation records the channel, every subsequent call
 * returns true from the latch check and skips both the count
 * comparison and the canary probes.  Without this, the batch loop in
 * cmp_hints_flush_pending would multiply a single stomp event by up
 * to CMP_HINTS_PENDING_BATCH bumps per cmp_hints_collect call and
 * the count_oob counter would track "exposures" instead of "events".
 */
static bool cmp_hints_pool_corrupted(struct cmp_hint_pool *pool,
				     unsigned int observed_count)
{
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return true;
	if (observed_count <= CMP_HINTS_PER_SYSCALL)
		return false;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
	}
	__atomic_store_n(&pool->corrupted, true, __ATOMIC_RELAXED);
	return true;
}

/*
 * Clamp wrapper for readers that need pool->count for accounting but
 * do NOT index into entries[] (stats accumulators, strategy classifier).
 * Returns 0 on a stomped pool so accounting code doesn't fold garbage
 * counts into totals.  Side-effects identical to cmp_hints_pool_corrupted:
 * first observation of an OOB count records the channel via the kcov_shm
 * counters and latches pool->corrupted, so these readers participate in
 * the same one-shot accounting as the index-into-entries readers.
 *
 * Also closes a TOCTOU on the existing call sites that read .count
 * twice in quick succession ('if (count > 0) total += count;'): a
 * single atomic load drives both the test and the value used.
 */
unsigned int cmp_hints_pool_safe_count(struct cmp_hint_pool *pool)
{
	unsigned int count = __atomic_load_n(&pool->count, __ATOMIC_RELAXED);

	if (cmp_hints_pool_corrupted(pool, count))
		return 0;
	return count;
}

/*
 * Bucket the lock-free LRU-clock delta (pool->last_used_stamp -
 * picked->last_used) measured at pick time into CMP_HINT_AGE_BUCKETS
 * coarse log2 ranges.  Bucket 0 == delta 0 (entry is the most recently
 * refreshed in the pool); higher buckets == entry has been carried over
 * many pool mutations since its last_used was bumped.  Static-asserted
 * against the kcov_shm array width so a future widening of the
 * histogram doesn't silently overflow the kcov_shm counter array.
 */
_Static_assert(CMP_HINT_AGE_BUCKETS == 7U,
	       "cmp_hint_age_bucket() arms must match CMP_HINT_AGE_BUCKETS");
static inline uint8_t cmp_hint_age_bucket(uint64_t age)
{
	if (age == 0)
		return 0;
	if (age < 8)
		return 1;
	if (age < 32)
		return 2;
	if (age < 128)
		return 3;
	if (age < 512)
		return 4;
	if (age < 2048)
		return 5;
	return 6;
}

/*
 * Insert (cmp_ip, val, size) into the entries[] array.  Dedups via linear
 * scan on the full (cmp_ip, value, size) key.  When the pool is full,
 * evicts the entry with the smallest last_used (least-recently-inserted)
 * to make room.  Duplicate hits refresh last_used so an actively-observed
 * constant doesn't get evicted by transient long-tail noise.  Caller must
 * hold pool->lock.
 *
 * pool->generation is bumped ONLY on real content changes (fresh insert
 * or evict-replace), never on dedup-refresh.  That keeps the
 * cmp_hints_total_generation() snapshot dirty-bit honest: a saturated
 * pool whose hot tuples keep dedup-refreshing produces no generation
 * delta and therefore no redundant snapshot save.  The LRU clock that
 * stamps each entry's last_used uses a separate per-pool counter
 * (pool->last_used_stamp) which advances on every call — including
 * dedup-refresh — so the eviction policy is unchanged from before this
 * split: an actively-observed tuple still gets its stamp refreshed and
 * is still the last thing the evictor will pick.
 */
static bool pool_add_locked(struct cmp_hint_pool *pool,
			    unsigned int nr,
			    unsigned long cmp_ip,
			    unsigned long val,
			    unsigned int size)
{
	unsigned int i, count = pool->count;
	uint64_t stamp;
	unsigned int victim;
	uint64_t oldest;

	/* SHM stomp from a fuzzed syscall arg has scribbled count past the
	 * 16-slot cap; the dedup loop below would walk off entries[].  Bail
	 * before mutating anything (including last_used_stamp). */
	if (cmp_hints_pool_corrupted(pool, count))
		return false;

	stamp = ++pool->last_used_stamp;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_dup,
						   1UL, __ATOMIC_RELAXED);
			return false;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		/* SHADOW feedback score starts at zero for a freshly inserted
		 * tuple.  Dedup-refresh above keeps the existing score (same
		 * tuple, same identity); only this fresh-insert and the
		 * evict-replace below reset. */
		e->wins = 0;
		e->misses = 0;
		e->last_used = stamp;
		__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
		/*
		 * RELEASE-store count so a lockless reader in cmp_hints_try_get
		 * that observes the new count is guaranteed to also see the
		 * entries[] store above.
		 */
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hints_unique_inserts,
					   1UL, __ATOMIC_RELAXED);
		return true;
	}

	victim = 0;
	oldest = pool->entries[0].last_used;
	for (i = 1; i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->entries[i].last_used < oldest) {
			oldest = pool->entries[i].last_used;
			victim = i;
		}
	}
	pool->entries[victim].value = val;
	pool->entries[victim].cmp_ip = cmp_ip;
	pool->entries[victim].size = size;
	/* Evict-replace: zero the SHADOW score so the displaced tuple's
	 * history does not bleed into the new identity that now lives in
	 * this slot. */
	pool->entries[victim].wins = 0;
	pool->entries[victim].misses = 0;
	pool->entries[victim].last_used = stamp;
	__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_unique_inserts, 1UL,
				   __ATOMIC_RELAXED);
		/* Evict-replace pressure: a tuple displaced an older one
		 * because the per-syscall cap was full.  The new entry won
		 * the slot (counted via cmp_hints_unique_inserts above) and
		 * the evicted entry is the silent loser; the cap counter
		 * tracks displacement events so a saturated pool is
		 * directly visible as cap > unique_inserts_delta over a
		 * window once the per-syscall pool tops out. */
		__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_cap, 1UL,
				   __ATOMIC_RELAXED);
		/* Per-syscall partition of the cap-pressure counter.
		 * Sibling of per_syscall_cmp_inserts[nr] (bumped above
		 * via cmp_hints_unique_inserts and again at the
		 * cmp_hints_collect tail).  nr is gated to MAX_NR_SYSCALL
		 * at cmp_hints_collect() entry; this insert path is only
		 * ever reached through cmp_hints_flush_pending which
		 * threads the same nr through unchanged, so the index is
		 * in-bounds. */
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->per_syscall_cmp_reject_cap[nr],
					   1UL, __ATOMIC_RELAXED);
	}
	return true;
}

/*
 * Per-child seen-bloom hashes over the (cmp_ip, val, size) tuple.  Two
 * independent splitmix64-style mixes -- the same shape the cmp_novelty
 * bloom in strategy.c uses, kept local so the two hash families are
 * free to drift if one turns out to need a different mixing constant
 * for the load it actually sees.  Indices are masked to
 * CMP_HINTS_BLOOM_MASK so the bloom width can change without touching
 * the hashes.
 */
static inline uint32_t cmp_hints_bloom_h1(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)ip
		   ^ ((uint64_t)val * 0x9e3779b97f4a7c15ULL)
		   ^ ((uint64_t)size << 13);

	x ^= x >> 32;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

static inline uint32_t cmp_hints_bloom_h2(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)val
		   ^ ((uint64_t)ip * 0x94d049bb133111ebULL)
		   ^ ((uint64_t)size * 0xff51afd7ed558ccdULL);

	x ^= x >> 30;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 31;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

/*
 * Test-and-set both bloom bits for the tuple.  Returns true when both
 * bits were already set -- the tuple has been seen within the current
 * bloom window, so the caller can skip pool_add_locked.  A miss on
 * either bit returns false AND leaves both bits set, so the next
 * encounter with the same tuple hits.
 */
static bool cmp_hints_bloom_check_and_set(struct cmp_hints_bloom *b,
					  unsigned long ip,
					  unsigned long val,
					  unsigned int size)
{
	uint32_t i1 = cmp_hints_bloom_h1(ip, val, size);
	uint32_t i2 = cmp_hints_bloom_h2(ip, val, size);
	uint8_t m1 = (uint8_t)(1U << (i1 & 7));
	uint8_t m2 = (uint8_t)(1U << (i2 & 7));
	uint8_t *p1 = &b->bits[i1 >> 3];
	uint8_t *p2 = &b->bits[i2 >> 3];
	bool seen = ((*p1 & m1) != 0) && ((*p2 & m2) != 0);

	*p1 |= m1;
	*p2 |= m2;
	return seen;
}

/*
 * Per-call staging buffer for cmp_hints_collect's bloom-miss batch.
 * Sized to balance: small enough that the worst-case 3KB stack
 * footprint is comfortable in child context, large enough that the
 * common case (a hot bloom yielding tens of misses per call) clears
 * the loop with a single pool_lock cycle.  Bursts that exceed the
 * batch fall back to multiple flushes -- correct, just less optimal. */
#define CMP_HINTS_PENDING_BATCH 128

struct cmp_hints_pending {
	unsigned long ip;
	unsigned long val;
	unsigned int size;
};

/*
 * Recent-ring insert.  Called for every
 * pool_add_locked() return-true (fresh insert or evict-replace) under
 * the durable pool's lock, so the only writer at any instant is the
 * caller already holding pool->lock above; recent_pools[] needs no
 * lock of its own.  Lockless readers in cmp_hints_try_get_ex tolerate
 * a torn (cmp_ip, value, size) triplet the same way the durable pool's
 * lockless reader does -- hints are advisory.
 *
 * Ring write: overwrite the head slot, advance head modulo the cap.
 * Count grows up to CMP_RECENT_PER_SYSCALL and then sticks; an insert
 * over a populated slot bumps cmp_recent_evicts so the saturation
 * point is observable.  No dedup deliberately: "recent" semantics aren't
 * diluted by collapsing a tuple the kernel saw twice into one slot.
 */
static void cmp_recent_insert(unsigned int nr, bool do32,
			      unsigned long cmp_ip, unsigned long val,
			      unsigned int size)
{
	struct cmp_recent_pool *rp;
	unsigned int head;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	rp = &cmp_hints_shm->recent_pools[nr][do32 ? 1 : 0];
	head = rp->head;
	if (head >= CMP_RECENT_PER_SYSCALL)
		head = 0;	/* defensive: a stomp on head would index OOB */
	count = rp->count;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_recent_inserts, 1UL,
				   __ATOMIC_RELAXED);
		if (count >= CMP_RECENT_PER_SYSCALL)
			__atomic_fetch_add(&kcov_shm->cmp_recent_evicts, 1UL,
					   __ATOMIC_RELAXED);
	}

	rp->entries[head].value = val;
	rp->entries[head].cmp_ip = cmp_ip;
	rp->entries[head].size = size;
	rp->entries[head].pad = 0;

	head = (head + 1U) % CMP_RECENT_PER_SYSCALL;
	__atomic_store_n(&rp->head, head, __ATOMIC_RELAXED);
	if (count < CMP_RECENT_PER_SYSCALL)
		__atomic_store_n(&rp->count, count + 1U, __ATOMIC_RELEASE);
}

/*
 * Childop quarantine-lane insert.  Mirrors cmp_recent_insert() above
 * but writes to cmp_hints_shared.childop_recent_pools[nr][do32] --
 * the source-tagged, non-persisted, non-LRU-displacing lane that
 * the §3.2 trinity_cmp_syscall harvest feeds when
 * --childop-cmp-harvest=on.
 *
 * Single-writer per (nr, do32): every caller runs inside a
 * trinity_cmp_syscall() under a kcov_cmp_bracket on a CMP-mode
 * child, and a CMP-mode child only ever holds one bracket at a
 * time, so the head/count writes need no lock.  Lockless readers
 * in the eventual consume side will tolerate a torn (cmp_ip, val,
 * size) triplet the same way cmp_hints_try_get_ex() tolerates one
 * against recent_pools[] today.
 *
 * Pool-insert / pool-evict bumps land in kcov_shm under the same
 * per-nr keying the rest of the childop_cmp_* shadow counters use,
 * so the eviction-pressure signal the §3.1 promotion gate consumes
 * is observable per-nr from day one.
 */
void cmp_hints_childop_insert(unsigned int nr, bool do32,
			      unsigned long cmp_ip, unsigned long val,
			      unsigned int size)
{
	struct cmp_recent_pool *rp;
	unsigned int head;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	rp = &cmp_hints_shm->childop_recent_pools[nr][do32 ? 1 : 0];
	head = rp->head;
	if (head >= CMP_RECENT_PER_SYSCALL)
		head = 0;	/* defensive: stomp on head indexed OOB */
	count = rp->count;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->childop_cmp_pool_inserts[nr],
				   1UL, __ATOMIC_RELAXED);
		if (count >= CMP_RECENT_PER_SYSCALL)
			__atomic_fetch_add(&kcov_shm->childop_cmp_pool_evicts[nr],
					   1UL, __ATOMIC_RELAXED);
	}

	rp->entries[head].value = val;
	rp->entries[head].cmp_ip = cmp_ip;
	rp->entries[head].size = size;
	rp->entries[head].pad = 0;

	head = (head + 1U) % CMP_RECENT_PER_SYSCALL;
	__atomic_store_n(&rp->head, head, __ATOMIC_RELAXED);
	if (count < CMP_RECENT_PER_SYSCALL)
		__atomic_store_n(&rp->count, count + 1U, __ATOMIC_RELEASE);
}

static unsigned int cmp_hints_flush_pending(struct cmp_hint_pool *pool,
					    unsigned int nr, bool do32,
					    const struct cmp_hints_pending *batch,
					    unsigned int n)
{
	unsigned int j;
	unsigned int inserted = 0;

	if (n == 0)
		return 0;
	/* Pre-lock fast path for already-latched-corrupted pools.  Each
	 * pool_add_locked() below routes count through cmp_hints_pool_corrupted()
	 * and bails before any state mutation (including last_used_stamp)
	 * once the latch is set, so the lock acquire + N-iteration batch
	 * walk yields zero inserts and zero side effects on a latched pool
	 * -- pure overhead.  The latched-corrupted branch in
	 * cmp_hints_pool_corrupted() is itself side-effect free (no
	 * counter bumps, no re-latch, no canary probes) by design, so
	 * skipping the walk does not lose any per-record accounting that
	 * the in-walk check would have produced. */
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return 0;
	pool_lock(pool);
	for (j = 0; j < n; j++) {
		if (pool_add_locked(pool, nr, batch[j].ip, batch[j].val,
				    batch[j].size)) {
			inserted++;
			/* Mirror every durable content change into the
			 * run-local recent ring.  Under pool->lock so the
			 * recent insert has the same single-writer guarantee
			 * the durable insert has -- the only place that
			 * writes recent_pools[nr][do32] is this exact path. */
			cmp_recent_insert(nr, do32, batch[j].ip, batch[j].val,
					  batch[j].size);
			/* SHADOW typed-hypothesis inference fed every
			 * fresh (nr, do32, ip, val, size) tuple under the
			 * same lock window, so the hyp_pools writes
			 * serialise per-(nr, do32) without a second lock
			 * and no second walk over the trace buffer. */
			cmp_hyp_observe(nr, do32, batch[j].ip, batch[j].val,
					batch[j].size);
		}
	}
	pool_unlock(pool);
	return inserted;
}

/*
 * Field-pool table lookup.  splitmix64-style mix over the key tuple so
 * (nr, do32, arg_idx, field_idx, size) variations spread evenly across
 * buckets and the desc pointer's low bits don't dominate the index.  The
 * result is masked to CMP_FIELD_POOL_BUCKETS so the bucket count can
 * change without touching the hash.
 */
static inline uint32_t cmp_field_pool_hash(const struct struct_desc *desc,
					   unsigned int nr, unsigned int do32,
					   unsigned int arg_idx,
					   unsigned int field_idx,
					   unsigned int size)
{
	uint64_t x = (uint64_t)(uintptr_t) desc;

	x ^= ((uint64_t) nr * 0x9e3779b97f4a7c15ULL);
	x ^= ((uint64_t) arg_idx << 17);
	x ^= ((uint64_t) field_idx * 0xbf58476d1ce4e5b9ULL);
	x ^= ((uint64_t) size << 41);
	x ^= ((uint64_t) do32 << 53);
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	return (uint32_t)(x & (CMP_FIELD_POOL_BUCKETS - 1U));
}

/* Same wild-write gate as cmp_hints_pool_corrupted() but for field pools.
 * Independent latch + counter bumps so a stomp on a field pool is not
 * folded into the per-syscall pool's corruption rate (the two paths
 * write to different parts of cmp_hints_shm and pinpointing which one
 * tripped narrows root-causing wild-write reports). */
static bool cmp_field_pool_corrupted(struct cmp_field_pool *pool,
				     unsigned int observed_count)
{
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return true;
	if (observed_count <= CMP_HINTS_PER_SYSCALL)
		return false;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
	}
	__atomic_store_n(&pool->corrupted, true, __ATOMIC_RELAXED);
	return true;
}

/* Mirror of pool_add_locked() for the field pool entries[] array.  Same
 * dedup / LRU-eviction discipline -- caller must hold pool->lock. */
static bool cmp_field_pool_insert_locked(struct cmp_field_pool *pool,
				  unsigned long cmp_ip,
				  unsigned long val,
				  unsigned int size)
{
	unsigned int i, count = pool->count;
	uint64_t stamp;
	unsigned int victim;
	uint64_t oldest;

	if (cmp_field_pool_corrupted(pool, count))
		return false;

	stamp = ++pool->last_used_stamp;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			return false;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		/* Field pools inherit the same fresh-insert / evict-replace
		 * SHADOW-score reset discipline as the per-syscall pool above;
		 * the score field is recording-only because the score-based
		 * feedback selection is shadow for both pools and does not
		 * steer pool selection yet. */
		e->wins = 0;
		e->misses = 0;
		e->last_used = stamp;
		__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		return true;
	}

	victim = 0;
	oldest = pool->entries[0].last_used;
	for (i = 1; i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->entries[i].last_used < oldest) {
			oldest = pool->entries[i].last_used;
			victim = i;
		}
	}
	pool->entries[victim].value = val;
	pool->entries[victim].cmp_ip = cmp_ip;
	pool->entries[victim].size = size;
	pool->entries[victim].wins = 0;
	pool->entries[victim].misses = 0;
	pool->entries[victim].last_used = stamp;
	__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
	return true;
}

void cmp_hints_field_record(unsigned int nr, bool do32, unsigned int arg_idx,
			    const struct struct_desc *desc,
			    unsigned int field_idx, unsigned int size,
			    unsigned long val, unsigned long cmp_ip)
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
		bool inserted;

		/* ACQUIRE-load the occupancy gate so a non-NULL desc read is
		 * guaranteed to see the rest of the key the claimer published.
		 * NULL means empty -- candidate for our claim. */
		occ = __atomic_load_n(&pool->key.desc, __ATOMIC_ACQUIRE);
		if (occ != NULL && occ != desc)
			continue;

		lock(&pool->lock);
		/* Re-read under lock so a racing claimer can't slip a different
		 * desc in between our ACQUIRE-load and lock acquire. */
		occ = pool->key.desc;
		if (occ == NULL) {
			/* Claim: fill all key fields, then RELEASE-store desc
			 * last so a reader that ACQUIRE-loads desc sees a
			 * fully-populated key. */
			pool->key.nr = (uint16_t) nr;
			pool->key.do32 = (uint8_t) do32_idx;
			pool->key.arg_idx = (uint8_t) arg_idx;
			pool->key.field_idx = (uint16_t) field_idx;
			pool->key.size = (uint8_t) size;
			__atomic_store_n(&pool->key.desc, desc,
					 __ATOMIC_RELEASE);
		} else if (occ != desc ||
			   pool->key.nr != (uint16_t) nr ||
			   pool->key.do32 != (uint8_t) do32_idx ||
			   pool->key.arg_idx != (uint8_t) arg_idx ||
			   pool->key.field_idx != (uint16_t) field_idx ||
			   pool->key.size != (uint8_t) size) {
			/* Different key at this probe slot; keep walking. */
			unlock(&pool->lock);
			continue;
		}

		inserted = cmp_field_pool_insert_locked(pool, cmp_ip, val, size);
		unlock(&pool->lock);

		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_field_attribution_found,
					   1UL, __ATOMIC_RELAXED);
			(void) inserted;	/* dedup-refresh is a hit too */
		}
		return;
	}

	/* All probes filled with unrelated keys; advisory pool, drop. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_field_attribution_pool_full,
				   1UL, __ATOMIC_RELAXED);
}

void cmp_hints_field_record_self_check(void)
{
	/* Synthesise an insert against a sentinel desc pointer that can
	 * never collide with a real catalog entry (the catalog is an array
	 * of structs, never the address of the cmp_hints_shm itself), prove
	 * the counter bumps + the bucket claims, then clear the bucket back
	 * to empty so the live table starts clean.  Runs at every fresh
	 * trinity startup so a regression in the recording path surfaces
	 * loudly here rather than hiding behind silent zero counters during
	 * a fuzz run.
	 *
	 * A sentinel address that is non-NULL, canonical-aligned, and
	 * stable for the lifetime of the process: the address of
	 * cmp_hints_shm itself.  Cast through (const struct struct_desc *)
	 * for the key field type; we never deref it.
	 */
	const struct struct_desc *sentinel;
	unsigned int idx;
	unsigned int probe;
	uint32_t h;
	unsigned long before, after;
	struct cmp_field_pool *claimed = NULL;

	if (cmp_hints_shm == NULL || kcov_shm == NULL)
		return;

	sentinel = (const struct struct_desc *)(uintptr_t) cmp_hints_shm;
	before = __atomic_load_n(&kcov_shm->cmp_field_attribution_found,
				 __ATOMIC_RELAXED);

	cmp_hints_field_record(/*nr=*/0, /*do32=*/false, /*arg_idx=*/1,
			       sentinel, /*field_idx=*/0, /*size=*/8,
			       /*val=*/0x5a5a5a5a5a5a5a5aULL,
			       /*cmp_ip=*/0xc0ffee00c0ffee00ULL);

	after = __atomic_load_n(&kcov_shm->cmp_field_attribution_found,
				__ATOMIC_RELAXED);
	if (after != before + 1)
		BUG("cmp_hints: field-record self-check counter did not bump");

	/* Locate the claimed bucket (linear probe from the same hash) and
	 * reset it so the live table starts empty.  Walk the full probe
	 * window because a subsequent self-check that re-hashes the same
	 * sentinel must land on a freshly-empty slot, not the one we just
	 * filled. */
	h = cmp_field_pool_hash(sentinel, 0, 0, 1, 0, 8);
	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		if (cmp_hints_shm->field_pools[idx].key.desc == sentinel) {
			claimed = &cmp_hints_shm->field_pools[idx];
			break;
		}
	}
	if (claimed == NULL)
		BUG("cmp_hints: field-record self-check could not locate claimed bucket");

	/* Reset the claimed bucket back to empty.  The unreachable() inside
	 * BUG() above makes the NULL branch terminal, but gcc's fortify
	 * memset-bounds check on -O2 still complains about deref through a
	 * possibly-NULL pointer; clear the entries[] in a hand loop so the
	 * checker sees the bounded indexing directly. */
	for (probe = 0; probe < CMP_HINTS_PER_SYSCALL; probe++)
		claimed->entries[probe] = (struct cmp_hint_entry){ 0 };
	claimed->count = 0;
	claimed->generation = 0;
	claimed->last_used_stamp = 0;
	claimed->key = (struct cmp_field_pool_key){ 0 };
	/* Roll back the counter so the live table starts at zero -- the
	 * synthetic self-check insert isn't a real field attribution. */
	__atomic_fetch_sub(&kcov_shm->cmp_field_attribution_found, 1UL,
			   __ATOMIC_RELAXED);

	output(0, "KCOV: CMP field-record self-check passed\n");
}

/*
 * Field-attribution scan for one CMP record.  For each cataloged INPUT
 * struct arg, walk its fields and -- on a runtime field value matching
 * arg2 -- record the kernel constant arg1 into the field-keyed pool
 * via cmp_hints_field_record().  Independent of the scalar RedQueen
 * attribution path above; runs as a recording-side accumulator so a
 * future consumer can re-inject the constant at the named field.
 *
 * NARROW MVP scope: fixed-size cataloged structs only.  Tagged-union
 * descs (variants != NULL) and buffer-discriminated descs
 * (buffer_discrim_size != 0) are skipped -- the live variant isn't
 * carried in the dispatch_args[] snapshot and re-reading the post-fill
 * buffer to resolve it would race a sibling stomp.  Array / pointer /
 * length-pair tags are skipped because their sibling-coupled reads
 * need the array-aware attribution path, which lands later.  Only flat
 * scalar tags with size in {1,2,4,8} contribute records here.
 */
static void cmp_hints_field_scan_record(struct syscallrecord *srec,
					struct syscallentry *entry,
					unsigned int nr, bool do32,
					unsigned long arg1, unsigned long arg2,
					unsigned int size, unsigned long cmp_ip)
{
	unsigned int slot;
	unsigned int slot_max;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;
	slot_max = entry->num_args;
	if (slot_max > 6)
		slot_max = 6;

	for (slot = 0; slot < slot_max; slot++) {
		enum argtype t = entry->argtype[slot];
		const struct struct_desc *desc;
		const unsigned char *buf;
		unsigned long limit;
		size_t actual_len;
		unsigned int i;

		if (t != ARG_STRUCT_PTR_IN && t != ARG_STRUCT_PTR_INOUT)
			continue;

		desc = struct_arg_lookup(nr, slot + 1, do32, srec);
		if (desc == NULL || desc->struct_size == 0 ||
		    desc->fields == NULL || desc->num_fields == 0)
			continue;

		/* NARROW MVP: skip tagged-union and buffer-discriminated descs.
		 * Variant-scoped attribution needs the live variant choice
		 * which is post-fill state the CMP-time scan can't resolve
		 * safely from the snapshot alone. */
		if (desc->variants != NULL || desc->num_variants != 0 ||
		    desc->buffer_discrim_size != 0)
			continue;

		/* Pointer comes from the dispatch-time snapshot, not live
		 * rec->aN, so a sibling stomp between dispatch and this scan
		 * cannot redirect us at an unrelated buffer.  Shape-gate
		 * before the deref: a NULL / non-canonical / misaligned
		 * snapshot pointer means the snapshot was never written or
		 * the sanitiser handed the kernel something the field scan
		 * can't safely walk.  Bump the dedicated counter so the
		 * occurrence rate is observable. */
		buf = (const unsigned char *)(uintptr_t)
			srec->dispatch_args[slot];
		if (is_corrupt_ptr_shape(buf)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		/* Bound the field-walk against the real sanitiser allocation
		 * extent recovered from alloc_track, NOT range_readable_user
		 * (mappability, not allocation bounds) and NOT desc->struct_size
		 * alone (a variable-length / over-large catalog entry can claim
		 * more bytes than the runtime alloc behind @buf actually owns,
		 * walking the scan past the heap chunk and tripping ASAN
		 * heap-buffer-overflow).  Tracked buffers expose their length
		 * via lookup_size; an untracked buffer cannot prove its extent
		 * and we skip the slot entirely (conservative direction).
		 * limit = min(struct_size, actual_len) so a smaller real alloc
		 * tightens the per-field check while an oversized catalog row
		 * still cannot push us off the chunk. */
		actual_len = alloc_track_lookup_size((void *)(uintptr_t)buf);
		if (actual_len == 0) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_short_alloc,
					1UL, __ATOMIC_RELAXED);
			continue;
		}
		limit = desc->struct_size;
		if ((unsigned long)actual_len < limit)
			limit = (unsigned long)actual_len;

		/*
		 * A tracked alloc-extent does not prove the page is still
		 * mapped readable at scan time.  CMP harvest runs post-
		 * dispatch and the dispatched syscall (brk()/munmap()/
		 * mprotect(), or a sibling consuming the same shared
		 * region) may have dropped or PROT_NONE'd the page holding
		 * @buf between the dispatch-time alloc and this walk.  The
		 * follow-on memcpy() / direct deref inside the field loop
		 * would then SEGV_ACCERR (mapped-but-wrong-perm or freed-
		 * then-recycled VMA) and kill the child mid-collection.
		 *
		 * Same hazard d51f1a67 closed on the field-scoped TIMESPEC
		 * deref via range_readable_user(); apply the same cached-
		 * VMA readability gate over [buf, limit) here.  alloc_track
		 * still owns the size bound (range_readable_user proves
		 * mappability, not allocation extent -- the two invariants
		 * are complementary, exactly the split eea70d8 called out).
		 * On the unreadable path absorb into
		 * cmp_field_attribution_arg_skipped_bad_ptr (the existing
		 * counter for "@buf is not safe to walk"); shape-corruption
		 * and stale-mapping share semantic family from the caller's
		 * point of view -- both mean "skip this slot".
		 */
		if (!range_readable_user(buf, limit)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_field_attribution_scanned,
				1UL, __ATOMIC_RELAXED);

		for (i = 0; i < desc->num_fields; i++) {
			const struct struct_field *f = &desc->fields[i];
			unsigned long fv;

			/* NARROW MVP: only flat scalar tags.  Array / pointer
			 * / length-pair / aggregate tags need either array-
			 * aware sibling resolution or sub-buffer reads, both
			 * deferred to a follow-up. */
			switch (f->tag) {
			case FT_PTR_BYTES:
			case FT_PTR_ARRAY:
			case FT_PTR_STRUCT:
			case FT_LEN_BYTES:
			case FT_LEN_COUNT:
			case FT_TAGGED_UNION:
			case FT_BPF_PROGRAM:
			case FT_VOCAB:
				continue;
			default:
				break;
			}

			if (f->size != size)
				continue;
			/* Per-field cap against the smaller of the cataloged
			 * struct extent and the real alloc extent (limit above).
			 * Cataloged structs whose real alloc is shorter than
			 * struct_size (variable-length tails, over-large catalog
			 * rows) get rejected here before the deref. */
			if ((unsigned long) f->offset + size > limit)
				continue;

			fv = 0;
			switch (size) {
			case 1:
				fv = *(const uint8_t *)(buf + f->offset);
				break;
			case 2: {
				uint16_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 4: {
				uint32_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 8: {
				uint64_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			}

			if (fv == arg2)
				cmp_hints_field_record(nr, do32, slot + 1, desc,
						       i, size, arg1, cmp_ip);
		}
	}
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
static unsigned long cmp_hint_apply_transform(unsigned long c,
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
static void cmp_hints_stash_consumed(unsigned int nr, bool do32,
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

static bool cmp_hint_livepick_arm_b_active(void)
{
	if (!cmp_hint_livepick_arm_stamped) {
		cmp_hint_livepick_arm_b = ONE_IN(2);
		cmp_hint_livepick_arm_stamped = true;
	}
	return cmp_hint_livepick_arm_b;
}

static unsigned int cmp_hint_weighted_pick(struct cmp_hint_entry *entries,
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
					return false;

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
				return true;
			}
		} else if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_recent_would_miss,
					   1UL, __ATOMIC_RELAXED);
		}
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
 * SHADOW gate for the field-scoped pool consumer.  Defaults off so the
 * lookup, would-pick / would-miss counters, and the rest of the pick
 * path are wired end-to-end below without the in-buffer overwrite ever
 * firing -- shadow-first observability before the live arm is wired.
 * The follow-up commit will expose this via a CLI flag; today the field
 * pool stays observation-only.
 */
static bool cmp_field_consumer_live_arm;

bool cmp_hints_field_try_get(unsigned int nr, bool do32, unsigned int arg_idx,
			     const struct struct_desc *desc,
			     unsigned int field_idx, unsigned int size,
			     enum cmp_hint_use use, unsigned long old,
			     unsigned long *out)
{
	struct cmp_field_pool *pool = NULL;
	struct cmp_hint_entry *picked;
	unsigned long picked_value;
	unsigned long picked_cmp_ip;
	uint32_t picked_size;
	unsigned int count;
	uint32_t h;
	unsigned int probe;
	unsigned int do32_idx = do32 ? 1U : 0U;

	if (cmp_hints_shm == NULL || desc == NULL)
		return false;
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return false;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return false;

	/* Chaos-mode gate.  Mirror cmp_hints_try_get_ex so suppressed
	 * windows skip the field consumer the same way they skip the
	 * scalar one -- a chaos window that only suppresses one consumer
	 * arm would bias the kernel-validated mix on the other. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->cmp_hints_chaos_active,
			    __ATOMIC_RELAXED))
		return false;

	/* Bucket lookup: same hash + ACQUIRE-load key probe loop as the
	 * recorder (cmp_hints_field_record above).  Full-key match
	 * required at every probe slot -- a hash collision on a different
	 * key continues walking until either a matching key is found or
	 * the probe window exhausts. */
	h = cmp_field_pool_hash(desc, nr, do32_idx, arg_idx, field_idx, size);

	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		unsigned int idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		struct cmp_field_pool *cand = &cmp_hints_shm->field_pools[idx];
		const struct struct_desc *occ;

		occ = __atomic_load_n(&cand->key.desc, __ATOMIC_ACQUIRE);
		if (occ == NULL)
			break;
		if (occ != desc ||
		    cand->key.nr != (uint16_t) nr ||
		    cand->key.do32 != (uint8_t) do32_idx ||
		    cand->key.arg_idx != (uint8_t) arg_idx ||
		    cand->key.field_idx != (uint16_t) field_idx ||
		    cand->key.size != (uint8_t) size)
			continue;

		pool = cand;
		break;
	}

	if (pool == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_key_absent,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}

	/* Lockless count + corruption gate, byte-for-byte parallel to the
	 * per-syscall pick path: a kernel-side wild write that stomps
	 * pool->count would otherwise feed garbage into rnd_modulo_u32 and
	 * index off the field_pools[] array.  Hints are advisory -- skip
	 * is the safe response. */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_would_miss,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}
	if (cmp_field_pool_corrupted(pool, count)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_pool_corrupted,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}

	/* SHADOW: count the would-be-pick on EVERY call regardless of arm
	 * so the would-pick rate is legible from a default (LIVE off) run.
	 * The LIVE arm bumps the separate cmp_field_consumer_live_picks
	 * counter so the two rates stay cleanly separable. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_would_pick,
				   1UL, __ATOMIC_RELAXED);

	if (!cmp_field_consumer_live_arm)
		return false;

	/* A/B-gated live-pick policy, identical discipline to the
	 * per-syscall pool pick above: arm A keeps the uniform draw, arm
	 * B routes through the weighted draw on the per-entry score the
	 * SHADOW credit drain maintains.  Both arms still stash the
	 * consumed tuple below so the credit drain keeps populating the
	 * .wins / .misses fields the weighted draw consumes. */
	if (cmp_hint_livepick_arm_b_active())
		picked = &pool->entries[
			cmp_hint_weighted_pick(pool->entries, count)];
	else
		picked = &pool->entries[rnd_modulo_u32(count)];
	/* Snapshot the triplet BEFORE the transform so the stash carries
	 * the raw pool-entry identity (cmp_ip, value, size) -- the tuple
	 * the credit drain uses to re-find the same entry.  Reading each
	 * field once locally also avoids a torn (cmp_ip, value, size)
	 * triplet on a concurrent eviction: even if a sibling overwrites
	 * the slot between our loads, the credit drain just fails to
	 * re-find a matching entry and the per-entry score for that pull
	 * is lost (the flat counter still bumps). */
	picked_value = picked->value;
	picked_cmp_ip = picked->cmp_ip;
	picked_size = picked->size;
	/* Staleness sample.  Field pools share the same durable LRU
	 * discipline as the per-syscall pool (cmp_field_pool_insert_locked
	 * bumps pool->last_used_stamp on every insert/dedup-refresh and
	 * stamps the entry's last_used at insert time), so the same
	 * bucketing partition applies.  Same torn-read tolerance + b<=a
	 * underflow guard as the per-syscall pick. */
	{
		uint64_t cur_stamp = __atomic_load_n(&pool->last_used_stamp,
						     __ATOMIC_RELAXED);
		uint64_t entry_stamp = __atomic_load_n(&picked->last_used,
						       __ATOMIC_RELAXED);
		uint64_t age = (cur_stamp >= entry_stamp) ?
				(cur_stamp - entry_stamp) : 0;
		uint8_t bucket = cmp_hint_age_bucket(age);

		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hint_durable_consumed_age[bucket],
					   1UL, __ATOMIC_RELAXED);

		*out = cmp_hint_apply_transform(picked_value, use, old);

		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_live_picks,
					   1UL, __ATOMIC_RELAXED);

		cmp_hints_stash_consumed(nr, do32, CMP_HINT_POOL_FIELD,
					 picked_cmp_ip, picked_value, picked_size, use,
					 arg_idx, field_idx, desc,
					 false, bucket, false);
	}
	return true;
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
