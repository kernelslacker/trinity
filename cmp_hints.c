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
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "kcov.h"
#include "persist-util.h"
#include "random.h"
#include "rnd.h"
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
	output(0, "KCOV: CMP hint pool allocated (%lu KB)\n",
		(unsigned long) sizeof(struct cmp_hints_shared) / 1024);

	cmp_hints_strip_install(cmp_hints_strip_targets,
				ARRAY_SIZE(cmp_hints_strip_targets));
	cmp_hints_strip_no_arg_syscalls();
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

static unsigned int cmp_hints_flush_pending(struct cmp_hint_pool *pool,
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
		if (pool_add_locked(pool, batch[j].ip, batch[j].val,
				    batch[j].size))
			inserted++;
	}
	pool_unlock(pool);
	return inserted;
}

void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr, bool do32)
{
	unsigned long count;
	unsigned long i;
	unsigned long skipped = 0;
	unsigned long inserted = 0;
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

				if (n > 6)
					n = 6;
				rec_num_args = n;
				rec_args[0] = rec->dispatch_args[0];
				rec_args[1] = rec->dispatch_args[1];
				rec_args[2] = rec->dispatch_args[2];
				rec_args[3] = rec->dispatch_args[3];
				rec_args[4] = rec->dispatch_args[4];
				rec_args[5] = rec->dispatch_args[5];
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
				 * the [11-snapshot] dispatch_args[] feed
				 * is missing -- attribution correctly
				 * skips the call, surface the rate so the
				 * snapshot-feed health is not silently
				 * folded into the eligible cohort. */
				__atomic_fetch_add(
					&kcov_shm->cmp_attribution_snapshot_unavailable,
					1UL, __ATOMIC_RELAXED);
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
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_nonconst,
						   1UL, __ATOMIC_RELAXED);
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
		 * skip 0/1/2/3 (caught by the ~3UL mask going to 0) and the
		 * all-ones sentinel.
		 */
		if ((arg1 & ~3UL) == 0) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_uninteresting,
						   1UL, __ATOMIC_RELAXED);
			continue;
		}
		if (arg1 == (unsigned long) -1) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_hints_save_reject_sentinel,
						   1UL, __ATOMIC_RELAXED);
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
		}

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
			inserted += cmp_hints_flush_pending(pool, batch, n_batch);
			n_batch = 0;
		}
	}

	inserted += cmp_hints_flush_pending(pool, batch, n_batch);

	if (skipped != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hints_bloom_skipped, skipped,
				   __ATOMIC_RELAXED);

	if (inserted != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->per_syscall_cmp_inserts[nr],
				   inserted, __ATOMIC_RELAXED);
}

/*
 * Per-use-case output transform applied after the pool entry is picked.
 * Factored out of the (formerly inline) try_get body so each transform
 * lives next to its own documentation; the four use cases map onto
 * three distinct rotations (EXACT and FIELD share the bare-C path while
 * the FIELD pool lookup waits on PHASE 3's [11-field-scoped] work).
 *
 * The transform does not consult the pool entry's recorded comparison
 * width: PHASE 2 deliberately keeps every existing pull byte-for-byte
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
		 * this path until PHASE 3 wires a field-scoped pool
		 * lookup. */
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

bool cmp_hints_try_get_ex(unsigned int nr, bool do32, enum cmp_hint_use use,
			  unsigned long old, unsigned long *out)
{
	struct cmp_hint_pool *pool;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_try_get_attempts, 1UL,
				   __ATOMIC_RELAXED);
		/* per-nr partition of the consumer-demand
		 * counter.  The shm/nr guard above already pinned nr <
		 * MAX_NR_SYSCALL so the index is in-bounds. */
		__atomic_fetch_add(&kcov_shm->per_syscall_cmp_attempts[nr],
				   1UL, __ATOMIC_RELAXED);
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

	pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];

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

	*out = cmp_hint_apply_transform(pool->entries[rnd_modulo_u32(count)].value,
					use, old);

	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->cmp_hints_try_get_returned, 1UL,
				   __ATOMIC_RELAXED);
		/* per-nr partition of the producer-side
		 * pool-hit counter.  Same in-bounds guard reasoning as the
		 * attempts bump above. */
		__atomic_fetch_add(&kcov_shm->per_syscall_cmp_returned[nr],
				   1UL, __ATOMIC_RELAXED);
	}
	return true;
}

bool cmp_hints_try_get(unsigned int nr, bool do32, unsigned long *out)
{
	return cmp_hints_try_get_ex(nr, do32, CMP_HINT_BOUNDARY, 0, out);
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
