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
#include "child-api.h"
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

struct cmp_hints_shared *cmp_hints_shm = NULL;

/*
 * Rollout mode for the fleet-wide shared cmp_ip tier.  Default OFF is
 * bit-for-bit identical to a build before the tier landed: every hot-
 * path shared-tier access (collect-side insert and get-side shadow
 * probe) short-circuits before touching the tier shm.  See the enum
 * cmp_shared_tier_mode comment in include/cmp_hints.h for the SHADOW /
 * COMBINED contract and the ramp discipline.  Param-settable via
 * --cmp-shared-tier=off|shadow|combined.
 */
enum cmp_shared_tier_mode cmp_shared_tier_mode =
	CMP_SHARED_TIER_MODE_OFF;

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


