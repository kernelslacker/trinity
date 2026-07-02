/*
 * KCOV coverage collection for coverage-guided fuzzing.
 *
 * Each child tries to open /sys/kernel/debug/kcov at startup. If the
 * kernel supports KCOV, per-thread trace buffers are mmapped and PC
 * tracing is enabled around each syscall. Collected PCs are hashed
 * into a global shared bucket-seen table to track edge coverage with
 * AFL-style hit-count bucketing: a syscall that hits the same edge five
 * times is distinguishable from one that hits it two hundred times, so
 * mutations that nudge loop-trip counts past bucket boundaries register
 * as new coverage.
 *
 * When KCOV_REMOTE_ENABLE is available, a fraction of syscalls use
 * remote mode to also collect coverage from softirqs, threaded IRQ
 * handlers, and kthreads triggered by the syscall — deferred work
 * that per-thread KCOV_ENABLE would miss.
 *
 * If KCOV is not available, everything is silently skipped with no
 * runtime overhead beyond the initial open() attempt per child.
 */

#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CONFIG_GUARD_SHARED
#include "signals.h"	/* kcov_protect_recover / kcov_protect_active */
#endif

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "kcov.h"
#include "kcov-internal.h"
#include "minicorpus.h"
#include "params.h"
#include "persist-util.h"
#include "pids.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

struct kcov_shared *kcov_shm = NULL;

/* The per-childop arrays in struct kcov_shared are sized off
 * KCOV_CHILDOP_NR_MAX because include/kcov.h cannot pull in child.h
 * for the real NR_CHILD_OP_TYPES (child.h includes kcov.h for struct
 * kcov_child).  Bump KCOV_CHILDOP_NR_MAX in include/kcov.h if a
 * childop slot beyond the bound is ever added. */
_Static_assert(NR_CHILD_OP_TYPES <= KCOV_CHILDOP_NR_MAX,
	"NR_CHILD_OP_TYPES exceeds KCOV_CHILDOP_NR_MAX; "
	"bump KCOV_CHILDOP_NR_MAX in include/kcov.h");

enum childop_kcov_attribution_mode childop_kcov_attr_mode =
	CHILDOP_KCOV_ATTR_DUAL;

/* Default is OFF: the childop CMP harvest path is dormant and the
 * childop dispatch surface is byte-identical to a build without the
 * --childop-cmp-harvest knob.  Flipping to ON opens the §3.2 bracket
 * on every CMP-mode child whose dispatch reaches the existing
 * op_uses_outer_bracket gate (see child.c) so childop syscalls routed
 * through trinity_cmp_syscall harvest their CMP operands into the
 * quarantined childop_recent_pools[nr][do32] lane.  See the
 * childop_cmp_harvest_mode enum in include/kcov.h for the per-mode
 * contract. */
enum childop_cmp_harvest_mode childop_cmp_harvest_mode =
	CHILDOP_CMP_HARVEST_OFF;

/* Default is SHADOW: collect into the transition map and surface it
 * through the stats dump, but do not feed deltas into any steering
 * consumer.  See the kcov_transition_coverage_mode enum in include/
 * kcov.h for the contract. */
enum kcov_transition_coverage_mode kcov_transition_coverage_mode =
	KCOV_TRANSITION_COVERAGE_SHADOW;

/* Default is COMBINED: feed the capped transition delta into
 * frontier_cold_weight()'s blend, bandit_record_pull()'s per-arm
 * reward total, and the frontier-edge ring via frontier_record_
 * transition_edge() so syscalls that produce only transitions (a new
 * ordering through warm-known code, no fresh PC bits) still earn live
 * frontier credit.  The shadow-mode A/B prior to this default flip
 * showed the blend weighting frontier-transition syscalls upward an
 * order of magnitude more often than downward (frontier_blend_new_
 * higher vs frontier_blend_new_lower in shm->stats), which is the
 * divergence gate justifying the live promotion.  --kcov-transition-
 * reward=shadow-only and =off remain as rollback paths.  See the
 * kcov_transition_reward_mode enum in include/kcov.h for the full
 * contract. */
enum kcov_transition_reward_mode kcov_transition_reward_mode =
	KCOV_TRANSITION_REWARD_COMBINED;
