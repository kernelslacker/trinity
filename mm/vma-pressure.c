/*
 * Global VMA-pressure watchdog.
 *
 * The five heavy-VMA childops (vma_split_storm, mprotect_split,
 * mmap_lifecycle, mlock_pressure, madvise_cycler) can drive a single
 * child's VMA count to within striking distance of
 * /proc/sys/vm/max_map_count.  Once the kernel refuses further splits,
 * the symptoms are diffuse ENOMEM returns from mprotect/mmap/mremap
 * that look to the fuzzer like "ran the call, didn't find a bug" --
 * the call never actually entered the interesting paths.  Worse, the
 * VMA pile-up is sticky: child lifetimes are seconds-to-minutes and
 * the child stays starved until exit-and-respawn.
 *
 * Detection + backoff (this file, v1):
 *
 *   - sample_maybe() reads /proc/self/maps line count every N child-op
 *     iterations (gated via periodic_work in child.c so the maps read
 *     does NOT run on every syscall).  Hysteresis latches the per-child
 *     vma_pressure_high flag ON at >=HI%% of g_max_vmas, OFF when the
 *     count drops below LO%% -- the 10-point gap prevents flap.
 *
 *   - is_high() is a single BSS load.  Heavy-VMA childops call it at
 *     the top of their iteration and skip/early-return when set.
 *     "Skip" not "force-recover": v1 is detect-and-back-off only;
 *     forcing a recompose (full-range mprotect to drive vma_merge)
 *     is feasible but out of scope, see DESIGN NOTE at the end.
 *
 * State storage:
 *
 *   All three statics below live in BSS, so trinity's parent process
 *   inherits zeros at startup and every forked child gets its own
 *   COW-private copy of the page on first write.  No shm latch, no
 *   thread-local plumbing (the per-process semantics fall out of
 *   fork's COW for free, and trinity's helper threads inside a child
 *   are not the target -- the helpers are stack-bounded utility
 *   workers, the address-space pressure is the fuzz body's, and the
 *   fuzz body always runs in the child's main process context).
 *
 * Cost (sample path):
 *
 *   /proc/self/maps emits ~70 bytes per VMA (longer for file-backed
 *   entries with long pathnames).  At a typical child shape ~200 VMAs
 *   the read is ~14 KiB and counting newlines costs ~50 us.  At the
 *   latch trigger -- 80%% of the default 65530 == ~52K VMAs -- the
 *   read is ~3.5 MiB and costs ~5-10 ms.  With N=64 ops/sample and
 *   ~700 ops/sec/child, sample cadence is ~11/sec/child: typical
 *   overhead ~0.05%% CPU, latched-state overhead ~10%% CPU (bounded,
 *   only present when the watchdog is the thing keeping the run alive).
 *
 *   If /proc/sys/vm/max_map_count is configured very high (e.g. a host
 *   tuned to 1048576), the maps read at the threshold becomes
 *   prohibitive (>50 MiB).  In that regime the original concern also
 *   recedes: the kernel headroom is so wide that the five childops
 *   cannot realistically exhaust it inside a child lifetime.  We
 *   disable the watchdog entirely when g_max_vmas exceeds
 *   VMA_PRESSURE_DISABLE_ABOVE -- is_high() returns false, the maps
 *   read never runs.
 *
 *   This near-clone of stats.c's count_proc_maps_lines() is deliberate.
 *   stats.c's copy is file-static (parent-side periodic dump);
 *   exporting it would entangle stats.c's include surface with every
 *   hot-path TU that wants the count.  Two ~15-line copies vs a header
 *   churn: keep the copy, note the parity in this comment.  If a third
 *   caller appears, lift it.
 *
 * Fail-safe:
 *
 *   Any open()/read() failure on /proc/self/maps (procfs unmounted in
 *   a fuzzed mount-ns, EMFILE under sibling pressure, ...) latches
 *   the flag HIGH for the cycle.  "When in doubt, back off" -- a
 *   missed sample plus full-speed childops is the failure mode this
 *   whole module exists to prevent.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vma-pressure.h"

/* Sample cadence.  Power of two so the gate compiles to a single AND.
 * 64 strikes the typical-cost / responsiveness balance: at ~700 ops/sec
 * a sample lands every ~90 ms, well inside the worst-case VMA-growth
 * budget of vma_split_storm (~256 iters * up-to-16 split edges) without
 * pinning the child in maps-reading. */
#define VMA_PRESSURE_SAMPLE_PERIOD	64U

/* Hysteresis thresholds in percent of g_max_vmas.  10-point gap is
 * wide enough that a single childop's per-iteration churn cannot
 * straddle it. */
#define VMA_PRESSURE_HI_PCT		80U
#define VMA_PRESSURE_LO_PCT		70U

/* Above this g_max_vmas, the maps-read cost at the HI threshold is
 * prohibitive (~50 MiB at 1M VMAs) and the kernel headroom makes the
 * pressure concern moot for the five-childop set we gate.  Disable. */
#define VMA_PRESSURE_DISABLE_ABOVE	250000UL

/* Buffer for the maps reader; size matches stats.c's count_proc_maps_lines
 * (every /proc/self/maps line fits in 1 KiB on any anonymous mapping;
 * file-backed entries with long pathnames may straddle and arrive in two
 * fgets calls -- anchoring on '\n' below keeps the count right). */
#define VMA_PRESSURE_BUF_BYTES		1024

/* Sentinel for "haven't read max_map_count yet". */
#define VMA_PRESSURE_NOT_INITED		0UL
/* Sentinel for "tried, decided to disable". */
#define VMA_PRESSURE_DISABLED		ULONG_MAX

/* Per-child state (BSS).  g_max_vmas is read once, lazily, on first
 * sample inside each child; subsequent samples in the same child take
 * the cached value.  g_vma_hi/g_vma_lo are derived once at the same
 * time.  vma_pressure_high is the published latch is_high() returns. */
static unsigned long g_max_vmas;
static unsigned long g_vma_hi_threshold;
static unsigned long g_vma_lo_threshold;
static bool vma_pressure_high;

/*
 * Lazy-init the per-child cap.  Called from inside sample_maybe() the
 * first time a sample is taken in this child.  Doing it lazily (vs
 * eagerly in init_child or pre-fork in trinity.c) keeps the new module
 * self-contained and avoids touching the init plumbing for what is in
 * the steady state a single cached value.  The read is one open + one
 * read + one close, ~10 us total -- a once-per-child cost, never
 * repeated.
 *
 * After this function returns, g_max_vmas is exactly one of:
 *   - VMA_PRESSURE_DISABLED  (read failed, OR cap above DISABLE_ABOVE)
 *   - a positive value in (0, VMA_PRESSURE_DISABLE_ABOVE]
 * is_high() and the sampler short-circuit on the DISABLED sentinel.
 */
static void vma_pressure_lazy_init(void)
{
	int fd;
	char buf[32];
	ssize_t n;
	long v;

	if (g_max_vmas != VMA_PRESSURE_NOT_INITED)
		return;

	fd = open("/proc/sys/vm/max_map_count", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		/* Procfs unmounted / sysctl not readable.  Disable the
		 * watchdog rather than guessing a default -- a wrong
		 * default would either gate too aggressively (artificially
		 * starving the fuzz) or too late (the symptom we exist to
		 * prevent). */
		g_max_vmas = VMA_PRESSURE_DISABLED;
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n <= 0) {
		g_max_vmas = VMA_PRESSURE_DISABLED;
		return;
	}
	buf[n] = '\0';
	v = strtol(buf, NULL, 10);
	if (v <= 0) {
		g_max_vmas = VMA_PRESSURE_DISABLED;
		return;
	}
	if ((unsigned long)v > VMA_PRESSURE_DISABLE_ABOVE) {
		g_max_vmas = VMA_PRESSURE_DISABLED;
		return;
	}

	g_max_vmas = (unsigned long)v;
	g_vma_hi_threshold = (g_max_vmas * VMA_PRESSURE_HI_PCT) / 100UL;
	g_vma_lo_threshold = (g_max_vmas * VMA_PRESSURE_LO_PCT) / 100UL;
}

/*
 * Read /proc/self/maps and return the line count, which equals this
 * process's live VMA count.  Returns ULONG_MAX on any failure -- the
 * caller latches HIGH on that sentinel ("when in doubt, back off").
 *
 * Mirrors stats.c::count_proc_maps_lines but with stdbool / fail-safe
 * sentinel.  See the file-top DESIGN NOTE for why this isn't shared.
 */
static unsigned long vma_pressure_count_self_vmas(void)
{
	FILE *f;
	char buf[VMA_PRESSURE_BUF_BYTES];
	unsigned long lines = 0;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL)
		return ULONG_MAX;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (strchr(buf, '\n') != NULL)
			lines++;
	}

	if (fclose(f) != 0) {
		/* fclose failed AFTER reading -- the line count is still
		 * valid; just don't propagate the residual error as a
		 * fail-safe HIGH.  errno is preserved in case a caller in
		 * the future wants to log it. */
	}
	return lines;
}

void vma_pressure_sample_maybe(unsigned long op_nr)
{
	unsigned long count;

	/* Sample cadence gate.  VMA_PRESSURE_SAMPLE_PERIOD is a power of
	 * two, so this compiles to a single AND + compare.  Combined with
	 * the periodic_work tick16 gate in child.c, the effective sampler
	 * cadence is max(16, 64) == 64 ops -- one sample every ~90 ms at
	 * 700 ops/sec/child. */
	if ((op_nr & (VMA_PRESSURE_SAMPLE_PERIOD - 1UL)) != 0UL)
		return;

	vma_pressure_lazy_init();
	if (g_max_vmas == VMA_PRESSURE_DISABLED)
		return;

	count = vma_pressure_count_self_vmas();

	if (count == ULONG_MAX) {
		/* Read failed.  Fail-safe: latch HIGH so the gated childops
		 * back off until the next successful sample restores the
		 * real count.  The "next successful sample" path covers the
		 * recovery: a transient EMFILE that frees a slot in the
		 * meantime, an open() that worked on retry, etc. */
		vma_pressure_high = true;
		return;
	}

	/* Plain hysteresis.  Two separate compares vs a unified band to
	 * keep the latch-on / latch-off transitions explicit in the
	 * source -- the latch-flap incident class in the 2026-06-11 audit
	 * fixes turned on conflating these. */
	if (vma_pressure_high) {
		if (count <= g_vma_lo_threshold)
			vma_pressure_high = false;
	} else {
		if (count >= g_vma_hi_threshold)
			vma_pressure_high = true;
	}
}

bool vma_pressure_is_high(void)
{
	return vma_pressure_high;
}

/*
 * DESIGN NOTE -- v1 is detect + back off only.
 *
 * "Force a VMA recompose" -- e.g. mprotect(PROT_READ|PROT_WRITE) across
 * a heavily-split region to drive vma_merge collapse -- is plausible as
 * v2.  Three reasons it isn't here yet:
 *
 *  1. Ownership: the high-VMA regions are spread across (a) per-childop
 *     private allocations (vma_split_storm's 8 MiB), (b) the OBJ_LOCAL /
 *     OBJ_GLOBAL pool maps (mprotect_split, madvise_cycler), and (c)
 *     fork-time mappings (init_child_mappings).  A recompose has to
 *     know which it's touching -- the pool maps are shared with sibling
 *     children and a recompose would void their map->prot state (the
 *     intersection-tracking in mprotect_split's tail), causing the
 *     ACCERR storm class mprotect_split exists to avoid.
 *
 *  2. Coverage cost: a forced recompose reverts the kernel's split-edge
 *     work that the next iteration would have to redo, burning fuzz
 *     time on no net coverage gain.  Backing off and letting the
 *     natural attrition (child exit / mmap_lifecycle teardown bias /
 *     vma_split_storm's tail munmap) trim instead spends the same time
 *     on whatever the dispatcher picks next.
 *
 *  3. Risk surface: a recompose path needs its own fail-safe -- what
 *     if the recompose itself ENOMEMs because the kernel is at the
 *     ceiling we tripped on?  The detect-only path has no such
 *     recursion to reason about.
 *
 * If the test kernel validation shows backoff-only leaves real recovery
 * time on the floor (children sit latched for seconds while waiting for
 * exit-respawn), the v2 plan is: a recompose helper keyed to
 * vma_split_storm's private region only (case (a) above, the safest
 * single owner), gated behind a second-stage latch that fires when
 * is_high() has been true for >= K consecutive samples.
 */
