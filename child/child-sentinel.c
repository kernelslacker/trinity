/*
 * Periodic-work divergence sentinel.
 *
 * Each tick (every 16 syscalls, gated in child_process), re-issue a
 * curated set of "should be deterministic across short windows"
 * syscalls and compare against the previous tick's reading cached in
 * childdata.sentinel_prev.  Any unexpected drift in the stable fields
 * is the fingerprint of a wild write -- either a fuzzed value-result
 * syscall buffer scribbling our cache, or a fuzzed buffer aimed at the
 * kernel-managed copy that backs one of these reads (utsname's
 * boot-stable strings, sysinfo's boot-stable scalars).  In both
 * directions the divergence surfaces here as adjacent ticks disagreeing.
 *
 * The probe set is deliberately tiny and cheap (two fast syscalls), and
 * sysinfo's loads/uptime/freeram are excluded because they legitimately
 * drift between two adjacent ticks.  Sample fields stay limited to
 * those that should not change at all unless someone stomps memory:
 * utsname's sysname/release/version/machine and sysinfo's
 * totalram/totalswap/totalhigh/mem_unit.  utsname's nodename,
 * RLIMIT_NOFILE rlim_cur/rlim_max, and the task's scheduling priority
 * are deliberately excluded -- they are routinely mutated by successful
 * sethostname / setrlimit / prlimit64 / sched_setparam calls trinity
 * itself fuzzes, so comparing them produces false-positive divergences
 * on every operator-driven write rather than detecting kernel-side
 * corruption.
 *
 * On a hit we push a sentinel-marked entry into the per-child
 * pre_crash_ring (so the post-mortem dumper has the offending field
 * and the first 16 bytes of the old + new readings on hand) and bump a
 * relaxed-atomic stats counter.  Per-field bumping is intentional: a
 * multi-field clobber should outweigh a single-field drift in the
 * counter so noise from a singleton false positive stays visible-but-
 * not-dominant.
 */

#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/utsname.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "pre_crash_ring.h"
#include "shm.h"
#include "syscall.h"

#ifndef SYS_uname
#define SYS_uname __NR_uname
#endif
#ifndef SYS_sysinfo
#define SYS_sysinfo __NR_sysinfo
#endif

/*
 * enum sentinel_field is declared in include/stats.h alongside the
 * per-field anomaly array in struct stats_s.  Pin SF__MAX to the
 * highest field id so a future field added to the enum without
 * bumping SF__MAX trips the build instead of silently writing past
 * the counter array.
 */
_Static_assert((int)SF_SYSINFO_MEM_UNIT < (int)SF__MAX,
	       "SF__MAX must exceed the highest sentinel_field id");

/*
 * Magic value stuffed into rec.a6 of the synthetic pre_crash_ring entry
 * so a post-mortem reader can distinguish a sentinel divergence record
 * from a real syscall record that happens to share the syscall number.
 */
#define SENTINEL_MARKER 0xD1AE5EA1D1AE5EA1UL

/*
 * Capture-family selectors for sentinel_capture().  uname and sysinfo
 * each take a kernel-global rwsem on entry, so the tick path stays at
 * one syscall per call by alternating families across ticks (see
 * divergence_sentinel_tick()).  The first tick after clean_childdata
 * still passes SENT_CAP_ALL to seed both halves of sentinel_prev.
 */
#define SENT_CAP_UNAME		(1U << 0)
#define SENT_CAP_SYSINFO	(1U << 1)
#define SENT_CAP_ALL		(SENT_CAP_UNAME | SENT_CAP_SYSINFO)

/*
 * Capture the curated readings selected by `flags` into `out`.  Returns
 * true on full success; false if any requested probe failed (in which
 * case `out` is left in a partially-filled state and the caller should
 * treat the sample as unusable to avoid comparing torn data).  Fields
 * outside the requested families are left untouched so a caller that
 * merges the result into a longer-lived stash keeps the previously
 * captured values for the deferred family.
 *
 * Direct syscall() throughout so a libc wrapper that caches its result
 * (uname, prlimit) cannot mask a kernel-side regression -- the existing
 * uname.c oracle uses the same approach for the same reason.
 */
static bool sentinel_capture(struct sentinel_reading *out, unsigned int flags)
{
	if (flags & SENT_CAP_UNAME) {
		struct new_utsname uts;

		memset(&uts, 0, sizeof(uts));
		if (syscall(SYS_uname, &uts) != 0)
			return false;

		memcpy(out->sysname,  uts.sysname,  sizeof(out->sysname));
		memcpy(out->release,  uts.release,  sizeof(out->release));
		memcpy(out->version,  uts.version,  sizeof(out->version));
		memcpy(out->machine,  uts.machine,  sizeof(out->machine));
	}

	if (flags & SENT_CAP_SYSINFO) {
		struct sysinfo si;

		memset(&si, 0, sizeof(si));
		if (syscall(SYS_sysinfo, &si) != 0)
			return false;

		out->sysinfo_totalram	= si.totalram;
		out->sysinfo_totalswap	= si.totalswap;
		out->sysinfo_totalhigh	= si.totalhigh;
		out->sysinfo_mem_unit	= si.mem_unit;
	}

	out->valid = true;
	return true;
}

/*
 * Push a sentinel-marked record into the per-child pre_crash_ring and
 * bump the divergence counter.  Encoding:
 *
 *   rec.nr  = real syscall number of the diverging probe (so the
 *             pre_crash_ring dumper resolves a name)
 *   rec.a1  = enum sentinel_field
 *   rec.a2  = first 8 bytes of old reading
 *   rec.a3  = next  8 bytes of old reading
 *   rec.a4  = first 8 bytes of new reading
 *   rec.a5  = next  8 bytes of new reading
 *   rec.a6  = SENTINEL_MARKER (lets a reader filter sentinel entries
 *             out of the real-syscall stream)
 *   retval  = (unsigned long) -1L
 *
 * 16 bytes per side is what fits cleanly in the existing ring slot
 * (args is 6 unsigned longs); for the multi-field utsname strings this
 * is enough to capture the divergent prefix in nearly every realistic
 * clobber pattern, and for the scalar sysinfo / rlimit / sched_param
 * fields the entire value fits in the first 8 bytes of each side.
 */
static void sentinel_report(struct childdata *child,
			    unsigned int syscall_nr,
			    enum sentinel_field field,
			    const void *old_bytes,
			    const void *new_bytes,
			    size_t bytes)
{
	struct syscallrecord rec;
	struct timespec now;
	unsigned long old_packed[2] = { 0, 0 };
	unsigned long new_packed[2] = { 0, 0 };
	size_t copy = bytes;

	if (copy > sizeof(old_packed))
		copy = sizeof(old_packed);
	memcpy(old_packed, old_bytes, copy);
	memcpy(new_packed, new_bytes, copy);

	memset(&rec, 0, sizeof(rec));
	rec.nr		= syscall_nr;
	rec.a1		= (unsigned long) field;
	rec.a2		= old_packed[0];
	rec.a3		= old_packed[1];
	rec.a4		= new_packed[0];
	rec.a5		= new_packed[1];
	rec.a6		= SENTINEL_MARKER;
	rec.retval	= (unsigned long) -1L;
	rec.errno_post	= 0;
	rec.do32bit	= false;

	clock_gettime(CLOCK_MONOTONIC, &now);
	pre_crash_ring_record(child, &rec, &now);

	/* SF_UNAME_RELEASE and SF_UNAME_MACHINE are legitimately rewritten
	 * by personality(PER_LINUX32|UNAME26), which the fuzzer hits often
	 * enough during a bandit plateau (~130 bumps/window) to drown the
	 * real corruption signal if it goes onto the anomaly histogram.
	 * Route those into a separate "expected drift" counter — the
	 * pre_crash_ring entry is still recorded above so the post-mortem
	 * decoder can replay the divergence, only the live histogram is
	 * carved out.  Mirror of the 2026-05-09 uid_change_logged split. */
	if (field == SF_UNAME_RELEASE || field == SF_UNAME_MACHINE) {
		__atomic_add_fetch(&shm->stats.divergence_sentinel.expected_drift,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Per-field shard.  The bounds-guard pairs with the _Static_assert
	 * above; a corrupt `field` value (out-of-range) is dropped from the
	 * histogram rather than scribbling past the array. */
	if ((unsigned int) field < (unsigned int) SF__MAX) {
		__atomic_add_fetch(&shm->stats.divergence_sentinel.anomalies[field],
				   1, __ATOMIC_RELAXED);
	}
}

static void compare_uname_field(struct childdata *child,
				enum sentinel_field field,
				const char *old_str,
				const char *new_str,
				size_t len)
{
	if (memcmp(old_str, new_str, len) == 0)
		return;
	sentinel_report(child, (unsigned int) SYS_uname, field,
			old_str, new_str, len);
}

static void compare_scalar(struct childdata *child,
			   unsigned int syscall_nr,
			   enum sentinel_field field,
			   unsigned long old_val,
			   unsigned long new_val)
{
	if (old_val == new_val)
		return;
	sentinel_report(child, syscall_nr, field,
			&old_val, &new_val, sizeof(old_val));
}

void divergence_sentinel_tick(struct childdata *child)
{
	struct sentinel_reading cur;
	unsigned int cap_flags;

	if (child == NULL)
		return;

	if (!child->sentinel_prev.valid) {
		/* First tick (or first after clean_childdata): seed both
		 * halves of the stash so the staggered ticks that follow
		 * always have a baseline for the family they don't refresh. */
		memset(&cur, 0, sizeof(cur));
		if (!sentinel_capture(&cur, SENT_CAP_ALL))
			return;
		child->sentinel_prev = cur;
		return;
	}

	/* Stagger uname vs sysinfo across two ticks: each syscall takes a
	 * kernel-global rwsem, so paying one per tick instead of two halves
	 * the sentinel's per-tick cost.  Detection latency for a divergence
	 * in the deferred family slips by one tick -- acceptable because
	 * the divergences this oracle catches (wild writes into the cached
	 * reading or the kernel-managed datum behind it) persist. */
	cap_flags = (child->sentinel_tick_ix++ & 1U)
			? SENT_CAP_SYSINFO
			: SENT_CAP_UNAME;

	memset(&cur, 0, sizeof(cur));
	if (!sentinel_capture(&cur, cap_flags))
		return;

	if (cap_flags & SENT_CAP_UNAME) {
		compare_uname_field(child, SF_UNAME_SYSNAME,
				    child->sentinel_prev.sysname, cur.sysname,
				    sizeof(cur.sysname));
		compare_uname_field(child, SF_UNAME_RELEASE,
				    child->sentinel_prev.release, cur.release,
				    sizeof(cur.release));
		compare_uname_field(child, SF_UNAME_VERSION,
				    child->sentinel_prev.version, cur.version,
				    sizeof(cur.version));
		compare_uname_field(child, SF_UNAME_MACHINE,
				    child->sentinel_prev.machine, cur.machine,
				    sizeof(cur.machine));

		memcpy(child->sentinel_prev.sysname, cur.sysname,
		       sizeof(cur.sysname));
		memcpy(child->sentinel_prev.release, cur.release,
		       sizeof(cur.release));
		memcpy(child->sentinel_prev.version, cur.version,
		       sizeof(cur.version));
		memcpy(child->sentinel_prev.machine, cur.machine,
		       sizeof(cur.machine));
	}

	if (cap_flags & SENT_CAP_SYSINFO) {
		compare_scalar(child, (unsigned int) SYS_sysinfo, SF_SYSINFO_TOTALRAM,
			       child->sentinel_prev.sysinfo_totalram,
			       cur.sysinfo_totalram);
		compare_scalar(child, (unsigned int) SYS_sysinfo, SF_SYSINFO_TOTALSWAP,
			       child->sentinel_prev.sysinfo_totalswap,
			       cur.sysinfo_totalswap);
		compare_scalar(child, (unsigned int) SYS_sysinfo, SF_SYSINFO_TOTALHIGH,
			       child->sentinel_prev.sysinfo_totalhigh,
			       cur.sysinfo_totalhigh);
		compare_scalar(child, (unsigned int) SYS_sysinfo, SF_SYSINFO_MEM_UNIT,
			       (unsigned long) child->sentinel_prev.sysinfo_mem_unit,
			       (unsigned long) cur.sysinfo_mem_unit);

		child->sentinel_prev.sysinfo_totalram  = cur.sysinfo_totalram;
		child->sentinel_prev.sysinfo_totalswap = cur.sysinfo_totalswap;
		child->sentinel_prev.sysinfo_totalhigh = cur.sysinfo_totalhigh;
		child->sentinel_prev.sysinfo_mem_unit  = cur.sysinfo_mem_unit;
	}
}
