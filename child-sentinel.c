/*
 * Periodic-work divergence sentinel.
 *
 * Each tick (every 16 syscalls, gated in child_process), re-issue a
 * curated set of "should be deterministic across short windows"
 * syscalls and compare against the previous tick's reading cached in
 * childdata.sentinel_prev.  Any unexpected drift in the stable fields
 * is the fingerprint of a wild write -- either a fuzzed value-result
 * syscall buffer scribbling our cache, or a fuzzed buffer aimed at the
 * kernel-managed copy that backs one of these reads (utsname,
 * RLIMIT_NOFILE, sched_param).  In both directions the divergence
 * surfaces here as adjacent ticks disagreeing.
 *
 * The probe set is deliberately tiny and cheap (five vDSO-or-fast
 * syscalls), and sysinfo's loads/uptime/freeram are excluded because
 * they legitimately drift between two adjacent ticks.  Sample fields
 * stay limited to those that should not change at all unless someone
 * stomps memory: utsname strings, sysinfo's boot-stable counters,
 * RLIMIT_NOFILE rlim_cur/rlim_max, and the calling task's scheduling
 * priority.
 *
 * On a hit we push a sentinel-marked entry into the per-child
 * pre_crash_ring (so the post-mortem dumper has the offending field
 * and the first 16 bytes of the old + new readings on hand) and bump a
 * relaxed-atomic stats counter.  Per-field bumping is intentional: a
 * multi-field clobber should outweigh a single-field drift in the
 * counter so noise from a singleton false positive stays visible-but-
 * not-dominant.
 */

#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <linux/utsname.h>

#include "child.h"
#include "pre_crash_ring.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#ifndef SYS_uname
#define SYS_uname __NR_uname
#endif
#ifndef SYS_sysinfo
#define SYS_sysinfo __NR_sysinfo
#endif
#ifndef SYS_getrlimit
#define SYS_getrlimit __NR_getrlimit
#endif
#ifndef SYS_prlimit64
#define SYS_prlimit64 __NR_prlimit64
#endif
#ifndef SYS_sched_getparam
#define SYS_sched_getparam __NR_sched_getparam
#endif

/*
 * Per-field identifiers, packed into the synthetic syscallrecord we
 * push into pre_crash_ring on a hit.  Grouped by source syscall so a
 * post-mortem reader can decode "which syscall, which field" from the
 * single id without a side table.
 */
enum sentinel_field {
	SF_UNAME_SYSNAME	= 0,
	SF_UNAME_NODENAME	= 1,
	SF_UNAME_RELEASE	= 2,
	SF_UNAME_VERSION	= 3,
	SF_UNAME_MACHINE	= 4,

	SF_SYSINFO_TOTALRAM	= 10,
	SF_SYSINFO_TOTALSWAP	= 11,
	SF_SYSINFO_TOTALHIGH	= 12,
	SF_SYSINFO_MEM_UNIT	= 13,

	SF_GETRLIMIT_CUR	= 20,
	SF_GETRLIMIT_MAX	= 21,

	SF_PRLIMIT64_CUR	= 30,
	SF_PRLIMIT64_MAX	= 31,

	SF_SCHED_PRIORITY	= 40,
};

/*
 * Magic value stuffed into rec.a6 of the synthetic pre_crash_ring entry
 * so a post-mortem reader can distinguish a sentinel divergence record
 * from a real syscall record that happens to share the syscall number.
 */
#define SENTINEL_MARKER 0xD1AE5EA1D1AE5EA1UL

/*
 * Capture the curated readings into `out`.  Returns true on full
 * success; false if any single probe failed (in which case `out` is
 * left in a partially-filled state and the caller should treat the
 * sample as unusable to avoid comparing torn data).
 *
 * Direct syscall() throughout so a libc wrapper that caches its result
 * (uname, prlimit) cannot mask a kernel-side regression -- the existing
 * uname.c oracle uses the same approach for the same reason.
 */
static bool sentinel_capture(struct sentinel_reading *out)
{
	struct new_utsname uts;
	struct sysinfo si;
	struct rlimit rl_g;
	struct rlimit rl_p;
	struct sched_param sp;

	memset(&uts, 0, sizeof(uts));
	memset(&si, 0, sizeof(si));
	memset(&rl_g, 0, sizeof(rl_g));
	memset(&rl_p, 0, sizeof(rl_p));
	memset(&sp, 0, sizeof(sp));

	if (syscall(SYS_uname, &uts) != 0)
		return false;
	if (syscall(SYS_sysinfo, &si) != 0)
		return false;
	if (syscall(SYS_getrlimit, RLIMIT_NOFILE, &rl_g) != 0)
		return false;
	if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &rl_p) != 0)
		return false;
	if (syscall(SYS_sched_getparam, 0, &sp) != 0)
		return false;

	memcpy(out->sysname,  uts.sysname,  sizeof(out->sysname));
	memcpy(out->nodename, uts.nodename, sizeof(out->nodename));
	memcpy(out->release,  uts.release,  sizeof(out->release));
	memcpy(out->version,  uts.version,  sizeof(out->version));
	memcpy(out->machine,  uts.machine,  sizeof(out->machine));

	out->sysinfo_totalram	= si.totalram;
	out->sysinfo_totalswap	= si.totalswap;
	out->sysinfo_totalhigh	= si.totalhigh;
	out->sysinfo_mem_unit	= si.mem_unit;

	out->getrlimit_cur	= (unsigned long) rl_g.rlim_cur;
	out->getrlimit_max	= (unsigned long) rl_g.rlim_max;

	out->prlimit64_cur	= (unsigned long) rl_p.rlim_cur;
	out->prlimit64_max	= (unsigned long) rl_p.rlim_max;

	out->sched_priority	= sp.sched_priority;

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

	__atomic_add_fetch(&shm->stats.divergence_sentinel_anomalies, 1,
			   __ATOMIC_RELAXED);
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

	if (child == NULL)
		return;

	if (!sentinel_capture(&cur))
		return;

	if (!child->sentinel_prev.valid) {
		/* First tick (or first after clean_childdata): nothing to
		 * compare against.  Stash and return. */
		child->sentinel_prev = cur;
		return;
	}

	compare_uname_field(child, SF_UNAME_SYSNAME,
			    child->sentinel_prev.sysname, cur.sysname,
			    sizeof(cur.sysname));
	compare_uname_field(child, SF_UNAME_NODENAME,
			    child->sentinel_prev.nodename, cur.nodename,
			    sizeof(cur.nodename));
	compare_uname_field(child, SF_UNAME_RELEASE,
			    child->sentinel_prev.release, cur.release,
			    sizeof(cur.release));
	compare_uname_field(child, SF_UNAME_VERSION,
			    child->sentinel_prev.version, cur.version,
			    sizeof(cur.version));
	compare_uname_field(child, SF_UNAME_MACHINE,
			    child->sentinel_prev.machine, cur.machine,
			    sizeof(cur.machine));

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

	compare_scalar(child, (unsigned int) SYS_getrlimit, SF_GETRLIMIT_CUR,
		       child->sentinel_prev.getrlimit_cur,
		       cur.getrlimit_cur);
	compare_scalar(child, (unsigned int) SYS_getrlimit, SF_GETRLIMIT_MAX,
		       child->sentinel_prev.getrlimit_max,
		       cur.getrlimit_max);

	compare_scalar(child, (unsigned int) SYS_prlimit64, SF_PRLIMIT64_CUR,
		       child->sentinel_prev.prlimit64_cur,
		       cur.prlimit64_cur);
	compare_scalar(child, (unsigned int) SYS_prlimit64, SF_PRLIMIT64_MAX,
		       child->sentinel_prev.prlimit64_max,
		       cur.prlimit64_max);

	compare_scalar(child, (unsigned int) SYS_sched_getparam,
		       SF_SCHED_PRIORITY,
		       (unsigned long) child->sentinel_prev.sched_priority,
		       (unsigned long) cur.sched_priority);

	child->sentinel_prev = cur;
}
