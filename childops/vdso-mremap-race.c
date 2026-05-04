/*
 * vdso_mremap_race - race vDSO mutation against a clock_gettime spinner.
 *
 * The vDSO ([vdso] in /proc/self/maps) is a kernel-supplied mapping
 * exported into every userspace process's AS so that a small set of
 * syscalls (clock_gettime / gettimeofday / time / getcpu on x86_64,
 * varies by arch) can be serviced in user mode without trapping.  The
 * mapping is created in arch_setup_additional_pages() at exec(2) time
 * and its base is recorded in the AT_SYSINFO_EHDR aux-vector slot the
 * dynamic linker reads to bind the __vdso_* symbols.
 *
 * Userspace can mutate the [vdso] mapping like any other VMA: mremap()
 * to relocate it, mprotect() to flip its perms, madvise(MADV_DONTNEED)
 * to drop its pages, or munmap() to remove it entirely.  The kernel
 * paths exercised by these operations include:
 *
 *   - mremap of a special-mapping VMA (vdso_mremap special-mapping op):
 *     the AT_SYSINFO_EHDR aux-vector update + per-task vdso_base field
 *     fixup so subsequent vDSO entry routes via the new address.
 *   - mprotect against a special_mapping_vmops VMA: the may_mprotect
 *     callback that special mappings can install to refuse RW flips
 *     (some arches refuse, others permit).
 *   - madvise(DONTNEED) on the vDSO: drops the user-visible page cache
 *     copy; the next vDSO entry must re-fault from the kernel-side
 *     vdso_image (vdso_fault).
 *   - munmap of the vDSO: leaves AT_SYSINFO_EHDR pointing at unmapped
 *     memory; the next clock_gettime via vDSO traps with SIGSEGV and
 *     glibc's per-task vsyscall-page fallback (where supported) takes
 *     over.
 *
 * All four paths are reachable in production by buggy userspace, but
 * trinity's random_syscall path almost never lines up the right (addr,
 * len) pair against the vDSO extent, so coverage of these paths is
 * effectively zero.  This op fixes that by reading [vdso] once at init
 * and racing one of the four mutations against a tight clock_gettime
 * spinner that drives vDSO entry from a sibling task.
 *
 * Per-task isolation: mutating the [vdso] in our own AS would corrupt
 * subsequent code in this trinity child that relies on clock_gettime
 * (the budget loop, the stall detector, basically everything).  To
 * keep the main child's AS clean, both the spinner and the mutator
 * run in dedicated forked helpers.  fork() copies the vDSO mapping
 * into each helper's AS via copy_page_range like any other VMA, so
 * the mutator only damages its own copy and the spinner only sees
 * its own copy go away (or get RW-flipped, or get DONTNEED-faulted).
 *
 * Race-hit indicator: helper_A (spinner) is expected to die with
 * SIGSEGV / SIGBUS when the kernel raced the mutation in just before
 * the next vDSO entry.  vdso_race_helper_segvs counts that — a non-
 * zero value over a fuzz run means the per-task vsyscall fallback
 * path got exercised by mutation racing entry, which is the whole
 * point.  Helper_A exiting cleanly just means the mutation landed
 * after its budget elapsed, also fine.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps the inner loop (vDSO ops are coarse).
 *   - BUDGET_NS sits in the same band as the other thrash ops.
 *   - Both helpers _exit() within microseconds of their work, so the
 *     waitpid drain is bounded.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged helper still trips the SIGALRM stall detector.
 *
 * Init-once, dormant-by-default: the [vdso] discovery reads
 * /proc/self/maps once and caches the extent in static globals.  If
 * no [vdso] line is present (kernels without vDSO support, some
 * exotic configs) every invocation no-ops and returns true.
 */

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#define BUDGET_NS	200000000L	/* 200 ms */
#define MAX_ITERATIONS	8

/*
 * Cached [vdso] extent, populated once on first entry by find_vdso().
 * vdso_inited == false until the first lookup; vdso_present is true
 * iff /proc/self/maps had a [vdso] line.
 */
static bool vdso_inited;
static bool vdso_present;
static unsigned long vdso_start;
static unsigned long vdso_size;

/*
 * Parse /proc/self/maps once.  The [vdso] line looks like:
 *   7ffd1234a000-7ffd1234c000 r-xp 00000000 00:00 0     [vdso]
 * Two hex addresses separated by '-', followed by perms etc., with the
 * trailing path component being the literal string "[vdso]".
 */
static void find_vdso(void)
{
	FILE *f;
	char line[512];

	vdso_inited = true;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL)
		return;

	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long start, end;

		if (strstr(line, "[vdso]") == NULL)
			continue;
		if (sscanf(line, "%lx-%lx", &start, &end) != 2)
			continue;
		if (end <= start)
			continue;

		vdso_start = start;
		vdso_size  = end - start;
		vdso_present = true;
		break;
	}

	fclose(f);
}

enum vdso_mutation {
	MUT_MREMAP = 0,
	MUT_MPROTECT,
	MUT_MADVISE,
	MUT_MUNMAP,
	NR_VDSO_MUTATIONS,
};

/*
 * Spinner helper: tight loop on clock_gettime(CLOCK_MONOTONIC) for
 * BUDGET_NS / 2.  clock_gettime routes through the vDSO on x86_64 and
 * aarch64 by default, so this is the syscall most likely to hit a
 * mutated mapping.  Exits 0 on clean completion; the kernel sets the
 * exit signal on SIGSEGV / SIGBUS if the vDSO was yanked under us.
 */
static void __attribute__((noreturn)) spinner_helper(void)
{
	struct timespec start, now;
	long elapsed_ns;
	unsigned long iters = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		iters++;

		/* Sample budget every 256 iters so the cost of the
		 * subtraction doesn't dominate the loop. */
		if ((iters & 0xff) == 0) {
			elapsed_ns = (now.tv_sec  - start.tv_sec)  * 1000000000L
				   + (now.tv_nsec - start.tv_nsec);
			if (elapsed_ns >= BUDGET_NS / 2)
				break;
		}
	}

	_exit(0);
}

/*
 * Mutator helper: one random mutation against the vDSO range, then
 * exit.  Each mutation touches the helper's own AS only — the parent
 * trinity child's vDSO is unaffected because fork() gave each helper
 * its own copy of the mapping.
 */
static void __attribute__((noreturn)) mutator_helper(void)
{
	enum vdso_mutation mut;
	void *vdso_addr = (void *) vdso_start;
	void *fresh;

	mut = (enum vdso_mutation) ((unsigned int) rand() % NR_VDSO_MUTATIONS);

	switch (mut) {
	case MUT_MREMAP:
		/* Pick a fresh-but-aligned destination via a throwaway
		 * mmap, then mremap with MREMAP_FIXED onto it.  The
		 * scratch reservation gets released by the kernel as
		 * mremap takes ownership of the destination range. */
		fresh = mmap(NULL, vdso_size, PROT_NONE,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (fresh != MAP_FAILED) {
			/* 1-in-RAND_NEGATIVE_RATIO sub the curated
			 * MAYMOVE|FIXED for a curated edge value —
			 * exercises mremap's flag-mask check
			 * (flags & ~(MREMAP_MAYMOVE|MREMAP_FIXED|
			 * MREMAP_DONTUNMAP) -> EINVAL) which the
			 * curated pair never reaches. */
			(void) mremap(vdso_addr, vdso_size, vdso_size,
				      (int)RAND_NEGATIVE_OR(MREMAP_MAYMOVE |
							    MREMAP_FIXED),
				      fresh);
		}
		break;

	case MUT_MPROTECT:
		(void) mprotect(vdso_addr, vdso_size, PROT_READ | PROT_WRITE);
		break;

	case MUT_MADVISE:
		(void) madvise(vdso_addr, vdso_size, MADV_DONTNEED);
		break;

	case MUT_MUNMAP:
		(void) munmap(vdso_addr, vdso_size);
		break;

	case NR_VDSO_MUTATIONS:
		break;
	}

	__atomic_add_fetch(&shm->stats.vdso_race_mutations, 1, __ATOMIC_RELAXED);

	_exit(0);
}

bool vdso_mremap_race(struct childdata *child)
{
	unsigned int iter;
	unsigned int iters = JITTER_RANGE(MAX_ITERATIONS);
	struct timespec start, now;
	long elapsed_ns;

	(void) child;

	if (!vdso_inited)
		find_vdso();
	if (!vdso_present)
		return true;

	__atomic_add_fetch(&shm->stats.vdso_race_runs, 1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < iters; iter++) {
		pid_t spinner_pid, mutator_pid;
		int status;

		spinner_pid = fork();
		if (spinner_pid < 0)
			break;
		if (spinner_pid == 0)
			spinner_helper();

		mutator_pid = fork();
		if (mutator_pid < 0) {
			/* Couldn't fork the mutator — drain spinner and bail. */
			(void) waitpid_eintr(spinner_pid, &status, 0);
			break;
		}
		if (mutator_pid == 0)
			mutator_helper();

		if (waitpid_eintr(spinner_pid, &status, 0) == spinner_pid) {
			if (WIFSIGNALED(status)) {
				int sig = WTERMSIG(status);

				if (sig == SIGSEGV || sig == SIGBUS)
					__atomic_add_fetch(&shm->stats.vdso_race_helper_segvs,
							   1, __ATOMIC_RELAXED);
			}
		}
		(void) waitpid_eintr(mutator_pid, &status, 0);

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ns = (now.tv_sec  - start.tv_sec)  * 1000000000L
			   + (now.tv_nsec - start.tv_nsec);
		if (elapsed_ns >= BUDGET_NS)
			break;
	}

	return true;
}
