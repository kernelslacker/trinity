/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>	// getpagesize
#include <string.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"	// get_address
#include "shm.h"
#include "utils.h"
#include "pids.h"

#include "kernel/falloc.h"
static bool mark_map_rw(struct map *map)
{
	int prot = PROT_READ | PROT_WRITE;
	int ret;

	ret = mprotect(map->ptr, map->size, prot);
	if (ret < 0) {
		log_mprotect_failure(map->ptr, (size_t) map->size, prot,
				     __builtin_return_address(0), errno);
		return false;
	}

	map->prot = prot;
	return true;
}

static bool mark_page_rw(void *page)
{
	int prot = PROT_READ | PROT_WRITE;
	int ret;

	ret = mprotect(page, page_size, prot);
	if (ret < 0) {
		log_mprotect_failure(page, (size_t) page_size, prot,
				     __builtin_return_address(0), errno);
		return false;
	}

	return true;
}

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset;

	if (map->size == 0)
		return;

	offset = rnd_modulo_u64(map->size) & PAGE_MASK;

	if (mark_page_rw(p + offset) == true)
		p[offset] = rnd_u32();
}

/*
 * Per-call upper bound on mark_page_rw() invocations.  Each mark_page_rw
 * is an mprotect(4096) that triggers a TLB shootdown IPI to every other
 * CPU running a thread of the same mm.  Walking N pages of a large
 * mapping in a tight loop generates an IPI storm proportional to N x
 * num_children.  The fuzz value of dirtying any one page after the first
 * few is marginal — the goal is "this VMA gets touched", not "every
 * page in this VMA gets touched".  Cap the per-call work; pages above
 * the cap get hit on a future tick instead.
 */
#define DIRTY_PAGES_PER_CALL_MAX	32U

static unsigned int dirty_walk_count(struct map *map)
{
	unsigned int nr = nr_pages(map);

	if (nr > DIRTY_PAGES_PER_CALL_MAX)
		nr = DIRTY_PAGES_PER_CALL_MAX;
	return nr;
}

static void dirty_whole_mapping(struct map *map)
{
	unsigned int i, nr;

	if (mark_map_rw(map) == false)
		return;

	nr = dirty_walk_count(map);

	for (i = 0; i < nr; i++) {
		char *p = map->ptr + (i * page_size);
		*p = rnd_u32();
	}
}

static void dirty_every_other_page(struct map *map)
{
	unsigned int i, walk, total, first;

	total = nr_pages(map);
	walk = dirty_walk_count(map);
	first = RAND_BOOL();

	/* Step by 2, but stop after `walk` iterations rather than after
	 * `total` pages, so we cap the per-call mprotect count.  walk*2
	 * <= total*2 so the index never overruns. */
	for (i = 0; i < walk; i++) {
		unsigned int idx = first + (i * 2);

		if (idx >= total)
			break;
		char *p = map->ptr + (idx * page_size);
		if (mark_page_rw(p) == true)
			*p = rnd_u32();
	}
}

static void dirty_mapping_reverse(struct map *map)
{
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = dirty_walk_count(map);

	/* Walk the topmost `walk` pages, descending. */
	for (i = 0; i < walk; i++) {
		unsigned int idx = total - 1 - i;
		char *p = map->ptr + (idx * page_size);

		if (mark_page_rw(p) == true)
			*p = rnd_u32();
	}
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = dirty_walk_count(map);

	for (i = 0; i < walk; i++) {
		/* Offset is uniform across the FULL mapping; only the
		 * iteration count is capped.  Preserves the
		 * "any page in the mapping" sampling distribution. */
		off_t offset = rnd_modulo_u32(total) * (off_t) page_size;
		char *p = map->ptr + offset;
		if (mark_page_rw(p) == true)
			*p = rnd_u32();
	}
}

static void dirty_first_page(struct map *map)
{
	char *p = map->ptr;

	if (mark_page_rw(map->ptr) == true)
		generate_random_page(p);
}

/* Dirty the last page in a mapping
 * Fill it with ascii, in the hope we do something like
 * a strlen and go off the end. */
static void dirty_last_page(struct map *map)
{
	char *p;

	if (map->size < page_size)
		return;

	p = map->ptr + map->size - page_size;

	if (mark_page_rw(p) == true)
		memset((void *) p, 'A', page_size);
}

static const struct faultfn write_faultfns_single[] = {
	{ .func = dirty_one_page },
	{ .func = dirty_first_page },
};

static const struct faultfn write_faultfns[] = {
	{ .func = dirty_whole_mapping },
	{ .func = dirty_every_other_page },
	{ .func = dirty_mapping_reverse },
	{ .func = dirty_random_pages },
	{ .func = dirty_last_page },
};

/*
 * Per-walk SIGBUS / SIGSEGV guard.  dirty_random_mapping (mm/maps.c)
 * already snapshot+fstat-clamps the walkable extent before dispatch,
 * but two TOCTOU races remain unclosable without a signal handler:
 *
 *   - File-backed: between the clamp and the per-page store, a sibling
 *     ftruncate() can shrink the file and a sibling fallocate(
 *     FALLOC_FL_PUNCH_HOLE) / fallocate(FALLOC_FL_COLLAPSE_RANGE) /
 *     madvise(MADV_REMOVE) can leave a hole inside the live extent.
 *     The per-page store then SIGBUSes BUS_ADRERR on the holed page.
 *   - Anonymous: a sibling munmap / mremap MAYMOVE / MAP_FIXED replace
 *     can drop the VMA underneath us.  No backing inode involved, so
 *     the kernel raises SIGSEGV SEGV_MAPERR instead of SIGBUS.
 *
 * The handler longjmps back to random_map_writefn iff the fault
 * si_addr lands inside the active mapping range, otherwise it
 * restores SIG_DFL and re-raises so child_fault_handler diagnoses
 * + exits and the per-pid bug log path is preserved for genuine
 * unrelated faults.
 *
 * volatile / sigjmp_buf rationale matches the equivalent statics in
 * mm/fault-read.c and childops/mm/madvise-pattern-cycler.c: ISO C
 * 7.13.2.1 only guarantees post-longjmp values for objects with
 * volatile-qualified type, and GCC's -Wclobbered analysis flags
 * non-volatile locals as possibly clobbered through the wrap.
 */
static sigjmp_buf write_walk_jmp;
static volatile uintptr_t write_walk_lo;
static volatile uintptr_t write_walk_hi;
static volatile sig_atomic_t write_walk_armed;

static __attribute__((no_sanitize("address")))
void write_walk_signal_handler(int sig, siginfo_t *info, void *ctx)
{
	uintptr_t fault_addr;

	(void)ctx;

	if (!write_walk_armed) {
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling-spoofed — kernel has consumed it already. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent (glibc abort etc.) — restore default and
		 * re-raise so child_fault_handler diagnoses + exits.
		 * siglongjmp here would skip in-flight cleanup. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	fault_addr = (uintptr_t)info->si_addr;
	if (fault_addr < write_walk_lo || fault_addr >= write_walk_hi) {
		/* Real kernel fault but si_addr is outside the active
		 * mapping range — not the race we're guarding against.
		 * Restore default and re-raise so child_fault_handler
		 * diagnoses + exits and the bug log path is preserved. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(write_walk_jmp, 1);
}

void random_map_writefn(struct map *map)
{
	struct sigaction sa, old_segv, old_bus;
	volatile bool aborted = false;

	if (map->size == 0)
		return;

	write_walk_lo = (uintptr_t) map->ptr;
	write_walk_hi = (uintptr_t) map->ptr + map->size;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = write_walk_signal_handler;
	if (sigaction(SIGBUS,  &sa, &old_bus) != 0)
		return;
	if (sigaction(SIGSEGV, &sa, &old_segv) != 0) {
		(void)sigaction(SIGBUS, &old_bus, NULL);
		return;
	}

	write_walk_armed = 1;

	if (sigsetjmp(write_walk_jmp, 1) == 0) {
		if (map->size == page_size) {
			write_faultfns_single[rnd_modulo_u32(ARRAY_SIZE(write_faultfns_single))].func(map);
		} else {
			if (RAND_BOOL()) {
				write_faultfns[rnd_modulo_u32(ARRAY_SIZE(write_faultfns))].func(map);
			} else {
				write_faultfns_single[rnd_modulo_u32(ARRAY_SIZE(write_faultfns_single))].func(map);
			}
		}
	} else {
		aborted = true;
	}

	write_walk_armed = 0;
	write_walk_lo = 0;
	write_walk_hi = 0;
	(void)sigaction(SIGSEGV, &old_segv, NULL);
	(void)sigaction(SIGBUS,  &old_bus,  NULL);

	if (aborted)
		__atomic_add_fetch(&shm->stats.diag.write_walk_aborted, 1,
				   __ATOMIC_RELAXED);
}
