/*
 * Routines to fault-in mapped pages.
 */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"
#include "pids.h"

#include "kernel/falloc.h"
/* 64KB covers the largest page size (arm64 with 64KB pages). */
static char page_buf[65536];

/*
 * Wrapper so every read-side mprotect() in this file logs a structured
 * failure line (PROT bits + region size + caller PC) instead of the
 * original "silently ignore non-zero returns" behaviour.  The reader
 * still proceeds to the memcpy on failure — pages already mapped with
 * a stricter prot will just satisfy the read regardless, and a true
 * EFAULT surfaces in the memcpy where we can't do anything more useful
 * about it.
 */
static void read_mprotect(void *addr, size_t len, int prot)
{
	if (mprotect(addr, len, prot) != 0)
		log_mprotect_failure(addr, len, prot,
				     __builtin_return_address(0), errno);
}

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset;

	if (map->size == 0)
		return;

	offset = rnd_modulo_u64(map->size) & PAGE_MASK;

	p += offset;
	read_mprotect((void *) p, page_size, PROT_READ);
	memcpy(page_buf, p, page_size);
}


/*
 * Same per-call cap as the write-side dirty_* functions: every
 * read_mprotect() is an mprotect(4096) that triggers a TLB shootdown
 * IPI to every other CPU running a thread of the same mm.  Walking N
 * pages of a large mapping in a tight loop generates an IPI storm
 * proportional to N x num_children.  The fuzz value of read-faulting
 * every page beyond the first few is marginal -- the goal is "this
 * VMA gets read-touched", not "every page in this VMA gets touched".
 */
#define READ_PAGES_PER_CALL_MAX	32U

static unsigned int read_walk_count(struct map *map)
{
	unsigned int nr = nr_pages(map);

	if (nr > READ_PAGES_PER_CALL_MAX)
		nr = READ_PAGES_PER_CALL_MAX;
	return nr;
}

static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, walk;

	walk = read_walk_count(map);

	for (i = 0; i < walk; i++) {
		char *page = p + (i * page_size);
		read_mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

static void read_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, walk, total, first;

	total = nr_pages(map);
	walk = read_walk_count(map);
	first = RAND_BOOL();

	for (i = 0; i < walk; i++) {
		unsigned int idx = first + (i * 2);

		if (idx >= total)
			break;
		char *page = p + (idx * page_size);
		read_mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

static void read_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = read_walk_count(map);

	for (i = 0; i < walk; i++) {
		unsigned int idx = total - 1 - i;
		char *page = p + (idx * page_size);

		read_mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

/* fault in a sample of the mapping's pages. */
static void read_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = read_walk_count(map);

	for (i = 0; i < walk; i++) {
		/* Offset is uniform across the FULL mapping; only the
		 * iteration count is capped. */
		char *page = p + (rnd_modulo_u32(total) * (unsigned long) page_size);
		read_mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

/* Fault in the last page in a mapping */
static void read_last_page(struct map *map)
{
	char *p = map->ptr;
	char *ptr;

	if (map->size < page_size)
		return;

	ptr = p + (map->size - page_size);
	read_mprotect((void *) ptr, page_size, PROT_READ);
	memcpy(page_buf, ptr, page_size);
}

static const struct faultfn read_faultfns[] = {
	{ .func = read_whole_mapping },
	{ .func = read_every_other_page },
	{ .func = read_mapping_reverse },
	{ .func = read_random_pages },
	{ .func = read_last_page },
};

/*
 * Snapshot the caller's map into a stack-local and re-fstat the backing
 * fd to clamp the walkable extent against current i_size.  Mirrors the
 * defense already present in dirty_random_mapping (mm/maps.c) so every
 * read entry path benefits from a fresh clamp instead of just the
 * dirty_random_mapping caller.
 *
 * The original obj->map is left untouched — other callers reuse the
 * stored value and a different walker may race with us; mutating it
 * would leak the narrowed view to anyone holding the same handle.
 *
 * fstat failure (EBADF after a sibling close, etc.) is treated as
 * "no walkable extent" and the read walk is dropped entirely rather
 * than falling back to the stale stored size.  Anonymous mappings
 * (INITIAL_ANON, CHILD_ANON) carry no underlying file extent and pass
 * through unchanged — their sibling-munmap / MADV_DONTNEED race is
 * caught by the sigsetjmp wrap below instead.
 *
 * Returns true with *out filled in if the walk should proceed; false
 * if the walk should be dropped.
 */
static bool read_clamp_size(struct map *map, struct map *out)
{
	*out = *map;

	if (out->type == MMAPED_FILE && out->fd >= 0) {
		struct stat st;

		if (fstat(out->fd, &st) != 0)
			return false;
		if (st.st_size == 0)
			return false;
		if ((unsigned long) st.st_size < out->size)
			out->size = (unsigned long) st.st_size & PAGE_MASK;
	}

	return out->size > 0;
}

/*
 * Per-walk SIGBUS / SIGSEGV guard.  Even after the local-snapshot+
 * fstat clamp above narrows the truncate window, two TOCTOU races
 * remain unclosable without a signal handler:
 *
 *   - File-backed: a sibling fallocate(FALLOC_FL_PUNCH_HOLE) /
 *     fallocate(FALLOC_FL_COLLAPSE_RANGE) / madvise(MADV_REMOVE) can
 *     leave a hole inside the live extent that a fresh fstat would not
 *     catch (st_size unchanged).  The per-page memcpy then SIGBUSes
 *     BUS_ADRERR on the holed page.
 *   - Anonymous: a sibling munmap / mremap MAYMOVE / MAP_FIXED replace
 *     can drop the VMA underneath us.  No backing inode involved, so
 *     the kernel raises SIGSEGV SEGV_MAPERR instead of SIGBUS.
 *
 * The handler longjmps back to random_map_readfn iff the fault
 * si_addr lands inside the active mapping range, otherwise it
 * restores SIG_DFL and re-raises so child_fault_handler diagnoses
 * + exits and the per-pid bug log path is preserved for genuine
 * unrelated faults.
 *
 * volatile / sigjmp_buf rationale matches the equivalent statics in
 * childops/mm/madvise-pattern-cycler.c and childops/pagecache-canary-
 * check.c: ISO C 7.13.2.1 only guarantees post-longjmp values for
 * objects with volatile-qualified type, and GCC's -Wclobbered
 * analysis flags non-volatile locals as possibly clobbered through
 * the wrap.
 */
static sigjmp_buf read_walk_jmp;
static volatile uintptr_t read_walk_lo;
static volatile uintptr_t read_walk_hi;
static volatile sig_atomic_t read_walk_armed;

static __attribute__((no_sanitize("address")))
void read_walk_signal_handler(int sig, siginfo_t *info, void *ctx)
{
	uintptr_t fault_addr;

	(void)ctx;

	if (!read_walk_armed) {
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
	if (fault_addr < read_walk_lo || fault_addr >= read_walk_hi) {
		/* Real kernel fault but si_addr is outside the active
		 * mapping range — not the race we're guarding against.
		 * Restore default and re-raise so child_fault_handler
		 * diagnoses + exits and the bug log path is preserved. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(read_walk_jmp, 1);
}

void random_map_readfn(struct map *map)
{
	struct map local;
	struct sigaction sa, old_segv, old_bus;
	volatile bool aborted = false;

	if (!read_clamp_size(map, &local))
		return;

	read_walk_lo = (uintptr_t) local.ptr;
	read_walk_hi = (uintptr_t) local.ptr + local.size;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = read_walk_signal_handler;
	if (sigaction(SIGBUS,  &sa, &old_bus) != 0)
		return;
	if (sigaction(SIGSEGV, &sa, &old_segv) != 0) {
		(void)sigaction(SIGBUS, &old_bus, NULL);
		return;
	}

	read_walk_armed = 1;

	if (sigsetjmp(read_walk_jmp, 1) == 0) {
		if (local.size == page_size) {
			read_one_page(&local);
		} else {
			if (RAND_BOOL())
				read_one_page(&local);
			else
				read_faultfns[rnd_modulo_u32(ARRAY_SIZE(read_faultfns))].func(&local);
		}
	} else {
		aborted = true;
	}

	read_walk_armed = 0;
	read_walk_lo = 0;
	read_walk_hi = 0;
	(void)sigaction(SIGSEGV, &old_segv, NULL);
	(void)sigaction(SIGBUS,  &old_bus,  NULL);

	if (aborted)
		__atomic_add_fetch(&shm->stats.diag.read_walk_aborted, 1,
				   __ATOMIC_RELAXED);
}
