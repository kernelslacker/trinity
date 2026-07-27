/*
 * Syscall table copy / stamping + init-time EXPENSIVE bitmap build.
 *
 * Carved out of tables/tables.c: this file owns copy_syscall_table(),
 * the one-time entry point select_syscall_tables() that copies the
 * per-arch static descriptor arrays into shared memory, and the
 * read-only EXPENSIVE bitmaps + syscall_is_expensive() query the
 * pickers hit on their reject fast path.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "arch-syscalls.h"
#include "results.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"	// ARRAY_SIZE

/*
 * EXPENSIVE-syscall bitmaps, one bit per table index, populated by
 * select_syscall_tables() after copy_syscall_table() has stamped the
 * caches.  EXPENSIVE is a static, compile-time flag never modified at
 * runtime, so the bitmap is built once at init and read-only after.
 * Lets the three pickers reject the 999/1000 of EXPENSIVE picks
 * before validate_specific_syscall_silent() and get_syscall_entry(),
 * skipping the cache miss on the syscallentry on the common reject
 * path.  Indexed by from-table index (== entry->number), the same
 * value the pickers hold in syscallnr after the active_syscalls[]
 * reduction.
 */
#define EXPENSIVE_BITMAP_WORDS ((MAX_NR_SYSCALL + 63) / 64)
static uint64_t expensive_bits_uniarch[EXPENSIVE_BITMAP_WORDS];
static uint64_t expensive_bits_32[EXPENSIVE_BITMAP_WORDS];
static uint64_t expensive_bits_64[EXPENSIVE_BITMAP_WORDS];

static void build_expensive_bitmap(const struct syscalltable *table,
				   unsigned int nr, uint64_t *bitmap)
{
	unsigned int i;
	unsigned int cap = (nr < MAX_NR_SYSCALL) ? nr : MAX_NR_SYSCALL;

	for (i = 0; i < cap; i++) {
		if (table[i].entry == NULL)
			continue;
		if (table[i].entry->flags & EXPENSIVE)
			bitmap[i / 64] |= ((uint64_t) 1) << (i % 64);
	}
}

bool syscall_is_expensive(unsigned int nr, bool do32)
{
	const uint64_t *bm;

	if (nr >= MAX_NR_SYSCALL)
		return false;

	if (biarch == false)
		bm = expensive_bits_uniarch;
	else
		bm = do32 ? expensive_bits_32 : expensive_bits_64;

	return (bm[nr / 64] >> (nr % 64)) & 1;
}

/*
 * Rewrite the pointers in table 'from' so each .entry points at a
 * copy in a shared mmap visible across all children.  Every runtime-
 * mutable field of the descriptor has moved off to the parallel RW
 * syscall_runtime array (see struct syscall_runtime); the descriptor
 * itself is written only from here and from munge_tables()'s flag-
 * stamping helpers, so it can be frozen PROT_READ once munge_tables
 * completes.
 *
 * The descriptor `copy` array is routed through alloc_shared_page_-
 * aligned() so its base is page-aligned and its length is whole-page
 * padded.  This lets protect_syscall_tables() mprotect(PROT_READ) the
 * span exactly after munge_tables() finishes stamping flag bits and
 * before the child fleet forks.  The parallel RW `syscall_runtime`
 * array stays on its own alloc_shared() mapping so it remains
 * writable at runtime.  The out-params return the descriptor's base
 * and rounded length so the caller can hand both to the mprotect.
 */
static struct syscalltable * copy_syscall_table(struct syscalltable *from, unsigned int nr,
						void **out_desc_base, size_t *out_desc_len)
{
	unsigned int n, m;
	struct syscallentry *copy;
	struct syscall_runtime *runtime;
	size_t bytes, rt_bytes, desc_len = 0;

	if (!shared_size_mul(nr, sizeof(struct syscallentry), &bytes)) {
		outputerr("copy_syscall_table: nr=%u * sizeof(struct syscallentry) overflows size_t\n",
			  nr);
		exit(EXIT_FAILURE);
	}
	copy = alloc_shared_page_aligned(bytes, &desc_len);
	if (copy == NULL)
		exit(EXIT_FAILURE);

	/*
	 * Parallel RW runtime state array (RO-table split, Phase 1 step b).
	 * Same length (nr slots) and same slot index (m) as `copy`, so an
	 * over-allocated tail is fine -- what matters is that copy[m].rt
	 * points at runtime[m] and never moves.  alloc_shared POISONS the
	 * fresh mapping with random bytes to expose uninitialized reads
	 * (see utils/shared_mem.c __alloc_shared), so the runtime slots
	 * must be explicitly zeroed here -- both back-indices (and every
	 * counter/scoreboard field added by the later commits in this
	 * stack) are read as "not-yet-set" via a zero compare.
	 */
	if (!shared_size_mul(nr, sizeof(struct syscall_runtime), &rt_bytes)) {
		outputerr("copy_syscall_table: nr=%u * sizeof(struct syscall_runtime) overflows size_t\n",
			  nr);
		exit(EXIT_FAILURE);
	}
	runtime = alloc_shared(rt_bytes);
	if (runtime == NULL)
		exit(EXIT_FAILURE);
	memset(runtime, 0, rt_bytes);

	for (n = 0, m = 0; n < nr; n++) {
		struct syscallentry *entry = from[n].entry;

		if (entry == NULL)
			continue;

		memcpy(copy + m , entry, sizeof(struct syscallentry));
		copy[m].number = n;
		copy[m].rt = &runtime[m];
		copy[m].syscall_category = stats_syscall_category(copy[m].name);
		copy[m].is_close_syscall = (strcmp(copy[m].name, "close") == 0);
		/*
		 * Per-discriminator flags consumed by the shared .sanitise /
		 * .post hooks for the five biarch / variant pairs trinity
		 * fuzzes.  Resolved once here so the per-call discriminator
		 * collapses to a single-byte load (see current_entry_is_*()
		 * in include/tables.h) instead of running this_syscallname()'s
		 * lookup-and-strcmp on every probe.
		 */
		copy[m].is_mmap2 = (strcmp(copy[m].name, "mmap2") == 0);
		copy[m].is_sync_file_range2 = (strcmp(copy[m].name, "sync_file_range2") == 0);
		copy[m].is_inotify_init1 = (strcmp(copy[m].name, "inotify_init1") == 0);
		copy[m].is_epoll_create1 = (strcmp(copy[m].name, "epoll_create1") == 0);
		copy[m].is_execve = (strcmp(copy[m].name, "execve") == 0);
		copy[m].is_epoll_wait_family =
			(strcmp(copy[m].name, "epoll_wait") == 0 ||
			 strcmp(copy[m].name, "epoll_pwait") == 0 ||
			 strcmp(copy[m].name, "epoll_pwait2") == 0);
		copy[m].numeric_substitute_mask = compute_numeric_substitute_mask(&copy[m]);
		copy[m].address_scrub_mask = compute_address_scrub_mask(&copy[m]);
		/*
		 * SKIP_BLANKET_SCRUB syscalls opt out of the defense-in-depth
		 * walk in blanket_address_scrub() — their sanitisers place
		 * pointers whose VA and backing bytes the kernel must observe
		 * unchanged.  Zeroing the cached mask collapses the per-dispatch
		 * walk to the existing mask==0 early-return without any extra
		 * branch on the hot path.
		 */
		if (copy[m].flags & SKIP_BLANKET_SCRUB)
			copy[m].address_scrub_mask = 0;
		copy[m].cleanup_arg_mask = compute_cleanup_arg_mask(&copy[m]);
		copy[m].fd_arg_mask = compute_fd_arg_mask(&copy[m]);
		copy[m].len_arg_mask = compute_len_arg_mask(&copy[m]);
		populate_arglist_all_bits(&copy[m]);
		copy[m].nested_address_scrub_mask =
			compute_nested_address_scrub_mask(&copy[m]);
		if (copy[m].flags & SKIP_BLANKET_SCRUB)
			copy[m].nested_address_scrub_mask = 0;

		/* The runtime array is memset(0) above, which leaves
		 * results[].len_score decoding as (min=0, max=0) -- a valid
		 * range, not the not-seen sentinel.  Stamp every per-arg
		 * slot so a reader sees min > max on a fresh slot. */
		{
			unsigned int i;
			for (i = 0; i < 6; i++)
				results_init_one(&runtime[m].results[i]);
		}

		from[n].entry = &copy[m];
		m++;
	}

	if (out_desc_base != NULL)
		*out_desc_base = copy;
	if (out_desc_len != NULL)
		*out_desc_len = desc_len;

	return from;
}

void select_syscall_tables(void)
{
#ifdef ARCH_IS_BIARCH
	syscalls_64bit = copy_syscall_table(SYSCALLS64, ARRAY_SIZE(SYSCALLS64),
					    &desc_extents[1].base,
					    &desc_extents[1].len);
	syscalls_32bit = copy_syscall_table(SYSCALLS32, ARRAY_SIZE(SYSCALLS32),
					    &desc_extents[2].base,
					    &desc_extents[2].len);

	max_nr_64bit_syscalls = ARRAY_SIZE(SYSCALLS64);
	max_nr_32bit_syscalls = ARRAY_SIZE(SYSCALLS32);
	biarch = true;

	build_expensive_bitmap(syscalls_64bit, max_nr_64bit_syscalls,
			       expensive_bits_64);
	build_expensive_bitmap(syscalls_32bit, max_nr_32bit_syscalls,
			       expensive_bits_32);
#else
	syscalls = copy_syscall_table(SYSCALLS, ARRAY_SIZE(SYSCALLS),
				      &desc_extents[0].base,
				      &desc_extents[0].len);
	max_nr_syscalls = ARRAY_SIZE(SYSCALLS);

	build_expensive_bitmap(syscalls, max_nr_syscalls,
			       expensive_bits_uniarch);
#endif
}
