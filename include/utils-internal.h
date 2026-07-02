#pragma once

/*
 * Internal header for the utils/ cluster.  Holds the shared struct/enum
 * defs, extern decls for cross-cluster variables, and prototypes for
 * cross-cluster helpers that are not part of the public utils API.
 *
 * The public API for utils lives in include/utils.h; anything callers
 * outside utils/ need continues to be declared there.  This header is
 * private to the utils/ subdirectory and utils.c itself.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils.h"	/* MAX_SHARED_ALLOCS, plus the public utils API */

/*
 * Cross-cluster shared state for the shared_regions[] registry.
 * Definitions live in utils/shared_mem.c; utils/range_overlap.c reads
 * the arrays and counters below.  Kept behind a stable struct name so
 * both TUs agree on the layout without duplicating the definition.
 */
#define SHARED_REGIONS_OVERFLOW_TAIL	256

#define SHARED_BITMAP_GRANULARITY_LOG2	21UL	/* 2 MiB per bit */
#define SHARED_BITMAP_VA_LOG2		47UL	/* 128 TiB user VA span */
#define SHARED_BITMAP_VA_SPAN		(1UL << SHARED_BITMAP_VA_LOG2)
#define SHARED_BITMAP_NBITS		(SHARED_BITMAP_VA_SPAN >> SHARED_BITMAP_GRANULARITY_LOG2)
#define SHARED_BITMAP_BITS_PER_WORD	(8UL * sizeof(unsigned long))
#define SHARED_BITMAP_NWORDS		(SHARED_BITMAP_NBITS / SHARED_BITMAP_BITS_PER_WORD)

struct shared_region_entry {
	unsigned long addr;
	unsigned long size;
#ifdef CONFIG_GUARD_SHARED
	uint8_t guarded;
	const char *origin;
#endif
};

extern struct shared_region_entry shared_regions[MAX_SHARED_ALLOCS];
extern struct shared_region_entry shared_regions_overflow[SHARED_REGIONS_OVERFLOW_TAIL];
extern unsigned int nr_shared_regions_overflow;
extern unsigned long shared_region_bitmap[SHARED_BITMAP_NWORDS];
extern unsigned long tracked_size_bm;

/*
 * Inverse-polarity heap-range check exposed for post_snapshot use.
 * Defined in utils/heap_bounds.c alongside heap_bounds_init() and
 * the extra_heap_regions[] snapshot; the post_snapshot cluster needs
 * it as the second leg of range_readable_user()'s fast-path gate.
 */
bool range_inside_libc_heap(unsigned long addr, unsigned long len);
