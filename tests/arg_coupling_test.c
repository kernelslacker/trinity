/*
 * Self-check for the per-syscall rules validate_arg_coupling() holds the
 * final argument slots to: a rewrite after the sanitiser (chain
 * substitution, a RedQueen pin) must not leave the kernel a range the
 * sanitiser would have refused.  madvise is the one that can discard
 * pages every child shares, so its (addr, len) is checked against the
 * regions trinity tracks.
 */

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include "arg_coupling.h"
#include "debug.h"			/* BUG */
#include "syscall.h"			/* struct syscallrecord */

/* Region tracking in tests/fake_shm.c. */
void fake_track_region(unsigned long addr, unsigned long size);
void fake_untrack_regions(void);
extern bool fake_overlaps_libc_heap;

#define REGION		0x7f0000000000UL
#define REGION_SIZE	0x100000UL
#define MADV_REMOVE_ADVICE	9UL

/* The shape of madvise's table entry; its sanitiser needs the OBJ_MMAP
 * pools, which the test binary does not have. */
static struct syscallentry madvise_entry = {
	.name = "madvise",
	.num_args = 3,
	.argtype = { ARG_MMAP, ARG_LEN, ARG_OP },
	.is_madvise = true,
};

/* Same slots, not madvise. */
static struct syscallentry other_entry = {
	.name = "mprotect",
	.num_args = 3,
	.argtype = { ARG_MMAP, ARG_LEN, ARG_OP },
};

static struct syscallrecord rec;

/* Run the validator over one call and leave the final slots in rec. */
static void validated(struct syscallentry *entry, unsigned long addr,
		      unsigned long len)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = entry;
	rec.a1 = addr;
	rec.a2 = len;
	rec.a3 = MADV_REMOVE_ADVICE;

	if (validate_arg_coupling(&rec) != 0)
		BUG("arg coupling: a call with no rule against it was refused");
	if (rec.a3 != MADV_REMOVE_ADVICE)
		BUG("arg coupling: the advice slot was rewritten");
}

static void expect_zeroed(unsigned long addr, unsigned long len)
{
	validated(&madvise_entry, addr, len);
	if (rec.a1 != 0 || rec.a2 != 0)
		BUG("arg coupling: madvise range reaching a tracked region was kept");
}

static void expect_kept(struct syscallentry *entry, unsigned long addr,
			unsigned long len)
{
	validated(entry, addr, len);
	if (rec.a1 != addr || rec.a2 != len)
		BUG("arg coupling: a range the rule has no reason to touch was rewritten");
}

/* The range the kernel will read is held to what the sanitiser would have
 * accepted: nothing of trinity's own, nothing of the libc heap. */
static void madvise_range_held_off_regions(void)
{
	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);

	/* Wholly inside the region, and a length that grows a clean start
	 * into it: the two things a pin or a substituted return value do. */
	expect_zeroed(REGION + 0x1000, 0x1000);
	expect_zeroed(REGION - 0x10000, 0x7ffff000UL);
	expect_zeroed(REGION - 0x1000, 0x2000);
	expect_zeroed(REGION + REGION_SIZE - 0x1000, 0x10000);

	/* A range that wraps the address space is refused as the sanitiser
	 * refuses it, whatever it started as. */
	expect_zeroed(ULONG_MAX - 0xfffUL, 0x4000);

	/* Clear ranges, below and above the region, keep both slots. */
	expect_kept(&madvise_entry, REGION - 0x10000, 0x1000);
	expect_kept(&madvise_entry, REGION + REGION_SIZE, 0x1000);
	expect_kept(&madvise_entry, 0x10000000UL, 0x4000);

	/* Any other entry with the same slots is not this rule's. */
	expect_kept(&other_entry, REGION + 0x1000, 0x1000);
	expect_kept(&other_entry, REGION - 0x10000, 0x7ffff000UL);

	/* The libc heap is held off the same way. */
	fake_overlaps_libc_heap = true;
	expect_zeroed(0x10000000UL, 0x4000);
	expect_kept(&other_entry, 0x10000000UL, 0x4000);
	fake_overlaps_libc_heap = false;

	fake_untrack_regions();
}

void arg_coupling_self_check(void);
void arg_coupling_self_check(void)
{
	madvise_range_held_off_regions();
}
