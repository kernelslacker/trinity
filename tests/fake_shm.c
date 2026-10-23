/*
 * Test-binary shm provider: an in-process shm_s, page_size, this_child(),
 * the shared-region and heap probes, and the stubs that let
 * persist/deferred-free*.c link as REAL_SRCs.  A scaffold, not a mock of
 * production: plumb a shm-derived value (a child seed) through test_main.c
 * rather than inventing a global here.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "shm.h"		/* struct shm_s, extern shm */
#include "params.h"		/* bool deferred_free_batch */
#include "stats_ring.h"		/* struct stats_aggregate, stats_ring_enqueue */
#include "utils-mem.h"		/* track/untrack_shared_region, range_overlaps_shared,
				   range_overlaps_libc_heap, is_in_glibc_heap,
				   heap_bounds_init */
#include "utils-alloc.h"	/* deferred_free_reject_bump,
				   looks_like_corrupted_ptr_pc,
				   log_self_corrupt_culprit */
#include "pc_format.h"		/* pc_to_string */

/* ---------- Globals ------------------------------------------------------ */

/*
 * In-process substitute for the shared-memory segment.  A static,
 * zero-initialised struct is sufficient: the test binary is
 * single-process and never calls create_shm() / init_shm(), so all
 * shm->stats.* writes by the deferred-free internals go to BSS and
 * are harmlessly discarded at exit.
 */
static struct shm_s fake_shm_storage;
struct shm_s *shm = &fake_shm_storage;

/* Batch-mode protection-change optimisation: always disabled in the
 * test binary (no mprotect brackets needed). */
bool deferred_free_batch = false;

/* System page size: 4 KiB placeholder.  deferred_free_init() is not
 * called by any test fixture today, so the value is never used in
 * anger; it must be non-zero so PAGE_MASK arithmetic does not
 * compute a nonsense mask. */
unsigned int page_size = 4096;

/* Parent-context statistics aggregate.  deferred-free writes into
 * parent_stats.* when this_child() returns NULL (i.e. outside a test
 * that installs fake_this_child).  The write target must be a valid,
 * writable symbol. */
struct stats_aggregate parent_stats;

/* this_child()'s answer: NULL (parent context) unless a test installs
 * a child for the duration of the call it drives. */
struct childdata *fake_this_child;

/* ---------- Function stubs ----------------------------------------------- */

void track_shared_region(unsigned long addr, unsigned long size)
{
	(void)addr; (void)size;
}

void untrack_shared_region(unsigned long addr, unsigned long size)
{
	(void)addr; (void)size;
}

/* What range_overlaps_shared() and shared_region_size_for() answer.
 * Nothing is tracked in the test binary, so the first says no and the
 * second 0 unless a test wants a range reported as shared or registers a
 * region with fake_track_region(). */
bool fake_overlaps_shared;
bool fake_overlaps_libc_heap;

static struct {
	unsigned long addr;
	unsigned long size;
} fake_regions[4];
static unsigned int fake_nr_regions;

void fake_track_region(unsigned long addr, unsigned long size);
void fake_track_region(unsigned long addr, unsigned long size)
{
	if (fake_nr_regions < sizeof(fake_regions) / sizeof(fake_regions[0])) {
		fake_regions[fake_nr_regions].addr = addr;
		fake_regions[fake_nr_regions].size = size;
		fake_nr_regions++;
	}
}

void fake_untrack_regions(void);
void fake_untrack_regions(void)
{
	fake_nr_regions = 0;
}

/* The production test: a wrapped range counts as overlapping, an empty one
 * only when its address lies strictly inside a region. */
bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned int i;

	if (fake_overlaps_shared)
		return true;
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	for (i = 0; i < fake_nr_regions; i++) {
		unsigned long rstart = fake_regions[i].addr;
		unsigned long rend = rstart + fake_regions[i].size;

		if (len == 0 ? (addr >= rstart && addr < rend)
			     : (addr < rend && rstart < addr + len))
			return true;
	}
	return false;
}

unsigned long shared_region_size_for(unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < fake_nr_regions; i++) {
		unsigned long rstart = fake_regions[i].addr;
		unsigned long rsize = fake_regions[i].size;

		if (addr >= rstart && addr < rstart + rsize)
			return rsize - (addr - rstart);
	}
	return 0;
}

bool range_overlaps_libc_heap(unsigned long addr, unsigned long len)
{
	(void)addr; (void)len;
	return fake_overlaps_libc_heap;
}

/* What is_in_glibc_heap() answers: every pointer, so the deferred-free
 * gates do not prematurely reject addresses, unless a test sets
 * fake_heap_size to have only [fake_heap_start, +fake_heap_size) count
 * as heap, the way the real check refuses whatever lies outside it. */
unsigned long fake_heap_start;
unsigned long fake_heap_size;

bool is_in_glibc_heap(const void *p)
{
	unsigned long v = (unsigned long)p;

	if (fake_heap_size == 0)
		return true;
	return v >= fake_heap_start && v - fake_heap_start < fake_heap_size;
}

void heap_bounds_init(void)
{
}

struct childdata *this_child(void)
{
	return fake_this_child;
}

bool stats_ring_enqueue(struct stats_ring *ring, enum stats_field field,
			uint16_t aux, uint32_t delta)
{
	(void)ring; (void)field; (void)aux; (void)delta;
	return true;
}

void deferred_free_reject_bump(void *caller_pc)
{
	(void)caller_pc;
}

const char *pc_to_string(void *pc, char *buf, size_t buflen)
{
	(void)pc; (void)buf; (void)buflen;
	return "(unknown)";
}

bool looks_like_corrupted_ptr_pc(struct syscallrecord *rec, const void *p,
				 void *caller_pc)
{
	(void)rec; (void)p; (void)caller_pc;
	return false;
}

void log_self_corrupt_culprit(const char *site, unsigned long wild,
			      const struct syscallrecord *rec)
{
	(void)site; (void)wild; (void)rec;
}
