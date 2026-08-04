/*
 * Test-binary shm provider.
 *
 * PURE modules under test today (args/struct_mutate.c and its
 * struct_catalog/{variant,address}.c helpers) do not reference the
 * shm layer directly, so this TU is a scaffold: it exists so that
 * later Phase-1+ modules migrated onto the arena (whose PURE forms
 * still touch a small subset of shm globals for seed/childno) have
 * a defined home for their fakes without churning the test binary's
 * link line.
 *
 * Fakes go here as symbols are added to the PURE set.  Keep the
 * definitions minimally shaped: a fake shm provider is a scaffold
 * for the test, not a mock of production behaviour, and the goal is
 * "the module links and runs deterministically", not "shm is
 * simulated".  Where a module needs a real shm-derived value
 * (e.g. a child seed), prefer plumbing the value through the test
 * driver in test_main.c over inventing a global here.
 */

/*
 * persist/deferred-free.c seam (prerequisite for direct
 * deferred-free unit coverage on the test seam).
 *
 * Globals and function stubs that satisfy the link when
 * persist/deferred-free.c is compiled as a REAL_SRC.  No fixture
 * exercises the deferred-free machinery in this commit; the stubs
 * exist solely so the seam links and future fixture TUs can be added
 * without mixing link fixes into test logic.
 */
#include <stddef.h>
#include <stdint.h>

#include "shm.h"		/* struct shm_s, extern shm */
#include "params.h"		/* bool deferred_free_batch */
#include "stats_ring.h"		/* struct stats_aggregate, stats_ring_enqueue */
#include "utils-mem.h"		/* track/untrack_shared_region, range_overlaps_shared,
				   is_in_glibc_heap, heap_bounds_init */
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
 * parent_stats.* when this_child() returns NULL (i.e. always, in the
 * test binary).  The write target must be a valid, writable symbol. */
struct stats_aggregate parent_stats;

/* ---------- Function stubs ----------------------------------------------- */

void track_shared_region(unsigned long addr, unsigned long size)
{
	(void)addr; (void)size;
}

void untrack_shared_region(unsigned long addr, unsigned long size)
{
	(void)addr; (void)size;
}

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	(void)addr; (void)len;
	return false;
}

bool is_in_glibc_heap(const void *p)
{
	(void)p;
	/* Conservative: report every pointer as heap-resident so the
	 * deferred-free gates do not prematurely reject addresses. */
	return true;
}

void heap_bounds_init(void)
{
}

struct childdata *this_child(void)
{
	return NULL;
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
