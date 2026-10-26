/*
 * SYSCALL_DEFINE3(mseal, unsigned long, start, size_t, len, unsigned long, flags)
 *
 * A seal lasts as long as the mm, so the call only ever seals a small
 * mapping the sanitiser makes for it, never a pool mapping, final slots
 * included (vet_final_mseal()).
 */
#include <sys/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/* The disposable mapping, with room for a sub-range of it. */
#define MSEAL_MAP_PAGES		4

/*
 * Sealed mappings a child keeps before its calls get an empty range: each
 * pins its pages and up to three VMAs until the child exits.
 */
#define MSEAL_MAX_SEALED	16

/* Per process is per child: a fork copies the seals along with the count. */
static unsigned int mseal_sealed;

/*
 * The disposable mapping the sanitiser made, base 0 when it made none,
 * and the flags it drew.  Lives in rec->post_state, a slot the syscall
 * ABI does not expose, so cleanup_mseal() unmaps by this extent and never
 * by the arg slots, which a rewrite may have pointed anywhere.
 */
#define MSEAL_POST_STATE_MAGIC	0x4D5345414C5F5F5FUL	/* "MSEAL___" */
struct mseal_post_state {
	unsigned long magic;
	unsigned long base;
	unsigned long size;
	unsigned long flags;
};

/*
 * The final range may name pages of the disposable mapping only: mseal()
 * reads it as munmap() does (map_range_pages()) and seals every VMA in
 * it, and a sealed VMA refuses munmap, mprotect and mremap for the life
 * of the mm, map_destructor()'s munmap and trinity's own mprotect
 * brackets included.  mseal() refuses any flags but 0 before it reads the
 * range, so the final flags may not cross 0 from the ones drawn either.
 * Both are refused rather than repaired.  A record with no snapshot of
 * ours, or no mapping in it, passes only a range the kernel seals nothing
 * of.  Shape, then ownership, then magic, as post_state_claim_owned()
 * orders them.
 */
static int vet_final_mseal(struct syscallrecord *rec,
			   const struct syscallentry *entry)
{
	struct mseal_post_state *snap =
		(struct mseal_post_state *) rec->post_state;
	struct page_span pages;

	if (is_corrupt_ptr_shape(snap) || !post_state_is_owned(snap) ||
	    snap->magic != MSEAL_POST_STATE_MAGIC)
		snap = NULL;

	if (map_range_pages(rec->a1, rec->a2, rec->do32bit, false, &pages) &&
	    (snap == NULL || snap->base == 0 ||
	     !page_span_inside(&pages, snap->base, snap->size))) {
		outputerr("arg-coupling: %s rejected: the range leaves the mapping sanitise made\n",
			  entry->name);
		return -1;
	}
	if (snap != NULL && (rec->a3 == 0) != (snap->flags == 0)) {
		outputerr("arg-coupling: %s rejected: the flags crossed 0 from the ones sanitise drew\n",
			  entry->name);
		return -1;
	}
	return 0;
}

static void sanitise_mseal(struct syscallrecord *rec)
{
	struct mseal_post_state *snap;
	unsigned long first, pages;
	void *p;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = MSEAL_POST_STATE_MAGIC;

	/*
	 * A sub-range of a fresh anonymous mapping, outside every pool and
	 * tracked region, its length now and then short of its last page,
	 * which the kernel rounds up to.  Past the cap, or with no mapping,
	 * the range is empty: the kernel still checks the flags and the
	 * start, then returns 0 having sealed nothing.
	 */
	rec->a1 = 0;
	rec->a2 = 0;
	if (mseal_sealed < MSEAL_MAX_SEALED) {
		p = mmap(NULL, MSEAL_MAP_PAGES * page_size,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
		if (p != MAP_FAILED) {
			snap->base = (unsigned long) p;
			snap->size = MSEAL_MAP_PAGES * page_size;
			first = rnd_modulo_u32(MSEAL_MAP_PAGES);
			pages = 1 + rnd_modulo_u32(MSEAL_MAP_PAGES - first);
			rec->a1 = snap->base + first * page_size;
			rec->a2 = pages * page_size;
			if (RAND_BOOL())
				rec->a2 -= rnd_modulo_u32(page_size);
		}
	}

	/*
	 * Mostly send 0 so we exercise the success path; occasionally
	 * send something the kernel must reject.  Bias toward single-bit
	 * flips over fully-random because every legitimate flag gain is
	 * one new bit, and a single-bit walk catches `flags & ~ALLOWED_MASK`
	 * regressions sooner than a uniform random 64-bit value.
	 */
	if (ONE_IN(16)) {
		rec->a3 = 1UL << (rnd_modulo_u32(64));
	} else if (ONE_IN(64)) {
		rec->a3 = rand64();
	} else {
		rec->a3 = 0;	/* no flags defined yet, must be zero */
	}

	snap->flags = rec->a3;
	post_state_install(rec, snap);
}

/*
 * The disposable mapping goes on every path, unless the call sealed it.
 * munmap() of a range that holds a sealed VMA fails with EPERM before it
 * unmaps any of it (vms_gather_munmap_vmas()), so the kernel's answer
 * says what was sealed, whatever the return value or the final slots
 * claim: a mapping it refuses to unmap stays, counted against
 * MSEAL_MAX_SEALED.  A munmap() refused for another reason, ENOMEM at the
 * map-count limit when the mapping merged with the VMAs on both sides so
 * the unmap would split one VMA in three, leaves the mapping too, and is
 * counted the same way.
 */
static void cleanup_mseal(struct syscallrecord *rec)
{
	struct mseal_post_state *snap;

	snap = post_state_claim_owned(rec, MSEAL_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (snap->base != 0) {
		if (munmap((void *) snap->base, snap->size) != 0)
			mseal_sealed++;
	}

	post_state_release(rec, snap);
}

struct syscallentry syscall_mseal = {
	.name = "mseal",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_mseal,
	.sanitiser_owned_mask = (1u << 0) | (1u << 1) | (1u << 2),
	.vet_final = vet_final_mseal,
	.cleanup = cleanup_mseal,
	.flags = REEXEC_SANITISE_OK,
};
