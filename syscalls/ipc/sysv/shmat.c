/*
 * SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg)
 *
 * A SHM_REMAP attach replaces only pages of the pool mapping the sanitiser
 * picked, final slots included (vet_final_shmat()), and one that worked
 * drops that mapping's pool entry (post_shmat()).
 */
#include <limits.h>
#include <sys/shm.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long shmat_flags[] = {
	SHM_RDONLY, SHM_RND, SHM_REMAP, SHM_EXEC,
};

/*
 * The SHM_REMAP attach the sanitiser vetted, for vet_final_shmat(), and
 * the mapping it attaches over, for post_shmat(): kept for a call that
 * keeps SHM_REMAP, since no other call is held or replaces anything.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so a
 * rewrite of rec->aN cannot move what the call is held to.  post_shmat()
 * claims it, and .cleanup releases it when .post never runs.
 */
#define SHMAT_POST_STATE_MAGIC	0x53484D41545F5654UL	/* "SHMAT_VT" */
struct shmat_post_state {
	unsigned long magic;
	unsigned long shmid;
	unsigned long addr;
	unsigned long flags;
	struct map *map;
};

/*
 * SHM_REMAP replaces whatever the attach lands on, and the sanitiser vets
 * that range, but a rewrite after it can move or grow it: chain
 * substitution puts a return value in the address (ARG_UNDEFINED), the
 * shmid, whose segment's size the range spans, or the flags, a RedQueen
 * pin a constant in any slot.  So a final call carrying SHM_REMAP with a
 * non-NULL address, the one shape that replaces anything, has to be the
 * one the sanitiser vetted in shmid, address and the whole flags word,
 * since SHM_RND moves the address.  A SHM_REMAP it did not draw, or
 * with no snapshot of ours, is refused too.  Refused rather than
 * repaired, each slot read as the kernel reads it: shmid and shmflg as
 * ints, a compat call's address as its low 32 bits.  Shape, then
 * ownership, then magic, as post_state_claim_owned() orders them.
 */
static int vet_final_shmat(struct syscallrecord *rec,
			   const struct syscallentry *entry __unused__)
{
	struct shmat_post_state *snap =
		(struct shmat_post_state *) rec->post_state;
	unsigned long mask = rec->do32bit ? UINT_MAX : ULONG_MAX;

	if (!((unsigned int) rec->a3 & SHM_REMAP) || !(rec->a2 & mask))
		return 0;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == SHMAT_POST_STATE_MAGIC &&
	    !((rec->a1 ^ snap->shmid) & UINT_MAX) &&
	    !((rec->a2 ^ snap->addr) & mask) &&
	    !((rec->a3 ^ snap->flags) & UINT_MAX))
		return 0;

	outputerr("arg-coupling: shmat rejected: SHM_REMAP replaces a range sanitise did not vet\n");
	return -1;
}

/*
 * Whether a SHM_REMAP attach of the segment in a1 at the start of @map
 * replaces pages of @map alone: do_shmat() maps the segment's file
 * MAP_FIXED over whatever lies there.  IPC_STAT reports the size shmget()
 * was asked for, but a hugetlb segment's file is that rounded up to a huge
 * page (newseg()), and the attach takes only an address that page divides
 * (hugetlb_get_unmapped_area()), so the largest power of two dividing the
 * address bounds the rounding whatever the segment is.  SHM_RND rounds the
 * address down to SHMLBA first, and a compat call's kernel reads the low
 * 32 bits of it.  An initial pool mapping is one of trinity's tracked
 * regions, which stay off limits, as does the heap.
 */
static bool shmat_remap_fits(const struct syscallrecord *rec,
			     const struct map *map)
{
	unsigned long base = (unsigned long) map->ptr;
	unsigned long start = base, align, len;
	struct shmid_ds ds;

	if (rec->a3 & SHM_RND)
		start &= ~((unsigned long) SHMLBA - 1);
	if (start == 0 || (rec->do32bit && start > UINT_MAX))
		return false;
	if (shmctl((int) rec->a1, IPC_STAT, &ds) != 0 || ds.shm_segsz == 0)
		return false;

	align = start & -start;
	if (ds.shm_segsz > ULONG_MAX - (align - 1))
		return false;
	len = (ds.shm_segsz + align - 1) & ~(align - 1);

	return start >= base && len <= map->size &&
	       start - base <= map->size - len &&
	       !RANGE_OVERLAPS_SHARED_AUDITED("shmat", start, len) &&
	       !range_overlaps_libc_heap(start, len);
}

static void sanitise_shmat(struct syscallrecord *rec)
{
	struct shmat_post_state *snap;
	struct map *map = NULL;

	/*
	 * shmaddr must be NULL (kernel chooses) or page-aligned.
	 * Non-aligned addresses return EINVAL unless SHM_RND is set.
	 * Use NULL 80% of the time for better success rate, and the start
	 * of a pool mapping otherwise.
	 */
	if (rnd_modulo_u32(5) == 0)
		map = get_map();
	rec->a2 = map != NULL ? (unsigned long) map->ptr : 0;

	/*
	 * SHM_REMAP replaces whatever the attach lands on, so it is kept
	 * only for a segment that fits the mapping (shmat_remap_fits()).
	 * The kernel rejects it with a NULL shmaddr before any vma work,
	 * and an attach over the mapping that lacks it can only fail
	 * (find_vma_intersection() in do_shmat()), so a dropped SHM_REMAP
	 * takes the address with it and the call attaches where the kernel
	 * picks.  A call drawn without SHM_REMAP keeps the address on
	 * purpose: it exercises that occupied-range refusal, and keeps one
	 * draw in five at an address.
	 */
	if ((rec->a3 & SHM_REMAP) &&
	    (map == NULL || !shmat_remap_fits(rec, map))) {
		rec->a3 &= ~SHM_REMAP;
		rec->a2 = 0;
	}

	if (rec->a3 & SHM_REMAP) {
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic = SHMAT_POST_STATE_MAGIC;
		snap->shmid = rec->a1;
		snap->addr  = rec->a2;
		snap->flags = rec->a3;
		snap->map   = map;
		post_state_install(rec, snap);
	}
}

/*
 * The backstop for a call that never reaches .post; a no-op once .post has
 * released the snapshot.
 */
static void cleanup_shmat(struct syscallrecord *rec)
{
	struct shmat_post_state *snap;

	snap = post_state_claim_owned(rec, SHMAT_POST_STATE_MAGIC, __func__);
	post_state_release(rec, snap);
}

/*
 * A SHM_REMAP attach that worked replaced pages of the mapping the
 * sanitiser picked with the segment's, read-only under SHM_RDONLY, so the
 * pool entry no longer describes what lies there, and a consumer that
 * writes through it would fault.  Drop the entry as post_munmap() drops
 * one it punched a hole in: prot 0 keeps get_map_with_prot() off it, and
 * the known_rw skip-cache goes too.  A call whose rewritten slots lost both
 * SHM_REMAP and the address, and so attached where the kernel picked,
 * loses the entry as well, which only costs the pool a mapping.
 */
static void post_shmat(struct syscallrecord *rec)
{
	struct shmat_post_state *snap;
	void *addr = (void *) rec->retval;

	/* Claimed first so every exit releases it, a failed call's too. */
	snap = post_state_claim_owned(rec, SHMAT_POST_STATE_MAGIC, __func__);

	if (addr == (void *) -1)
		goto out;

	if ((unsigned long) addr & (page_size - 1))
		post_handler_corrupt_ptr_bump(rec, NULL);

	if (snap != NULL && !looks_like_corrupted_ptr(rec, snap->map)) {
		snap->map->prot = 0;
		snap->map->known_rw = false;
	}
out:
	post_state_release(rec, snap);
}

struct syscallentry syscall_shmat = {
	.name = "shmat",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_SYSV_SHM, [2] = ARG_LIST },
	.argname = { [0] = "shmid", [1] = "shmaddr", [2] = "shmflg" },
	.arg_params[2].list = ARGLIST(shmat_flags),
	.sanitise = sanitise_shmat,
	.vet_final = vet_final_shmat,
	.flags = REEXEC_SANITISE_OK,
	.post = post_shmat,
	.cleanup = cleanup_shmat,
	.rettype = RET_ADDRESS,
};
