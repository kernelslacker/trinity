/*
 * SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg)
 */
#include <limits.h>
#include <sys/shm.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long shmat_flags[] = {
	SHM_RDONLY, SHM_RND, SHM_REMAP, SHM_EXEC,
};

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
}

static void post_shmat(struct syscallrecord *rec)
{
	void *addr = (void *) rec->retval;

	if (addr == (void *) -1)
		return;

	if ((unsigned long) addr & (page_size - 1))
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_shmat = {
	.name = "shmat",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_SYSV_SHM, [2] = ARG_LIST },
	.argname = { [0] = "shmid", [1] = "shmaddr", [2] = "shmflg" },
	.arg_params[2].list = ARGLIST(shmat_flags),
	.sanitise = sanitise_shmat,
	.flags = REEXEC_SANITISE_OK,
	.post = post_shmat,
	.rettype = RET_ADDRESS,
};
