/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 *
 * The final len reports no more pages than the vec the sanitiser sized
 * holds, into that vec (vet_final_mincore()).
 */
#include <stdint.h>
#include "arch.h"
#include "maps.h"
#include "output-poison.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * mincore needs (a1, a2) to land inside the target mapping and a3
 * to point at a vec buffer holding at least (a2 / page_size) bytes.
 * Previously a1/a2 came from ARG_MMAP+ARG_LEN and were never
 * touched -- a1 was always pinned at map->ptr and a2 was a random
 * value with no relationship to vec's size.  The sizing computed
 * here happened to round up enough that the kernel rarely wrote past
 * the allocation, but the syscall's start/len input space was
 * effectively one point (base, random in [0, map->size)), which
 * starved both the partial-mapping case and the non-base-start vma
 * walk.
 *
 * Drive a1 and a2 from explicit buckets so the three meaningful
 * length shapes (single page, half map, full map) and two start
 * shapes (base, page-aligned non-base) are exercised at known
 * proportions, then size vec to match the picked length so the
 * kernel's writeback into vec is always within bounds.
 */
static unsigned long pick_mincore_start(struct map *map)
{
	unsigned long pages;

	if (rnd_modulo_u32(4) != 0)
		return (unsigned long) map->ptr;
	pages = map->size / page_size;
	if (pages < 2)
		return (unsigned long) map->ptr;
	return (unsigned long) map->ptr +
	       (unsigned long) page_size *
	       rnd_modulo_u32((uint32_t) (pages - 1));
}

static unsigned long pick_mincore_len(unsigned long map_size)
{
	switch (rnd_modulo_u32(3)) {
	case 0:
		return page_size;
	case 1:
		return (map_size / 2) & PAGE_MASK;
	default:
		return map_size & PAGE_MASK;
	}
}

/*
 * Snapshot of the vec OUT-pointer arg captured at sanitise time and
 * consumed by post_mincore.  Lives in rec->post_state so a sibling
 * syscall scribbling rec->a3 between the syscall returning and the
 * post handler running cannot redirect the untouched-buffer check at
 * a foreign user page.  poison_seed == 0 is the sanitise-refused-to-
 * stamp signal (vec == 0 or vec_bytes == 0) and the post handler must
 * no-op the untouched-buffer arm.  vec_bytes is what vec holds, until
 * vet_final_mincore() moves it to the bytes the len it judged has the
 * kernel fill.
 */
#define MINCORE_POST_STATE_MAGIC	0x4D434F52UL	/* "MCOR" */
#define MINCORE_POISON_SEED		0x4D434F52504F5321ULL /* "MCORPOS!" */
struct mincore_post_state {
	unsigned long magic;
	unsigned long vec;
	size_t vec_bytes;
	uint64_t poison_seed;
};

/*
 * The kernel writes a byte into vec for each page of the final len, a
 * partial page counted whole, up to the first hole (sys_mincore()), so
 * that count has to fit the vec the sanitiser sized, and the slot has to
 * name that vec: a len rewritten after it, a substituted return value or a
 * pinned constant, runs the write past the buffer, and a pinned vec aims
 * it anywhere.  What vec holds and where is the snapshot's, and a record
 * with no snapshot of ours passes only a len of no pages.  Refused rather
 * than repaired, each slot read once, as the kernel reads it: the low 32
 * bits for a compat call.  A pass leaves the snapshot the bytes that len
 * has the kernel fill, all the post handler's untouched-buffer check may
 * look at: none for a len of 0.  The address and length rule after the
 * hook can still shorten len, and the kernel then fills fewer, but a vec
 * filled in part never matches the poison, so the check stays quiet.
 * Shape, then ownership, then magic, as post_state_claim_owned() orders
 * them.
 */
static int vet_final_mincore(struct syscallrecord *rec,
			     const struct syscallentry *entry __unused__)
{
	struct mincore_post_state *snap =
		(struct mincore_post_state *) rec->post_state;
	unsigned long mask = rec->do32bit ? UINT_MAX : ULONG_MAX;
	unsigned long len = rec->a2 & mask, vec = rec->a3 & mask;
	unsigned long pages = len / page_size + ((len & ~PAGE_MASK) != 0);
	size_t holds = 0;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == MINCORE_POST_STATE_MAGIC)
		holds = snap->vec_bytes;
	else
		snap = NULL;

	/* A page left after the first test fits vec_bytes, so snap is ours. */
	if (pages > holds || (pages != 0 && vec != snap->vec)) {
		outputerr("arg-coupling: mincore rejected: the len reports more pages than vec holds, or vec is not the one sanitise sized\n");
		return -1;
	}

	if (snap != NULL)
		snap->vec_bytes = pages;
	return 0;
}

static void sanitise_mincore(struct syscallrecord *rec)
{
	struct map *map;
	struct mincore_post_state *snap;
	unsigned long start, len, vec_bytes;
	void *vec;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;
	if (map->size < page_size)
		return;

	start = pick_mincore_start(map);
	len = pick_mincore_len(map->size);
	if (len < page_size)
		len = page_size;

	/*
	 * vec comes from the pool the call reaches: the writable pool, off
	 * trinity's regions by construction, or for a compat call, whose
	 * kernel reads the slot's low 32 bits, the low pool.  With no pool to
	 * draw from, the call reports no pages and the snapshot has nothing
	 * to check.  A map is at most GB(4), so its vec fits a pool.
	 */
	vec_bytes = (len + page_size - 1) / page_size;
	vec = get_call_writable_struct(rec, vec_bytes);
	if (vec == NULL) {
		len = 0;
		vec_bytes = 0;
	}

	rec->a1 = start;
	rec->a2 = len;
	rec->a3 = (unsigned long) vec;

	/*
	 * Untouched-buffer oracle setup.  Kernel writes exactly vec_bytes
	 * residency bytes (0x00 or 0x01 per page) on retval==0; a fixed-
	 * pattern nonzero poison can never survive a real write, so the
	 * check has zero false-positive risk.  Use a FIXED seed (not RNG)
	 * so --dry-run stays byte-identical.  Poison targets rec->a3 post-
	 * relocation so we stamp the final buffer the kernel will see.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = MINCORE_POST_STATE_MAGIC;
	snap->vec = rec->a3;
	snap->vec_bytes = vec_bytes;
	if (rec->a3 != 0 && vec_bytes > 0)
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a3,
					     vec_bytes, MINCORE_POISON_SEED);
	post_state_install(rec, snap);
}

static void post_mincore(struct syscallrecord *rec)
{
	struct mincore_post_state *snap;

	snap = post_state_claim_owned(rec, MINCORE_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_release;
	if (snap->poison_seed == 0)
		goto out_release;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->vec,
					     snap->vec_bytes,
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_mincore = {
	.name = "mincore",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "start", [1] = "len", [2] = "vec" },
	.group = GROUP_VM,
	.sanitise = sanitise_mincore,
	.vet_final = vet_final_mincore,
	.post = post_mincore,
	.rettype = RET_ZERO_SUCCESS,
	/*
	 * SKIP_BLANKET_SCRUB: vec is the only scrubbed slot, and
	 * vet_final_mincore() holds it to the buffer the sanitiser sized in a
	 * pool, off trinity's regions, so a scrub could only move it and
	 * turn the call into a refusal.
	 */
	.flags = REEXEC_SANITISE_OK | SKIP_BLANKET_SCRUB,
};
