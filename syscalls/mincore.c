/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 */
#include <stdint.h>
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
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

static void sanitise_mincore(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long start, len, vec_bytes;
	void *vec;

	/* Defensive: page_size is set in main() long before sanitisers run,
	 * but quiet the static analyzer about the divide below. */
	if (page_size == 0)
		return;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;
	if (map->size < page_size)
		return;

	start = pick_mincore_start(map);
	len = pick_mincore_len(map->size);
	if (len == 0)
		len = page_size;

	vec_bytes = (len + page_size - 1) / page_size;
	vec = zmalloc_tracked(vec_bytes);

	rec->a1 = start;
	rec->a2 = len;
	rec->a3 = (unsigned long) vec;

	avoid_shared_buffer_out(&rec->a3, vec_bytes);

	/* Hand vec to the per-rec owned-buffer carrier: rec_owned_drain()
	 * frees it unconditionally after dispatch, capturing the genuine
	 * tracked pointer here so a sibling scribble of a3 can't strand or
	 * misdirect the free, and covering the skip-.post paths
	 * (retfd-rejected / killed EXTRA_FORK grandchild) that previously
	 * leaked the buffer. */
	rec_own(rec, vec);
}

struct syscallentry syscall_mincore = {
	.name = "mincore",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "start", [1] = "len", [2] = "vec" },
	.group = GROUP_VM,
	.sanitise = sanitise_mincore,
	.rettype = RET_ZERO_SUCCESS,
};
