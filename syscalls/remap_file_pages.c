/*
 * SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
	 unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
 */
#include <stdlib.h>
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"

static void sanitise_remap_file_pages(struct syscallrecord *rec)
{
	struct map *map;
	size_t size, offset;
	size_t start = 0;

	map = common_set_mmap_ptr_len();
	if (map == NULL || map->size == 0)
		return;

	if (RAND_BOOL()) {
		start = rand() % map->size;
		start &= PAGE_MASK;
		rec->a1 += start;
	}

	/* We just want to remap a part of the mapping. */
	if (RAND_BOOL())
		size = page_size;
	else {
		size = rand() % map->size;

		/* if we screwed with the start, we need to take it
		 * into account so we don't go off the end.  size and
		 * start are independent draws so size <= start is
		 * possible — clamp to a single page rather than
		 * underflow into a huge size_t.
		 */
		if (start != 0) {
			if (size > start)
				size -= start;
			else
				size = page_size;
		}
	}
	rec->a2 = size;

	/* "The prot argument must be specified as 0" */
	rec->a3 = 0;

	/* Pick a random pgoff in [0, size_in_pages). */
	if (RAND_BOOL() && size >= page_size)
		offset = rand() % (size / page_size);
	else
		offset = 0;
	rec->a4 = offset;

	/*
	 * remap_file_pages(2) installs a non-linear mapping over
	 * [start, start + size), which on modern kernels is emulated by
	 * tearing down any existing VMA in that range and replacing it.
	 * After the start adjustment above, the [a1, a1 + a2) range can
	 * easily land inside a trinity-owned shared region (kcov
	 * trace_buf, stats blob, child-data) and silently punch a hole
	 * through it — the consumer then SIGBUSes on the next access
	 * past the new mapping's end.  Reject the call if it would.
	 */
	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}
}

static unsigned long remap_file_pages_flags[] = {
	MAP_NONBLOCK,
};

struct syscallentry syscall_remap_file_pages = {
	.name = "remap_file_pages",
	.num_args = 5,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "start", [1] = "size", [2] = "prot", [3] = "pgoff", [4] = "flags" },
	.arg_params[4].list = ARGLIST(remap_file_pages_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_remap_file_pages,
};
