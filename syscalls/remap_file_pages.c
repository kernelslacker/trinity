/*
 * SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
	 unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
 */
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_remap_file_pages(struct syscallrecord *rec)
{
	struct map *map;
	size_t size, offset;
	size_t start = 0;
	size_t file_pages;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL || map->size == 0)
		return;

	/*
	 * remap_file_pages(2) is the legacy nonlinear-mapping syscall;
	 * the kernel still emulates it, but only on MAP_SHARED file-backed
	 * VMAs.  Anonymous or MAP_PRIVATE targets short-circuit to -EINVAL
	 * before reaching the interesting emulation path, so they teach
	 * the fuzzer nothing about that code.  Skip them by neutralising
	 * rec->a1/a2 — matching the no-map short-circuit above — so the
	 * draws that do go through carry the legacy path.
	 */
	if (map->type != MMAPED_FILE || map->fd == -1 ||
	    !(map->flags & MAP_SHARED)) {
		rec->a1 = 0;
		rec->a2 = 0;
		return;
	}

	if (RAND_BOOL()) {
		start = rnd_modulo_u32(map->size);
		start &= PAGE_MASK;
		rec->a1 += start;
	}

	/* We just want to remap a part of the mapping. */
	if (RAND_BOOL())
		size = page_size;
	else {
		size = rnd_modulo_u32(map->size);

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
	/*
	 * Page-align size.  rnd_modulo_u32(map->size) returns an unaligned
	 * value that the kernel rejects with -EINVAL before any nonlinear
	 * code runs.  Round up so the call still covers at least the
	 * selected length, and fall back to a single page when the round
	 * lands on zero.
	 */
	size = (size + page_size - 1) & PAGE_MASK;
	if (size == 0)
		size = page_size;
	rec->a2 = size;

	/*
	 * "The prot argument must be specified as 0" — any nonzero value
	 * short-circuits to -EINVAL.  prot=0 hits the success path; a
	 * small invalid-prot bucket keeps the validation path warm.
	 */
	if (ONE_IN(10))
		rec->a3 = rnd_u32() & 0xff;
	else
		rec->a3 = 0;

	/*
	 * pgoff is in PAGE_SIZE units.  Pick inside [0, file_pages) for
	 * the success path; an overshoot bucket keeps the past-file-end
	 * -EINVAL validation path warm.  map->size is clamped to a
	 * page-aligned in-bounds extent by mmap_fd, so file_pages is the
	 * number of pages actually backed by the file.
	 */
	file_pages = map->size / page_size;
	if (file_pages == 0)
		file_pages = 1;
	if (ONE_IN(10))
		offset = file_pages + rnd_modulo_u32(8) + 1;
	else
		offset = rnd_modulo_u32(file_pages);
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

	/*
	 * Diagnostic: pin slips where the early MAP_SHARED file-backed
	 * filter and the shared-region gate above passed the addr but a
	 * fresh sbrk(0) right here proves it lies inside the live brk
	 * arena.  This syscall does not consult range_overlaps_libc_heap
	 * by design (the kernel rejects -EINVAL on non-MAP_SHARED targets
	 * and the brk arena is MAP_PRIVATE anon), so a non-zero slip
	 * count here would indicate a deeper assumption breaking.
	 */
	log_mm_syscall_post_gate_heap_slip("remap_file_pages", rec->a1,
					   rec->a2, rec->a3);
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
	.rettype = RET_ZERO_SUCCESS,
};
