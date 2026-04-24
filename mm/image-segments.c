/*
 * Register every writable PT_LOAD segment of trinity's loaded image
 * (main exe + every loaded DSO -- libc, libpthread, libdl, ld-linux,
 * libasan when built with `make asan`, the vDSO if it ever grows a
 * writable segment) with shared_regions[] so range_overlaps_shared()
 * refuses fuzzed mmap/munmap/mremap/madvise/mprotect calls that target
 * trinity's own .data, .bss, .got, .got.plt, etc.
 *
 * Read-only segments (text, .rodata) don't need protection: a fuzzed
 * mprotect that strips R+X just causes a SIGSEGV on the next
 * instruction fetch, which the existing fault handler catches and
 * post-mortems.  Writable segments are the real exposure -- a fuzzed
 * munmap of trinity's BSS would silently knock out static state
 * (shared_regions[] itself, deferred-free's ring pointer, every other
 * static), and the fuzzer would keep running on top of zero pages until
 * the next deref crashed in some unrelated code path -- a residual-
 * cores nightmare.  This is the same class of bug as the deferred-free
 * ring[] BSS exposure that the recent ring-to-mmap migration closed,
 * generalised to every other static.
 *
 * Use dl_iterate_phdr() to enumerate every loaded object's program
 * headers.  For each PT_LOAD with PF_W set, register
 *     base = info->dlpi_addr + p_vaddr
 *     len  = p_memsz       (memsz, not filesz -- BSS is the part of
 *                          the writable PT_LOAD that lives in memsz
 *                          beyond filesz, and BSS is exactly what we
 *                          most need to protect)
 * via track_shared_region().  Must run before fork_children() so every
 * child inherits the populated table via the COW post-fork copy.
 *
 * Only enumerates objects loaded at the call site -- a later dlopen()
 * (trinity does not currently do this) would not be tracked.  If trinity
 * ever grows runtime DSO loading, re-call this from the dlopen path.
 */

#include <link.h>
#include <stdbool.h>
#include <stddef.h>

#include "trinity.h"
#include "utils.h"

struct phdr_walk_state {
	unsigned int regions_registered;
	unsigned int objects_with_writable;
};

static const char *image_display_name(const char *dlpi_name)
{
	if (dlpi_name == NULL)
		return "<null>";
	if (dlpi_name[0] == '\0')
		return "<main>";
	return dlpi_name;
}

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct phdr_walk_state *st = data;
	unsigned int writable_in_object = 0;
	ElfW(Half) i;

	(void)size;

	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		unsigned long base, len;

		if (ph->p_type != PT_LOAD)
			continue;
		if ((ph->p_flags & PF_W) == 0)
			continue;
		if (ph->p_memsz == 0)
			continue;

		base = (unsigned long)info->dlpi_addr + ph->p_vaddr;
		len  = (unsigned long)ph->p_memsz;

		track_shared_region(base, len);
		st->regions_registered++;
		writable_in_object++;
	}

	if (writable_in_object > 0) {
		st->objects_with_writable++;
		output(1, "image-segments: %s base=0x%lx -> %u writable PT_LOAD region%s\n",
		       image_display_name(info->dlpi_name),
		       (unsigned long)info->dlpi_addr,
		       writable_in_object,
		       writable_in_object == 1 ? "" : "s");
	}

	return 0;
}

void register_loaded_image_segments(void)
{
	struct phdr_walk_state st = { 0, 0 };
	unsigned int after;

	dl_iterate_phdr(phdr_callback, &st);

	output(1, "image-segments: registered %u writable PT_LOAD segments across %u object%s\n",
	       st.regions_registered, st.objects_with_writable,
	       st.objects_with_writable == 1 ? "" : "s");

	/* High-water warning: if shared_regions[] is past 90% capacity
	 * after this batch, the per-child kcov ring registration that
	 * happens during open_fds() -- and any future tracker calls --
	 * are at risk of being dropped silently.  Raise MAX_SHARED_ALLOCS
	 * if this ever fires. */
	after = nr_shared_regions;
	if (after * 10 >= (unsigned int)MAX_SHARED_ALLOCS * 9) {
		outputerr("image-segments: shared_regions at %u/%d (>=90%%) "
			  "after image-segment registration; raise MAX_SHARED_ALLOCS "
			  "or later track_shared_region() calls will be dropped\n",
			  after, MAX_SHARED_ALLOCS);
	}
}
