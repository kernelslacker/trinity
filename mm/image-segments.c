/*
 * Register every writable PT_LOAD segment of trinity's loaded image (main exe
 * and every DSO) with shared_regions[], so range_overlaps_shared() refuses
 * fuzzed mmap/munmap/mremap/madvise/mprotect calls that target trinity's own
 * .data and .bss.  Runs once, before fork_children(), so every child inherits
 * the populated table.
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
		/* Read-only segments need no protection: a fuzzed mprotect
		 * that strips R+X only faults on the next instruction fetch,
		 * which the fault handler catches.  Writable ones are the
		 * exposure: a fuzzed munmap of the BSS would silently zero
		 * static state, shared_regions[] included. */
		if ((ph->p_flags & PF_W) == 0)
			continue;
		if (ph->p_memsz == 0)
			continue;

		base = (unsigned long)info->dlpi_addr + ph->p_vaddr;
		/* memsz, not filesz: the BSS is the part of a writable
		 * segment beyond filesz, and the part most worth protecting. */
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

/* Covers the objects loaded at the call; one dlopen()ed later is not tracked. */
void register_loaded_image_segments(void)
{
	struct phdr_walk_state st = { 0, 0 };
	unsigned int after;

	dl_iterate_phdr(phdr_callback, &st);

	output(1, "image-segments: registered %u writable PT_LOAD segments across %u object%s\n",
	       st.regions_registered, st.objects_with_writable,
	       st.objects_with_writable == 1 ? "" : "s");

	/* Sanity floor: every supported libc layout produces at least two
	 * writable PT_LOAD segments -- the main executable's data/BSS and
	 * libc's data/BSS.  Older distros where libpthread is a separate
	 * DSO add a third (libpthread data); modern glibc folds libpthread
	 * into libc and the count stays at two.  A count below two means
	 * dl_iterate_phdr() didn't enumerate what we expect (statically
	 * linked binary, exotic loader, or detection failure), and the
	 * shared_regions[] table is missing protection for trinity's own
	 * static state -- a fuzzed munmap of BSS would then go unblocked. */
	if (st.regions_registered < 2) {
		outputerr("image-segments: only %u writable PT_LOAD segment%s registered "
			  "(expected >=2: main exe data + libc data); trinity's static "
			  "state may not be protected from fuzzed mmap/munmap/mprotect\n",
			  st.regions_registered,
			  st.regions_registered == 1 ? "" : "s");
	}

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
