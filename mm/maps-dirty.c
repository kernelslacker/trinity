#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/mman.h>

#include "arch.h"
#include "maps.h"

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	switch (map->prot) {
	case PROT_WRITE:
	case PROT_WRITE|PROT_READ:
	case PROT_WRITE|PROT_EXEC:
	case PROT_WRITE|PROT_READ|PROT_EXEC:
		random_map_writefn(map);
		break;
	case PROT_READ:
	case PROT_READ|PROT_EXEC:
	case PROT_EXEC:
		random_map_readfn(map);
		break;
	case PROT_SEM:
	case PROT_NONE:
	default:
		break;
	}
}

/*
 * Pick a random mapping, and perform some r/w op on it.
 * Called from child on child init, and also periodically
 * from periodic_work()
 */
void dirty_random_mapping(void)
{
	struct map_handle h;
	struct map local;

	if (!get_map_handle(&h))
		return;

	/*
	 * Cheap defense-in-depth NULL re-check right before the deref-
	 * heavy dirty_mapping path (it reads map->prot to dispatch and
	 * then map->ptr / map->size inside random_map_writefn /
	 * random_map_readfn).  Pools are per-child private heap, so there
	 * is no concurrent destroyer to race with; this only guards
	 * against the handle being clobbered across the call gap above.
	 * It is a plain NULL check -- no counters are bumped here.
	 */
	if (!validate_map_handle(&h))
		return;

	/*
	 * The mmap_fd post-mmap fstat clamp pins obj->map.size to the file's
	 * backed extent at allocation time, but a sibling syscall can
	 * ftruncate() the underlying fd down between then and now.  Walking
	 * the stale stored size SIGBUSes BUS_ADRERR on the first page past
	 * the new EOF.
	 *
	 * Snapshot the map into a stack-local, re-fstat the fd, and clamp
	 * a local-effective walk extent using the same min / page-aligned
	 * down arithmetic as the mmap_fd clamp.  obj->map.size itself is
	 * left untouched -- other consumers reuse the stored value and a
	 * different walker may race with us; mutating it would leak the
	 * narrowed view to anyone holding the same handle.
	 *
	 * fstat failure (EBADF after a sibling close, etc.) is treated as
	 * "no walkable extent" and the dirty walk is dropped entirely
	 * rather than falling back to the stale stored size.  Anonymous
	 * mappings (INITIAL_ANON, CHILD_ANON) carry no underlying file
	 * extent and pass through unchanged.
	 */
	local = *h.map;

	if (local.type == MMAPED_FILE && local.fd >= 0) {
		struct stat st;

		if (fstat(local.fd, &st) != 0)
			return;
		if (st.st_size == 0)
			return;
		if ((unsigned long) st.st_size < local.size)
			local.size = (unsigned long) st.st_size & PAGE_MASK;
	}

	if (local.size == 0)
		return;

	dirty_mapping(&local);
}
