#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <asm/mman.h>

#include "child.h"
#include "maps.h"

/*
 * Read /proc/self/maps and verify a VMA invariant about [addr, addr+len).
 *
 * expect_present=true: at least one entry overlapping the range must exist
 * with rwx prot bits matching expected_prot.
 * expect_present=false: no entry may overlap the range at all.
 *
 * Returns true when the invariant holds, false when it is violated.
 * Returns true on I/O errors to avoid false positives.
 */
bool proc_maps_check(unsigned long addr, unsigned long len,
		     int expected_prot, bool expect_present)
{
	FILE *f;
	char line[256];
	unsigned long start, end;
	char perms[5];
	bool found = false;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return true;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
			continue;
		if (end <= addr || start >= addr + len)
			continue;

		if (expect_present) {
			int map_prot = 0;

			if (perms[0] == 'r')
				map_prot |= PROT_READ;
			if (perms[1] == 'w')
				map_prot |= PROT_WRITE;
			if (perms[2] == 'x')
				map_prot |= PROT_EXEC;

			if ((map_prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
			    (expected_prot & (PROT_READ | PROT_WRITE | PROT_EXEC))) {
				found = true;
				break;
			}
		} else {
			found = true;
			break;
		}
	}

	fclose(f);
	return expect_present ? found : !found;
}

/*
 * Soft-invalidate every entry in one OBJ_LOCAL OBJ_MMAP_* pool whose
 * mapped extent overlaps [addr, addr+end_excl).  Clears map->prot so
 * get_map_with_prot() will skip the entry on subsequent picks and
 * drops the known_rw skip-cache bit for the same reason post_munmap's
 * sub-range branch documents -- letting either survive across a
 * hole-punch hands a writer a pointer into a SIGBUS-on-access region.
 * Returns the number of entries touched.  Pool iteration is a plain
 * forward walk: this is a soft invalidate, no swap-with-last happens,
 * so num_entries is stable for the duration.
 */
static unsigned int
invalidate_mmap_pool_range(enum objecttype type,
			   unsigned long addr, unsigned long end_excl)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx, touched = 0;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->array == NULL)
		return 0;

	for_each_obj(head, obj, idx) {
		struct map *m;
		unsigned long m_start, m_end;

		/*
		 * Same sibling-scribble defence as addr_in_local_runtime_map:
		 * reject wild obj / obj_type before touching &obj->map or
		 * m->ptr / m->size.  Bad-slot stat bump happens inside;
		 * log_self_corrupt_culprit() on the reject path attributes
		 * the wild obj to the syscall that just ran.
		 */
		if (!objpool_check(obj, type)) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"mm:invalidate-range:objpool",
				(unsigned long)obj,
				cc != NULL ? &cc->syscall : NULL);
			continue;
		}

		m = &obj->map;

		if (m->ptr == NULL || m->size == 0)
			continue;

		m_start = (unsigned long) m->ptr;
		m_end = m_start + m->size;

		if (m_end <= addr || m_start >= end_excl)
			continue;

		m->prot = 0;
		m->known_rw = false;
		touched++;
	}

	return touched;
}

unsigned int invalidate_obj_mmap_in_range(unsigned long addr, unsigned long len)
{
	static const enum objecttype map_pool_types[3] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned long end_excl;
	unsigned int i, touched = 0;

	if (len == 0)
		return 0;

	/*
	 * Wraparound guard: a stomped addr/len whose sum overflows would
	 * make every interval test trivially true and blanket-clear the
	 * pool.  Reject silently; the caller already snapshotted from a
	 * cookie-validated post_state, so a wraparound here means the
	 * caller's own snapshot was junk.
	 */
	end_excl = addr + len;
	if (end_excl < addr)
		return 0;

	for (i = 0; i < 3; i++)
		touched += invalidate_mmap_pool_range(map_pool_types[i],
						      addr, end_excl);

	return touched;
}

unsigned int invalidate_obj_mmap_by_fd(int fd)
{
	static const enum objecttype map_pool_types[2] = {
		OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned int i, touched = 0;

	if (fd < 0)
		return 0;

	for (i = 0; i < 2; i++) {
		struct objhead *head;
		struct object *obj;
		unsigned int idx;

		head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
		if (head == NULL || head->array == NULL)
			continue;

		for_each_obj(head, obj, idx) {
			struct map *m;

			/*
			 * Same sibling-scribble defence as
			 * addr_in_local_runtime_map: reject wild obj /
			 * obj_type before touching &obj->map or m->fd.
			 * Bad-slot stat bump happens inside; the culprit
			 * logger attributes the reject to the just-run
			 * syscall so the wild-write producer is named in
			 * the child bug-log.
			 */
			if (!objpool_check(obj, map_pool_types[i])) {
				struct childdata *cc = this_child();

				log_self_corrupt_culprit(
					"mm:invalidate-fd:objpool",
					(unsigned long)obj,
					cc != NULL ? &cc->syscall : NULL);
				continue;
			}

			m = &obj->map;

			if (m->fd != fd)
				continue;

			m->prot = 0;
			m->known_rw = false;
			touched++;
		}
	}

	return touched;
}
