#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "arch.h"
#include "child.h"
#include "deferred-free.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "utils.h"

/*
 * Populate a handle for a randomly-picked entry in the
 * OBJ_MMAP_ANON / OBJ_MMAP_FILE / OBJ_MMAP_TESTFILE pools.  Same
 * pick-and-deref flow as get_map() (heap-range guard, size guard);
 * post-Stage-5 the pools live in private heap so there is no
 * concurrent destroyer racing the consumer's deref of map->ptr /
 * map->size / map->prot.
 */
bool get_map_handle(struct map_handle *h)
{
	struct childdata *child = this_child();
	enum obj_scope scope;
	enum objecttype type = 0;

	if (h == NULL)
		return false;

	h->map = NULL;

	if (child == NULL)
		scope = OBJ_GLOBAL;
	else
		scope = OBJ_LOCAL;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;

		static const enum objecttype map_pool_types[3] = {
			OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE
		};
		type = map_pool_types[rand() % 3];

		obj = get_random_object(type, scope);
		if (obj == NULL)
			continue;

		/*
		 * Defend against stale or corrupted slot pointers leaking
		 * out of the OBJ_MMAP pool.  Heap pointers land at
		 * >= 0x10000 and below the 47-bit user/kernel boundary;
		 * any obj pointer outside that window can't be a real obj
		 * struct, and dereferencing it via &obj->map then map->ptr
		 * scribbles garbage into whatever syscall arg buffer the
		 * caller is filling (alloc_iovec via the iovec generator
		 * was the trigger — its iov_base ended up at sub-page
		 * addresses like 0x1d8).  Skip the slot and try again.
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_map_handle: bogus obj %p in OBJ_MMAP "
				  "pool (type %u, scope %d)\n",
				  obj, type, scope);
			continue;
		}

		/*
		 * Ground-truth check before the first deref: obj pointers
		 * for OBJ_LOCAL pools come back through __zmalloc(), which
		 * registers them in the alloc-track ring.  A stomped slot
		 * can hand back a value that passes the heap-range guard
		 * above (8-byte aligned, inside user VA) yet doesn't match
		 * any allocation we ever made -- the first obj->map.size
		 * read then returns garbage and downstream consumers
		 * (gen_xattr_name, generate_syscall_args, alloc_iovec)
		 * walk into unmapped memory.  Skip the slot when the obj
		 * isn't in the live malloc-result set.  OBJ_GLOBAL pool
		 * objs come from alloc_shared_obj() which does not feed
		 * the alloc-track ring, so the lookup is gated on
		 * OBJ_LOCAL to avoid spurious rejections of legitimate
		 * shared-heap objs.
		 */
		if (scope == OBJ_LOCAL && !alloc_track_lookup(obj)) {
			outputerr("get_map_handle: obj %p not in alloc_track "
				  "(stomped slot, type %u, scope %d)\n",
				  obj, type, scope);
			continue;
		}

		/*
		 * Even when the obj pointer is sane, the map struct itself
		 * may have been stomped on by a stray syscall write, leaving
		 * a believable ptr but a wildly wrong size.  Consumers like
		 * gen_xattr_name's snprintf, generate_syscall_args, and
		 * alloc_iovec then read/write past the real mapping and we
		 * SEGV/SIGBUS at fixed-pattern addresses.
		 *
		 * Legitimate allocations top out at GB(1) (mapping_sizes[8]
		 * in maps-initial.c, pick_size in mmap-lifecycle.c).  Cap at
		 * GB(4) so the live 1GB tier passes cleanly while ASCII
		 * patterns and stomped pointers (which land in the TB+ range)
		 * are rejected.  Zero is also bogus — a real mapping always
		 * has at least one page.
		 */
		if (obj->map.size == 0) {
			/*
			 * Legitimate post-clamp state from mmap_fd:
			 * empty file, fstat failure, or offset past EOF.
			 * mmap_fd now drops these at seed time, but a
			 * pre-clamp pool entry from an earlier startup
			 * may still surface here.  Skip silently.
			 */
			continue;
		}
		if (obj->map.size > GB(4UL)) {
			outputerr("get_map_handle: bogus map->size %lu for "
				  "obj %p (type %u, scope %d)\n",
				  obj->map.size, obj, type, scope);
			continue;
		}

		h->map = &obj->map;
		h->type = type;
		h->scope = scope;
		return true;
	}

	__atomic_add_fetch(&shm->stats.maps_uaf_caught, 1, __ATOMIC_RELAXED);
	{
		struct childdata *c = this_child();
		if (c != NULL)
			c->local_maps_uaf_caught++;
	}
	return false;
}

/*
 * Post-Stage-5 every pool is private-heap; the handle stays valid for
 * the consumer's lifetime.  The check collapses to a NULL guard so
 * callers that always re-validate before dereferencing still have a
 * cheap canonical entry point and don't need to special-case scope.
 */
bool validate_map_handle(struct map_handle *h)
{
	return h != NULL && h->map != NULL;
}

/*
 * Walk the current child's OBJ_LOCAL OBJ_MMAP_* pools and report
 * whether [addr, addr+len) lies entirely inside a runtime mapping
 * the child created (CHILD_ANON / MMAPED_FILE).  Runtime mmap() results
 * land in the per-child object pool via post_mmap() but are not added
 * to shared_regions[] -- that tracker exists to defend trinity's own
 * bookkeeping from fuzzed kernel writes, not to enumerate every VMA
 * the child legitimately owns.  Without this helper the post-mprotect
 * tracked-shared gate in get_writable_address() drops every runtime
 * mapping as if it were a scribbled slot.
 *
 * INITIAL_ANON entries copied in by init_child_mappings() share their
 * ptr with the OBJ_GLOBAL entry seeded by setup_initial_mappings(),
 * which IS registered with track_shared_region().  range_in_tracked_
 * shared() already accepts those, so we deliberately skip them here
 * to keep the two acceptance paths from masking double-tracking bugs.
 *
 * Overflow defense: a wild write into map->size could fabricate a
 * (ptr, size) pair that wraps past ULONG_MAX, which would otherwise
 * make the containment test vacuously true for any addr.  Reject the
 * slot rather than accepting on wrap.
 */
bool addr_in_local_runtime_map(unsigned long addr, unsigned long len)
{
	static const enum objecttype map_pool_types[3] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned int i;

	if (len == 0)
		return false;

	for (i = 0; i < 3; i++) {
		struct objhead *head;
		struct object *obj;
		unsigned int idx;

		head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
		if (head == NULL || head->array == NULL)
			continue;

		for_each_obj(head, obj, idx) {
			struct map *m = &obj->map;
			unsigned long base, end;

			if (m->type != CHILD_ANON && m->type != MMAPED_FILE)
				continue;
			if (m->ptr == NULL || m->size == 0)
				continue;

			base = (unsigned long) m->ptr;
			end = base + m->size;
			if (end < base)
				continue;

			if (addr >= base && addr + len <= end &&
			    addr + len >= addr)
				return true;
		}
	}

	return false;
}

/*
 * Return a pointer a previous mmap() that we did, either during startup,
 * or from a fuzz result.  Thin wrapper around get_map_handle() for
 * callers that don't need to re-validate the slot at deref time.
 */
struct map * get_map(void)
{
	struct map_handle h;

	if (!get_map_handle(&h))
		return NULL;
	return h.map;
}

/*
 * Like get_map(), but only return entries whose protection bits include
 * every bit set in required_prot.  Pool entries (mm/maps-initial.c) are
 * created with EVERY combination of PROT_READ / PROT_WRITE / PROT_EXEC /
 * PROT_NONE — including PROT_NONE and write-less mappings — so consumers
 * that touch the region with a specific access pattern (e.g. a dirty-each-
 * page loop, or io_uring opcodes that direct the kernel to read or write
 * the user buffer) MUST filter, otherwise drawing a PROT_READ-only or
 * PROT_NONE entry will SEGV_ACCERR on the first incompatible access.
 *
 * The most common need is PROT_WRITE (the consumer writes to the region);
 * PROT_READ alone is also reasonable for read-only consumers.  Returns
 * NULL if no matching entry is drawn within the same retry budget as
 * get_map().
 */
struct map * get_map_with_prot(int required_prot)
{
	for (int i = 0; i < 1000; i++) {
		struct map *m = get_map();

		if (m == NULL)
			return NULL;

		if ((m->prot & required_prot) == required_prot)
			return m;
	}

	return NULL;
}

/*
 * Destructor for OBJ_LOCAL mmap entries (init_child_mappings copies and
 * the children's own runtime mmaps).  The obj struct and the name string
 * both live on the calling process's private heap, so we use the regular
 * libc free path.
 */
void map_destructor(struct object *obj)
{
	struct map *map;

	map = &obj->map;
	munmap(map->ptr, map->size);
	free(map->name);
	map->name = NULL;
}

/*
 * Destructor for OBJ_GLOBAL mmap entries created via mmap_fd() and
 * setup_initial_mappings().  The obj struct itself is freed by
 * release_obj() (it sees head->shared_alloc and routes to
 * free_shared_obj); we only need to release the name string and
 * unmap the actual mapping here.
 */
void map_destructor_shared(struct object *obj)
{
	struct map *map;

	map = &obj->map;
	munmap(map->ptr, map->size);
	if (map->name != NULL) {
		free_shared_str(map->name, strlen(map->name) + 1);
		map->name = NULL;
	}
}

void map_dump(struct object *obj, enum obj_scope scope)
{
	struct map *m;
	char buf[32];

	m = &obj->map;

	sizeunit(m->size, buf, sizeof(buf));
	output(2, " start: %p size:%s  flags:%s%s  name: %s scope:%d\n",
		m->ptr, buf,
		(m->flags & MAP_SHARED) ? "shared" : "private",
		(m->flags & MAP_HUGETLB) ? ",hugetlb" : "",
		m->name, scope);
}

/*
 * Set up a childs local mapping list.
 * A child inherits the initial mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(void)
{
	struct objhead *head, *globalhead;
	struct object *globalobj;
	unsigned int idx;

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	if (head == NULL)
		return;
	head->destroy = &map_destructor;
	head->dump = &map_dump;

	globalhead = get_objhead(OBJ_GLOBAL, OBJ_MMAP_ANON);
	if (globalhead == NULL || globalhead->array == NULL)
		return;

	/* Copy the initial mapping list to the child.
	 * Note we're only copying pointers here, the actual mmaps
	 * will be faulted into the child when they get accessed.
	 *
	 * Skip entries whose name pointer is bogus.  See child #9 spawn
	 * crash where m->name had been overwritten with 0x610000.  The
	 * iteration bound is provided by for_each_obj (array_capacity);
	 * no additional cap is needed.
	 */
	for_each_obj(globalhead, globalobj, idx) {
		struct map *m = &globalobj->map;
		struct object *newobj;

		if (m->name == NULL) {
			outputerr("init_child_mappings: skipping global map with NULL name\n");
			continue;
		}

		newobj = alloc_object();
		newobj->map.ptr = m->ptr;
		newobj->map.name = strdup(m->name);
		if (!newobj->map.name) {
			free(newobj);
			continue;
		}
		newobj->map.size = m->size;
		newobj->map.prot = m->prot;
		newobj->map.flags = m->flags;
		newobj->map.fd = m->fd;
		/* We leave type as 'INITIAL' until we change the mapping
		 * by mprotect/mremap/munmap etc..
		 */
		newobj->map.type = INITIAL_ANON;
		add_object(newobj, OBJ_LOCAL, OBJ_MMAP_ANON);
	}
}

/* used in several sanitise_* functions. */
struct map * common_set_mmap_ptr_len(void)
{
	struct syscallrecord *rec;
	struct map *map;
	struct childdata *child = this_child();

	rec = &child->syscall;
	map = (struct map *) rec->a1;
	if (map == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	/*
	 * ARG_MMAP plumbed a struct map * into rec->a1 at args-generation
	 * time, but a sibling kernel-write to childdata.syscall.a1 can
	 * replace it with a fuzzed value before we get here.  Validate the
	 * shape before the map->ptr / map->size derefs below; an unmapped
	 * or non-canonical pointer would SEGV the consumer (mincore,
	 * mremap, madvise, mlock, munlock, mbind, getrandom, ...).  Mirror
	 * the failure mode of the NULL path so existing callers' NULL
	 * short-circuits handle it cleanly.
	 */
	if (looks_like_corrupted_ptr(rec, map)) {
		outputerr("common_set_mmap_ptr_len: rejected suspicious map=%p (pid-scribbled?)\n",
			  map);
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	rec->a1 = (unsigned long) map->ptr;
	if (map->size == 0) {
		rec->a2 = 0;
	} else {
		rec->a2 = rand() % map->size;
		rec->a2 &= PAGE_MASK;
	}

	return map;
}

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
	 * Re-validate right before the deref-heavy dirty_mapping path
	 * (it reads map->prot to dispatch and then map->ptr / map->size
	 * inside random_map_writefn / random_map_readfn).  Even the few-
	 * cycle window between get_map_handle()'s internal validation
	 * and the call below is a window the parent's __destroy_object
	 * can race in; this re-narrow drops the slot rather than touching
	 * a recycled obj when it does.  validate_map_handle() bumps
	 * shm->stats.maps_uaf_caught on a detected mismatch so periodic
	 * defense-counter dumps surface live race rates.
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

/*
 * Set up a mmap object for an fd we already opened.
 */
void mmap_fd(int fd, const char *name, size_t len, int prot, enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;
	struct object *obj;
	off_t offset;
	int retries = 0;

	/*
	 * Create an MMAP of the same fd.  OBJ_GLOBAL entries are added to
	 * shm-visible lists that children walk, so the obj struct AND the
	 * name string MUST live in shared memory — otherwise children
	 * dereference parent-private pointers and SEGV in libc string
	 * functions when they read the name (the bug class the rest of
	 * the OBJ_GLOBAL sweep closed).
	 */
	if (scope == OBJ_GLOBAL) {
		obj = alloc_object();
		if (obj == NULL)
			return;
		obj->map.name = alloc_shared_strdup(name);
		if (obj->map.name == NULL) {
			deferred_free_enqueue(obj);
			return;
		}
	} else {
		obj = alloc_object();
		obj->map.name = strdup(name);
		if (!obj->map.name) {
			deferred_free_enqueue(obj);
			return;
		}
	}
	obj->map.size = len;

retry_mmap:
	if (len == 0) {
		offset = 0;
		obj->map.size = page_size;
	} else
		offset = (obj->map.size > 0 ? rand() % obj->map.size : 0) & PAGE_MASK;

	obj->map.prot = prot;
	obj->map.fd = fd;
	obj->map.type = MMAPED_FILE;
	/*
	 * Capture the flags word into a local before mmap() so the actual
	 * flags used for this mapping are stored on the obj.  Calling
	 * get_rand_mmap_flags() inline as the mmap() arg threw the bits
	 * away, leaving obj->map.flags at zero for every entry seeded
	 * through this path -- map_dump() and any flag-aware consumer
	 * then saw shared / hugetlb mappings as plain private ones.
	 * Mirrors the alloc_zero_map() pattern in mm/maps-initial.c. */
	{
		int mmap_flags = (int) get_rand_mmap_flags();

		obj->map.flags = mmap_flags;
		obj->map.ptr = mmap(NULL, obj->map.size, prot, mmap_flags,
				    fd, offset);
	}
	if (obj->map.ptr == MAP_FAILED) {
		retries++;
		if (retries == 100) {
			if (scope == OBJ_GLOBAL) {
				free_shared_str(obj->map.name,
						strlen(obj->map.name) + 1);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			} else {
				free(obj->map.name);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			}
			obj = NULL;
			return;
		} else
			goto retry_mmap;
	}

	/*
	 * obj->map.size currently records the length passed to mmap():
	 * for len > 0 the caller-supplied length, for len == 0 a forced
	 * page_size used only to give the obj a non-NULL ptr for type
	 * tracking.  Neither value is bounded against the chosen fd's
	 * actual backing extent.
	 *
	 * For len > 0 the offset above is a random page-aligned multiple
	 * in [0, len); the kernel happily creates a VMA covering pages
	 * past EOF when offset + len > st_size, but accessing those pages
	 * SIGBUSes with BUS_ADRERR.  For len == 0 we have no walkable
	 * extent at all -- the one-page mmap exists only as a handle.
	 *
	 * dirty_random_mapping (and other consumers that walk obj->map.size
	 * bytes from obj->map.ptr) burn the child on the first unbacked
	 * page, so clamp the recorded size to the in-bounds extent.  fstat
	 * failure or an empty regular file leaves no walkable pages -- gate
	 * downstream walkers off with size 0.  mmap_fd is reached only from
	 * regular-file paths, so st_size == 0 means a genuinely empty file
	 * (the special-fd carve-out used by post_mmap does not apply here).
	 */
	if (len == 0) {
		obj->map.size = 0;
	} else {
		struct stat st;

		if (fstat(fd, &st) != 0 || st.st_size == 0) {
			obj->map.size = 0;
		} else {
			off_t backed = (off_t) st.st_size - (off_t) offset;

			if (backed <= 0)
				obj->map.size = 0;
			else if ((unsigned long) backed < obj->map.size)
				obj->map.size = (unsigned long) backed & PAGE_MASK;
		}
	}

	/*
	 * A zero-clamped entry has no walkable extent and would only be
	 * rejected by every get_map_handle() consumer.  Drop it at the
	 * seed site instead of polluting the pool.
	 */
	if (obj->map.size == 0) {
		munmap(obj->map.ptr, len > 0 ? len : page_size);
		if (scope == OBJ_GLOBAL) {
			free_shared_str(obj->map.name,
					strlen(obj->map.name) + 1);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		} else {
			free(obj->map.name);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		}
		return;
	}

	track_shared_region((unsigned long)obj->map.ptr, obj->map.size);

	head = get_objhead(scope, type);
	if (head != NULL) {
		head->dump = &map_dump;
		if (scope == OBJ_GLOBAL) {
			head->destroy = &map_destructor_shared;
		}
	}

	add_object(obj, scope, type);
	return;
}

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
