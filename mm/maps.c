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
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "utils.h"

/*
 * Return a pointer a previous mmap() that we did, either during startup,
 * or from a fuzz result.
 */
struct map * get_map(void)
{
	struct object *obj = NULL;
	struct childdata *child = this_child();
	enum obj_scope scope;
	enum objecttype type = 0;

	/*
	 * Some of the fd providers need weird mappings on startup.
	 * (fd-perf for eg), these are called from the main process,
	 * and hence don't have a valid this_child, so we address the
	 * initial mappings list directly.
	 */
	if (child == NULL)
		scope = OBJ_GLOBAL;
	else
		scope = OBJ_LOCAL;

	for (int i = 0; i < 1000; i++) {
		switch (rand() % 3) {
		case 0:	type = OBJ_MMAP_ANON;
			break;
		case 1:	type = OBJ_MMAP_FILE;
			break;
		case 2:	type = OBJ_MMAP_TESTFILE;
			break;
		}

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
			outputerr("get_map: bogus obj %p in OBJ_MMAP pool "
				  "(type %u, scope %d)\n", obj, type, scope);
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
		if (obj->map.size == 0 || obj->map.size > GB(4UL)) {
			outputerr("get_map: bogus map->size %lu for obj %p "
				  "(type %u, scope %d)\n",
				  obj->map.size, obj, type, scope);
			continue;
		}

		return &obj->map;
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
	head->destroy = &map_destructor;
	head->dump = &map_dump;

	globalhead = &shm->global_objects[OBJ_MMAP_ANON];
	if (globalhead->array == NULL)
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
	struct map *map;

	map = get_map();
	if (map == NULL)
		return;

	dirty_mapping(map);
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
		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL)
			return;
		obj->map.name = alloc_shared_strdup(name);
		if (obj->map.name == NULL) {
			free_shared_obj(obj, sizeof(struct object));
			return;
		}
	} else {
		obj = alloc_object();
		obj->map.name = strdup(name);
		if (!obj->map.name) {
			free(obj);
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
	obj->map.ptr = mmap(NULL, obj->map.size, prot, get_rand_mmap_flags(), fd, offset);
	if (obj->map.ptr == MAP_FAILED) {
		retries++;
		if (retries == 100) {
			if (scope == OBJ_GLOBAL) {
				free_shared_str(obj->map.name,
						strlen(obj->map.name) + 1);
				obj->map.name = NULL;
				free_shared_obj(obj, sizeof(struct object));
			} else {
				free(obj->map.name);
				obj->map.name = NULL;
				free(obj);
			}
			obj = NULL;
			return;
		} else
			goto retry_mmap;
	}
	track_shared_region((unsigned long)obj->map.ptr, obj->map.size);

	head = get_objhead(scope, type);
	head->dump = &map_dump;
	if (scope == OBJ_GLOBAL) {
		head->shared_alloc = true;
		head->destroy = &map_destructor_shared;
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
