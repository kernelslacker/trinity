#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "list.h"
#include "locks.h"
#include "objects.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static struct list_head global_obj_list = { &global_obj_list, &global_obj_list };

void register_global_obj_init(struct global_obj_entry *entry)
{
	list_add_tail((struct list_head *) &entry->list, &global_obj_list);
}

void init_global_objects(void)
{
	struct list_head *pos;

	list_for_each(pos, &global_obj_list) {
		struct global_obj_entry *entry = (struct global_obj_entry *) pos;

		output(1, "Initializing %s objects.\n", entry->name);
		entry->init();
	}
}

/*
 * Hash table mapping fd → (object, type) for O(1) lookup in
 * remove_object_by_fd().  Open-addressing with linear probing.
 *
 * The table itself lives in shm (shm->fd_hash) so children can read
 * the per-slot generation counter the parent updates on every fd-table
 * mutation.  Mutations happen under shm->objlock; child reads of the
 * gen field are unlocked and use ACQUIRE semantics.
 */

void fd_hash_init(void)
{
	unsigned int i;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		shm->fd_hash[i].fd = -1;
		shm->fd_hash[i].gen = 0;
	}
	shm->fd_hash_count = 0;
}

static unsigned int fd_hash_slot(int fd)
{
	return (unsigned int) fd & (FD_HASH_SIZE - 1);
}

/*
 * Internal insert that preserves the entry's existing generation and
 * doesn't update fd_hash_count.  Used by fd_hash_remove to re-hash
 * displaced entries: the entry's identity is unchanged, only its slot,
 * so any cached gen on a child must continue to match.
 */
static void fd_hash_reinsert(int fd, struct object *obj, enum objecttype type,
			     uint32_t gen)
{
	unsigned int slot;
	unsigned int probe;

	slot = fd_hash_slot(fd);
	for (probe = 0; probe < FD_HASH_SIZE; probe++) {
		if (shm->fd_hash[slot].fd == -1)
			break;
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	if (probe == FD_HASH_SIZE)
		return;

	shm->fd_hash[slot].obj = obj;
	shm->fd_hash[slot].type = type;
	__atomic_store_n(&shm->fd_hash[slot].gen, gen, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->fd_hash[slot].fd, fd, __ATOMIC_RELEASE);
}

bool fd_hash_insert(int fd, struct object *obj, enum objecttype type)
{
	unsigned int slot;
	uint32_t gen;

	if (fd < 0)
		return true;

	if (shm->fd_hash_count >= FD_HASH_SIZE)
		return false;

	slot = fd_hash_slot(fd);
	while (shm->fd_hash[slot].fd != -1 && shm->fd_hash[slot].fd != fd)
		slot = (slot + 1) & (FD_HASH_SIZE - 1);

	if (shm->fd_hash[slot].fd == -1)
		shm->fd_hash_count++;

	shm->fd_hash[slot].obj = obj;
	shm->fd_hash[slot].type = type;
	/*
	 * Bump the slot's generation so any child that cached the
	 * previous occupant's (or absence) gen sees a mismatch.  The
	 * RELEASE-store on fd publishes the entry — children using
	 * ACQUIRE-load on fd see the updated gen too.
	 */
	gen = shm->fd_hash[slot].gen + 1;
	__atomic_store_n(&shm->fd_hash[slot].gen, gen, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->fd_hash[slot].fd, fd, __ATOMIC_RELEASE);
	return true;
}

void fd_hash_remove(int fd)
{
	unsigned int slot, next, i;

	if (fd < 0)
		return;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (shm->fd_hash[slot].fd == -1)
			return;
		if (shm->fd_hash[slot].fd == fd) {
			uint32_t gen;

			/*
			 * Mark the slot empty and bump its generation so a
			 * child that cached this fd's gen sees a mismatch
			 * even before any replacement is inserted here.
			 */
			gen = shm->fd_hash[slot].gen + 1;
			__atomic_store_n(&shm->fd_hash[slot].gen, gen,
					 __ATOMIC_RELEASE);
			__atomic_store_n(&shm->fd_hash[slot].fd, -1,
					 __ATOMIC_RELEASE);
			shm->fd_hash_count--;
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (shm->fd_hash[next].fd != -1) {
				struct fd_hash_entry displaced = shm->fd_hash[next];
				__atomic_store_n(&shm->fd_hash[next].fd, -1,
						 __ATOMIC_RELEASE);
				fd_hash_reinsert(displaced.fd, displaced.obj,
						 displaced.type, displaced.gen);
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
}

struct fd_hash_entry *fd_hash_lookup(int fd)
{
	unsigned int slot, i;

	if (fd < 0)
		return NULL;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		int slot_fd = __atomic_load_n(&shm->fd_hash[slot].fd, __ATOMIC_ACQUIRE);

		if (slot_fd == -1)
			return NULL;
		if (slot_fd == fd)
			return &shm->fd_hash[slot];
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	return NULL;
}

static bool is_fd_type(enum objecttype type)
{
	return type >= OBJ_FD_PIPE && type <= OBJ_FD_FS_CTX;
}

/*
 * The trinity obj pool is split across two allocators by design:
 *
 *   OBJ_GLOBAL: the obj struct lives in the shared obj heap
 *               (alloc_shared_obj).  Every OBJ_GLOBAL provider sets
 *               head->shared_alloc=true in its init function and
 *               allocates each obj from the shared heap.  Initialised
 *               in the parent before fork so children inherit the
 *               array via the shm mapping; children then read those
 *               pointers and follow them to the per-obj struct in
 *               shared memory.  Children MUST NOT add to or destroy
 *               from these pools (enforced by the early return in
 *               add_object/destroy_object when getpid() != mainpid).
 *
 *   OBJ_LOCAL:  the obj struct lives in the calling process's private
 *               heap (alloc_object → zmalloc → malloc).  Each child
 *               manages its own pool independently — head->array
 *               itself sits in shm (under child->objects[type]) so
 *               the parent's sanity walker can see slot count and
 *               raw addresses, but the obj structs the array points
 *               to are unreachable from any other process's address
 *               space.  head->shared_alloc is ignored for OBJ_LOCAL
 *               pools; release_obj() routes to plain free().
 *
 * The split is intentional.  OBJ_GLOBAL types are parent-curated
 * resources visible fleet-wide (testfiles, mq's, pidfds, ...).
 * OBJ_LOCAL types are per-child runtime state (sockets the child
 * opened, futexes the child created, ...).  Migrating OBJ_LOCAL into
 * the shared heap would mix per-child state into shared bookkeeping
 * with no benefit and would force every child to coordinate against
 * alloc_shared_obj's lock-free CAS bump on every syscall pre/post
 * hook — pointless contention on the hot path.
 *
 * Anything that walks another process's OBJ_LOCAL pool (debug.c
 * dump_childdata is the one current caller) cannot dereference the
 * obj pointers — they are foreign-private.  See the matching note
 * in dump_childdata().
 */
struct object * alloc_object(void)
{
	return zmalloc(sizeof(struct object));
}

/*
 * Release an obj struct via the right deallocator for its (scope, type).
 *
 * OBJ_GLOBAL types that opted into the shared obj heap (shared_alloc=true,
 * set by the type's init function) came from alloc_shared_obj() and must
 * be returned via free_shared_obj() — calling free() on a pointer into
 * the shared heap would hand a non-malloc'd address to glibc.
 *
 * Everything else (OBJ_LOCAL always, plus any OBJ_GLOBAL type that did
 * not opt into the shared heap) came from alloc_object() → zmalloc()
 * and is routed through deferred_free_enqueue() rather than free()'d
 * immediately.  Plain free() ends an obj struct's lifetime the moment
 * __destroy_object() drops the slot, but get_map() and friends read
 * &obj->map after taking the slot pointer out of head->array — if the
 * arg-gen path that invoked get_map() (or a stale slot pointer that
 * survived a wild value-result-syscall write) hands the freed chunk
 * back, the next deref hits a glibc-reclaimed cache line.  Routing
 * through deferred_free gives the chunk a 5-50 syscall TTL, which is
 * far longer than any in-flight get_map() consumer holds the pointer.
 *
 * Before handing the chunk to the deferred-free ring we memset it to
 * zero.  The destructor (called by __destroy_object before us) has
 * already torn down the obj's referenced state — for OBJ_MMAP_*
 * map_destructor() unmaps the VMA and frees map->name, so the
 * unzeroed remainder (map.ptr, map.size, map.prot, map.flags, fd,
 * type, array_idx) describes a mapping that no longer exists.  A
 * later get_map() read of those fields via a stale slot pointer
 * would happily pass the size>0 / size<4GB sanity check at
 * mm/maps.c:85 and return a map* whose ptr addresses an unmapped
 * VMA — a SIGSEGV/EFAULT in the very next consumer.  Zeroing makes
 * the post-destroy contents trip the size==0 band of that same check
 * instead, so a stale-slot read is rejected at the get_map boundary
 * rather than propagating into the syscall.  The memset is also
 * cheap on never-published objs (the add_object failure paths give
 * us a zmalloc'd chunk whose contents are already zero) and the
 * zeroed pointer fields make any double-deref reachable via a wild
 * slot pointer fault on a NULL access instead of a wild address.
 */
static void release_obj(struct object *obj, enum obj_scope scope,
			enum objecttype type)
{
	if (scope == OBJ_GLOBAL && shm->global_objects[type].shared_alloc) {
		free_shared_obj(obj, sizeof(struct object));
		return;
	}
	memset(obj, 0, sizeof(*obj));
	deferred_free_enqueue(obj, free);
}

struct objhead * get_objhead(enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;

	if (scope == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		struct childdata *child;

		child = this_child();
		if (child == NULL)
			return NULL;
		head = &child->objects[type];
	}
	return head;
}


/*
 * Fixed capacity for global object arrays.  These are allocated in
 * MAP_SHARED memory so children can safely read them.  Using realloc()
 * on private heap would put the new array in the parent's address space
 * only, causing children to SIGSEGV when they follow the pointer.
 *
 * Exposed in objects.h so other code (e.g. mm/maps.c) can use the
 * same upper bound when defending against a corrupt num_entries.
 */
void add_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;
	bool was_protected = false;
	char pcbuf[128];

	output(2, "ADD-OBJ slot=%p type=%d caller=%s\n", obj, type,
		pc_to_string(__builtin_return_address(0), pcbuf, sizeof(pcbuf)));

	/* Children must not mutate global objects — the objhead metadata
	 * is in shared memory but the objects/arrays are in per-process
	 * heap (COW after fork).  Mixing the two corrupts everything. */
	if (scope == OBJ_GLOBAL && getpid() != mainpid) {
		release_obj(obj, scope, type);
		return;
	}

	if (scope == OBJ_GLOBAL) {
		lock(&shm->objlock);
		/* Most parent-side OBJ_GLOBAL adds happen during init,
		 * before freeze.  The post-freeze case is fd regeneration
		 * via try_regenerate_fd() — temporarily lift the RO
		 * protection so the array writes can land. */
		if (globals_are_protected()) {
			thaw_global_objects();
			was_protected = true;
		}
	}

	head = get_objhead(scope, type);

	/* For global objects, the array was pre-allocated in shared
	 * memory by init_object_lists().  Never realloc — just reject
	 * if we've hit the fixed capacity. */
	if (scope == OBJ_GLOBAL) {
		if (head->num_entries >= head->array_capacity) {
			outputerr("add_object: global array full for type %u "
				  "(cap %u)\n", type, head->array_capacity);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			goto out_unlock;
		}
	} else if (head->num_entries >= head->array_capacity) {
		/*
		 * Local objects: grow on the private heap.
		 *
		 * Hand-rolled allocate-copy-defer-free instead of plain
		 * realloc().  realloc() returns the old chunk to glibc the
		 * moment the resize forces a move, but get_random_object()
		 * (and find_local_object_by_fd, for_each_obj iterators, the
		 * arg-gen path get_map → alloc_iovec → ...) read head->array
		 * lockless from the same child without any temporal barrier.
		 * A compiler-hoisted load of head->array, an interrupted code
		 * path holding the prior pointer, or a stale slot pointer
		 * that survived a wild value-result write can all keep the
		 * OLD array container live past the resize -- next deref
		 * lands inside a glibc-reclaimed chunk.
		 *
		 * Routing the old container through deferred_free_enqueue()
		 * gives it the same 5-50 syscall (effective 80-800 with
		 * DEFERRED_TICK_BATCH) TTL the obj struct frees already
		 * enjoy via release_obj() above.  That is far longer than
		 * any in-flight head->array reader's window, and closes the
		 * UAF on the array container the same way the get_map fix
		 * (3a8d344f0f73, 546f576fae24) closed the UAF on the obj
		 * struct.  Same hazard shape, same defence.
		 *
		 * The deferred_free ring rejects sub-page / canonical-out-of-
		 * range / misaligned ptrs (looks_like_corrupted_ptr) and ptrs
		 * overlapping any tracked shared region.  The OBJ_LOCAL
		 * head->array sits in private heap returned by malloc, so it
		 * passes both bands trivially.
		 */
		struct object **newarray;
		struct object **oldarray;
		unsigned int newcap, oldcap;

		newcap = head->array_capacity ? head->array_capacity * 2 : 16;
		newarray = malloc(newcap * sizeof(struct object *));
		if (newarray == NULL) {
			outputerr("add_object: malloc failed for type %u (cap %u)\n",
				  type, newcap);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			return;
		}
		oldcap = head->array_capacity;
		oldarray = head->array;
		if (oldarray != NULL && oldcap > 0)
			memcpy(newarray, oldarray,
			       oldcap * sizeof(struct object *));
		head->array = newarray;
		head->array_capacity = newcap;
		if (oldarray != NULL)
			deferred_free_enqueue(oldarray, free);
	}
	head->array[head->num_entries] = obj;
	obj->array_idx = head->num_entries;

	/*
	 * RELEASE-publish the new count so a child doing a lockless
	 * ACQUIRE-load in get_random_object() that sees count=N+1 also
	 * sees the array[N] = obj write that preceded it.  For OBJ_LOCAL
	 * the pool is per-child private, so a plain store suffices.
	 */
	if (scope == OBJ_GLOBAL)
		__atomic_store_n(&head->num_entries, head->num_entries + 1,
				 __ATOMIC_RELEASE);
	else
		head->num_entries++;

	/* Track global fd-type objects in the hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);
		if (!fd_hash_insert(fd, obj, type)) {
			unsigned int rollback = head->num_entries - 1;

			outputerr("add_object: fd hash full for type %u, dropping fd %d\n",
				  type, fd);
			/*
			 * Drop the count first so a concurrent lockless child
			 * read picking up the new snapshot sees the lower
			 * count and won't index past the (about-to-be-NULLed)
			 * tail slot.  RELEASE pairs with the child's ACQUIRE.
			 */
			__atomic_store_n(&head->num_entries, rollback,
					 __ATOMIC_RELEASE);
			head->array[rollback] = NULL;
			if (fd >= 0)
				close(fd);
			release_obj(obj, scope, type);
			goto out_unlock;
		}
	}

	/* Per-object dumps are debug noise at startup (NFUTEXES = 5 * cpus
	 * identical "futex: 0 owner:0 scope:1" lines, etc.).  Gate on -vv.
	 * dump_childdata() calls head->dump directly for crash diagnostics
	 * and is unaffected by this gate. */
	if (head->dump != NULL && verbosity > 2)
		head->dump(obj, scope);

out_unlock:
	if (scope == OBJ_GLOBAL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
	}

	/* if we just added something to a child list, check
	 * to see if we need to do some pruning.
	 */
	if (scope == OBJ_LOCAL)
		prune_objects();
}

void init_object_lists(enum obj_scope scope, struct childdata *child)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		if (scope == OBJ_GLOBAL)
			head = &shm->global_objects[i];
		else {
			if (child == NULL)
				return;
			head = &child->objects[i];
		}

		head->num_entries = 0;

		if (scope == OBJ_GLOBAL) {
			/* Pre-allocate the parallel array in MAP_SHARED memory
			 * so children can safely read it.  Never realloc.
			 * Tagged global so freeze_global_objects() will mprotect
			 * it RO once init is done. */
			head->array = alloc_shared_global(GLOBAL_OBJ_MAX_CAPACITY *
							  sizeof(struct object *));
			memset(head->array, 0, GLOBAL_OBJ_MAX_CAPACITY *
			       sizeof(struct object *));
			head->array_capacity = GLOBAL_OBJ_MAX_CAPACITY;
		} else {
			head->array = NULL;
			head->array_capacity = 0;
		}

		/*
		 * child lists can inherit properties from global lists.
		 */
		if (scope == OBJ_LOCAL) {
			struct objhead *globalhead;
			globalhead = &shm->global_objects[i];
			head->max_entries = globalhead->max_entries;
			head->destroy = globalhead->destroy;
			head->dump = globalhead->dump;
		}
	}
}

/*
 * Pick a random object from a pool.
 *
 * Lockless child read path (OBJ_GLOBAL):
 *   Children must NOT take shm->objlock here.  Doing so deadlocks the
 *   fleet whenever a child is killed mid-syscall while holding objlock —
 *   the parent's reaper then blocks forever waiting for the dead child
 *   to release a lock it can never release.  The defensive pid_alive()
 *   bypass added in e4e32ff0 (zombie pid_alive) papered over one
 *   instance of this; eliminating the lock acquisition on the child
 *   read path closes the whole class.  Audit (task 4LSD-ae2QTmkKyPKHPo7hQ)
 *   identified 23 HIGH sites where children reach this lock; this fix
 *   collapses the entire category-A cluster (get_random_object on the
 *   syscall arg-pickers' hot path).
 *
 * Memory ordering:
 *   The child snapshots head->num_entries with __ATOMIC_ACQUIRE,
 *   pairing with the parent mutators (add_object, __destroy_object)
 *   that publish updates with __ATOMIC_RELEASE.  Acquire/release
 *   guarantees that if the child observes count = N+1, it also
 *   observes the parent's array[N] = obj store that preceded the
 *   count bump.  Without this pairing, a child could pick an index
 *   into a slot whose backing store hadn't yet propagated.
 *   Modeled on fd_hash_lookup() (objects.c:159) which uses the same
 *   pattern for the parallel fd hash table.
 *
 * Worst-case race:
 *   The child reads array[idx] without taking objlock, so it can read
 *   a stale pointer that the parent is concurrently overwriting (swap-
 *   with-last in __destroy_object) or whose target object the parent
 *   has just free()d.  This is the SAME failure mode as the existing
 *   "OBJ_GLOBAL objects allocated in parent heap break for children"
 *   problem tracked in trinity-todo.md (item: OBJ_GLOBAL pool entries
 *   allocated in parent heap break for children) — the structural fix
 *   is to allocate the struct objects themselves in shared memory.
 *   Until that lands, the caller validates the returned pointer and
 *   the catch-all sighandler turns any raw deref crash into _exit;
 *   we are NOT making it worse, only widening an existing window.
 *
 * Why lockless is safe enough:
 *   1. Parent mutators run while shm->global_objects is mprotect-thawed
 *      and re-freeze on completion — the array memory itself isn't
 *      remapped or relocated under the child (capacity is fixed at
 *      init, GLOBAL_OBJ_MAX_CAPACITY).
 *   2. ACQUIRE/RELEASE on num_entries gives a consistent (count, slots)
 *      pair w.r.t. the most recent publish.
 *   3. The remaining race (stale array[idx] pointer) is upper-bounded
 *      by the OBJ_GLOBAL-in-parent-heap problem and addressed by the
 *      separately-tracked structural fix.
 */
struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	struct object *obj;

	head = get_objhead(scope, type);

	if (scope == OBJ_GLOBAL && getpid() != mainpid) {
		unsigned int snapshot;

		snapshot = __atomic_load_n(&head->num_entries,
					   __ATOMIC_ACQUIRE);
		if (snapshot == 0)
			return NULL;
		return head->array[rand() % snapshot];
	}

	if (scope == OBJ_GLOBAL)
		lock(&shm->objlock);

	if (head->num_entries == 0)
		obj = NULL;
	else
		obj = head->array[rand() % head->num_entries];

	if (scope == OBJ_GLOBAL)
		unlock(&shm->objlock);

	return obj;
}

bool objects_empty(enum objecttype type)
{
	return shm->global_objects[type].num_entries == 0;
}

/*
 * Periodic global-pool sanity walk.
 *
 * Post-Q3.1 OBJ_GLOBAL pools have no list ring — objects are tracked
 * exclusively through head->array[0..num_entries).  This routine is
 * the tripwire we lacked during the 2026-04-22 wild-write hunt: a
 * stomp into a global head or array slot is reported here, on the
 * parent's idle pass, instead of waiting for the next innocent caller
 * to deref the trampled slot and SEGV ~80k iterations later.
 *
 * For every type, we check:
 *   - array_capacity is either 0 (uninitialised slot) or exactly the
 *     pre-init cap (GLOBAL_OBJ_MAX_CAPACITY).  Anything else means the
 *     head struct itself has been overwritten — the array allocation
 *     is fixed at init and never resized for OBJ_GLOBAL.
 *   - num_entries is bounded by array_capacity.
 *   - head->array is non-NULL whenever num_entries > 0.
 *   - Every slot in [0, num_entries) is non-NULL.  Unlike OBJ_LOCAL
 *     where __destroy_object's swap-with-last can transiently leave a
 *     NULL inside the window between the array store and the count
 *     decrement, on OBJ_GLOBAL pools we hold shm->objlock around the
 *     whole mutation, so a NULL slot inside the live window from
 *     under the lock is unambiguously corruption.
 *   - For shared_alloc heads, every slot points into a tracked shared
 *     region.  A parent-private heap pointer here is the canonical
 *     "stray write stamped a malloc'd address into shared bookkeeping"
 *     failure mode the wild-write hunt was chasing.
 *
 * Parent-only.  Children's COW snapshot of head->array would be
 * stale relative to parent mutations and would generate spurious
 * reports.  The walker takes shm->objlock so it sees a consistent
 * snapshot even if a regen path is mid-mutation.  The mprotect-RO
 * guard on the array is left in place — reads work fine on RO maps
 * and we have no need to write.
 *
 * Reporting style follows the existing list-validator class
 * (debug.c::__list_add_valid_or_die et al.): one outputerr line per
 * finding, including type index and slot coordinates so a corruption
 * report can be cross-referenced against the -vv ADD-OBJ trace.
 */
void validate_global_objects(void)
{
	unsigned int type;
	unsigned int corruptions = 0;

	lock(&shm->objlock);

	for (type = 0; type < MAX_OBJECT_TYPES; type++) {
		struct objhead *head = &shm->global_objects[type];
		unsigned int n = head->num_entries;
		unsigned int cap = head->array_capacity;
		unsigned int idx;

		if (cap != 0 && cap != GLOBAL_OBJ_MAX_CAPACITY) {
			outputerr("global-list sanity: type=%u corrupt head: array_capacity=%u (expected 0 or %u) num_entries=%u max_entries=%u array=%p\n",
				type, cap, GLOBAL_OBJ_MAX_CAPACITY,
				n, head->max_entries, head->array);
			corruptions++;
			continue;
		}

		if (n > cap) {
			outputerr("global-list sanity: type=%u corrupt head: num_entries=%u > array_capacity=%u max_entries=%u array=%p\n",
				type, n, cap, head->max_entries, head->array);
			corruptions++;
			continue;
		}

		if (n > 0 && head->array == NULL) {
			outputerr("global-list sanity: type=%u corrupt head: num_entries=%u but array=NULL\n",
				type, n);
			corruptions++;
			continue;
		}

		for (idx = 0; idx < n; idx++) {
			struct object *obj = head->array[idx];

			if (obj == NULL) {
				outputerr("global-list sanity: type=%u slot %u/%u is NULL inside live window — wild write or torn destroy\n",
					type, idx, n);
				corruptions++;
				continue;
			}

			if (head->shared_alloc &&
			    !range_overlaps_shared((unsigned long)obj,
						   sizeof(struct object))) {
				outputerr("global-list sanity: type=%u slot %u/%u: obj=%p not in any tracked shared region (shared_alloc head — stamped private pointer?)\n",
					type, idx, n, obj);
				corruptions++;
			}
		}
	}

	unlock(&shm->objlock);

	if (corruptions > 0)
		outputerr("global-list sanity: %u corruption(s) detected this pass\n",
			corruptions);
}

/*
 * Invalidate the fd stored in an object by setting it to -1.
 * Used before calling the destructor when the fd was already closed
 * (e.g. after a successful close() syscall) to prevent double-close.
 * The destructor's close(-1) call will harmlessly return EBADF.
 */
static void invalidate_object_fd(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = -1; break;
	case OBJ_FD_DEVFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_PROCFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = -1; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = -1; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = -1; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = -1; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = -1; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = -1; break;
	case OBJ_FD_MEMFD_SECRET: obj->memfd_secretobj.fd = -1; break;
	case OBJ_FD_DRM:	obj->drmfd = -1; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = -1; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = -1; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = -1; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = -1; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = -1; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = -1; break;
	case OBJ_FD_BPF_LINK:	obj->bpflinkobj.fd = -1; break;
	case OBJ_FD_BPF_BTF:	obj->bpfbtfobj.fd = -1; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = -1; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = -1; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = -1; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = -1; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = -1; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = -1; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = -1; break;
	default:		break;
	}
}

/*
 * Call the destructor for this object, and then release it.
 * Internal version — caller must hold objlock if operating on globals.
 *
 * If already_closed is true, the fd has already been closed by the
 * kernel (e.g. after a successful close() syscall).  We invalidate
 * the fd in the object so the destructor's close() call is a harmless
 * no-op, while any other cleanup (munmap, free, etc.) still runs.
 */
static void __destroy_object(struct object *obj, enum obj_scope scope,
			     enum objecttype type, bool already_closed)
{
	struct objhead *head;
	unsigned int idx, last;

	head = get_objhead(scope, type);

	/* Swap-with-last removal from the parallel array */
	idx = obj->array_idx;
	last = head->num_entries - 1;
	if (idx != last) {
		head->array[idx] = head->array[last];
		if (head->array[idx] != NULL)
			head->array[idx]->array_idx = idx;
	}
	head->array[last] = NULL;

	/*
	 * Publish the new count with RELEASE semantics so a concurrent
	 * lockless child read in get_random_object() that observes the
	 * shrunk count cannot also observe an inconsistent earlier state
	 * of the array slots.  See the design comment above
	 * get_random_object().  __prune_objects(OBJ_GLOBAL) is currently
	 * disabled but routes through here, so this also covers it
	 * defensively.
	 */
	if (scope == OBJ_GLOBAL)
		__atomic_store_n(&head->num_entries, last, __ATOMIC_RELEASE);
	else
		head->num_entries--;

	/* Remove from fd hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type))
		fd_hash_remove(fd_from_object(obj, type));

	if (already_closed && is_fd_type(type))
		invalidate_object_fd(obj, type);

	if (head->destroy != NULL)
		head->destroy(obj);

	release_obj(obj, scope, type);
}

void destroy_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	bool was_protected = false;

	if (scope == OBJ_GLOBAL && getpid() != mainpid)
		return;

	if (scope == OBJ_GLOBAL) {
		lock(&shm->objlock);
		if (globals_are_protected()) {
			thaw_global_objects();
			was_protected = true;
		}
	}

	__destroy_object(obj, scope, type, false);

	if (scope == OBJ_GLOBAL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
	}
}

/*
 * Destroy a whole list of objects.
 */
static void destroy_objects(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;

	head = get_objhead(scope, type);
	if (head->num_entries == 0)
		return;

	if (head->array == NULL)
		return;

	/* Drain the array via repeated head->array[0] destroy.
	 * __destroy_object() does swap-with-last on the parallel array,
	 * so consuming the front slot each time pulls a fresh entry into
	 * slot 0 until num_entries reaches 0. */
	while (head->num_entries > 0) {
		struct object *obj = head->array[0];

		if (obj == NULL) {
			/* Shouldn't happen — num_entries says it's live —
			 * but guard against a torn state rather than
			 * looping forever. */
			head->num_entries--;
			continue;
		}
		__destroy_object(obj, scope, type, false);
	}

	/* Only free private-heap arrays (OBJ_LOCAL).  OBJ_GLOBAL arrays
	 * were allocated with alloc_shared() and cannot be freed. */
	if (scope == OBJ_LOCAL) {
		free(head->array);
		head->array = NULL;
		head->array_capacity = 0;
	} else {
		/* Zero out the shared array for reuse. */
		memset(head->array, 0, head->array_capacity * sizeof(struct object *));
	}
}

/* Destroy all global objects on exit. */
void destroy_global_objects(void)
{
	unsigned int i;

	/* The parallel arrays were mprotected RO after init.  Cleanup
	 * needs to mutate them, so re-enable writes in this process first.
	 * Children are gone by the time we get here so we do not need to
	 * coordinate with them. */
	thaw_global_objects();

	for (i = 0; i < MAX_OBJECT_TYPES; i++)
		destroy_objects(i, OBJ_GLOBAL);
}

/*
 * Store an fd into the appropriate union field for this object type.
 * The inverse of fd_from_object(); used by the generic post-hook that
 * registers fds returned by RET_FD syscalls without a custom handler.
 */
void set_object_fd(struct object *obj, enum objecttype type, int fd)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = fd; break;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = fd; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = fd; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = fd; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = fd; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = fd; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = fd; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = fd; break;
	case OBJ_FD_MEMFD_SECRET: obj->memfd_secretobj.fd = fd; break;
	case OBJ_FD_DRM:	obj->drmfd = fd; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = fd; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = fd; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = fd; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = fd; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = fd; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = fd; break;
	case OBJ_FD_BPF_LINK:	obj->bpflinkobj.fd = fd; break;
	case OBJ_FD_BPF_BTF:	obj->bpfbtfobj.fd = fd; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = fd; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = fd; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = fd; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = fd; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = fd; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = fd; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = fd; break;
	default:		break;
	}
}

/*
 * Linear search the per-child OBJ_LOCAL pool of one type for an fd.
 * Used by the generic post-hook to detect fds that a syscall-specific
 * post handler already registered, so we don't double-track them.
 * O(n) over a small n (typically tens of entries).
 */
struct object *find_local_object_by_fd(enum objecttype type, int fd)
{
	struct objhead *head;
	unsigned int i;

	if (fd < 0)
		return NULL;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->num_entries == 0)
		return NULL;

	for (i = 0; i < head->num_entries; i++) {
		struct object *obj = head->array[i];

		if (obj != NULL && fd_from_object(obj, type) == fd)
			return obj;
	}
	return NULL;
}

/*
 * Extract the fd from an object, given its type.
 * Returns -1 for non-fd object types.
 */
int fd_from_object(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	return obj->pipeobj.fd;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:	return obj->fileobj.fd;
	case OBJ_FD_PERF:	return obj->perfobj.fd;
	case OBJ_FD_EPOLL:	return obj->epollobj.fd;
	case OBJ_FD_EVENTFD:	return obj->eventfdobj.fd;
	case OBJ_FD_TIMERFD:	return obj->timerfdobj.fd;
	case OBJ_FD_TESTFILE:	return obj->testfileobj.fd;
	case OBJ_FD_MEMFD:	return obj->memfdobj.fd;
	case OBJ_FD_MEMFD_SECRET: return obj->memfd_secretobj.fd;
	case OBJ_FD_DRM:	return obj->drmfd;
	case OBJ_FD_INOTIFY:	return obj->inotifyobj.fd;
	case OBJ_FD_SOCKET:	return obj->sockinfo.fd;
	case OBJ_FD_USERFAULTFD: return obj->userfaultobj.fd;
	case OBJ_FD_FANOTIFY:	return obj->fanotifyobj.fd;
	case OBJ_FD_BPF_MAP:	return obj->bpfobj.map_fd;
	case OBJ_FD_BPF_PROG:	return obj->bpfprogobj.fd;
	case OBJ_FD_BPF_LINK:	return obj->bpflinkobj.fd;
	case OBJ_FD_BPF_BTF:	return obj->bpfbtfobj.fd;
	case OBJ_FD_IO_URING:	return obj->io_uringobj.fd;
	case OBJ_FD_LANDLOCK:	return obj->landlockobj.fd;
	case OBJ_FD_PIDFD:	return obj->pidfdobj.fd;
	case OBJ_FD_MQ:		return obj->mqobj.fd;
	case OBJ_FD_SECCOMP_NOTIF: return obj->seccomp_notifobj.fd;
	case OBJ_FD_IOMMUFD:	return obj->iommufdobj.fd;
	case OBJ_FD_FS_CTX:	return obj->fsctxobj.fd;
	default:		return -1;
	}
}

/*
 * Look up an fd in the hash table and destroy its object.
 * Called from fd_event_drain() after a child reported a close or dup2.
 *
 * The child closed its own copy of the fd (children have independent
 * fd tables after fork).  The parent's copy is still open and must be
 * closed here — pass already_closed=false so the destructor runs
 * close() on the parent's fd.  Without this, every child close event
 * leaks one fd in the parent, leading to fd exhaustion.
 */
void remove_object_by_fd(int fd)
{
	struct fd_hash_entry *entry;
	struct object *obj;
	enum objecttype type;
	bool was_protected = false;

	if (getpid() != mainpid)
		return;

	lock(&shm->objlock);

	if (globals_are_protected()) {
		thaw_global_objects();
		was_protected = true;
	}

	entry = fd_hash_lookup(fd);
	if (entry == NULL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
		return;
	}

	obj = entry->obj;
	type = entry->type;

	__atomic_add_fetch(&shm->stats.fd_closed_tracked, 1, __ATOMIC_RELAXED);
	__destroy_object(obj, OBJ_GLOBAL, type, false);

	unlock(&shm->objlock);

	/* try_regenerate_fd() may call add_object() which sees the
	 * thawed state (globals_are_protected() returns false here)
	 * and skips its own thaw/refreeze.  We refreeze afterwards
	 * so the regeneration's writes stay covered by our window. */
	try_regenerate_fd(type);

	if (was_protected)
		freeze_global_objects();
}

static void __prune_objects(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(scope, type);

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	if (head->array == NULL)
		return;

	/* Single pass: prune each entry with 1/10 probability.
	 *
	 * Walk the array in reverse.  destroy_object() does swap-with-last
	 * on the parallel array, so a forward walk would skip whichever
	 * entry got pulled into the current slot from the back.  Walking
	 * from the back means any swap-in source is from a position we
	 * have already visited, so each live entry is considered exactly
	 * once. */
	for (i = head->num_entries; i > 0; i--) {
		struct object *obj = head->array[i - 1];

		if (obj == NULL)
			continue;
		if (ONE_IN(10))
			destroy_object(obj, scope, type);
	}
}

void prune_objects(void)
{
	unsigned int i;

	/* We don't want to over-prune things and growing a little
	 * bit past the ->max is fine, we'll clean it up next time.
	 */
	if (!(ONE_IN(10)))
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		__prune_objects(i, OBJ_LOCAL);
		// For now, we're only pruning local objects.
		// __prune_objects(i, OBJ_GLOBAL);
	}
}
