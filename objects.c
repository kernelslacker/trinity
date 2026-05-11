#include <limits.h>
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
	/*
	 * fd_live[] entries are gated by fd_live_count, so initialising
	 * just the count is sufficient; stale slot contents past the
	 * count are never read.
	 */
	shm->fd_live_count = 0;
}

/*
 * Append fd to the parallel live-fd list.  Caller must hold shm->objlock
 * and have just transitioned an fd_hash[] slot from empty to occupied.
 * Publishes the new entry first, then bumps fd_live_count with RELEASE
 * so a lockless reader that ACQUIREs the count is guaranteed to see the
 * entry.  Silently drops the entry if the cap is hit; the only consumer
 * (refcount-auditor) is a sampling auditor and tolerates a missed fd.
 */
static void fd_live_append(int fd)
{
	unsigned int idx = shm->fd_live_count;

	if (idx >= FD_LIVE_MAX)
		return;

	__atomic_store_n(&shm->fd_live[idx], fd, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->fd_live_count, idx + 1, __ATOMIC_RELEASE);
}

/*
 * Swap-remove fd from the parallel live-fd list.  Caller must hold
 * shm->objlock and have just transitioned an fd_hash[] slot from
 * occupied to empty.  Linear scan over fd_live[0..count) is cheap —
 * the list is bounded by FD_HASH_SIZE in the worst case but typically
 * holds a few hundred entries.  The replacement-then-decrement order
 * keeps the visible window of fd_live[] entries valid: a concurrent
 * lockless reader that loads count after the decrement sees a list
 * whose every slot is a real live fd; one that loads count before the
 * decrement may re-read the just-removed fd, which the auditor's
 * dup() check naturally tolerates.
 */
static void fd_live_remove(int fd)
{
	unsigned int count = shm->fd_live_count;
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (shm->fd_live[i] != fd)
			continue;

		if (i != count - 1) {
			int last = shm->fd_live[count - 1];

			__atomic_store_n(&shm->fd_live[i], last,
					 __ATOMIC_RELEASE);
		}
		__atomic_store_n(&shm->fd_live_count, count - 1,
				 __ATOMIC_RELEASE);
		return;
	}
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
	if (probe == FD_HASH_SIZE) {
		shm->stats.fd_hash_reinsert_dropped++;
		outputerr("fd_hash_reinsert: table full, dropping fd %d\n", fd);
		return;
	}

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

	if (shm->fd_hash[slot].fd == -1) {
		shm->fd_hash_count++;
		fd_live_append(fd);
	}

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
			fd_live_remove(fd);
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (shm->fd_hash[next].fd != -1) {
				struct fd_hash_entry displaced = shm->fd_hash[next];
				__atomic_store_n(&shm->fd_hash[next].fd, -1,
						 __ATOMIC_RELEASE);
				fd_hash_reinsert(displaced.fd, displaced.obj,
						 displaced.type, displaced.gen);
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			/*
			 * Decrement after the displaced-entry walk: between
			 * the slot clear and the reinsert loop the table
			 * still holds the same number of live entries (the
			 * displaced ones get re-seated, not added).
			 * Decrementing here keeps fd_hash_count from
			 * undershooting the true occupancy for any reader
			 * that samples it during the walk.
			 */
			shm->fd_hash_count--;
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
	return type >= OBJ_FD_PIPE && type <= OBJ_FD_KVM_VCPU;
}

/*
 * Per-objhead fd→object hash for OBJ_LOCAL fd-typed pools.
 *
 * Open-addressing with linear probing into a fixed power-of-two slot array
 * (LOCAL_FD_HASH_SIZE).  fd == -1 marks empty.  The table lives in the
 * owning child's private heap — head->fd_hash itself sits in shm alongside
 * the rest of the objhead, but the buffer it points at is per-process and
 * unreachable from any other address space, the same shape head->array
 * uses for OBJ_LOCAL pools (objects.c:203-211).
 *
 * Replaces the O(n) linear walk over head->array in
 * find_local_object_by_fd() with a single hash probe.  That function is
 * called from register_returned_fd() on every successful RET_FD syscall
 * whose entry->ret_objtype is not OBJ_NONE (open, openat, socket, accept,
 * eventfd, timerfd, perf_event_open, io_uring_setup, memfd_create,
 * pidfd, fanotify_init, etc.), so the saving applies on the syscall hot
 * path with head->num_entries typically in the tens-to-low-hundreds.
 */
static unsigned int local_fd_hash_slot_idx(int fd)
{
	return (unsigned int)fd & (LOCAL_FD_HASH_SIZE - 1);
}

static void local_fd_hash_alloc(struct objhead *head)
{
	unsigned int i;

	head->fd_hash = malloc(LOCAL_FD_HASH_SIZE *
			       sizeof(struct local_fd_hash_slot));
	if (head->fd_hash == NULL)
		return;
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		head->fd_hash[i].fd = -1;
		head->fd_hash[i].obj = NULL;
	}
}

/*
 * Internal insert that does not check for an existing entry — used by
 * local_fd_hash_remove() to re-seat displaced entries after a removal.
 * The displaced entry's identity is unchanged, so the original (fd, obj)
 * pair is reinserted unconditionally into the first empty slot.
 */
static void local_fd_hash_reinsert(struct objhead *head, int fd,
				   struct object *obj)
{
	unsigned int slot, probe;

	slot = local_fd_hash_slot_idx(fd);
	for (probe = 0; probe < LOCAL_FD_HASH_SIZE; probe++) {
		if (head->fd_hash[slot].fd == -1) {
			head->fd_hash[slot].fd = fd;
			head->fd_hash[slot].obj = obj;
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
}

static void local_fd_hash_insert(struct objhead *head, int fd,
				 struct object *obj)
{
	unsigned int slot, probe;

	if (fd < 0)
		return;
	if (head->fd_hash == NULL) {
		local_fd_hash_alloc(head);
		if (head->fd_hash == NULL)
			return;
	}

	slot = local_fd_hash_slot_idx(fd);
	for (probe = 0; probe < LOCAL_FD_HASH_SIZE; probe++) {
		if (head->fd_hash[slot].fd == -1 ||
		    head->fd_hash[slot].fd == fd) {
			head->fd_hash[slot].fd = fd;
			head->fd_hash[slot].obj = obj;
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
	/*
	 * Table saturated.  Realistically unreachable — LOCAL_FD_HASH_SIZE
	 * sits well above any per-(child, type) pool we have observed —
	 * but if it ever happens the caller gracefully falls back to the
	 * uninserted state: find_local_object_by_fd() returns NULL and
	 * register_returned_fd() simply re-adds, which is the same outcome
	 * as the pre-hash linear walk missing the entry.
	 */
}

static void local_fd_hash_remove(struct objhead *head, int fd)
{
	unsigned int slot, next, i;

	if (fd < 0 || head->fd_hash == NULL)
		return;

	slot = local_fd_hash_slot_idx(fd);
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		if (head->fd_hash[slot].fd == -1)
			return;
		if (head->fd_hash[slot].fd == fd) {
			head->fd_hash[slot].fd = -1;
			head->fd_hash[slot].obj = NULL;
			/*
			 * Linear-probing removal: re-seat any entries in the
			 * chain following us so a later lookup that hashes
			 * past this newly-empty slot still finds them.
			 */
			next = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
			while (head->fd_hash[next].fd != -1) {
				struct local_fd_hash_slot displaced =
					head->fd_hash[next];
				head->fd_hash[next].fd = -1;
				head->fd_hash[next].obj = NULL;
				local_fd_hash_reinsert(head, displaced.fd,
						       displaced.obj);
				next = (next + 1) & (LOCAL_FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
}

static struct object *local_fd_hash_lookup(struct objhead *head, int fd)
{
	unsigned int slot, i;

	if (fd < 0 || head->fd_hash == NULL)
		return NULL;

	slot = local_fd_hash_slot_idx(fd);
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		if (head->fd_hash[slot].fd == -1)
			return NULL;
		if (head->fd_hash[slot].fd == fd)
			return head->fd_hash[slot].obj;
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
	return NULL;
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
 * Snapshot helper for the for_each_obj iterator macro.  Captures
 * num_entries (ACQUIRE), array_capacity and array into the caller's
 * state struct so the loop body never re-reads the live objhead
 * fields.  Without this freeze every iteration of every for_each_obj
 * caller exposed three TOCTOU windows (fresh num_entries bound,
 * fresh array_capacity defensive break, fresh array deref) that a
 * sibling value-result syscall whose buffer aliases the objhead can
 * scribble between -- the same wild-stomp shape the per-call snapshot
 * regimes in add_object(), get_random_object_versioned() and
 * __destroy_object() / destroy_objects() close on the symmetric
 * write-entry, read and destroy paths.
 *
 * Entry rejection mirrors those parent fixes: a snapshot capacity
 * past OBJHEAD_SANE_LIMIT (smoking-gun wild stomp -- OBJ_GLOBAL is
 * hard-capped at GLOBAL_OBJ_MAX_CAPACITY=1024, OBJ_LOCAL working
 * sets stay well below the 64K ceiling) or n_snap > cap_snap bumps
 * local_obj_num_entries_corrupted and forces the loop to zero
 * iterations by zeroing n_snap.  An array_snap == NULL is collapsed
 * to zero iterations without a counter bump -- legitimate state for
 * an OBJ_LOCAL pool that has never had an add_object().
 *
 * array_generation is intentionally not captured: iterators do not
 * validate handles, that is validate_object_handle()'s responsibility
 * for callers that hold an obj across a window where a parent
 * destroy or a same-process realloc could invalidate the slot.
 */
void __for_each_obj_init(struct objhead *head,
			 struct __for_each_obj_state *s)
{
	unsigned int cap_snap;

	s->n_snap = __atomic_load_n(&head->num_entries, __ATOMIC_ACQUIRE);
	cap_snap = head->array_capacity;
	s->array_snap = head->array;

	if (cap_snap > OBJHEAD_SANE_LIMIT || s->n_snap > cap_snap) {
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
				   1, __ATOMIC_RELAXED);
		s->n_snap = 0;
		return;
	}
	if (s->array_snap == NULL)
		s->n_snap = 0;
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

	if (unlikely(verbosity > 1)) {
		output(2, "ADD-OBJ slot=%p type=%d caller=%s\n", obj, type,
			pc_to_string(__builtin_return_address(0), pcbuf, sizeof(pcbuf)));
	}

	/*
	 * Reject obviously-corrupted fd values before they enter any pool.
	 * 1<<20 = 1048576 matches the kernel's NR_OPEN ceiling
	 * (include/uapi/linux/fs.h), the absolute upper bound RLIMIT_NOFILE
	 * may be raised to on every distro we exercise -- so any retval
	 * decoding to a value past this is a smoking-gun upper-bit
	 * corruption (sign-extended or wholesale-stomped rec->retval) that
	 * the existing "(long)retval >= 0" gate in register_returned_fd /
	 * the per-syscall .post handlers let through because the lower bits
	 * happened to be positive.  Registering such a value into an
	 * OBJ_FD_* pool causes a later get_random_object() consumer to hand
	 * it back to the kernel as a real fd, where it either trips EBADF
	 * noise or, worse, a coincidentally-truncated int slot lands on a
	 * file-table entry an unrelated path opened.  This is the same wild-
	 * write hazard class the per-caller-PC attribution ring landed in
	 * 8d1eade3b63c was built to surface; routing the rejection through
	 * post_handler_corrupt_ptr_bump on the rec==NULL path feeds that
	 * ring with the .post handler's return address so the dump names
	 * the syscall whose retval produced the bogus fd.
	 * __builtin_return_address read at depth 0 only -- depth >0 trips
	 * -Wframe-address and the resulting PC is unsafe under aggressive
	 * optimisation, so the PC capture site is always add_object itself
	 * and the recorded address names add_object's immediate caller.
	 */
	if (is_fd_type(type)) {
		int fd = fd_from_object(obj, type);

		if (fd < 0 || fd >= (1 << 20)) {
			outputerr("add_object: rejecting out-of-bound fd=%d "
				  "type=%u caller=%s\n", fd, type,
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)));
			post_handler_corrupt_ptr_bump(NULL,
						      __builtin_return_address(0));
			release_obj(obj, scope, type);
			return;
		}
	}

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

	/*
	 * Snapshot head->num_entries once and use the snapshot for the
	 * grow check, the size computation, the slot write, and the
	 * publish below.  head->num_entries lives in shm (per-child for
	 * OBJ_LOCAL, shm->global_objects[] for OBJ_GLOBAL) and is reachable
	 * from any fuzzed value-result syscall whose length argument lands
	 * inside that struct -- the same wild-write hazard that motivated
	 * the OBJHEAD_SANE_LIMIT defence in objhead_looks_sane().  Without
	 * a local snapshot, a stomp landing between the grow check and the
	 * slot write lets the index used at head->array[N]=obj diverge
	 * from the index the grow check sized for, and the slot write
	 * lands past the array's bounds (heap-buffer-overflow at
	 * objects.c:411).  Snapshotting once also collapses two reloads
	 * the compiler can't elide across the malloc / mprotect calls in
	 * the OBJ_LOCAL grow path, where every reload of head->num_entries
	 * widens the same TOCTOU window.
	 */
	unsigned int n = head->num_entries;

	/*
	 * Parallel snapshot of head->array and head->array_generation.
	 * The n snapshot above only addresses the index used at the slot
	 * write; head->array itself is re-loaded from shm at the deref
	 * (mov (%rcx),%rax immediately before mov %rbx,(%rax,%rdx,8) at
	 * objects.c:777 in the prod disasm), so a sibling value-result
	 * write that scribbles head->array between the grow check and the
	 * slot store faults on a freshly-corrupted pointer with the n
	 * snapshot intact.  Snapshot the array pointer alongside n and
	 * route the slot write through the snapshot so the deref is
	 * decoupled from any post-snapshot stomp.  gen_snap pairs with
	 * the RELEASE bump in the OBJ_LOCAL grow branch below and the
	 * read-side ACQUIRE-load in get_random_object_versioned() / the
	 * matching check in validate_object_handle(): a wild write that
	 * also clobbered head->array_generation is caught at the pre-
	 * write re-check before the store dereferences a stale snapshot
	 * (the wild-write may have invalidated array_snap in the same
	 * vicinity).  OBJ_LOCAL grow legitimately reseats head->array
	 * and bumps the generation, so the snapshots are refreshed
	 * inside that branch to the post-grow values.
	 */
	struct object **array_snap = head->array;
	unsigned int gen_snap = __atomic_load_n(&head->array_generation,
						__ATOMIC_ACQUIRE);
	/*
	 * Snapshot head->array_capacity alongside n / array_snap / gen_snap.
	 * Every capacity-bound decision below (the entry stomp-bound bail,
	 * the OBJ_GLOBAL "global array full" reject, the OBJ_LOCAL grow
	 * trigger and grow-loop arithmetic) routes through cap_snap so a
	 * sibling value-result write that scribbles head->array_capacity
	 * between two re-loads cannot let n=K pass a "K > cap_load_A"
	 * check at one site and then fail to trigger a grow at a later
	 * "K >= cap_load_B" check because a different load saw a stomped
	 * larger value.  Without this snapshot a joint stomp of
	 * (num_entries, array_capacity) to mutually-consistent large values
	 * passes the entry n>cap bail (cap_load_A also large), passes the
	 * OBJ_LOCAL grow trigger n>=cap (cap_load_B also large), and lands
	 * array_snap[n] = obj 153+ slots past the original 16-slot
	 * allocation -- the heap-buffer-overflow ASAN caught in add_object
	 * via post_eventfd_create.  Closes the last objhead field that was
	 * still being read fresh from shm at every use; mirrors the
	 * snapshot regimes added for num_entries (1ca419778f42), array
	 * (5f3851f029d8) and array_generation (58e9d01ac4d2).  The OBJ_LOCAL
	 * grow branch refreshes cap_snap to the post-grow newcap below
	 * alongside the existing array_snap / gen_snap refresh.
	 */
	unsigned int cap_snap = head->array_capacity;

	/*
	 * Reject snapshots whose head->array pointer is itself shape-
	 * unhealthy (sub-page / non-canonical / misaligned).  NULL is the
	 * legitimate first-add state -- head->array is only allocated by
	 * the OBJ_LOCAL grow branch below or init_object_lists() for
	 * OBJ_GLOBAL -- so skip the shape check on NULL.  Any non-NULL
	 * value that fails is_corrupt_ptr_shape() came from a wild stomp
	 * that hit head->array; fall through to the same release_obj +
	 * counter bump path the entry-time num_entries guard uses so the
	 * failure mode collapses onto one shape.
	 */
	if (array_snap != NULL && is_corrupt_ptr_shape(array_snap)) {
		outputerr("add_object: stomped head->array type=%u array=%p num_entries=%u capacity=%u\n",
			  type, array_snap, n, cap_snap);
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted, 1,
				   __ATOMIC_RELAXED);
		if (is_fd_type(type)) {
			int fd = fd_from_object(obj, type);
			if (fd >= 0)
				close(fd);
		}
		release_obj(obj, scope, type);
		goto out_unlock;
	}

	/*
	 * Reject snapshots whose array_capacity is past the OBJHEAD_SANE_
	 * LIMIT ceiling objhead_looks_sane() already uses for the dump
	 * path.  A snapshot above this is a smoking-gun wild stomp -- no
	 * legitimate grow can produce a capacity here (OBJ_GLOBAL is hard-
	 * capped at GLOBAL_OBJ_MAX_CAPACITY=1024, OBJ_LOCAL working sets
	 * stay well below 64K) -- and acting on it lets the joint
	 * (num_entries, array_capacity) stomp described above slip through
	 * the capacity-routed checks because cap_snap was already poisoned
	 * at snapshot time.  Same release_obj + counter path as the other
	 * snapshot-rejection sites.
	 */
	if (cap_snap > OBJHEAD_SANE_LIMIT) {
		outputerr("add_object: stomped capacity type=%u capacity=%u num_entries=%u\n",
			  type, cap_snap, n);
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted, 1,
				   __ATOMIC_RELAXED);
		if (is_fd_type(type)) {
			int fd = fd_from_object(obj, type);
			if (fd >= 0)
				close(fd);
		}
		release_obj(obj, scope, type);
		goto out_unlock;
	}

	if (n > cap_snap) {
		/* Wild-stomp defence — refuse to act on a snapshot that was already
		 * out-of-bounds at the moment we read it.  The grow loop's UINT_MAX/2
		 * guard would eventually catch this, but bail earlier so we don't
		 * attempt large allocations we know up-front to be illegitimate.
		 * Mirrors the symmetric pick-side guard in get_random_object_
		 * versioned()'s OBJ_LOCAL branch and the OBJ_GLOBAL guard at the
		 * grow check just below this line. */
		outputerr("add_object: stomped num_entries type=%u num_entries=%u capacity=%u\n",
			  type, n, cap_snap);
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted, 1,
				   __ATOMIC_RELAXED);
		if (is_fd_type(type)) {
			int fd = fd_from_object(obj, type);
			if (fd >= 0)
				close(fd);
		}
		release_obj(obj, scope, type);
		goto out_unlock;
	}

	/* For global objects, the array was pre-allocated in shared
	 * memory by init_object_lists().  Never realloc — just reject
	 * if we've hit the fixed capacity. */
	if (scope == OBJ_GLOBAL) {
		if (n >= cap_snap) {
			outputerr("add_object: global array full for type %u "
				  "(cap %u)\n", type, cap_snap);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			goto out_unlock;
		}
	} else if (n >= cap_snap) {
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

		/*
		 * Doubling-then-walk: the entry condition n >= array_capacity
		 * normally means n == array_capacity, so doubling
		 * array_capacity gives newcap = 2*n which strictly exceeds
		 * the index we are about to write.  If a wild write has
		 * scribbled head->num_entries past array_capacity, the
		 * single double can come back smaller than the snapshot --
		 * walk the doubling until newcap > n.  Bail with a
		 * release_obj if a further double would overflow unsigned
		 * int rather than letting the OOB land.
		 */
		if (cap_snap > UINT_MAX / 2) {
			outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
				  type, n, cap_snap);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			return;
		}
		newcap = cap_snap ? cap_snap * 2 : 16;
		while (newcap <= n) {
			if (newcap > UINT_MAX / 2) {
				outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
					  type, n, cap_snap);
				if (is_fd_type(type)) {
					int fd = fd_from_object(obj, type);
					if (fd >= 0)
						close(fd);
				}
				release_obj(obj, scope, type);
				return;
			}
			newcap *= 2;
		}
		newarray = zmalloc(newcap * sizeof(struct object *));
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
		oldcap = cap_snap;
		oldarray = head->array;
		if (oldarray != NULL && oldcap > 0)
			memcpy(newarray, oldarray,
			       oldcap * sizeof(struct object *));
		head->array = newarray;
		head->array_capacity = newcap;
		/*
		 * Bump the whole-array generation AFTER the new buffer is
		 * published.  A reader that snapshots the generation BEFORE
		 * loading head->array sees either (gen=N, array=oldarray) or
		 * (gen=N+1, array=newarray); validate_object_handle() compares
		 * its snapshotted gen against the current value and rejects
		 * any handle whose snapshot pre-dates the swap, so a consumer
		 * that loaded head->array into a local variable before this
		 * point and is now holding a slot pointer from the prior
		 * generation drops it instead of dereferencing into the
		 * deferred-free queue's pending chunk.  RELEASE so the bump
		 * orders after the head->array store from a reader's
		 * perspective.
		 */
		__atomic_add_fetch(&head->array_generation, 1,
				   __ATOMIC_RELEASE);
		/*
		 * Refresh the snapshots taken at the top of the function: we
		 * just legitimately reseated head->array and bumped
		 * head->array_generation, so the stale array_snap (== old
		 * deferred-freed buffer) and gen_snap (== pre-bump value)
		 * would both be rejected by the pre-write re-check below.
		 * Re-load with ACQUIRE so a sibling-scribble that also lands
		 * on head->array_generation between the bump and here is
		 * caught at the re-check rather than silently accepted.
		 */
		array_snap = head->array;
		gen_snap = __atomic_load_n(&head->array_generation,
					   __ATOMIC_ACQUIRE);
		/*
		 * Refresh cap_snap to the post-grow capacity for the same
		 * reason array_snap and gen_snap are refreshed above: the
		 * pre-write re-check below compares cap_snap against
		 * head->array_capacity to catch a sibling stomp landing
		 * between the entry snapshot and the slot store, and the
		 * legitimate grow we just performed bumped capacity itself.
		 * Use newcap rather than re-reading head->array_capacity so
		 * the refresh window stays closed on a sibling stomp landing
		 * between the publish at line ~768 and here.
		 */
		cap_snap = newcap;
		if (oldarray != NULL)
			deferred_free_enqueue(oldarray, free);
	}

	/*
	 * Bump the slot's version BEFORE publishing the new pointer so a
	 * concurrent lockless reader that snapshots slot_versions[n]
	 * after this point and reads array[n] sees a (version, ptr)
	 * pair that's internally consistent.  RELEASE so the bump is
	 * visible to the child's ACQUIRE-load in get_random_object().
	 * Skipped for OBJ_LOCAL (no slot_versions array there — no
	 * lockless reader to coordinate with).
	 */
	if (scope == OBJ_GLOBAL && head->slot_versions != NULL)
		__atomic_add_fetch(&head->slot_versions[n], 1,
				   __ATOMIC_RELEASE);

	/*
	 * Re-check head->array_generation immediately before the store.
	 * A sibling value-result write that scribbled head->array between
	 * the snapshot at the top and this point would also land in the
	 * same shm vicinity as head->array_generation; mirror the read-
	 * side mismatch reject in validate_object_handle() here on the
	 * write side.  Route through the existing local_obj_num_entries_
	 * corrupted path used by the entry-time stomped-num_entries guard
	 * so the failure mode collapses onto one counter and one error
	 * shape -- both observations are the same hazard class (a wild
	 * stomp on objhead state past the snapshot).  ACQUIRE pairs with
	 * the bumper's RELEASE in the OBJ_LOCAL grow branch above and in
	 * destroy_objects().  OBJ_GLOBAL arrays are pre-allocated and
	 * never legitimately reseated, so gen stays at the snapshotted
	 * value in steady state -- a mismatch there means a wild write
	 * has clobbered head->array_generation (and presumably head->array
	 * with it), which is exactly the case the snapshot is here to
	 * catch.
	 */
	{
		unsigned int gen_now = __atomic_load_n(&head->array_generation,
						       __ATOMIC_ACQUIRE);
		unsigned int cap_now;

		if (gen_now != gen_snap) {
			outputerr("add_object: stomped array_generation type=%u gen_snap=%u gen_now=%u\n",
				  type, gen_snap, gen_now);
			__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
					   1, __ATOMIC_RELAXED);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			goto out_unlock;
		}
		/*
		 * Pair with the cap_snap entry-snapshot above: re-check
		 * head->array_capacity hasn't been scribbled between the
		 * snapshot (or its post-grow refresh) and the slot store.
		 * The gen re-check just above catches a stomp that touched
		 * head->array_generation; a sibling value-result write that
		 * landed in the same shm vicinity but missed the gen field
		 * and only stomped array_capacity is caught here.  array_snap
		 * was sized for cap_snap slots; if the live capacity now
		 * disagrees, the snapshot we are about to deref no longer
		 * matches the array's true bound and the store at
		 * array_snap[n] = obj is no longer provably in-bounds.
		 */
		cap_now = head->array_capacity;
		if (cap_now != cap_snap) {
			outputerr("add_object: stomped array_capacity type=%u cap_snap=%u cap_now=%u num_entries=%u\n",
				  type, cap_snap, cap_now, n);
			__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
					   1, __ATOMIC_RELAXED);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			goto out_unlock;
		}
	}

	array_snap[n] = obj;
	obj->array_idx = n;

	/*
	 * RELEASE-publish the new count so a child doing a lockless
	 * ACQUIRE-load in get_random_object() that sees count=N+1 also
	 * sees the array[N] = obj write that preceded it.  For OBJ_LOCAL
	 * the pool is per-child private, so a plain store suffices.
	 */
	if (scope == OBJ_GLOBAL)
		__atomic_store_n(&head->num_entries, n + 1, __ATOMIC_RELEASE);
	else
		head->num_entries = n + 1;

	/* Mirror the parent-side global fd hash for OBJ_LOCAL fd-typed
	 * pools so find_local_object_by_fd() resolves in O(1).  The buffer
	 * is lazily allocated by local_fd_hash_insert() on first use. */
	if (scope == OBJ_LOCAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);

		if (fd >= 0)
			local_fd_hash_insert(head, fd, obj);
	}

	/* Track global fd-type objects in the hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);
		if (!fd_hash_insert(fd, obj, type)) {
			outputerr("add_object: fd hash full for type %u, dropping fd %d\n",
				  type, fd);
			/*
			 * Drop the count first so a concurrent lockless child
			 * read picking up the new snapshot sees the lower
			 * count and won't index past the (about-to-be-NULLed)
			 * tail slot.  RELEASE pairs with the child's ACQUIRE.
			 * Roll back to the same n the slot write used so a
			 * wild write that scribbled head->num_entries between
			 * the publish above and here can't drop the count to
			 * a stale value or NULL the wrong slot.
			 */
			__atomic_store_n(&head->num_entries, n,
					 __ATOMIC_RELEASE);
			/*
			 * Roll back through the same snapshotted pointer the
			 * publishing store at array_snap[n] = obj used.  A
			 * sibling-scribble that landed between the slot write
			 * above and the fd_hash_insert() reject here would
			 * fault on a freshly-corrupted head->array re-load
			 * otherwise; the snapshot was validated by the gen
			 * re-check before the publish, and OBJ_GLOBAL arrays
			 * never legitimately reseat, so the snapshot still
			 * names the slot we wrote.
			 */
			array_snap[n] = NULL;
			/*
			 * Rollback bump: a lockless reader that briefly
			 * observed snapshot=n+1 may have captured the pre-
			 * rollback (slot_versions[n], array[n]) pair and be
			 * mid-validation.  Bump the version again so its post-
			 * use re-acquire diverges and the obj — about to be
			 * release_obj()'d into the freelist — is rejected.
			 */
			if (head->slot_versions != NULL)
				__atomic_add_fetch(&head->slot_versions[n], 1,
						   __ATOMIC_RELEASE);
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
		head->array_generation = 0;

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
			/*
			 * Parallel per-slot version counter for the lockless
			 * child reader's seqlock-style consistency check.
			 * Same backing region as ->array (alloc_shared_global)
			 * so freeze/thaw/mprotect cycles cover both.
			 */
			head->slot_versions =
				alloc_shared_global(GLOBAL_OBJ_MAX_CAPACITY *
						    sizeof(unsigned int));
			memset(head->slot_versions, 0, GLOBAL_OBJ_MAX_CAPACITY *
			       sizeof(unsigned int));
		} else {
			head->array = NULL;
			head->array_capacity = 0;
			head->slot_versions = NULL;
		}

		/*
		 * Per-OBJ_LOCAL fd→object hash starts empty.  Lazily
		 * allocated in private heap on the first add_object() insert
		 * for fd-typed pools.  Reset here even on the OBJ_GLOBAL path
		 * because shm slot reuse across child generations could leave
		 * a stale pointer from a prior child in the shared objhead;
		 * an unconditional NULL write keeps the lazy-alloc check in
		 * local_fd_hash_insert() honest.
		 */
		head->fd_hash = NULL;

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
/*
 * Lockless seqlock-style sample of one OBJ_GLOBAL slot from a child.
 *
 * Reads slot_versions[idx] before and after sampling array[idx]; if the
 * two versions match AND the obj pointer is non-NULL we have a (version,
 * obj) pair that no concurrent destroy interleaved with.  On mismatch
 * the parent mutated the slot inside our window — return NULL to the
 * caller's retry loop.  On a stable but NULL slot (transient swap-with-
 * last torn state) likewise return NULL so the retry picks a fresh idx.
 *
 * The caller saves *version_out for a later validate_object_handle()
 * re-acquire if it carries the obj past its own deref window (e.g. the
 * arg-gen path, where get_map() returns &obj->map and the consumer
 * derefs map->ptr several frames downstream).
 */
static struct object *sample_global_slot(struct objhead *head,
					 unsigned int idx,
					 unsigned int *version_out)
{
	unsigned int v_a, v_b;
	struct object *obj;

	v_a = __atomic_load_n(&head->slot_versions[idx], __ATOMIC_ACQUIRE);
	obj = __atomic_load_n(&head->array[idx], __ATOMIC_ACQUIRE);
	v_b = __atomic_load_n(&head->slot_versions[idx], __ATOMIC_ACQUIRE);
	if (v_a != v_b || obj == NULL)
		return NULL;
	*version_out = v_a;
	return obj;
}

/*
 * Bounded retry budget for the lockless reader's seqlock loop.
 *
 * A single mismatch means one parent-side destroy raced with the
 * sample; a small handful of retries absorbs back-to-back regen churn
 * on the same pool without spinning forever in the (theoretical) case
 * of a parent that destroys faster than the child can sample.  Beyond
 * that, surface NULL to the caller — most consumers (get_map, the
 * fd_provider syscalls) treat NULL as "pick something else this round"
 * and just retry at their own granularity.
 */
#define GET_RANDOM_OBJECT_RETRY_BUDGET 8

static struct object *get_random_object_global_lockless(struct objhead *head,
							unsigned int *idx_out,
							unsigned int *version_out,
							unsigned int *array_gen_out)
{
	unsigned int snapshot;
	unsigned int idx;
	unsigned int version;
	struct object *obj;
	int attempt;
	/*
	 * For OBJ_GLOBAL pools array_capacity is fixed at
	 * GLOBAL_OBJ_MAX_CAPACITY in init_object_lists() and is never
	 * resized (the parallel array is alloc_shared_global()'d once and
	 * frozen RO via freeze_global_objects()).  Hoist the load out of
	 * the retry loop so we don't reread it on every attempt.
	 */
	const unsigned int cap = head->array_capacity;

	for (attempt = 0; attempt < GET_RANDOM_OBJECT_RETRY_BUDGET; attempt++) {
		unsigned int gen;

		snapshot = __atomic_load_n(&head->num_entries,
					   __ATOMIC_ACQUIRE);
		if (snapshot == 0)
			return NULL;
		/*
		 * Defence against a wild-write-stomped num_entries that
		 * exceeds the array bound; sample_global_slot below would
		 * OOB-read slot_versions/array otherwise.  validate_global_
		 * objects() reports this on the parent's idle pass; here we
		 * just fall back gracefully to NULL.
		 */
		if (snapshot > cap)
			return NULL;
		/*
		 * Snapshot the whole-array generation BEFORE the per-slot
		 * sample.  ACQUIRE pairs with the bumper's RELEASE in
		 * add_object()/destroy_objects().  OBJ_GLOBAL arrays don't
		 * realloc, so this is 0 in steady state — but a wild write
		 * that reseats head->array would also be visible here, and
		 * the matching check in validate_object_handle() rejects the
		 * handle before any consumer derefs the obj it references.
		 */
		gen = __atomic_load_n(&head->array_generation,
				      __ATOMIC_ACQUIRE);
		idx = rand() % snapshot;
		obj = sample_global_slot(head, idx, &version);
		if (obj != NULL) {
			*idx_out = idx;
			*version_out = version;
			*array_gen_out = gen;
			return obj;
		}
	}

	__atomic_add_fetch(&shm->stats.global_obj_uaf_caught, 1,
			   __ATOMIC_RELAXED);
	return NULL;
}

struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	unsigned int idx, version, array_gen;

	return get_random_object_versioned(type, scope, &idx, &version,
					   &array_gen);
}

struct object * get_random_object_versioned(enum objecttype type,
					    enum obj_scope scope,
					    unsigned int *idx_out,
					    unsigned int *version_out,
					    unsigned int *array_gen_out)
{
	struct objhead *head;
	struct object *obj;

	*idx_out = 0;
	*version_out = 0;
	*array_gen_out = 0;

	head = get_objhead(scope, type);
	if (head == NULL)
		return NULL;

	if (scope == OBJ_GLOBAL && getpid() != mainpid) {
		if (head->slot_versions == NULL) {
			/* Pool was never initialised (no
			 * REG_GLOBAL_OBJ for this type, or init was
			 * skipped); fall through to the legacy lockless
			 * read with no version validation rather than
			 * deref a NULL slot_versions[]. */
			unsigned int snapshot;
			unsigned int cap_snap;
			unsigned int gen_snap;
			struct object **array_snap;

			/*
			 * Snapshot every objhead field consulted below in
			 * one block so the bound check and the slot deref
			 * see a self-consistent view.  Mirror the regime
			 * add_object() uses on the write side: a sibling
			 * value-result write that scribbles
			 * (num_entries, array_capacity, array) past the
			 * point where we read num_entries cannot let
			 * snapshot pass a stale "snapshot > cap" check
			 * against a freshly-poisoned head->array_capacity
			 * and then deref a freshly-reseated head->array
			 * many slots out of the original allocation.
			 * Loading array_generation before head->array keeps
			 * the existing reader semantics: validate_object_
			 * handle()'s gen re-check fires on any reseating
			 * that races our deref.
			 */
			snapshot = __atomic_load_n(&head->num_entries,
						   __ATOMIC_ACQUIRE);
			cap_snap = head->array_capacity;
			gen_snap = __atomic_load_n(&head->array_generation,
						   __ATOMIC_ACQUIRE);
			array_snap = head->array;

			if (snapshot == 0)
				return NULL;
			if (cap_snap > OBJHEAD_SANE_LIMIT) {
				__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
						   1, __ATOMIC_RELAXED);
				return NULL;
			}
			if (snapshot > cap_snap)
				return NULL;
			*array_gen_out = gen_snap;
			return array_snap[rand() % snapshot];
		}
		return get_random_object_global_lockless(head, idx_out,
							 version_out,
							 array_gen_out);
	}

	if (scope == OBJ_GLOBAL)
		lock(&shm->objlock);

	{
		unsigned int snapshot;
		unsigned int cap_snap;
		unsigned int gen_snap;
		struct object **array_snap;

		/*
		 * Snapshot num_entries, array_capacity, array_generation and
		 * array together at branch entry so the bound check, the gen
		 * handed back to the caller and the slot deref all consult
		 * one self-consistent view.  Without this, num_entries was
		 * snapshotted but array_capacity and array were re-loaded
		 * fresh at the bound check and the deref respectively, so a
		 * sibling value-result write that scribbled
		 * (num_entries, array_capacity) to mutually-consistent large
		 * values between our num_entries snapshot and the deref
		 * would let snapshot pass the "snapshot > cap" check
		 * (cap re-load also poisoned) and then the rand() % snapshot
		 * index would deref into a head->array region whose actual
		 * allocation was sized under the pre-poisoning capacity --
		 * the symmetric read-side shape of the OOB write
		 * add_object() now defends against (parent fix
		 * b677185d752496ac7ee7751c66e86f432e108c54).  Loading
		 * array_generation before head->array preserves the existing
		 * reader semantics: validate_object_handle()'s gen re-check
		 * pairs with the RELEASE bump on the writer side and fires
		 * on any reseating that races our array_snap read.
		 */
		snapshot = __atomic_load_n(&head->num_entries,
					   __ATOMIC_ACQUIRE);
		cap_snap = head->array_capacity;
		gen_snap = __atomic_load_n(&head->array_generation,
					   __ATOMIC_ACQUIRE);
		array_snap = head->array;

		if (snapshot == 0) {
			obj = NULL;
		} else if (cap_snap > OBJHEAD_SANE_LIMIT) {
			/*
			 * Snapshot of array_capacity above the ceiling
			 * objhead_looks_sane() uses for the dump path can
			 * only have come from a wild stomp -- OBJ_GLOBAL is
			 * hard-capped at GLOBAL_OBJ_MAX_CAPACITY=1024 and
			 * OBJ_LOCAL working sets stay well below 64K -- so
			 * acting on it (and on the num_entries snapshot we
			 * paired it with) is the joint-stomp shape the
			 * cap_snap defence in add_object() exists to reject.
			 * Mirror that bail here on the read side.
			 */
			__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
					   1, __ATOMIC_RELAXED);
			obj = NULL;
		} else if (snapshot > cap_snap) {
			/*
			 * Wild-stomp defence — mirror the OBJ_GLOBAL guards at
			 * the lockless-reader path and the legacy fall-through
			 * just above (snapshot > cap returns NULL).  A fuzzed
			 * value-result write whose buffer aliased an objhead
			 * has scribbled head->num_entries past the array
			 * bound; converting that into a NULL return keeps the
			 * array_snap[idx] deref below from running off the
			 * end.  See struct stats::local_obj_num_entries_
			 * corrupted in include/stats.h for the broader hazard
			 * description; the symmetric write-side guard in
			 * add_object() bumps the same counter.
			 */
			__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
					   1, __ATOMIC_RELAXED);
			obj = NULL;
		} else {
			unsigned int idx = rand() % snapshot;

			*array_gen_out = gen_snap;
			obj = array_snap[idx];
			*idx_out = idx;
			if (scope == OBJ_GLOBAL && head->slot_versions != NULL)
				*version_out = head->slot_versions[idx];
		}
	}

	if (scope == OBJ_GLOBAL)
		unlock(&shm->objlock);

	return obj;
}

bool validate_object_handle(enum objecttype type, enum obj_scope scope,
			    struct object *obj, unsigned int idx,
			    unsigned int version, unsigned int array_gen)
{
	struct objhead *head;
	unsigned int gen_now;
	unsigned int v_now;
	struct object *cur;

	if (obj == NULL)
		return false;

	/*
	 * Parent OBJ_GLOBAL reads run under shm->objlock and synchronously
	 * with all mutators, so neither the slot-version nor the array-
	 * generation race window exists from the parent's perspective.
	 * (The parent never touches OBJ_LOCAL — get_objhead returns NULL
	 * for OBJ_LOCAL when this_child() is NULL — so the parent path
	 * collapses cleanly to OBJ_GLOBAL only.)
	 */
	if (scope == OBJ_GLOBAL && getpid() == mainpid)
		return true;

	head = get_objhead(scope, type);
	if (head == NULL)
		return true;

	/*
	 * Whole-array generation check.  A mismatch means head->array was
	 * reseated since the caller snapshotted array_gen at pick time —
	 * the OBJ_LOCAL grow path's zmalloc-copy-defer-free, the teardown
	 * NULL-out, or a wild write that stomped both head->array and
	 * head->array_generation in the same vicinity.  The caller's idx
	 * is now indexing into either a deferred-free chunk that may have
	 * been recycled by libc (the failure mode that surfaced as a UAF
	 * read inside a stdio FILE buffer the OBJ_LOCAL maps pool's prior
	 * generation had been free()'d into) or an unrelated buffer
	 * entirely.  Reject without dereferencing array[idx].  ACQUIRE
	 * pairs with the bumper's RELEASE in add_object()/destroy_objects.
	 *
	 * For OBJ_LOCAL this is the whole validation: there is no
	 * lockless reader to coordinate with via slot_versions, the bug
	 * we are catching is buffer-level rather than slot-level, and any
	 * deref of head->array inside this function would simply re-trip
	 * the same UAF we are trying to detect.
	 */
	gen_now = __atomic_load_n(&head->array_generation, __ATOMIC_ACQUIRE);
	if (gen_now != array_gen) {
		__atomic_add_fetch(&shm->stats.global_obj_uaf_caught, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	if (scope != OBJ_GLOBAL)
		return true;

	if (head->slot_versions == NULL)
		return true;

	if (idx >= head->array_capacity)
		return false;

	v_now = __atomic_load_n(&head->slot_versions[idx], __ATOMIC_ACQUIRE);
	cur = __atomic_load_n(&head->array[idx], __ATOMIC_ACQUIRE);
	if (v_now != version || cur != obj) {
		__atomic_add_fetch(&shm->stats.global_obj_uaf_caught, 1,
				   __ATOMIC_RELAXED);
		return false;
	}
	return true;
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
	case OBJ_FD_KVM_SYSTEM:	obj->kvmsysobj.fd = -1; break;
	case OBJ_FD_KVM_VM:	obj->kvmvmobj.fd = -1; break;
	case OBJ_FD_KVM_VCPU:	obj->kvmvcpuobj.fd = -1; break;
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
	unsigned int n_snap;
	unsigned int cap_snap;
	struct object **array_snap;

	head = get_objhead(scope, type);

	/*
	 * Snapshot the objhead fields the swap-with-last path consults so
	 * a sibling value-result syscall whose buffer aliases this
	 * objhead cannot scribble (num_entries, array_capacity, array)
	 * past our entry-time read and steer the array[idx] = array[last]
	 * / array[last] = NULL stores past the end of the live
	 * allocation.  Mirrors the regime add_object() established
	 * (b677185d752496ac7ee7751c66e86f432e108c54) and the read-side
	 * companion in get_random_object_versioned()
	 * (2c5d84e5d67b7e843ceb0a0ed42f0a996568caa9).  Locking is
	 * unchanged -- objlock for OBJ_GLOBAL acquired by the
	 * destroy_object()/destroy_objects() callers, single-child for
	 * OBJ_LOCAL.  array_generation is intentionally not snapshotted:
	 * the destroy path neither returns generation to a caller nor
	 * pairs with a reader on it, only the OBJ_LOCAL teardown in
	 * destroy_objects() bumps it via RMW which keeps the existing
	 * pairing with validate_object_handle().
	 */
	n_snap = __atomic_load_n(&head->num_entries, __ATOMIC_ACQUIRE);
	cap_snap = head->array_capacity;
	array_snap = head->array;

	/*
	 * Reject snapshots whose array_capacity is past the
	 * OBJHEAD_SANE_LIMIT ceiling objhead_looks_sane() uses for the
	 * dump path -- a smoking-gun wild stomp, since OBJ_GLOBAL is
	 * hard-capped at GLOBAL_OBJ_MAX_CAPACITY=1024 and OBJ_LOCAL
	 * working sets stay well below 64K.  Same shape as the entry
	 * cap_snap reject in add_object().
	 */
	if (cap_snap > OBJHEAD_SANE_LIMIT) {
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (n_snap > cap_snap) {
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (n_snap == 0 || array_snap == NULL)
		return;

	/*
	 * obj->array_idx is the slot we're about to swap-with-last and
	 * NULL.  add_object() set it once at insertion (objects.c:516)
	 * and the swap branch below maintains it on every reshuffle —
	 * the canonical invariant is head->array[obj->array_idx] == obj.
	 *
	 * obj itself lives in either the shared obj heap (OBJ_GLOBAL with
	 * shared_alloc=true) or per-process heap (everything else).  The
	 * shared path is reachable to every child's wild fuzzed writes and
	 * a value-result syscall whose length-arg lands inside an obj
	 * struct will scribble its array_idx field; the private path is
	 * still reachable to a stale slot pointer that survived the
	 * deferred-free TTL and got handed back through get_random_object().
	 *
	 * Indexing without verifying the invariant therefore produces one
	 * of two silent failures:
	 *   - array_idx >= num_entries: the array_snap[idx] = array_snap[last]
	 *     write lands past the live window, smashing whichever slot the
	 *     stomp's index pointed at (or, for OBJ_GLOBAL, OOB past the
	 *     fixed GLOBAL_OBJ_MAX_CAPACITY allocation entirely);
	 *   - array_idx < num_entries but array_snap[idx] != obj: we NULL
	 *     and free a different live object, then call its type-correct
	 *     destructor on what we still believe is `obj` — a UAF on the
	 *     unrelated object's backing storage on the very next read of
	 *     it through the pool.
	 *
	 * Validate the invariant up front.  On mismatch, drop the destroy
	 * cleanly (no slot mutation, no destructor, no release) and bump
	 * the corruption counter — `obj` may not even belong to this pool
	 * any more, so touching it is exactly the wrong move.
	 */
	idx = obj->array_idx;
	if (idx >= n_snap || array_snap[idx] != obj) {
		__atomic_add_fetch(&shm->stats.destroy_object_idx_corrupt, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	/* Swap-with-last removal from the parallel array */
	last = n_snap - 1;

	/*
	 * Bump the per-slot version BEFORE mutating the array, on every
	 * slot we are about to touch (the destroyed slot at idx, plus the
	 * formerly-last slot at `last` we are about to NULL).  A lockless
	 * child reader running through the seqlock-style protocol in
	 * get_random_object()/validate_object_handle() snapshots the
	 * slot version, samples array[idx], then re-snapshots the version;
	 * a mismatch means a destroy raced with the read and the picked
	 * obj must NOT be dereferenced (release_obj() may already have
	 * routed it through free_shared_obj()'s freelist where a sibling
	 * alloc_shared_obj() can recycle it under us — the asan-poisoned
	 * redzone reads at 0x51900064f758 in the overnight 2026-05-05 run
	 * were exactly this).  Order matters: version bump first, then
	 * array mutation, then count decrement; the reader's ACQUIRE on
	 * the version pairs with these RELEASEs.  Skipped for OBJ_LOCAL
	 * (no slot_versions array, no lockless reader).
	 */
	if (head->slot_versions != NULL) {
		__atomic_add_fetch(&head->slot_versions[idx], 1,
				   __ATOMIC_RELEASE);
		if (last != idx)
			__atomic_add_fetch(&head->slot_versions[last], 1,
					   __ATOMIC_RELEASE);
	}

	if (idx != last) {
		array_snap[idx] = array_snap[last];
		if (array_snap[idx] != NULL)
			array_snap[idx]->array_idx = idx;
	}
	array_snap[last] = NULL;

	/*
	 * Publish the new count with RELEASE semantics so a concurrent
	 * lockless child read in get_random_object() that observes the
	 * shrunk count cannot also observe an inconsistent earlier state
	 * of the array slots.  See the design comment above
	 * get_random_object().  __prune_objects(OBJ_GLOBAL) is currently
	 * disabled but routes through here, so this also covers it
	 * defensively.  Write `last` (== n_snap - 1) rather than reading
	 * head->num_entries fresh and decrementing -- a sibling stomp
	 * landing between snapshot and store would otherwise propagate
	 * the wild value back into the field.
	 */
	if (scope == OBJ_GLOBAL)
		__atomic_store_n(&head->num_entries, last, __ATOMIC_RELEASE);
	else
		head->num_entries = last;

	/* Remove from fd hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type))
		fd_hash_remove(fd_from_object(obj, type));
	else if (scope == OBJ_LOCAL && is_fd_type(type))
		local_fd_hash_remove(head, fd_from_object(obj, type));

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
	unsigned int prev_n;
	unsigned int n_snap;
	unsigned int cap_snap;
	struct object **array_snap;

	head = get_objhead(scope, type);

	/*
	 * Snapshot at entry the same three objhead fields the drain loop
	 * and the post-loop OBJ_GLOBAL memset consult.  Without this the
	 * loop's per-iter head->array[0] deref and the final
	 *     memset(head->array, 0, head->array_capacity * sizeof(...))
	 * both re-load array and array_capacity fresh from shm, so a
	 * sibling value-result syscall whose buffer aliases this objhead
	 * can scribble (array_capacity, array, num_entries) to wild
	 * values mid-teardown and turn the global-pool zero-out into an
	 * OOB write of (cap_snap_wild * 8) bytes through array_snap_wild.
	 * Mirrors the regime add_object() established
	 * (b677185d752496ac7ee7751c66e86f432e108c54) and the read-side
	 * companion in get_random_object_versioned()
	 * (2c5d84e5d67b7e843ceb0a0ed42f0a996568caa9).  array_generation
	 * is intentionally not snapshotted: this function does not read
	 * it, and the OBJ_LOCAL teardown bump below stays a RELEASE RMW
	 * to preserve the existing pairing with validate_object_handle().
	 *
	 * head->array is never reseated mid-teardown -- only add_object()'s
	 * OBJ_LOCAL grow branch reseats it, and that path does not run
	 * concurrently with destroy_objects() (the OBJ_GLOBAL caller
	 * holds objlock; OBJ_LOCAL is single-child).  array_snap therefore
	 * remains the live array pointer for the entire loop and the
	 * post-loop free()/memset.
	 */
	n_snap = __atomic_load_n(&head->num_entries, __ATOMIC_ACQUIRE);
	cap_snap = head->array_capacity;
	array_snap = head->array;

	if (n_snap == 0)
		return;

	if (array_snap == NULL)
		return;

	/*
	 * OBJHEAD_SANE_LIMIT bail mirrors add_object()'s entry guard.  A
	 * snapshot capacity above the 64K ceiling can only have come
	 * from a wild stomp; acting on it would let the post-loop memset
	 * write (cap_snap * 8) bytes past the real allocation.
	 */
	if (cap_snap > OBJHEAD_SANE_LIMIT) {
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (n_snap > cap_snap) {
		__atomic_add_fetch(&shm->stats.local_obj_num_entries_corrupted,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Drain the array via repeated array_snap[0] destroy.
	 * __destroy_object() does swap-with-last on the parallel array,
	 * so consuming the front slot each time pulls a fresh entry into
	 * slot 0 until num_entries reaches 0.  Use n_snap as the loop
	 * bound so a sibling stomp re-bumping head->num_entries cannot
	 * extend the drain past the entries we counted at snapshot
	 * time. */
	while (n_snap > 0) {
		struct object *obj = array_snap[0];

		if (obj == NULL) {
			/* Shouldn't happen — num_entries said it was live —
			 * but guard against a torn state rather than
			 * looping forever. */
			head->num_entries--;
			n_snap--;
			continue;
		}
		prev_n = head->num_entries;
		__destroy_object(obj, scope, type, false);
		if (head->num_entries == prev_n && array_snap[0] == obj) {
			/* __destroy_object early-returned without making progress —
			 * obj has corrupt array_idx invariant.  Skip past it the
			 * same way we skip a torn NULL slot, otherwise we spin
			 * forever at parent shutdown blocking process reaping. */
			array_snap[0] = NULL;
			head->num_entries--;
		}
		n_snap--;
	}

	/* Only free private-heap arrays (OBJ_LOCAL).  OBJ_GLOBAL arrays
	 * were allocated with alloc_shared() and cannot be freed. */
	if (scope == OBJ_LOCAL) {
		free(array_snap);
		head->array = NULL;
		head->array_capacity = 0;
		/*
		 * Bump the generation so any handle still snapshotted from
		 * the just-freed buffer fails validation rather than indexing
		 * back into a libc-reclaimed chunk.
		 */
		__atomic_add_fetch(&head->array_generation, 1,
				   __ATOMIC_RELEASE);
	} else {
		/* Zero out the shared array for reuse.  cap_snap rather than
		 * a fresh head->array_capacity re-load: a sibling stomp on
		 * the capacity field landing between the entry sanity check
		 * and this memset would otherwise size the zero-out off the
		 * post-stomp wild value through the snapshot array pointer. */
		memset(array_snap, 0, cap_snap * sizeof(struct object *));
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
	case OBJ_FD_KVM_SYSTEM:	obj->kvmsysobj.fd = fd; break;
	case OBJ_FD_KVM_VM:	obj->kvmvmobj.fd = fd; break;
	case OBJ_FD_KVM_VCPU:	obj->kvmvcpuobj.fd = fd; break;
	default:		break;
	}
}

/*
 * Look up the obj that owns a given fd in the per-child OBJ_LOCAL pool of
 * one type.  Used by the generic post-hook to detect fds that a syscall-
 * specific post handler already registered, so we don't double-track them.
 *
 * O(1) probe through the per-objhead hash maintained by add_object() and
 * __destroy_object().  The previous implementation walked head->array
 * linearly, which on the syscall hot path cost one cache line per slot;
 * the hash collapses that into a single keyed lookup.  The hash is lazily
 * allocated on the first fd-typed insert, so an empty pool's lookup short-
 * circuits via the head->fd_hash == NULL check inside local_fd_hash_lookup
 * with no allocation pressure.
 */
struct object *find_local_object_by_fd(enum objecttype type, int fd)
{
	struct objhead *head;

	if (fd < 0)
		return NULL;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->num_entries == 0)
		return NULL;

	return local_fd_hash_lookup(head, fd);
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
	case OBJ_FD_KVM_SYSTEM:	return obj->kvmsysobj.fd;
	case OBJ_FD_KVM_VM:	return obj->kvmvmobj.fd;
	case OBJ_FD_KVM_VCPU:	return obj->kvmvcpuobj.fd;
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

static void __prune_objects(struct childdata *child, enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int snapshot, expected_kills, i;

	head = &child->objects[type];

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	if (head->array == NULL)
		return;

	/* Direct random-victim sampling.  The old form walked all N slots
	 * and rolled ONE_IN(10) per slot -- ~N rand() calls and N branches
	 * to perform ~N/10 destroys.  Pick expected_kills victims directly:
	 * ~N/10 rand() calls and N/10 branches for the same eviction rate.
	 *
	 * snapshot is taken once: destroy_object() decrements num_entries
	 * via swap-with-last, but we sample over the original index space.
	 * Slots beyond the shrunken num_entries are NULLed by
	 * __destroy_object, so the obj == NULL skip absorbs them.  When a
	 * swap lands a previously-tail entry into a not-yet-picked slot,
	 * that resident is statistically equivalent to having been picked
	 * directly -- so the old reverse-walk invariant (each live entry
	 * visited exactly once) is no longer load-bearing.
	 *
	 * Duplicate picks land on the same idx with probability
	 * ~expected_kills/snapshot (~10%); a duplicate finds NULL on the
	 * second visit and is silently skipped. */
	snapshot = head->num_entries;
	expected_kills = snapshot / 10U;
	if (expected_kills == 0)
		expected_kills = 1U;

	for (i = 0; i < expected_kills; i++) {
		unsigned int idx = rand() % snapshot;
		struct object *obj = head->array[idx];

		if (obj == NULL)
			continue;
		destroy_object(obj, scope, type);
	}
}

void prune_objects(void)
{
	struct childdata *child;
	unsigned int i;

	/* We don't want to over-prune things and growing a little
	 * bit past the ->max is fine, we'll clean it up next time.
	 */
	if (!(ONE_IN(10)))
		return;

	/* Resolve the per-child object pool once.  Without this hoist,
	 * each __prune_objects() call would re-enter get_objhead() ->
	 * this_child() (a getpid + cache probe) for every one of the
	 * MAX_OBJECT_TYPES iterations -- a wasted lookup per type.
	 */
	child = this_child();
	if (child == NULL)
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		__prune_objects(child, i, OBJ_LOCAL);
		// For now, we're only pruning local objects.
		// __prune_objects(child, i, OBJ_GLOBAL);
	}
}
