#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "arch.h"
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

/*
 * Parent-private OBJ_GLOBAL pool.  Populated pre-fork by every
 * REG_GLOBAL_OBJ provider via add_object(OBJ_GLOBAL); the per-child
 * snapshot in clone_global_objects_to_child() reads this array.
 * Lives in the parent's data segment, fork-COW'd into children whose
 * resolver (get_objhead) routes around it in favour of their own
 * private copy.
 */
static struct objhead parent_global_objects[MAX_OBJECT_TYPES];

/*
 * Parent-private fd->object hash and parallel compact live-fd list.
 * Same shape as the per-child snapshots; fd_hash_insert / fd_hash_remove
 * mutate these from the parent's pre-fork init and post-fork fd-event
 * drains.  Children read their own snapshots; the parent reads these
 * directly when servicing remove_object_by_fd() out of fd_event_drain().
 */
static struct fd_hash_entry parent_fd_hash[FD_HASH_SIZE];
static int parent_fd_live[FD_LIVE_MAX];
static unsigned int parent_fd_hash_count;
static unsigned int parent_fd_live_count;

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
 * Hash table mapping fd → (object, type) for O(1) lookup in the
 * parent's remove_object_by_fd().  Open-addressing with linear
 * probing.  The parent's view sits in parent_fd_hash[]; each child
 * holds an independent snapshot in child->fd_hash[] populated by
 * clone_global_objects_to_child().
 */

void fd_hash_init(void)
{
	unsigned int i;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		parent_fd_hash[i].fd = -1;
		parent_fd_hash[i].gen = 0;
	}
	parent_fd_hash_count = 0;
	/*
	 * fd_live[] entries are gated by fd_live_count, so initialising
	 * just the count is sufficient; stale slot contents past the
	 * count are never read.
	 */
	parent_fd_live_count = 0;
}

/*
 * Append fd to the parent's parallel live-fd list.  Called from
 * fd_hash_insert() after transitioning a slot from empty to occupied.
 * Single-writer (the parent); no cross-process coherence required.
 * Silently drops the entry if the cap is hit; the auditor that reads
 * via the per-child snapshot tolerates a missed fd.
 */
static void fd_live_append(int fd)
{
	unsigned int idx = parent_fd_live_count;

	if (idx >= FD_LIVE_MAX)
		return;

	parent_fd_live[idx] = fd;
	parent_fd_live_count = idx + 1;
}

/*
 * Swap-remove fd from the parent's parallel live-fd list.  Linear scan
 * over parent_fd_live[0..count); typical occupancy is a few hundred
 * entries so the cost is negligible.
 */
static void fd_live_remove(int fd)
{
	unsigned int count = parent_fd_live_count;
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (parent_fd_live[i] != fd)
			continue;

		if (i != count - 1)
			parent_fd_live[i] = parent_fd_live[count - 1];
		parent_fd_live_count = count - 1;
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
 * displaced entries: the entry's identity is unchanged, only its slot.
 */
static void fd_hash_reinsert(int fd, struct object *obj, enum objecttype type,
			     uint32_t gen)
{
	unsigned int slot;
	unsigned int probe;

	slot = fd_hash_slot(fd);
	for (probe = 0; probe < FD_HASH_SIZE; probe++) {
		if (parent_fd_hash[slot].fd == -1)
			break;
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	if (probe == FD_HASH_SIZE) {
		shm->stats.fd_hash_reinsert_dropped++;
		outputerr("fd_hash_reinsert: table full, dropping fd %d\n", fd);
		return;
	}

	parent_fd_hash[slot].obj = obj;
	parent_fd_hash[slot].type = type;
	parent_fd_hash[slot].gen = gen;
	parent_fd_hash[slot].fd = fd;
}

bool fd_hash_insert(int fd, struct object *obj, enum objecttype type)
{
	unsigned int slot;

	if (fd < 0)
		return true;

	if (parent_fd_hash_count >= FD_HASH_SIZE)
		return false;

	slot = fd_hash_slot(fd);
	while (parent_fd_hash[slot].fd != -1 && parent_fd_hash[slot].fd != fd)
		slot = (slot + 1) & (FD_HASH_SIZE - 1);

	if (parent_fd_hash[slot].fd == -1) {
		parent_fd_hash_count++;
		fd_live_append(fd);
	}

	parent_fd_hash[slot].obj = obj;
	parent_fd_hash[slot].type = type;
	parent_fd_hash[slot].gen++;
	parent_fd_hash[slot].fd = fd;
	return true;
}

void fd_hash_remove(int fd)
{
	unsigned int slot, next, i;

	if (fd < 0)
		return;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (parent_fd_hash[slot].fd == -1)
			return;
		if (parent_fd_hash[slot].fd == fd) {
			parent_fd_hash[slot].gen++;
			parent_fd_hash[slot].fd = -1;
			fd_live_remove(fd);
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (parent_fd_hash[next].fd != -1) {
				struct fd_hash_entry displaced = parent_fd_hash[next];
				parent_fd_hash[next].fd = -1;
				fd_hash_reinsert(displaced.fd, displaced.obj,
						 displaced.type, displaced.gen);
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			parent_fd_hash_count--;
			return;
		}
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
}

struct fd_hash_entry *fd_hash_lookup(int fd)
{
	struct fd_hash_entry *table;
	unsigned int slot, i;

	if (fd < 0)
		return NULL;

	/*
	 * Children resolve against their fork-time snapshot of the
	 * parent's table; the parent resolves against its own writer
	 * view.  Fall back to the parent view in the early init_child
	 * window where the snapshot has not yet been allocated.
	 */
	if (getpid() == mainpid) {
		table = parent_fd_hash;
	} else {
		struct childdata *child = this_child();

		table = (child != NULL && child->fd_hash != NULL)
			? child->fd_hash : parent_fd_hash;
	}

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		int slot_fd = table[slot].fd;

		if (slot_fd == -1)
			return NULL;
		if (slot_fd == fd)
			return &table[slot];
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
	 * as the pre-hash linear walk missing the entry.  Bump a stat so
	 * the silent drop is observable in the end-of-run summary.
	 */
	__atomic_add_fetch(&shm->stats.local_fd_hash_insert_dropped, 1,
			   __ATOMIC_RELAXED);
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
 * Every obj struct comes from alloc_object() (zmalloc) and lives in
 * the allocating process's private heap.  OBJ_GLOBAL pools are
 * populated pre-fork in the parent, then fork-COW'd into children's
 * snapshots; OBJ_LOCAL pools are wholly per-child.  No path crosses
 * the shared mapping for obj storage.
 */
struct object * alloc_object(void)
{
	return zmalloc(sizeof(struct object));
}

/*
 * Release an obj struct.  Routed through deferred_free_enqueue()
 * rather than free()'d immediately so a stale slot pointer that
 * survived past __destroy_object() lands on a chunk with a 5-50
 * syscall TTL (effective 80-800 with DEFERRED_TICK_BATCH) instead
 * of glibc-reclaimed memory: get_map() and friends read &obj->map
 * after taking the slot pointer out of head->array, and the arg-gen
 * path that invoked get_map() can hold the pointer across the
 * window in which the slot's owner destroys the obj.
 *
 * Zero the chunk before handing it to the deferred-free ring so a
 * post-destroy read (via a stale slot pointer) trips the size==0
 * band of consumer sanity checks instead of dereferencing an obj
 * whose name string or mmap pointer was already torn down by the
 * destructor.
 */
static void release_obj(struct object *obj,
			enum obj_scope scope __attribute__((unused)),
			enum objecttype type __attribute__((unused)))
{
	memset(obj, 0, sizeof(*obj));
	deferred_free_enqueue(obj);
}

struct objhead * get_objhead(enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;

	if (scope == OBJ_GLOBAL) {
		/*
		 * Children resolve against their fork-time snapshot of the
		 * parent's pre-fork pool (allocated by
		 * clone_global_objects_to_child).  The parent's writer view
		 * lives in parent_global_objects[] in this file.  Fall back
		 * to the parent view in the early init_child window before
		 * the clone runs, so any incidental lookup still resolves.
		 */
		if (getpid() != mainpid) {
			struct childdata *child = this_child();

			if (child != NULL && child->global_objects != NULL)
				return &child->global_objects[type];
		}
		head = &parent_global_objects[type];
	} else {
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
 * num_entries and array into the caller's state struct so the loop
 * body operates on a per-invocation hoist rather than re-loading
 * head fields on every iteration.  No cross-process coherence is
 * required post-Stage-5 — every pool lives in the iterating
 * process's private heap.
 */
void __for_each_obj_init(struct objhead *head,
			 struct __for_each_obj_state *s)
{
	s->n_snap = head->num_entries;
	s->array_snap = head->array;

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
	unsigned int n, cap;
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
	 * happened to be positive.
	 */
	if (is_fd_type(type)) {
		int fd = fd_from_object(obj, type);

		if (fd < 0 || fd >= (1 << 20)) {
			outputerr("add_object: rejecting out-of-bound fd=%d "
				  "type=%u caller=%s\n", fd, type,
				  pc_to_string(__builtin_return_address(0),
					       pcbuf, sizeof(pcbuf)));
			post_handler_corrupt_ptr_bump_site(NULL,
							   __builtin_return_address(0),
							   "add_object:fd");
			release_obj(obj, scope, type);
			return;
		}
	}

	/*
	 * OBJ_GLOBAL is pre-fork-only by construction: every provider
	 * REG_GLOBAL_OBJ init runs in the parent before fork_children(),
	 * and the per-child snapshot is taken at fork time.  A post-fork
	 * child that reached add_object(OBJ_GLOBAL) would mutate only its
	 * private copy with no benefit, so route the call to nowhere.
	 */
	if (scope == OBJ_GLOBAL && getpid() != mainpid) {
		release_obj(obj, scope, type);
		return;
	}

	head = get_objhead(scope, type);
	if (head == NULL) {
		release_obj(obj, scope, type);
		return;
	}

	n = head->num_entries;
	cap = head->array_capacity;

	if (scope == OBJ_GLOBAL) {
		if (n >= cap) {
			/*
			 * Grow on the parent's private heap.  No concurrent
			 * reader to coordinate with -- children see a snapshot
			 * pinned at fork time, so a post-fork grow in the
			 * parent is invisible to them and a pre-fork grow has
			 * no readers yet.
			 */
			struct object **newarray;
			unsigned int newcap = cap ? cap * 2 : 16;

			if (cap > UINT_MAX / 2) {
				outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
					  type, n, cap);
				if (is_fd_type(type)) {
					int fd = fd_from_object(obj, type);
					if (fd >= 0)
						close(fd);
				}
				release_obj(obj, scope, type);
				return;
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
			if (head->array != NULL && cap > 0)
				memcpy(newarray, head->array,
				       cap * sizeof(struct object *));
			free(head->array);
			head->array = newarray;
			head->array_capacity = newcap;
			cap = newcap;
		}
	} else if (n >= cap) {
		/*
		 * OBJ_LOCAL grow on the owning child's private heap.  Use
		 * the same allocate-copy-defer-free shape that closed the
		 * UAF on the array container reachable through cached
		 * head->array reads in the arg-gen path: the deferred-free
		 * ring gives the old chunk a 5-50 syscall (effective
		 * 80-800 with DEFERRED_TICK_BATCH) TTL, far longer than
		 * any in-flight reader's window.  Same hazard shape as
		 * the obj-struct fix (3a8d344f0f73, 546f576fae24).
		 */
		struct object **newarray;
		struct object **oldarray;
		unsigned int newcap = cap ? cap * 2 : 16;

		if (cap > UINT_MAX / 2) {
			outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
				  type, n, cap);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			release_obj(obj, scope, type);
			return;
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
		oldarray = head->array;
		if (oldarray != NULL && cap > 0)
			memcpy(newarray, oldarray, cap * sizeof(struct object *));
		head->array = newarray;
		head->array_capacity = newcap;
		cap = newcap;
		if (oldarray != NULL)
			deferred_free_enqueue(oldarray);
	}

	head->array[n] = obj;
	obj->array_idx = n;
	head->num_entries = n + 1;

	/* Mirror the parent-side global fd hash for OBJ_LOCAL fd-typed
	 * pools so find_local_object_by_fd() resolves in O(1).  The buffer
	 * is lazily allocated by local_fd_hash_insert() on first use. */
	if (scope == OBJ_LOCAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);

		if (fd >= 0)
			local_fd_hash_insert(head, fd, obj);
	}

	/* Track global fd-type objects in the parent's fd_hash so
	 * remove_object_by_fd() and the per-child snapshot can resolve
	 * them by fd. */
	if (scope == OBJ_GLOBAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);

		if (!fd_hash_insert(fd, obj, type)) {
			outputerr("add_object: fd hash full for type %u, dropping fd %d\n",
				  type, fd);
			head->num_entries = n;
			head->array[n] = NULL;
			if (fd >= 0)
				close(fd);
			release_obj(obj, scope, type);
			return;
		}
	}

	/* Per-object dumps are debug noise at startup (NFUTEXES = 5 * cpus
	 * identical "futex: 0 owner:0 scope:1" lines, etc.).  Gate on -vv. */
	if (head->dump != NULL && verbosity > 2)
		head->dump(obj, scope);

	/* if we just added something to a child list, check
	 * to see if we need to do some pruning. */
	if (scope == OBJ_LOCAL)
		prune_objects();
}

/*
 * Lazy per-child alloc for the OBJ_LOCAL objhead array, in the owning
 * child's private heap.  Runs from init_child() after fork, so the
 * allocation lands in the child's own address space and is unreachable
 * from any other process.  Failure leaves child->objects == NULL and
 * the OBJ_LOCAL path inert for this child -- callers must NULL-check
 * before touching child->objects.
 */
static void local_objects_alloc(struct childdata *child)
{
	if (child == NULL || child->objects != NULL)
		return;

	child->objects = zmalloc(sizeof(struct objhead) * MAX_OBJECT_TYPES);
}

void init_object_lists(enum obj_scope scope, struct childdata *child)
{
	unsigned int i;

	if (scope == OBJ_LOCAL) {
		if (child == NULL)
			return;
		/*
		 * struct childdata lives in alloc_shared() memory, which
		 * __alloc_shared() poisons with random bytes to expose
		 * uninitialised reads.  The objects pointer therefore
		 * arrives at first init holding a wild value, not NULL --
		 * local_objects_alloc()'s "skip if non-NULL" guard would
		 * then leave child->objects pointing at the poison.  Zero
		 * the field before the alloc to neutralise the poison.
		 */
		child->objects = NULL;
		local_objects_alloc(child);
		if (child->objects == NULL)
			return;
	}

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		if (scope == OBJ_GLOBAL)
			head = &parent_global_objects[i];
		else
			head = &child->objects[i];

		head->num_entries = 0;
		head->array = NULL;
		head->array_capacity = 0;
		head->fd_hash = NULL;

		/*
		 * child lists can inherit properties from global lists.
		 */
		if (scope == OBJ_LOCAL) {
			struct objhead *globalhead;
			globalhead = &parent_global_objects[i];
			head->max_entries = globalhead->max_entries;
			head->destroy = globalhead->destroy;
			head->dump = globalhead->dump;
		}
	}
}

/*
 * Lift the parent's pre-fork OBJ_GLOBAL pool into the owning child's
 * private heap.  The parent populates shm->global_objects[] in
 * init_global_objects() before fork; each child then runs this routine
 * from init_child() to take a shallow snapshot of the head fields and
 * the live slot pointers into the child's own zmalloc'd backing.
 *
 * Bookkeeping only.  The obj structs themselves (and the kernel-side
 * fds / mmap regions they describe) are reached via fork's table dup
 * and the existing MAP_SHARED obj heap that backs the parent's pool —
 * snapshotting the directory of pointers is sufficient for the child
 * to pick, dereference and locally destroy entries without crossing
 * back into shared memory.
 *
 * Per-type array allocation is sized to the parent's current
 * num_entries rather than the pre-fork GLOBAL_OBJ_MAX_CAPACITY ceiling
 * so an empty pool costs zero heap bytes here and a small pool costs
 * exactly num_entries pointers, keeping the per-child memory cost
 * proportional to the live working set.
 *
 * NULL on out-of-memory leaves child->global_objects unset so the
 * get_objhead() fallback to shm->global_objects[] is selected for
 * this child's lifetime; the OBJ_GLOBAL path degrades to its pre-
 * lift behaviour rather than crashing.
 */
void clone_global_objects_to_child(struct childdata *child)
{
	unsigned int i;

	if (child == NULL)
		return;

	child->global_objects = NULL;
	child->fd_hash = NULL;
	child->fd_live = NULL;
	child->fd_hash_count = 0;
	child->fd_live_count = 0;

	child->global_objects = zmalloc(sizeof(struct objhead) * MAX_OBJECT_TYPES);
	if (child->global_objects == NULL)
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *src = &parent_global_objects[i];
		struct objhead *dst = &child->global_objects[i];
		unsigned int n = src->num_entries;

		dst->max_entries = src->max_entries;
		dst->destroy = src->destroy;
		dst->dump = src->dump;
		dst->num_entries = n;
		dst->array_capacity = n;
		dst->fd_hash = NULL;
		dst->array = NULL;

		if (n == 0 || src->array == NULL)
			continue;

		dst->array = zmalloc(n * sizeof(struct object *));
		if (dst->array == NULL) {
			dst->array_capacity = 0;
			dst->num_entries = 0;
			continue;
		}
		memcpy(dst->array, src->array, n * sizeof(struct object *));
	}

	child->fd_hash = zmalloc(FD_HASH_SIZE * sizeof(struct fd_hash_entry));
	if (child->fd_hash != NULL) {
		memcpy(child->fd_hash, parent_fd_hash,
		       FD_HASH_SIZE * sizeof(struct fd_hash_entry));
		child->fd_hash_count = parent_fd_hash_count;
	}

	child->fd_live = zmalloc(FD_LIVE_MAX * sizeof(int));
	if (child->fd_live != NULL) {
		memcpy(child->fd_live, parent_fd_live, FD_LIVE_MAX * sizeof(int));
		child->fd_live_count = parent_fd_live_count;
	}
}

/*
 * Pick a random object from a pool.  Single-writer per pool, single
 * reader per call (the owning process) -- no locks, no version
 * counters, no snapshot defences.  Children read their fork-time
 * snapshot of the parent's pre-fork OBJ_GLOBAL pool; OBJ_LOCAL pools
 * are wholly per-child.  An empty pool returns NULL.
 */
struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int n;

	head = get_objhead(scope, type);
	if (head == NULL)
		return NULL;

	n = head->num_entries;
	if (n == 0 || head->array == NULL)
		return NULL;

	return head->array[rand() % n];
}

bool objects_empty(enum objecttype type)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, type);

	if (head == NULL)
		return true;
	return head->num_entries == 0;
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
	unsigned int idx, n, last;

	head = get_objhead(scope, type);
	if (head == NULL)
		return;
	n = head->num_entries;
	if (n == 0 || head->array == NULL)
		return;

	/*
	 * obj->array_idx is the slot we're about to swap-with-last and
	 * NULL.  add_object() set it once at insertion and the swap branch
	 * maintains it on every reshuffle -- the canonical invariant is
	 * head->array[obj->array_idx] == obj.
	 *
	 * Validate the invariant up front.  On mismatch the obj may not
	 * even belong to this pool any more (a stale slot pointer that
	 * survived deferred_free's TTL and got handed back through
	 * get_random_object()).  Drop the destroy cleanly rather than
	 * touching the wrong slot.
	 */
	idx = obj->array_idx;
	if (idx >= n || head->array[idx] != obj) {
		__atomic_add_fetch(&shm->stats.destroy_object_idx_corrupt, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	/* Swap-with-last removal from the parallel array */
	last = n - 1;
	if (idx != last) {
		head->array[idx] = head->array[last];
		if (head->array[idx] != NULL)
			head->array[idx]->array_idx = idx;
	}
	head->array[last] = NULL;
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
	if (scope == OBJ_GLOBAL && getpid() != mainpid)
		return;

	__destroy_object(obj, scope, type, false);
}

/*
 * Destroy a whole list of objects.
 */
static void destroy_objects(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;

	head = get_objhead(scope, type);
	if (head == NULL || head->array == NULL)
		return;

	/* Drain the array via repeated array[0] destroy.
	 * __destroy_object() does swap-with-last on the parallel array,
	 * so consuming the front slot each time pulls a fresh entry into
	 * slot 0 until num_entries reaches 0. */
	while (head->num_entries > 0) {
		struct object *obj = head->array[0];
		unsigned int prev_n;

		if (obj == NULL) {
			head->num_entries--;
			continue;
		}
		prev_n = head->num_entries;
		__destroy_object(obj, scope, type, false);
		if (head->num_entries == prev_n && head->array[0] == obj) {
			/* corrupt array_idx invariant -- skip past it. */
			head->array[0] = NULL;
			head->num_entries--;
		}
	}

	free(head->array);
	head->array = NULL;
	head->array_capacity = 0;
}

/* Destroy all global objects on exit. */
void destroy_global_objects(void)
{
	unsigned int i;

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
 * Look up an fd in the parent's hash table and destroy its object.
 * Called from fd_event_drain() after a child reported a close.
 *
 * The child closed its own copy of the fd (children have independent
 * fd tables after fork).  The parent's copy is still open and must be
 * closed here -- pass already_closed=false so the destructor runs
 * close() on the parent's fd.  Without this, every child close event
 * leaks one fd in the parent, leading to fd exhaustion.
 */
void remove_object_by_fd(int fd)
{
	struct fd_hash_entry *entry;
	struct object *obj;
	enum objecttype type;

	if (getpid() != mainpid)
		return;

	entry = fd_hash_lookup(fd);
	if (entry == NULL)
		return;

	obj = entry->obj;
	type = entry->type;

	__atomic_add_fetch(&shm->stats.fd_closed_tracked, 1, __ATOMIC_RELAXED);
	__destroy_object(obj, OBJ_GLOBAL, type, false);
}

static void __prune_objects(struct childdata *child, enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int n, expected_kills, i;
	struct object **array;

	head = &child->objects[type];

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	array = head->array;
	if (array == NULL)
		return;

	/* Direct random-victim sampling.  The old form walked all N slots
	 * and rolled ONE_IN(10) per slot -- ~N rand() calls and N branches
	 * to perform ~N/10 destroys.  Pick expected_kills victims directly:
	 * ~N/10 rand() calls and N/10 branches for the same eviction rate.
	 *
	 * Take n once: destroy_object() decrements num_entries via swap-
	 * with-last, but we sample over the original index space.  Slots
	 * beyond the shrunken num_entries are NULLed by __destroy_object,
	 * so the obj == NULL skip absorbs them.  Duplicate picks land on
	 * the same idx with probability ~expected_kills/n (~10%); a
	 * duplicate finds NULL on the second visit and is silently skipped.
	 */
	n = head->num_entries;

	expected_kills = n / 10U;
	if (expected_kills == 0)
		expected_kills = 1U;

	for (i = 0; i < expected_kills; i++) {
		unsigned int idx = rand() % n;
		struct object *obj = array[idx];

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
