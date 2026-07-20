#include <stdbool.h>
#include <string.h>
#include "child.h"
#include "debug.h"
#include "list.h"
#include "objects.h"
#include "objects-internal.h"
#include "pids.h"
#include "shm.h"
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
struct objhead parent_global_objects[MAX_OBJECT_TYPES];

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
 * Lift the parent's pre-fork OBJ_GLOBAL pool into the owning child's
 * private heap.  The parent populates shm->global_objects[] in
 * init_global_objects() before fork; each child then runs this routine
 * from init_child() to take a shallow snapshot of the head fields and
 * the live slot pointers into the child's own zmalloc'd backing.
 *
 * Bookkeeping only.  The obj structs come from alloc_object()
 * (zmalloc_tracked) in the parent's private heap and the OBJ_GLOBAL
 * pool is inherited by every child through fork/COW.  This routine
 * clones the directory of slot pointers into the child's own
 * zmalloc'd backing so the child can pick, dereference and locally
 * destroy entries.  No obj storage lives in shared memory.
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
		/*
		 * Carry the parent's next_slot_version into the child snapshot
		 * so any captured (obj, version) pair stashed by a consumer
		 * pre-fork continues to compare correctly against entries the
		 * child sees post-fork.  The child never adds to OBJ_GLOBAL
		 * (the mypid()!=mainpid early-return in add_object()) so the
		 * snapshot value is read-only on the child side; copying it
		 * just keeps the field self-consistent rather than starting
		 * the child's mirror at zero.
		 */
		dst->next_slot_version = src->next_slot_version;
		/*
		 * Mirror the snapshot's starting array_generation.  The child
		 * grows its own copy via add_object(OBJ_GLOBAL) never (the
		 * post-fork guard rejects every such call) so the value is
		 * effectively read-only on the child side; start it at the
		 * parent's last published value so the field is self-consistent
		 * rather than fresh-from-zero.  Any indexed-read snapshot in
		 * the child that observes a destroy_objects() teardown on this
		 * pool will see its own monotonic bump and discard.
		 */
		dst->array_generation = src->array_generation;

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

/* Destroy all global objects on exit. */
void destroy_global_objects(void)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++)
		destroy_objects(i, OBJ_GLOBAL);
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

	if (mypid() != mainpid)
		return;

	entry = fd_hash_lookup(fd);
	if (entry == NULL)
		return;

	obj = entry->obj;
	type = entry->type;

	__atomic_add_fetch(&shm->stats.fd.closed_tracked, 1, __ATOMIC_RELAXED);
	__destroy_object(obj, OBJ_GLOBAL, type, false);
}
