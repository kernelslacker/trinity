/*
 * Cross-child shared futex word pool.
 *
 * Existing OBJ_FUTEX entries live in the parent's private heap (via
 * alloc_object()) and are copied into per-child OBJ_LOCAL pools at
 * fork time, so each child writes to its own COW copy of the futex
 * word.  That gives us per-child contention but never crosses a child
 * boundary -- the kernel hashes futex(2) keys by virtual address, and
 * private-COW pages don't share a backing inode with siblings.
 *
 * This pool extends the OBJ_GLOBAL pattern (already used for the
 * anon-mmap / sysv-shm pools) to a non-mmap resource: a fixed pool of
 * uint32_t words allocated from the shared obj heap before fork, so
 * every child sees the SAME virtual address for any given pool entry.
 * Two children passing &pool[idx] to FUTEX_WAIT / FUTEX_WAKE now
 * actually exercise cross-task wake/wait, which the existing per-child
 * COW-private pool cannot reach.
 *
 * The pool is small and fixed: NR_SHARED_FUTEX_WORDS entries, sized to
 * concentrate contention across many children onto the same handful of
 * keys.  Larger would dilute the cross-child collisions; smaller would
 * make the picker biased toward whichever entry the rand() landed on
 * first.  All entries are populated by the parent in
 * create_shared_futex_pool() and never destroyed -- the pool is
 * frozen-in-place once init runs and freeze_global_objects() flips the
 * shared obj heap to PROT_READ.  Children only ever read the obj
 * pointers via the lockless reader in get_random_object().
 */

#include <stdint.h>
#include "futex.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

#define NR_SHARED_FUTEX_WORDS 32

static void dump_shared_futex(struct object *obj, enum obj_scope scope)
{
	output(0, "shared-futex: word=%x owner=%d scope=%d\n",
	       obj->lock.futex, obj->lock.owner_pid, scope);
}

static void create_shared_futex_pool(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FUTEX_SHARED);
	head->dump = dump_shared_futex;
	head->shared_alloc = true;

	for (i = 0; i < NR_SHARED_FUTEX_WORDS; i++) {
		struct object *obj = alloc_shared_obj(sizeof(struct object));

		if (obj == NULL)
			break;

		/*
		 * alloc_shared_obj zero-initialises the slot, so .futex and
		 * .owner_pid are already 0.  No additional setup required --
		 * a freshly-zeroed futex word is the canonical "unlocked,
		 * unowned" starting state for both regular and PI ops.
		 */
		add_object(obj, OBJ_GLOBAL, OBJ_FUTEX_SHARED);
	}

	output(0, "Reserved %u shared futex words.\n", i);
}

uint32_t * get_shared_futex_word(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_FUTEX_SHARED, OBJ_GLOBAL);
	if (obj == NULL)
		return NULL;

	return &obj->lock.futex;
}

REG_GLOBAL_OBJ(shared_futex_pool, create_shared_futex_pool);
