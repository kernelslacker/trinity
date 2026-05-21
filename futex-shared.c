/*
 * Cross-child shared futex word pool.
 *
 * Each entry's obj wrapper lives in the parent's private heap
 * (alloc_object()), but the futex WORD itself lives in a single
 * shared mapping allocated via alloc_shared() before fork.  Every
 * obj's sharedfutexobj.word points into that shared region, so
 * &word[i] is the same virtual address in every child and a pair
 * of children passing it to FUTEX_WAIT / FUTEX_WAKE actually
 * exercises cross-task wake/wait -- which the existing OBJ_FUTEX
 * pool (whose word is per-child private-COW) cannot reach.
 *
 * Keeping the obj wrapper in private heap preserves the structural
 * fix from d7836fef66c8 ("objects: remove shm-resident OBJ_GLOBAL
 * pool and snapshot defences"): sibling writes can no longer alias
 * objhead / slot-version metadata and steer derefs past the live
 * allocation.  Only the value-only futex word -- whose racy
 * contents are the racy-by-design contract of this pool -- crosses
 * into shared memory.
 *
 * The pool is small and fixed: NR_SHARED_FUTEX_WORDS entries, sized
 * to concentrate contention across many children onto the same
 * handful of keys.  Larger would dilute the cross-child collisions;
 * smaller would make the picker biased toward whichever entry the
 * rand() landed on first.  All entries are populated by the parent
 * in create_shared_futex_pool() and never destroyed.  Children only
 * ever read the obj pointers via the lockless reader in
 * get_random_object().
 */

#include <stdint.h>
#include <string.h>
#include "futex.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

#define NR_SHARED_FUTEX_WORDS 32

static uint32_t *shared_futex_words;

static void dump_shared_futex(struct object *obj, enum obj_scope scope)
{
	output(0, "shared-futex: word=%x scope=%d\n",
	       obj->sharedfutexobj.word ? *obj->sharedfutexobj.word : 0, scope);
}

static void create_shared_futex_pool(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FUTEX_SHARED);
	head->dump = dump_shared_futex;

	shared_futex_words = alloc_shared(NR_SHARED_FUTEX_WORDS * sizeof(uint32_t));
	if (shared_futex_words == NULL)
		return;	/* alloc_shared logs its own failure */

	/* alloc_shared poisons the mapping with random bytes to expose
	 * uninitialised reads; zero every slot so each starts at the
	 * canonical "unlocked, unowned" value for both regular and PI
	 * futex ops.  Without this, FUTEX_WAIT hits EAGAIN and PI ops
	 * see bogus owner state before any cross-child contention can
	 * actually occur.
	 */
	memset(shared_futex_words, 0, NR_SHARED_FUTEX_WORDS * sizeof(uint32_t));

	for (i = 0; i < NR_SHARED_FUTEX_WORDS; i++) {
		struct object *obj = alloc_object();

		if (obj == NULL)
			break;

		obj->sharedfutexobj.word = &shared_futex_words[i];
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

	return obj->sharedfutexobj.word;
}

REG_GLOBAL_OBJ(shared_futex_pool, create_shared_futex_pool);
