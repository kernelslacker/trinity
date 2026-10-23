/*
 * Cross-child shared futex word pool: the word lives in one shared mapping,
 * so two children passing &word[i] to FUTEX_WAIT / FUTEX_WAKE really
 * contend, which the per-child private-COW OBJ_FUTEX pool cannot reach.
 * Only the value-only word, racy by design, is shared: the obj wrappers stay
 * in the parent's private heap so sibling writes cannot alias pool metadata.
 */

#include <stdint.h>
#include <string.h>
#include "futex.h"
#include "objects.h"
#include "shm.h"
#include "utils.h"

/* Small and fixed on purpose: contention from many children concentrates
 * on a handful of words, which a larger pool would dilute. */
#define NR_SHARED_FUTEX_WORDS 32

static uint32_t *shared_futex_words;

static void dump_shared_futex(struct object *obj, enum obj_scope scope)
{
	output(0, "shared-futex: word=%x scope=%d\n",
	       obj->sharedfutexobj.word ? *obj->sharedfutexobj.word : 0, scope);
}

/* The parent fills every entry before fork and never destroys one, so
 * children only read the obj pointers, locklessly, through
 * get_random_object(). */
static void create_shared_futex_pool(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FUTEX_SHARED);
	head->dump = dump_shared_futex;

	shared_futex_words = alloc_shared_pool(NR_SHARED_FUTEX_WORDS * sizeof(uint32_t));
	if (shared_futex_words == NULL)
		return;	/* alloc_shared_pool logs its own failure */

	/* alloc_shared_pool poisons the mapping with random bytes to expose
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
	if (!objpool_check(obj, OBJ_FUTEX_SHARED))
		return NULL;

	return obj->sharedfutexobj.word;
}

REG_GLOBAL_OBJ(shared_futex_pool, create_shared_futex_pool);
