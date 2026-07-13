/*
 * Per-(nr, do32) opaque-blob content corpus.
 *
 * See include/blob_corpus.h for the per-mode contract.  This TU is
 * the storage backend; the parse / wire-up sites are
 *   - blob_fill()                      (args/pools/blob_mutator.c)
 *   - minicorpus_save_with_reason()    (persist/minicorpus.c)
 *   - generate_syscall_args()          (args/generate-args.c)
 *   - init_shm_publish_and_subsystems()(utils/shm.c)
 *
 * Storage: a single fixed-capacity flat table of BLOB_CORPUS_SLOTS
 * entries, each holding up to BLOB_CORPUS_MAX_LEN bytes plus a
 * (nr, do32) key.  A per-table lock serialises stores and evictions;
 * lookups take a read-only snapshot under the same lock (short scan,
 * bounded memcpy).
 *
 * Eviction: FIFO via a monotonic write cursor.  A same-key store
 * overwrites the existing slot (last-writer-wins) so a productive
 * key doesn't burn multiple slots; a new-key store lands in the next
 * cursor slot, evicting the oldest entry there.  No LRU, no scoring
 * -- the productivity gate is on the CALLER (minicorpus_save_with_
 * reason() only promotes when its own admission filter passed) so a
 * scoring pass here would be redundant.
 *
 * RNG discipline: none.  This module makes no random draws -- the
 * pick is deterministic (first same-key match) so a fixed-seed dry
 * run remains reproducible across the corpus retrieval path.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blob_corpus.h"
#include "debug.h"
#include "locks.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

struct blob_corpus_entry {
	unsigned char bytes[BLOB_CORPUS_MAX_LEN];
	uint32_t len;			/* 0 == slot empty */
	uint16_t nr;
	uint8_t  do32;
	uint8_t  pad;
};

struct blob_corpus_shared {
	lock_t lock;
	uint32_t head;			/* next write slot (mod BLOB_CORPUS_SLOTS) */
	uint32_t pad;
	struct blob_corpus_entry slots[BLOB_CORPUS_SLOTS];
};

static struct blob_corpus_shared *blob_corpus_shm;

/*
 * Pending stash lives per-process.  A child owns one copy inherited
 * COW; it's never written from a sibling child.  The array is small
 * enough (6 * BLOB_CORPUS_MAX_LEN = 24 KiB) that it fits comfortably
 * in the child's already-COWed pages -- the whole slab is touched
 * every dispatch by the clear+stash pair so no lazy-fault surprise.
 */
struct blob_corpus_pending {
	unsigned char bytes[BLOB_CORPUS_MAX_LEN];
	uint32_t len;
	uint16_t nr;
	uint8_t  do32;
	uint8_t  used;
};

static struct blob_corpus_pending pending[BLOB_CORPUS_PENDING_MAX];
static unsigned int pending_count;

void blob_corpus_init(void)
{
	blob_corpus_shm = alloc_shared_pool(sizeof(struct blob_corpus_shared));
	if (blob_corpus_shm == NULL)
		return;
	memset(blob_corpus_shm, 0, sizeof(*blob_corpus_shm));

	output(0, "KCOV: blob-corpus allocated (%lu KB, %u slots, %u B/slot)\n",
	       (unsigned long) sizeof(struct blob_corpus_shared) / 1024u,
	       BLOB_CORPUS_SLOTS, BLOB_CORPUS_MAX_LEN);
}

bool blob_corpus_try_get_base(unsigned int nr, bool do32,
			      unsigned char *buf, size_t len)
{
	unsigned int i;
	bool hit = false;

	if (blob_corpus_shm == NULL || buf == NULL || len == 0)
		return false;
	if (nr >= MAX_NR_SYSCALL)
		return false;

	lock(&blob_corpus_shm->lock);
	for (i = 0; i < BLOB_CORPUS_SLOTS; i++) {
		struct blob_corpus_entry *e = &blob_corpus_shm->slots[i];
		size_t copy;

		if (e->len == 0)
			continue;
		if (e->nr != (uint16_t) nr)
			continue;
		if ((bool) e->do32 != do32)
			continue;

		copy = (size_t) e->len;
		if (copy > BLOB_CORPUS_MAX_LEN)
			copy = BLOB_CORPUS_MAX_LEN;
		if (copy > len)
			copy = len;
		memcpy(buf, e->bytes, copy);
		hit = true;
		break;
	}
	unlock(&blob_corpus_shm->lock);

	if (hit)
		__atomic_fetch_add(&shm->stats.blob_base_from_corpus, 1UL,
				   __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.blob_base_from_random, 1UL,
				   __ATOMIC_RELAXED);
	return hit;
}

void blob_corpus_stash_pending(unsigned int nr, bool do32,
			       const unsigned char *buf, size_t len)
{
	struct blob_corpus_pending *slot = NULL;
	unsigned int i;
	size_t copy;

	if (buf == NULL || len == 0)
		return;
	if (nr >= MAX_NR_SYSCALL)
		return;

	/* Overwrite an existing pending stash for the same key so a
	 * second ARG_BUF_SIZED draw for the same (nr, do32) inside one
	 * dispatch doesn't burn two slots. */
	for (i = 0; i < pending_count; i++) {
		if (pending[i].used &&
		    pending[i].nr == (uint16_t) nr &&
		    (bool) pending[i].do32 == do32) {
			slot = &pending[i];
			break;
		}
	}

	if (slot == NULL) {
		if (pending_count >= BLOB_CORPUS_PENDING_MAX)
			return;
		slot = &pending[pending_count++];
	}

	copy = len;
	if (copy > BLOB_CORPUS_MAX_LEN)
		copy = BLOB_CORPUS_MAX_LEN;
	memcpy(slot->bytes, buf, copy);
	slot->len = (uint32_t) copy;
	slot->nr = (uint16_t) nr;
	slot->do32 = do32 ? 1u : 0u;
	slot->used = 1u;
}

void blob_corpus_promote_pending(void)
{
	unsigned int i;

	if (blob_corpus_shm == NULL || pending_count == 0)
		return;

	lock(&blob_corpus_shm->lock);
	for (i = 0; i < pending_count; i++) {
		struct blob_corpus_pending *p = &pending[i];
		struct blob_corpus_entry *dst = NULL;
		unsigned int j;

		if (!p->used || p->len == 0)
			continue;

		/* Same-key hit inside the table: overwrite in place. */
		for (j = 0; j < BLOB_CORPUS_SLOTS; j++) {
			struct blob_corpus_entry *e =
				&blob_corpus_shm->slots[j];
			if (e->len == 0)
				continue;
			if (e->nr == p->nr && e->do32 == p->do32) {
				dst = e;
				break;
			}
		}

		if (dst == NULL) {
			/* Free slot preferred, else FIFO cursor eviction. */
			for (j = 0; j < BLOB_CORPUS_SLOTS; j++) {
				if (blob_corpus_shm->slots[j].len == 0) {
					dst = &blob_corpus_shm->slots[j];
					break;
				}
			}
			if (dst == NULL) {
				uint32_t h = blob_corpus_shm->head %
					     BLOB_CORPUS_SLOTS;
				dst = &blob_corpus_shm->slots[h];
				blob_corpus_shm->head = h + 1u;
			}
		}

		memcpy(dst->bytes, p->bytes, p->len);
		dst->len = p->len;
		dst->nr = p->nr;
		dst->do32 = p->do32;
	}
	unlock(&blob_corpus_shm->lock);

	blob_corpus_clear_pending();
}

void blob_corpus_clear_pending(void)
{
	unsigned int i;

	for (i = 0; i < pending_count; i++)
		pending[i].used = 0u;
	pending_count = 0u;
}

void blob_corpus_self_check(void)
{
	/*
	 * Invariant 1: BLOB_CORPUS_PENDING_MAX must not exceed the
	 * trinity num_args cap.  A dispatch with 6 ARG_BUF_SIZED slots
	 * (theoretical worst case) must be stashable without overflow.
	 */
	if (BLOB_CORPUS_PENDING_MAX < 6u)
		BUG("BLOB_CORPUS_PENDING_MAX below trinity num_args cap");

	/*
	 * Invariant 2: BLOB_CORPUS_SLOTS non-zero and BLOB_CORPUS_MAX_LEN
	 * non-zero.  Either at zero would silently disable the whole
	 * corpus (all try_get returns false, all stash writes clamp to 0).
	 */
	if (BLOB_CORPUS_SLOTS == 0u || BLOB_CORPUS_MAX_LEN == 0u)
		BUG("blob_corpus capacity constants must be non-zero");

	/*
	 * Invariant 3: stash on len=0 or NULL buf must be a true no-op.
	 * A regression that dropped the guard would advance pending_count
	 * against a zero-length slot and hide a real subsequent stash.
	 */
	{
		unsigned int saved = pending_count;
		unsigned char dummy = 0;

		blob_corpus_stash_pending(0, false, NULL, 16);
		blob_corpus_stash_pending(0, false, &dummy, 0);
		if (pending_count != saved)
			BUG("blob_corpus_stash_pending accepted NULL/zero");
	}

	/*
	 * Invariant 4: try_get on an out-of-range nr must reject
	 * without touching the table.  A regression here would index
	 * off the end of the (nr, do32) key check.
	 */
	{
		unsigned char buf[16] = { 0 };

		if (blob_corpus_try_get_base(MAX_NR_SYSCALL + 1, false,
					     buf, sizeof(buf)))
			BUG("blob_corpus_try_get_base accepted nr >= MAX");
	}
}
