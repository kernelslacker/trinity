/*
 * Edge-pair tracking: (prev_syscall, curr_syscall) -> coverage data.
 *
 * Open-addressed hash table with linear probing in shared memory.
 * All updates are lock-free via atomics.  Minor races (e.g. two
 * children inserting the same pair simultaneously) are tolerable —
 * worst case we get a duplicate entry that wastes a slot.
 */

#include <stdio.h>
#include <string.h>

#include "edgepair.h"
#include "trinity.h"
#include "utils.h"

struct edgepair_shared *edgepair_shm = NULL;

void edgepair_init_global(void)
{
	/* Only allocate if KCOV is available (caller checks). */
	edgepair_shm = alloc_shared(sizeof(struct edgepair_shared));
	memset(edgepair_shm, 0, sizeof(struct edgepair_shared));

	/* Mark all slots empty. */
	for (unsigned int i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		edgepair_shm->table[i].prev_nr = EDGEPAIR_EMPTY;
		edgepair_shm->table[i].curr_nr = EDGEPAIR_EMPTY;
	}

	output(0, "KCOV: edge-pair tracking enabled (%lu KB, %u slots)\n",
		sizeof(struct edgepair_shared) / 1024,
		EDGEPAIR_TABLE_SIZE);
}

static unsigned int pair_hash(unsigned int prev, unsigned int curr)
{
	/* Simple but effective: mix both syscall numbers. */
	unsigned int h = prev * 31 + curr;
	h ^= h >> 16;
	h *= 0x45d9f3b;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
}

/*
 * Find or insert a pair in the table.  Returns pointer to the entry,
 * or NULL if the table is full in this probe window.
 */
static struct edgepair_entry *find_or_insert(unsigned int prev_nr,
					     unsigned int curr_nr)
{
	unsigned int idx = pair_hash(prev_nr, curr_nr);

	for (unsigned int probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		struct edgepair_entry *e = &edgepair_shm->table[idx];
		unsigned int slot_prev, slot_curr;

		slot_prev = __atomic_load_n(&e->prev_nr, __ATOMIC_ACQUIRE);
		slot_curr = __atomic_load_n(&e->curr_nr, __ATOMIC_RELAXED);

		/* Found existing entry for this pair. */
		if (slot_prev == prev_nr && slot_curr == curr_nr)
			return e;

		/* Empty slot — try to claim it.
		 *
		 * Store curr_nr first (relaxed), then CAS prev_nr with
		 * release ordering.  A reader that loads prev_nr with
		 * acquire and sees a non-EMPTY value is guaranteed to
		 * also see the curr_nr store, closing the window where
		 * a half-initialized entry was visible.
		 */
		if (slot_prev == EDGEPAIR_EMPTY) {
			unsigned int expected = EDGEPAIR_EMPTY;

			/* Write curr_nr before publishing via CAS. */
			__atomic_store_n(&e->curr_nr, curr_nr,
				__ATOMIC_RELAXED);

			/* CAS on prev_nr to claim the slot (release). */
			if (__atomic_compare_exchange_n(&e->prev_nr,
				&expected, prev_nr, false,
				__ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
				__atomic_fetch_add(&edgepair_shm->pairs_tracked,
					1, __ATOMIC_RELAXED);
				return e;
			}
			/* CAS failed — another child claimed it.
			 * Restore curr_nr (best effort, may be overwritten). */
			__atomic_store_n(&e->curr_nr, EDGEPAIR_EMPTY,
				__ATOMIC_RELAXED);

			/* Re-check if they inserted the same pair. */
			slot_prev = __atomic_load_n(&e->prev_nr,
				__ATOMIC_ACQUIRE);
			slot_curr = __atomic_load_n(&e->curr_nr,
				__ATOMIC_RELAXED);
			if (slot_prev == prev_nr && slot_curr == curr_nr)
				return e;
		}

		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return NULL;	/* table region full, give up */
}

void edgepair_record(unsigned int prev_nr, unsigned int curr_nr,
		     bool found_new)
{
	struct edgepair_entry *e;
	unsigned long call_nr;

	if (edgepair_shm == NULL)
		return;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return;

	call_nr = __atomic_fetch_add(&edgepair_shm->total_pair_calls,
		1, __ATOMIC_RELAXED);

	e = find_or_insert(prev_nr, curr_nr);
	if (e == NULL)
		return;

	__atomic_fetch_add(&e->total_count, 1, __ATOMIC_RELAXED);

	if (found_new) {
		__atomic_fetch_add(&e->new_edge_count, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&e->last_new_at, call_nr, __ATOMIC_RELAXED);
	}
}

static struct edgepair_entry *find_entry(unsigned int prev_nr,
					 unsigned int curr_nr)
{
	unsigned int idx = pair_hash(prev_nr, curr_nr);

	for (unsigned int probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		struct edgepair_entry *e = &edgepair_shm->table[idx];
		unsigned int slot_prev, slot_curr;

		slot_prev = __atomic_load_n(&e->prev_nr, __ATOMIC_ACQUIRE);
		if (slot_prev == EDGEPAIR_EMPTY)
			return NULL;

		slot_curr = __atomic_load_n(&e->curr_nr, __ATOMIC_RELAXED);
		if (slot_prev == prev_nr && slot_curr == curr_nr)
			return e;

		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return NULL;
}

bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr)
{
	struct edgepair_entry *e;
	unsigned long total, last;

	if (edgepair_shm == NULL)
		return false;

	e = find_entry(prev_nr, curr_nr);
	if (e == NULL)
		return false;

	/* Never found new edges — not cold, just unproductive. */
	if (__atomic_load_n(&e->new_edge_count, __ATOMIC_RELAXED) == 0)
		return false;

	total = __atomic_load_n(&edgepair_shm->total_pair_calls,
		__ATOMIC_RELAXED);
	last = __atomic_load_n(&e->last_new_at, __ATOMIC_RELAXED);

	return (total - last) > EDGEPAIR_COLD_THRESHOLD;
}

bool edgepair_is_productive(unsigned int prev_nr, unsigned int curr_nr)
{
	struct edgepair_entry *e;

	if (edgepair_shm == NULL)
		return false;

	e = find_entry(prev_nr, curr_nr);
	if (e == NULL)
		return false;

	return __atomic_load_n(&e->new_edge_count, __ATOMIC_RELAXED) > 0;
}

void edgepair_dump_to_file(const char *path)
{
	FILE *f;
	uint32_t magic = EDGEPAIR_DUMP_MAGIC;

	if (edgepair_shm == NULL)
		return;

	f = fopen(path, "wb");
	if (f == NULL) {
		perror("edgepair: failed to open dump file");
		return;
	}

	if (fwrite(&magic, sizeof(magic), 1, f) != 1 ||
	    fwrite(edgepair_shm, sizeof(*edgepair_shm), 1, f) != 1) {
		perror("edgepair: failed to write dump file");
		fclose(f);
		return;
	}

	fclose(f);
	output(0, "KCOV: edge-pair data dumped to %s\n", path);
}
