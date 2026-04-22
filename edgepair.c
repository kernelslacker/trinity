/*
 * Edge-pair tracking: (prev_syscall, curr_syscall) -> coverage data.
 *
 * Open-addressed hash table with linear probing in shared memory.
 * All updates are lock-free via atomics.  Minor races (e.g. two
 * children inserting the same pair simultaneously) are tolerable —
 * worst case we get a duplicate entry that wastes a slot.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "edgepair.h"
#include "trinity.h"
#include "utils.h"

/*
 * The first two fields of edgepair_entry (prev_nr, curr_nr) are both
 * unsigned int (4 bytes each), laid out contiguously at offset 0 inside
 * the anonymous union.  We load/CAS them via the .key uint64_t union
 * member to atomically claim slots — accessing the same storage through
 * the union is well-defined in C11, avoiding the strict-aliasing UB that
 * a raw (uint64_t *) cast would incur.
 */
_Static_assert(offsetof(struct edgepair_entry, prev_nr) == 0,
	       "prev_nr must be at offset 0 for packed CAS");
_Static_assert(offsetof(struct edgepair_entry, curr_nr) == 4,
	       "curr_nr must be at offset 4 for packed CAS");
_Static_assert(sizeof(unsigned int) == 4,
	       "unsigned int must be 4 bytes for packed CAS");

/* Pack a (prev, curr) pair into the uint64_t layout matching memory order. */
static uint64_t pack_pair(unsigned int prev, unsigned int curr)
{
	struct { unsigned int p; unsigned int c; } tmp = { prev, curr };
	uint64_t packed;
	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

struct edgepair_shared *edgepair_shm = NULL;

void edgepair_init_global(void)
{
	/* Only allocate if KCOV is available (caller checks).
	 *
	 * Stays alloc_shared() rather than alloc_shared_global().
	 * Children are the producers for the table[] entries (find_or_insert
	 * CASes the packed key, then bumps total_count / new_edge_count /
	 * last_new_at) and for the top-level counters (pairs_tracked,
	 * pairs_dropped, total_pair_calls).  edgepair_record() runs in
	 * child context after every non-cmp syscall.  An mprotect PROT_READ
	 * on this region would EFAULT every child's edge-pair update and
	 * cripple the (prev, curr) coverage path.
	 *
	 * Wild-write risk this leaves open: a child syscall whose user-buffer
	 * arg aliases into the table could let the kernel zero a slot's
	 * packed key, which a subsequent find_or_insert would re-claim — at
	 * worst the cold-pair detector loses one bucket of history.  No
	 * parent-side crash surface.
	 */
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
 *
 * Uses a single CAS on the packed {prev_nr, curr_nr} uint64_t to
 * atomically claim an empty slot.  This eliminates the race where
 * two threads could interleave separate stores to prev_nr and curr_nr,
 * corrupting the entry.
 */
static struct edgepair_entry *find_or_insert(unsigned int prev_nr,
					     unsigned int curr_nr)
{
	unsigned int idx = pair_hash(prev_nr, curr_nr);
	uint64_t target = pack_pair(prev_nr, curr_nr);
	uint64_t empty = pack_pair(EDGEPAIR_EMPTY, EDGEPAIR_EMPTY);

	for (unsigned int probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		struct edgepair_entry *e = &edgepair_shm->table[idx];
		uint64_t slot = __atomic_load_n(&e->key, __ATOMIC_ACQUIRE);

		/* Found existing entry for this pair. */
		if (slot == target)
			return e;

		/* Empty slot — try to claim it with a single CAS. */
		if (slot == empty) {
			uint64_t expected = empty;

			if (__atomic_compare_exchange_n(&e->key,
				&expected, target, false,
				__ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
				__atomic_fetch_add(&edgepair_shm->pairs_tracked,
					1, __ATOMIC_RELAXED);
				return e;
			}
			/* CAS failed — another child claimed it.
			 * Check if they inserted the same pair. */
			if (expected == target)
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
	if (e == NULL) {
		__atomic_fetch_add(&edgepair_shm->pairs_dropped,
			1, __ATOMIC_RELAXED);
		return;
	}

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
	uint64_t target = pack_pair(prev_nr, curr_nr);
	uint64_t empty = pack_pair(EDGEPAIR_EMPTY, EDGEPAIR_EMPTY);

	for (unsigned int probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		struct edgepair_entry *e = &edgepair_shm->table[idx];
		uint64_t slot = __atomic_load_n(&e->key, __ATOMIC_ACQUIRE);

		if (slot == empty)
			return NULL;

		if (slot == target)
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
