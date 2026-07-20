#include <stdbool.h>
#include <stdint.h>
#include "child.h"
#include "compiler.h"
#include "debug.h"
#include "objects.h"
#include "objects-internal.h"
#include "pids.h"
#include "shm.h"
#include "utils.h"

/*
 * Parent-private fd->object hash and parallel compact live-fd list.
 * Same shape as the per-child snapshots; fd_hash_insert / fd_hash_remove
 * mutate these from the parent's pre-fork init and post-fork fd-event
 * drains.  Children read their own snapshots; the parent reads these
 * directly when servicing remove_object_by_fd() out of fd_event_drain().
 */
struct fd_hash_entry parent_fd_hash[FD_HASH_SIZE];
int parent_fd_live[FD_LIVE_MAX];
unsigned int parent_fd_hash_count;
unsigned int parent_fd_live_count;

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
 *
 * The "typical few hundred entries" comment is the very
 * thing a planned fd live-list index should be gated on confirming.
 * Bump a log2 histogram of the position the match lands at + a miss
 * counter so the "does the scan actually cost" question is
 * directly answerable from the periodic dump without a profile run.
 * Single-writer (parent) so RELAXED add-fetch is uniform with the
 * shm->stats convention rather than load-bearing for ordering.
 */
static void fd_live_remove(int fd)
{
	unsigned int count = parent_fd_live_count;
	unsigned int i;

	__atomic_add_fetch(&shm->stats.fd.live_remove_calls, 1, __ATOMIC_RELAXED);

	for (i = 0; i < count; i++) {
		unsigned int depth;
		unsigned int bucket;

		if (parent_fd_live[i] != fd)
			continue;

		if (i != count - 1)
			parent_fd_live[i] = parent_fd_live[count - 1];
		parent_fd_live_count = count - 1;

		/* Bucket index = floor(log2(depth)) + 1, with depth==0
		 * landing in bucket 0 (match-on-first-slot).  Saturates at
		 * the last bucket so >=64 collapses into one tail slot. */
		depth = i;
		if (depth == 0)
			bucket = 0;
		else {
			unsigned int lz = (unsigned int)__builtin_clz(depth);
			unsigned int hi_bit = 31u - lz;

			bucket = hi_bit + 1u;
			if (bucket >= ARRAY_SIZE(shm->stats.fd.live_remove_scan_histogram))
				bucket = ARRAY_SIZE(shm->stats.fd.live_remove_scan_histogram) - 1u;
		}
		__atomic_add_fetch(&shm->stats.fd.live_remove_scan_histogram[bucket],
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.fd.live_remove_miss, 1, __ATOMIC_RELAXED);
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
		__atomic_add_fetch(&shm->stats.fd.hash_reinsert_dropped, 1,
				   __ATOMIC_RELAXED);
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

void fd_hash_remove_local(int fd)
{
	struct childdata *child;
	struct fd_hash_entry *table;
	unsigned int slot, next, i;

	if (fd < 0)
		return;

	if (mypid() == mainpid)
		return;

	child = this_child();
	if (child == NULL || child->fd_hash == NULL)
		return;

	table = child->fd_hash;
	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (table[slot].fd == -1)
			return;
		if (table[slot].fd == fd) {
			table[slot].gen++;
			table[slot].fd = -1;
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (table[next].fd != -1) {
				struct fd_hash_entry displaced = table[next];
				unsigned int rs;

				table[next].fd = -1;
				rs = fd_hash_slot(displaced.fd);
				while (table[rs].fd != -1 &&
				       table[rs].fd != displaced.fd)
					rs = (rs + 1) & (FD_HASH_SIZE - 1);
				table[rs] = displaced;
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
}

void fd_hash_remove_local_range(int lo, int hi)
{
	struct childdata *child;
	struct fd_hash_entry *table;
	unsigned int i;

	if (lo > hi)
		return;

	child = this_child();
	if (child == NULL || child->fd_hash == NULL)
		return;
	table = child->fd_hash;

	/*
	 * One walk over the local hash table, evicting every slot whose
	 * fd is in [lo, hi].  Replaces the prior fd-by-fd loop that paid
	 * an FD_HASH_SIZE-bounded linear probe per fd in the range --
	 * O(N*M) for close_range(lo=3, hi=1024) collapses to O(M).
	 *
	 * fd_hash_remove_local() walks the displacement chain after the
	 * evicted slot and re-hashes any entries it finds; a re-hashed
	 * entry can land back into the slot we just cleared (its natural
	 * slot may map there) but never into a slot earlier than the one
	 * we removed from -- the probe-from-natural walk always finds the
	 * just-emptied slot before any wrap-around landing site.  i--
	 * therefore re-examines this slot (which may now hold a different
	 * fd, possibly itself in [lo, hi]) without revisiting anything
	 * we've already cleared.
	 */
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (table[i].fd >= lo && table[i].fd <= hi) {
			fd_hash_remove_local(table[i].fd);
			i--;
		}
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
	if (mypid() == mainpid) {
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
