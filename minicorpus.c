/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * Stores syscall argument snapshots that discovered new KCOV edges.
 * During future arg generation for the same syscall, a stored
 * snapshot may be replayed with per-argument mutations to explore
 * nearby input space.
 *
 * Syscalls with sanitise callbacks or with arg types that carry
 * heap pointers (ARG_IOVEC, ARG_PATHNAME, ARG_SOCKADDR, ARG_MMAP)
 * are excluded — those pointers become stale after deferred-free
 * eviction, causing UAF on replay.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "random.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

struct minicorpus_shared *minicorpus_shm = NULL;

void minicorpus_init(void)
{
	if (kcov_shm == NULL)
		return;

	minicorpus_shm = alloc_shared(sizeof(struct minicorpus_shared));
	memset(minicorpus_shm, 0, sizeof(struct minicorpus_shared));
	output(0, "KCOV: mini-corpus allocated (%lu KB, %d entries/syscall)\n",
		(unsigned long) sizeof(struct minicorpus_shared) / 1024,
		CORPUS_RING_SIZE);
}

static void ring_lock(struct corpus_ring *ring)
{
	unsigned int spins = 0;

	while (__atomic_test_and_set(&ring->lock, __ATOMIC_ACQUIRE)) {
		if (++spins > 1000000) {
			unsigned int gen = __atomic_load_n(&ring->lock_gen,
				__ATOMIC_ACQUIRE);
			pid_t owner = __atomic_load_n(&ring->locker_pid, __ATOMIC_RELAXED);

			if (owner != 0 && kill(owner, 0) == -1 &&
			    errno == ESRCH &&
			    __atomic_load_n(&ring->lock_gen,
				__ATOMIC_RELAXED) == gen)
				__atomic_clear(&ring->lock, __ATOMIC_RELEASE);
			spins = 0;
		}
	}
	__atomic_store_n(&ring->locker_pid, getpid(), __ATOMIC_RELAXED);
	__atomic_fetch_add(&ring->lock_gen, 1, __ATOMIC_RELEASE);
}

static void ring_unlock(struct corpus_ring *ring)
{
	__atomic_store_n(&ring->locker_pid, 0, __ATOMIC_RELAXED);
	__atomic_clear(&ring->lock, __ATOMIC_RELEASE);
}

void minicorpus_save(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry *ent;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return;

	/* Reject syscalls whose args carry heap pointers allocated by
	 * generic_sanitise().  After deferred-free eviction those pointers
	 * go stale, and replaying them feeds freed memory to the kernel. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
			return;
		default:
			break;
		}
	}

	ring = &minicorpus_shm->rings[nr];

	ring_lock(ring);

	ent = &ring->entries[ring->head % CORPUS_RING_SIZE];
	ent->args[0] = rec->a1;
	ent->args[1] = rec->a2;
	ent->args[2] = rec->a3;
	ent->args[3] = rec->a4;
	ent->args[4] = rec->a5;
	ent->args[5] = rec->a6;
	ent->num_args = entry->num_args;

	/* Saved fd numbers are stale on replay — zero them out so mutate_arg
	 * gets a fresh fd rather than trying to reuse a closed one. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]))
			ent->args[i] = 0;
	}

	ring->head++;
	if (ring->count < CORPUS_RING_SIZE)
		ring->count++;

	ring_unlock(ring);
}

/*
 * Apply a small mutation to a single argument value.
 * The mutations are designed to explore nearby input space:
 *   - bit flip: toggle a single random bit
 *   - add/sub:  adjust by a small delta (1..16)
 *   - boundary: replace with a boundary value (0, -1, page_size, etc.)
 */
static unsigned long mutate_arg(unsigned long val)
{
	switch (rand() % 6) {
	case 0:
		/* flip a random bit */
		val ^= 1UL << (rand() % (sizeof(unsigned long) * 8));
		break;
	case 1: {
		/* add small delta, saturate at ULONG_MAX */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = ((unsigned long)-1 - val < delta) ? (unsigned long)-1 : val + delta;
		break;
	}
	case 2: {
		/* subtract small delta, saturate at 0 */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = (val < delta) ? 0 : val - delta;
		break;
	}
	case 3:
		/* replace with boundary */
		val = get_boundary_value();
		break;
	case 4:
		/* byte-level shuffle: randomize one byte */
		{
			unsigned int byte_pos = rand() % sizeof(unsigned long);
			unsigned long mask = 0xffUL << (byte_pos * 8);
			val = (val & ~mask) | ((unsigned long) RAND_BYTE() << (byte_pos * 8));
		}
		break;
	case 5:
		/* keep original — sometimes the saved value is good as-is */
		break;
	}
	return val;
}

bool minicorpus_replay(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry snapshot;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int slot;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	ring = &minicorpus_shm->rings[nr];

	/* No saved entries yet. */
	if (ring->count == 0)
		return false;

	/* ~25% chance to replay, 75% fresh generation. */
	if (!ONE_IN(4))
		return false;

	ring_lock(ring);

	if (ring->count == 0) {
		ring_unlock(ring);
		return false;
	}

	/* Pick a random entry from the ring. */
	slot = rand() % ring->count;
	/* The ring is written at head and wraps, so the oldest valid
	 * entry starts at (head - count) mod CORPUS_RING_SIZE. */
	slot = (ring->head - ring->count + slot) % CORPUS_RING_SIZE;
	snapshot = ring->entries[slot];

	ring_unlock(ring);

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return false;

	/* Don't replay into syscalls with pointer-bearing arg types.
	 * Same rationale as minicorpus_save(). */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
			return false;
		default:
			break;
		}
	}

	/* Apply the snapshot with per-argument mutations. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		unsigned long val = snapshot.args[i];

		/* ~25% chance to mutate each arg. */
		if (ONE_IN(4))
			val = mutate_arg(val);

		/* Don't let fd args land on stdin/stdout/stderr. */
		if (is_fdarg(entry->argtype[i]) && val <= 2)
			val = (unsigned long) get_random_fd();

		switch (i) {
		case 0: rec->a1 = val; break;
		case 1: rec->a2 = val; break;
		case 2: rec->a3 = val; break;
		case 3: rec->a4 = val; break;
		case 4: rec->a5 = val; break;
		case 5: rec->a6 = val; break;
		}
	}

	return true;
}
