#pragma once

#include <sys/types.h>

/*
 * The fds one provider has minted through .try_replenish and still owns.
 * child_fd_ring_push() only hints at fds and cannot close what it evicts,
 * so the provider owns at most MAX_OWNED_FDS of them and closes the oldest
 * to make room for the next.  Larger than CHILD_FD_RING_SIZE (checked in
 * owned-fd-ring.c), so an fd has left live_fds before it is closed.
 *
 * Meant to be a function-static in the provider: only the child fills it,
 * and a zeroed ring evicts nothing until it has wrapped, so an unwritten
 * slot is never closed.
 */
#define MAX_OWNED_FDS	32

struct owned_fd_slot {
	int fd;
	dev_t dev;
	ino_t ino;
};

struct owned_fd_ring {
	struct owned_fd_slot slot[MAX_OWNED_FDS];
	unsigned int head;
};

/*
 * Take ownership of @fd.  Once the ring is full, the oldest owned fd is
 * closed first, but only while its number still names the file it was
 * recorded as: a fuzzed close() or dup2() can free or take over the number,
 * and the next fd-creating call hands it to an unrelated file.
 */
void owned_fd_ring_record(struct owned_fd_ring *ring, int fd);
