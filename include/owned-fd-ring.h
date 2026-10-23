#pragma once

#include <stdbool.h>
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
 * slot is never closed.  The first record links the ring into a
 * process-wide list, so a ring must keep its address and must not be
 * cleared or copied afterwards.
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
	struct owned_fd_ring *next;	/* list of every ring that has recorded */
	bool linked;
};

/*
 * Take ownership of @fd.  Once the ring is full, the oldest owned fd is
 * closed first, but only while its number still names the file it was
 * recorded as: a fuzzed close() or dup2() can free or take over the number,
 * and the next fd-creating call hands it to an unrelated file.  Recording a
 * number also retires it from every ring.
 */
void owned_fd_ring_record(struct owned_fd_ring *ring, int fd);

/*
 * Forget every slot, in every ring, that names @fd, and close nothing.  The
 * kernel only hands out a free number, so a slot that still names one the
 * kernel has just handed to someone else is stale: for the files fstat()
 * cannot tell apart it would close the new owner when its ring wraps.  A
 * walk of MAX_OWNED_FDS slots in each ring that has recorded, with no
 * syscall.
 */
void owned_fd_ring_retire(int fd);
