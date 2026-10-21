#include <sys/stat.h>
#include <unistd.h>

#include "child-api.h"
#include "owned-fd-ring.h"

/*
 * Every record is followed by a live_fds push, so an fd has seen
 * MAX_OWNED_FDS - 1 later pushes when its ring closes it.  Only a ring
 * larger than live_fds guarantees that is enough to push it out, where a
 * consumer could still pick it.
 */
_Static_assert(MAX_OWNED_FDS > CHILD_FD_RING_SIZE,
	       "an fd must have left live_fds before its ring closes it");

/*
 * Close the fd a slot owns, if its number still names the file recorded.
 * Otherwise the number belongs to someone else (a socket, another
 * provider's fd) or is free (EBADF), and closing it would kill a
 * stranger.  A slot whose identity could not be read is never closed:
 * leaking one fd beats closing the wrong one.
 */
static void owned_fd_slot_evict(const struct owned_fd_slot *slot)
{
	struct stat st;

	if (slot->fd < 0)
		return;
	if (fstat(slot->fd, &st) < 0)
		return;
	if (st.st_dev != slot->dev || st.st_ino != slot->ino)
		return;

	close(slot->fd);
}

void owned_fd_ring_record(struct owned_fd_ring *ring, int fd)
{
	struct owned_fd_slot *slot = &ring->slot[ring->head % MAX_OWNED_FDS];
	struct stat st;
	unsigned int i;

	/*
	 * fstat() cannot tell a recycled number from the original for the fds
	 * hooked onto the one inode that anon_inode_getfile() and
	 * anon_inode_getfd() hand out (eventfd, epoll, signalfd, timerfd,
	 * inotify, fanotify, ...).  But the kernel only hands out a free
	 * number, so an older slot naming @fd is stale.  Retire it before the
	 * eviction below, which may be that very slot.
	 */
	for (i = 0; i < MAX_OWNED_FDS; i++) {
		if (ring->slot[i].fd == fd)
			ring->slot[i].fd = -1;
	}

	if (ring->head >= MAX_OWNED_FDS)
		owned_fd_slot_evict(slot);

	if (fstat(fd, &st) < 0) {
		slot->fd = -1;
	} else {
		slot->fd = fd;
		slot->dev = st.st_dev;
		slot->ino = st.st_ino;
	}
	ring->head++;
}
