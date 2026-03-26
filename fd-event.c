/*
 * fd event ring buffer — lock-free SPSC queue for child-to-parent
 * fd state change reporting.
 *
 * Each child produces events (dup, close) into its own ring.
 * The parent drains events and updates the global object pool.
 */

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "fd.h"
#include "fd-event.h"
#include "locks.h"
#include "objects.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

void fd_event_ring_init(struct fd_event_ring *ring)
{
	memset(ring, 0, sizeof(*ring));
	atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&ring->overflow, 0, memory_order_relaxed);
}

/*
 * Enqueue from child context.  Single-producer: only the child
 * writes head.  Returns false if the ring is full.
 */
bool fd_event_enqueue(struct fd_event_ring *ring,
		      enum fd_event_type type,
		      int fd1, int fd2,
		      enum objecttype objtype)
{
	uint32_t head, tail, next;

	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	next = (head + 1) & (FD_EVENT_RING_SIZE - 1);
	if (next == tail) {
		/* Ring full — drop the event.  Stale detection is backstop. */
		atomic_fetch_add_explicit(&ring->overflow, 1,
					  memory_order_relaxed);
		return false;
	}

	ring->events[head].type = type;
	ring->events[head].fd1 = fd1;
	ring->events[head].fd2 = fd2;
	ring->events[head].objtype = objtype;

	/* Ensure the event data is visible before advancing head. */
	atomic_store_explicit(&ring->head, next, memory_order_release);
	return true;
}

/*
 * Set the fd field in an object's type-specific union member.
 * Used to create minimal dup'd objects that inherit type from the source.
 */
static void set_object_fd(struct object *obj, enum objecttype type, int fd)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = fd; break;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = fd; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = fd; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = fd; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = fd; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = fd; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = fd; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = fd; break;
	case OBJ_FD_DRM:	obj->drmfd = fd; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = fd; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = fd; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = fd; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = fd; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = fd; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = fd; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = fd; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = fd; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = fd; break;
	default:		break;
	}
}

/*
 * Process a single FD_EVENT_DUP: look up the source fd's type in the
 * hash table and create a new object with inherited type for the new fd.
 *
 * If the source fd has already been destroyed (race between child's dup
 * and parent's close processing), we skip silently — the dup'd fd will
 * be detected as stale via the generation counter.
 */
static void handle_dup_event(int oldfd, int newfd)
{
	struct fd_hash_entry *entry;
	struct object *obj;
	enum objecttype type;

	/* Look up source fd under objlock.  Copy the type out so we can
	 * release the lock before allocating. */
	lock(&shm->objlock);
	entry = fd_hash_lookup(oldfd);
	if (entry == NULL) {
		unlock(&shm->objlock);
		return;
	}
	type = entry->type;
	unlock(&shm->objlock);

	/* Create a minimal object for the dup'd fd, inheriting type.
	 * We only set the fd field — the rest of the type-specific
	 * metadata is irrelevant since this is a dup'd handle. */
	obj = alloc_object();
	if (obj == NULL)
		return;

	set_object_fd(obj, type, newfd);

	/* add_object takes objlock internally. */
	add_object(obj, OBJ_GLOBAL, type);
}

/*
 * Drain all pending events from one child's ring.
 * Single-consumer: only the parent writes tail.
 */
unsigned int fd_event_drain(struct fd_event_ring *ring)
{
	uint32_t head, tail, overflow;
	unsigned int processed = 0;

	/* Check and reset overflow counter. */
	overflow = atomic_exchange_explicit(&ring->overflow, 0,
					    memory_order_relaxed);
	if (overflow > 0)
		output(1, "fd_event: ring overflow, %u events dropped\n",
		       overflow);

	tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	/* Acquire pairs with child's release-store of head. */
	head = atomic_load_explicit(&ring->head, memory_order_acquire);

	while (tail != head) {
		struct fd_event *ev = &ring->events[tail];

		switch (ev->type) {
		case FD_EVENT_DUP:
			handle_dup_event(ev->fd1, ev->fd2);
			break;

		case FD_EVENT_CLOSE:
			remove_object_by_fd(ev->fd1);
			break;

		case FD_EVENT_CREATED: {
			struct object *obj = alloc_object();
			if (obj != NULL) {
				set_object_fd(obj, ev->objtype, ev->fd1);
				add_object(obj, OBJ_GLOBAL, ev->objtype);
			}
			break;
		}
		}

		tail = (tail + 1) & (FD_EVENT_RING_SIZE - 1);
		processed++;
	}

	/* Release-store so the child sees the updated tail. */
	atomic_store_explicit(&ring->tail, tail, memory_order_release);
	return processed;
}

/*
 * Drain events from all children's rings.
 * Called from the parent main loop (handle_children / watchdog path).
 */
void fd_event_drain_all(void)
{
	unsigned int i;
	unsigned int total = 0;

	for_each_child(i) {
		struct childdata *child = shm->children[i];
		struct fd_event_ring *ring;

		if (child == NULL)
			continue;

		ring = child->fd_event_ring;
		if (ring == NULL)
			continue;

		total += fd_event_drain(ring);
	}

	if (total > 0)
		__atomic_add_fetch(&shm->stats.fd_events_processed, total,
				   __ATOMIC_RELAXED);
}
