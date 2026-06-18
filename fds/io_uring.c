/* io_uring FD provider. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

#ifndef IORING_SETUP_IOPOLL
#define IORING_SETUP_IOPOLL	(1U << 0)
#endif
#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL	(1U << 1)
#endif
#ifndef IORING_SETUP_CQSIZE
#define IORING_SETUP_CQSIZE	(1U << 3)
#endif
#ifndef IORING_SETUP_CLAMP
#define IORING_SETUP_CLAMP	(1U << 4)
#endif
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER	(1U << 12)
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN	(1U << 13)
#endif

/* Offsets within the mmap'd SQ ring where key fields live. */
struct trinity_sqring_offsets {
	unsigned int head;
	unsigned int tail;
	unsigned int ring_mask;
	unsigned int ring_entries;
	unsigned int flags;
	unsigned int dropped;
	unsigned int array;
	unsigned int resv1;
	unsigned long long user_addr;
};

/* Full io_uring_params including the output fields we need. */
struct trinity_io_uring_params {
	unsigned int sq_entries;
	unsigned int cq_entries;
	unsigned int flags;
	unsigned int sq_thread_cpu;
	unsigned int sq_thread_idle;
	unsigned int features;
	unsigned int wq_fd;
	unsigned int resv[3];
	struct trinity_sqring_offsets sq_off;
	/* cq_off follows but we don't need it */
	unsigned char cq_off[40];
};

/* Ring topologies to create at startup.  Varied flags exercise different
 * kernel submission/completion paths.  Failures are silently skipped —
 * SQPOLL and IOPOLL require privileges or hardware that may not be present. */
static const struct {
	unsigned int entries;
	unsigned int flags;
} ring_configs[] = {
	{ 4,  0 },
	{ 16, IORING_SETUP_CLAMP },
	{ 32, IORING_SETUP_CQSIZE },
	{ 8,  IORING_SETUP_SQPOLL },
	{ 4,  IORING_SETUP_IOPOLL },
	{ 8,  IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN },
};

/* Child-side read of mapped_ring: ACQUIRE pairs with the parent-side RELEASE
 * store in open_io_uring_fd_config().  No lock needed — mapped_ring is a
 * single pointer published once at init and not freed while rings are live. */
struct io_uringobj *get_io_uring_ring(void)
{
	return __atomic_load_n(&shm->mapped_ring, __ATOMIC_ACQUIRE);
}

static void io_uring_destructor(struct object *obj)
{
	struct io_uringobj *ring = &obj->io_uringobj;
	struct io_uringobj *expected = ring;

	if (ring->sqes) {
		untrack_shared_region((unsigned long)ring->sqes, ring->sqes_sz);
		munmap(ring->sqes, ring->sqes_sz);
	}
	if (ring->sq_ring) {
		untrack_shared_region((unsigned long)ring->sq_ring,
				      ring->sq_ring_sz);
		munmap(ring->sq_ring, ring->sq_ring_sz);
	}

	/* Lockless clear: pairs with the ACQUIRE load in get_io_uring_ring()
	 * and the RELEASE store in open_io_uring_fd_config().  The destructor
	 * is reachable from child context via prune_objects() destroying
	 * OBJ_LOCAL OBJ_FD_IO_URING entries (post_io_uring_setup adds those,
	 * and the destructor is inherited from the OBJ_GLOBAL provider).
	 * Taking shm->objlock from a child would risk deadlocking the parent
	 * if the child was killed mid-lock — same class as e4e32ff0. */
	__atomic_compare_exchange_n(&shm->mapped_ring, &expected, NULL,
				    false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);

	close(ring->fd);
}

static void io_uring_dump(struct object *obj, enum obj_scope scope)
{
	struct io_uringobj *ring = &obj->io_uringobj;

	output(2, "io_uring fd:%d sq_entries:%u flags:0x%x mapped:%s scope:%d\n",
		ring->fd, ring->sq_entries, ring->setup_flags,
		ring->sq_ring ? "yes" : "no", scope);
}

static int open_io_uring_fd_config(unsigned int entries, unsigned int flags,
				   bool init_phase)
{
#ifdef __NR_io_uring_setup
	struct trinity_io_uring_params params;
	struct object *obj;
	struct io_uringobj *ring;
	size_t sq_ring_sz, sqes_sz;
	void *sq_ring, *sqes;
	int fd;

	memset(&params, 0, sizeof(params));
	params.flags = flags;
	/* IORING_SETUP_CQSIZE: supply a CQ twice the SQ depth */
	if (flags & IORING_SETUP_CQSIZE)
		params.cq_entries = entries * 2;

	fd = trinity_raw_syscall(__NR_io_uring_setup, entries, &params);
	if (fd < 0)
		return false;

	/* mmap the SQ ring. Size is sq_off.array + sq_entries * sizeof(u32).
	 * Guard against integer overflow from kernel-controlled values.
	 */
	if (__builtin_mul_overflow((size_t)params.sq_entries, sizeof(unsigned int), &sq_ring_sz) ||
	    __builtin_add_overflow(sq_ring_sz, (size_t)params.sq_off.array, &sq_ring_sz)) {
		close(fd);
		return false;
	}
	sq_ring = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED) {
		close(fd);
		return false;
	}
	track_shared_region((unsigned long)sq_ring, sq_ring_sz);

	/* mmap the SQE array — sizeof(struct io_uring_sqe) == 64. */
	if (__builtin_mul_overflow((size_t)params.sq_entries, (size_t)64, &sqes_sz)) {
		untrack_shared_region((unsigned long)sq_ring, sq_ring_sz);
		munmap(sq_ring, sq_ring_sz);
		close(fd);
		return false;
	}
	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		untrack_shared_region((unsigned long)sq_ring, sq_ring_sz);
		munmap(sq_ring, sq_ring_sz);
		close(fd);
		return false;
	}
	track_shared_region((unsigned long)sqes, sqes_sz);

	obj = alloc_object();
	if (obj == NULL) {
		untrack_shared_region((unsigned long)sqes, sqes_sz);
		munmap(sqes, sqes_sz);
		untrack_shared_region((unsigned long)sq_ring, sq_ring_sz);
		munmap(sq_ring, sq_ring_sz);
		close(fd);
		return false;
	}
	ring = &obj->io_uringobj;
	ring->fd = fd;
	ring->setup_flags = flags;
	ring->sq_ring = sq_ring;
	ring->sq_ring_sz = sq_ring_sz;
	ring->sqes = sqes;
	ring->sqes_sz = sqes_sz;
	ring->sq_entries = params.sq_entries;
	ring->off_head = params.sq_off.head;
	ring->off_tail = params.sq_off.tail;
	ring->off_mask = params.sq_off.ring_mask;
	ring->off_array = params.sq_off.array;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_IO_URING);

	/*
	 * Publish to shm->mapped_ring only for rings created during the
	 * pre-fork init phase.  An init-time ring's sq_ring/sqes mappings
	 * are inherited at the same VA by every child via fork(), which
	 * is what get_io_uring_ring() consumers (sanitise_io_uring_enter
	 * reading sq_off_mask via ring->sq_ring) need.  RELEASE store
	 * pairs with the child-side ACQUIRE in get_io_uring_ring().
	 *
	 * Last-init-wins is deliberate: init_io_uring_fds() iterates
	 * ring_configs[] and each successful open_io_uring_fd_config()
	 * overwrites shm->mapped_ring with its own ring.  Downstream
	 * consumers (io_uring_enter / io_uring_register sanitisers,
	 * sanitise_io_uring_register cross-ring checks) only need ONE
	 * valid set of inherited mappings; every ring populated in this
	 * loop has equally usable sq_ring/sqes pointers because they
	 * were all mapped pre-fork in the same parent VA space.  The
	 * final iteration's ring is the one whose pointers survive
	 * publication, but the choice is arbitrary by design.
	 *
	 * If a future caller needs a per-config ring (e.g. one whose
	 * IORING_SETUP_* flags it can read off the obj), the right move
	 * is a mapped_ring[] array indexed by config idx rather than
	 * dropping the gate -- post-fork callers must not republish
	 * because their mappings are not visible in other children.
	 */
	if (init_phase)
		__atomic_store_n(&shm->mapped_ring, ring, __ATOMIC_RELEASE);

	return true;
#else
	(void)entries; (void)flags;
	return false;
#endif
}

static int init_io_uring_fds(void)
{
	struct objhead *head;
	unsigned int i, count = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_IO_URING);
	head->destroy = &io_uring_destructor;
	head->dump = &io_uring_dump;
	/*
	 * The io_uringobj struct lives in the OBJ_GLOBAL pool, populated
	 * pre-fork and inherited by children via fork/COW, so the
	 * cross-process dump path (head->dump from dump_childdata in the
	 * parent crash diagnostics) can read its scalar fields (fd,
	 * off_*, sq_entries, sq_ring_sz, sqes_sz) regardless of which
	 * process triggered the crash.
	 *
	 * Scope: the obj struct ONLY.  The mmap'd pointers (sq_ring,
	 * sqes) are kernel-backed mappings obtained via mmap(MAP_SHARED)
	 * on the io_uring fd, not heap allocations.  Pre-fork mappings
	 * inherited via fork() are visible at the same VA in every child,
	 * which is what sanitise_io_uring_enter (reading sq_off_mask via
	 * ring->sq_ring) requires.  Pool is populated once pre-fork and
	 * not regenerated post-fork; if a ring's fd is destroyed, the
	 * pool shrinks until the session ends.
	 */

	for (i = 0; i < ARRAY_SIZE(ring_configs); i++)
		count += open_io_uring_fd_config(ring_configs[i].entries,
						 ring_configs[i].flags,
						 true);
	return count > 0;
}

static int get_rand_io_uring_fd(void)
{
	if (objects_empty(OBJ_FD_IO_URING) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->io_uringobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the io_uring fd handed to io_uring_setup/enter/register via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_IO_URING, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_IO_URING))
			continue;

		fd = obj->io_uringobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider io_uring_fd_provider = {
	.name = "io_uring",
	.objtype = OBJ_FD_IO_URING,
	.enabled = true,
	.init = &init_io_uring_fds,
	.get = &get_rand_io_uring_fd,
	/*
	 * io_uring_poll() waits for completion-queue activity; an idle ring
	 * with no submitted SQEs leaves ep_item_poll spinning on the CQ
	 * waitqueue indefinitely.  Bar from epoll/select/poll watch sets.
	 */
	.poll_can_block = true,
};

REG_FD_PROV(io_uring_fd_provider);
