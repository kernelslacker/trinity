/* io_uring FD provider. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "fd.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

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

/* The ring with valid mappings is stored in shm->mapped_ring,
 * shared across all children.  Protected by shm->objlock. */

struct io_uringobj *get_io_uring_ring(void)
{
	struct io_uringobj *ring;

	lock(&shm->objlock);
	ring = shm->mapped_ring;
	unlock(&shm->objlock);
	return ring;
}

static void io_uring_destructor(struct object *obj)
{
	struct io_uringobj *ring = &obj->io_uringobj;

	if (ring->sqes)
		munmap(ring->sqes, ring->sqes_sz);
	if (ring->sq_ring)
		munmap(ring->sq_ring, ring->sq_ring_sz);

	lock(&shm->objlock);
	if (shm->mapped_ring == ring)
		shm->mapped_ring = NULL;
	unlock(&shm->objlock);

	close(ring->fd);
}

static void io_uring_dump(struct object *obj, enum obj_scope scope)
{
	struct io_uringobj *ring = &obj->io_uringobj;

	output(2, "io_uring fd:%d sq_entries:%u flags:0x%x mapped:%s scope:%d\n",
		ring->fd, ring->sq_entries, ring->setup_flags,
		ring->sq_ring ? "yes" : "no", scope);
}

static int open_io_uring_fd_config(unsigned int entries, unsigned int flags)
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

	fd = syscall(__NR_io_uring_setup, entries, &params);
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

	/* mmap the SQE array — sizeof(struct io_uring_sqe) == 64. */
	if (__builtin_mul_overflow((size_t)params.sq_entries, (size_t)64, &sqes_sz)) {
		munmap(sq_ring, sq_ring_sz);
		close(fd);
		return false;
	}
	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		munmap(sq_ring, sq_ring_sz);
		close(fd);
		return false;
	}

	obj = alloc_object();
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

	lock(&shm->objlock);
	shm->mapped_ring = ring;
	unlock(&shm->objlock);

	return true;
#else
	(void)entries; (void)flags;
	return false;
#endif
}

static int open_io_uring_fd(void)
{
	unsigned int i = rand() % ARRAY_SIZE(ring_configs);

	return open_io_uring_fd_config(ring_configs[i].entries,
				       ring_configs[i].flags);
}

static int init_io_uring_fds(void)
{
	struct objhead *head;
	unsigned int i, count = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_IO_URING);
	head->destroy = &io_uring_destructor;
	head->dump = &io_uring_dump;

	for (i = 0; i < ARRAY_SIZE(ring_configs); i++)
		count += open_io_uring_fd_config(ring_configs[i].entries,
						 ring_configs[i].flags);
	return count > 0;
}

static int get_rand_io_uring_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_IO_URING) == true)
		return -1;

	obj = get_random_object(OBJ_FD_IO_URING, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->io_uringobj.fd;
}

static const struct fd_provider io_uring_fd_provider = {
	.name = "io_uring",
	.objtype = OBJ_FD_IO_URING,
	.enabled = true,
	.init = &init_io_uring_fds,
	.get = &get_rand_io_uring_fd,
	.open = &open_io_uring_fd,
};

REG_FD_PROV(io_uring_fd_provider);
