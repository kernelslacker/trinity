/*
 * iouring-ring -- shared SQ/CQ/SQE ring-setup helper.  See
 * childops/iouring-ring.h for the rationale.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <unistd.h>

#include "childops/iouring-ring.h"
#include "compat.h"
#include "syscall-gate.h"
#include "errno-classify.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#endif

#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING	0x8000000ULL
#endif

/*
 * Map io_uring_setup's failure errno onto the three-state status.  Any
 * errno that can only mean "kernel won't ever support this" latches
 * UNSUPPORTED; everything else (ENOMEM / EAGAIN / EMFILE / EINVAL on
 * an edge-value entry count, ...) is TRANSIENT and the caller may
 * retry on the next cycle.
 */
static enum iour_setup_status classify_setup_errno(int err)
{
	if (is_syscall_unsupported(err))
		return IOUR_UNSUPPORTED;
	return IOUR_TRANSIENT;
}

/*
 * Compute one ring-region length: base + entries * elem_size, with
 * both the multiply and the add guarded by __builtin_*_overflow so a
 * hostile kernel return doesn't wrap into a tiny mmap that later
 * indexed-write blows past.  Returns true on success, false on
 * overflow.
 */
static bool size_add_mul(size_t base, size_t entries, size_t elem_size,
			 size_t *out)
{
	size_t prod;

	if (__builtin_mul_overflow(entries, elem_size, &prod))
		return false;
	if (__builtin_add_overflow(base, prod, out))
		return false;
	return true;
}

/*
 * Validate a kernel-returned ring-field offset lands inside the mapped
 * span.  An "in-range" offset must allow at least elem_size bytes of
 * access without walking off the end, since the head/tail/mask reads
 * the helper exposes are all 4-byte loads.
 */
static bool offset_in_range(size_t off, size_t elem_size, size_t map_sz)
{
	size_t end;

	if (__builtin_add_overflow(off, elem_size, &end))
		return false;
	return end <= map_sz;
}

enum iour_setup_status iour_ring_setup(struct io_uring_params *p,
				       unsigned int entries,
				       struct iour_ring *out)
{
	size_t sq_sz, cq_sz, sqes_sz, single_sz, cq_eff;
	void *sq_ring, *cq_ring, *sqes;
	int fd, saved_errno;

	memset(out, 0, sizeof(*out));
	out->fd = -1;

	fd = (int)trinity_raw_syscall(__NR_io_uring_setup, entries, p);
	if (fd < 0) {
		/* Capture the setup-failure errno BEFORE any cleanup
		 * runs (there's no cleanup on this path, but the rule
		 * is uniform: setup-failure classification never
		 * crosses an errno-clobbering syscall). */
		return classify_setup_errno(errno);
	}

	/* SQ ring: sq_off.array + sq_entries * sizeof(unsigned int). */
	if (!size_add_mul((size_t)p->sq_off.array,
			  (size_t)p->sq_entries, sizeof(unsigned int),
			  &sq_sz))
		goto fail_close;

	/* CQ ring: cq_off.cqes + cq_entries * sizeof(struct io_uring_cqe). */
	if (!size_add_mul((size_t)p->cq_off.cqes,
			  (size_t)p->cq_entries,
			  sizeof(struct io_uring_cqe), &cq_sz))
		goto fail_close;

	/* SQE array: sq_entries * sizeof(struct io_uring_sqe). */
	if (__builtin_mul_overflow((size_t)p->sq_entries,
				   sizeof(struct io_uring_sqe), &sqes_sz))
		goto fail_close;

	/* IORING_FEAT_SINGLE_MMAP shares one mapping between SQ and CQ
	 * sized to max(sq_sz, cq_sz).  Mapping only sq_sz (which the
	 * per-childop copies all did) under-maps when cq_sz > sq_sz,
	 * so a later CQ-ring write walks past the mapping. */
	if (p->features & IORING_FEAT_SINGLE_MMAP) {
		single_sz = sq_sz > cq_sz ? sq_sz : cq_sz;
		sq_ring = mmap(NULL, single_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE, fd,
			       IORING_OFF_SQ_RING);
		if (sq_ring == MAP_FAILED)
			goto fail_close;
		cq_ring = sq_ring;
		out->sq_map_sz = single_sz;
		out->cq_map_sz = 0;
		out->single_mmap = true;
		cq_eff = single_sz;
	} else {
		sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE, fd,
			       IORING_OFF_SQ_RING);
		if (sq_ring == MAP_FAILED)
			goto fail_close;
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE, fd,
			       IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED) {
			saved_errno = errno;
			munmap(sq_ring, sq_sz);
			close(fd);
			errno = saved_errno;
			memset(out, 0, sizeof(*out));
			out->fd = -1;
			return IOUR_TRANSIENT;
		}
		out->sq_map_sz = sq_sz;
		out->cq_map_sz = cq_sz;
		cq_eff = cq_sz;
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		saved_errno = errno;
		if (!out->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, out->sq_map_sz);
		close(fd);
		errno = saved_errno;
		memset(out, 0, sizeof(*out));
		out->fd = -1;
		return IOUR_TRANSIENT;
	}

	/* Validate every kernel-returned offset lands inside its mapped
	 * region BEFORE the caller starts dereferencing them.  An
	 * out-of-range offset on a hostile kernel return would otherwise
	 * be the first thing the caller's ring_u32(head/tail/mask) load
	 * tripped on. */
	if (!offset_in_range(p->sq_off.head, sizeof(unsigned int),
			     out->sq_map_sz) ||
	    !offset_in_range(p->sq_off.tail, sizeof(unsigned int),
			     out->sq_map_sz) ||
	    !offset_in_range(p->sq_off.ring_mask, sizeof(unsigned int),
			     out->sq_map_sz) ||
	    !offset_in_range(p->sq_off.array, sizeof(unsigned int),
			     out->sq_map_sz) ||
	    !offset_in_range(p->cq_off.head, sizeof(unsigned int),
			     cq_eff) ||
	    !offset_in_range(p->cq_off.tail, sizeof(unsigned int),
			     cq_eff) ||
	    !offset_in_range(p->cq_off.ring_mask, sizeof(unsigned int),
			     cq_eff) ||
	    !offset_in_range(p->cq_off.cqes, sizeof(struct io_uring_cqe),
			     cq_eff)) {
		saved_errno = errno;
		munmap(sqes, sqes_sz);
		if (!out->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, out->sq_map_sz);
		close(fd);
		errno = saved_errno;
		memset(out, 0, sizeof(*out));
		out->fd = -1;
		return IOUR_TRANSIENT;
	}

	out->fd          = fd;
	out->sq_ring     = sq_ring;
	out->cq_ring     = cq_ring;
	out->sqes        = sqes;
	out->sqe_map_sz  = sqes_sz;
	out->sq_entries  = p->sq_entries;
	out->cq_entries  = p->cq_entries;

	out->sq_off_head  = p->sq_off.head;
	out->sq_off_tail  = p->sq_off.tail;
	out->sq_off_mask  = p->sq_off.ring_mask;
	out->sq_off_array = p->sq_off.array;

	out->cq_off_head  = p->cq_off.head;
	out->cq_off_tail  = p->cq_off.tail;
	out->cq_off_mask  = p->cq_off.ring_mask;
	out->cq_off_cqes  = p->cq_off.cqes;

	return IOUR_SUPPORTED;

fail_close:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	memset(out, 0, sizeof(*out));
	out->fd = -1;
	return IOUR_TRANSIENT;
}

void iour_ring_teardown(struct iour_ring *ring)
{
	int saved_errno = errno;

	if (ring->sqes)
		munmap(ring->sqes, ring->sqe_map_sz);
	if (ring->cq_ring && !ring->single_mmap)
		munmap(ring->cq_ring, ring->cq_map_sz);
	if (ring->sq_ring)
		munmap(ring->sq_ring, ring->sq_map_sz);
	if (ring->fd >= 0)
		close(ring->fd);
	errno = saved_errno;
}
