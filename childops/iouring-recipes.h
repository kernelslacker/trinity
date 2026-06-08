#pragma once
/*
 * Shared io_uring ring context + setup/teardown helpers.
 *
 * The SQ/CQ ring lifecycle (io_uring_setup, the three IORING_OFF_*
 * mmap regions, and the corresponding munmap/close on teardown) is
 * boilerplate that's identical across every childop that opens a
 * private ring.  This header is the single home for the ring-context
 * struct and the matching setup/teardown helpers so the boilerplate
 * is not duplicated.
 */

#include <stdbool.h>
#include <stddef.h>

/*
 * Local ring context — set up per-invocation, torn down before return.
 * Keeps all mmap'd regions together so cleanup is a single goto-chain.
 */
struct iour_ctx {
	int		fd;
	void		*sq_ring;
	void		*cq_ring;	/* may equal sq_ring if SINGLE_MMAP */
	void		*sqes;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;	/* 0 when SINGLE_MMAP */
	size_t		sqes_sz;
	bool		single_mmap;

	unsigned int	sq_entries;
	unsigned int	cq_entries;

	/* SQ ring field offsets within the mmap'd region. */
	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

	/* CQ ring field offsets within the mmap'd region. */
	unsigned int	cq_off_head;
	unsigned int	cq_off_tail;
	unsigned int	cq_off_mask;
	unsigned int	cq_off_cqes;
};

/*
 * Set up a private io_uring with the requested number of SQ entries.
 * Returns true on success; ctx is fully populated.  On failure, ctx is
 * zeroed (ctx->fd = -1) and no resources need freeing; errno is
 * preserved across the cleanup path so the caller can distinguish
 * io_uring_setup vs mmap failures.
 */
bool iour_setup(struct iour_ctx *ctx, unsigned int entries);

/*
 * Release every resource owned by ctx.  Idempotent: safe to call on a
 * zeroed/failed ctx, where every sentinel check short-circuits.
 */
void iour_teardown(struct iour_ctx *ctx);
