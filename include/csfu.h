#pragma once

#include <stddef.h>

/*
 * copy_struct_from_user() bucket-aware userspace struct builder.
 *
 * A growing family of Linux syscalls takes a (struct __user *, size_t
 * usize) pair and marshals it through copy_struct_from_user(dst,
 * ksize, src, usize).  Members of that family include openat2,
 * clone3, mount_setattr, the landlock_* set, sched_setattr,
 * and statmount.
 *
 * The kernel-side contract has five distinct usize-vs-ksize buckets,
 * each exercising a different validator path:
 *
 *   UNDERSIZE         usize <  ksize   (kernel zero-pads forward;
 *                                       some ABIs accept, some reject)
 *   EXACT             usize == ksize   (canonical, no slack involved)
 *   OVERSIZE_ZERO     usize >  ksize, every tail byte zero  (accepted)
 *   OVERSIZE_NONZERO  usize >  ksize, tail filled with garbage (-E2BIG)
 *   TAIL_MISMATCH     usize >  ksize, single stray nonzero byte at a
 *                                     weird offset inside the declared
 *                                     tail (boundary fuzz on the
 *                                     check_zeroed_user loop)
 *
 * Centralising bucket selection here lets every CSFU-shaped ABI hit
 * all five with one helper call, instead of each syscall sanitiser
 * open-coding its own (typically partial) distribution.
 */

enum csfu_bucket {
	CSFU_BUCKET_UNDERSIZE,
	CSFU_BUCKET_EXACT,
	CSFU_BUCKET_OVERSIZE_ZERO,
	CSFU_BUCKET_OVERSIZE_NONZERO,
	CSFU_BUCKET_TAIL_MISMATCH,
	CSFU_NR_BUCKETS,
};

/*
 * Descriptor for one CSFU-shaped kernel struct.  Each consumer
 * defines a file-scope const literal, e.g.
 *   static const struct csfu_desc desc_openat2 = {
 *       .name = "open_how", .ksize = sizeof(struct open_how),
 *   };
 * and passes its address to build_csfu_struct().
 */
struct csfu_desc {
	const char *name;
	size_t ksize;
	/*
	 * Curated UNDERSIZE pool.  If non-NULL, the UNDERSIZE bucket
	 * draws from this set instead of [0, ksize).  Used by
	 * ABI-versioned consumers (clone3, landlock, mount_setattr)
	 * that have meaningful pre-ksize sizes (e.g.
	 * CLONE_ARGS_SIZE_VER0 / VER1 / VER2).
	 */
	const size_t *known_sizes;
	size_t n_known_sizes;
};

/*
 * Result handed back to the caller: a zeroed heap buffer of at least
 * @desc->ksize bytes (with extra tail slack for the OVERSIZE_* and
 * TAIL_MISMATCH buckets), the chosen @usize to pass to the syscall,
 * and the bucket that was rolled (for tracing / future stats).
 *
 * Ownership: @ptr comes from zmalloc_tracked() and is intended to
 * flow through the existing deferred_free_enqueue() path, matching
 * the cleanup convention already used by the openat2 / clone3 / bpf
 * sanitisers.  No csfu_free() exists by design -- there is one
 * authoritative release path (deferred-free) and the helper does not
 * duplicate it.
 */
struct csfu_buf {
	void *ptr;
	size_t buflen;
	size_t usize;
	enum csfu_bucket bucket;
};

struct csfu_buf build_csfu_struct(const struct csfu_desc *desc);
