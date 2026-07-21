#pragma once

#include <stdint.h>
#include <sys/types.h>

/*
 * Canary file pool.
 *
 * Trinity has long defended against kernels that crash; it has not
 * defended against kernels that quietly mutate file content via a
 * code path that bypasses the file's normal write-side validation.
 * The symptom shape is: a syscall returns success, the kernel keeps
 * running, but a subsequent read of an unrelated file returns wrong
 * bytes.  No splat, no taint, nothing for the existing oracles to
 * latch on.
 *
 * The canary pool is a small set of files whose content trinity
 * itself owns end-to-end and whose bytes are deterministic at every
 * (file_idx, offset).  A separate verifier childop re-reads the
 * pool periodically and asserts byte-for-byte equality with the
 * expected pattern.  Any divergence is logged loudly and counted
 * via shm->stats.diag.pagecache_canary_corrupt_caught.
 *
 * The pool is registered as an fd_provider so trinity's existing
 * splice/mmap/sendfile dispatch can pick canary fds at random as
 * SOURCES.  Every entry is opened O_RDONLY and tagged with
 * OBJ_FLAG_NO_WRITE so the natural defence (kernel returns EBADF
 * for write/splice-out/sendfile-out/copy_file_range-out/ftruncate/
 * fallocate against an O_RDONLY fd) keeps the pool's contents
 * stable through normal trinity write-side syscall picks.  Any
 * mutation that gets through is, by construction, a kernel bug in
 * the class this oracle exists to catch.
 */

/*
 * Per-fileobj flag word bit.  Set on every canary entry by
 * fds/canary.c::init_canary_fds().  Reserved for future write-side
 * fd dispatch filtering (a syscall picker that asks for "an fd I'm
 * about to write to" can skip entries with this bit set instead of
 * relying on the O_RDONLY EBADF backstop).  Bit 0; remaining bits
 * are unallocated.
 */
#define OBJ_FLAG_NO_WRITE	(1u << 0)

#define NR_CANARY_FILES		8

/*
 * Deterministic mixer that computes the expected byte at a given
 * (file_idx, offset).  Pure function — no shared state, no PRNG, no
 * dependency on rand()/random()/getrandom().  The verifier and the
 * file-creation path both call this and so always agree on the
 * expected pattern without coordinating through memory.
 *
 * Implementation is the Murmur3 64-bit finaliser applied to a
 * (file_idx, offset) seed.  Suitable for byte-level uniqueness
 * across the (file_idx, offset) product up to billions of bytes;
 * not cryptographic and not intended to be.
 */
static inline uint8_t canary_finalize_byte(uint64_t k)
{
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccdULL;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53ULL;
	k ^= k >> 33;
	return (uint8_t)k;
}

static inline uint8_t canary_expected_byte(unsigned int file_idx,
					   off_t offset)
{
	return canary_finalize_byte(((uint64_t)file_idx << 40) ^
				    (uint64_t)offset);
}

struct canary_file_info {
	const char *path;	/* shared-string absolute path, NUL terminated */
	size_t      size;	/* exact byte count written at init */
	unsigned int idx;	/* index handed to canary_expected_byte() */
};

/*
 * Lookup the per-file metadata for a canary slot.  Returns NULL for
 * out-of-range indices or before init_canary_fds() has populated the
 * pool.  The returned pointer is into shared memory and is valid for
 * the lifetime of the run.
 */
const struct canary_file_info *canary_file_get(unsigned int idx);

/*
 * Number of canary files actually created.  May be less than
 * NR_CANARY_FILES if the init path failed partway (filesystem
 * full, permissions, etc.).  Zero if init failed entirely.
 */
unsigned int canary_pool_size(void);
