#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fill `buf[0..sz)` with the 8-byte pattern in `seed`, repeated.  If
 * `seed` is 0, generate one via rnd_u64().  Returns the seed actually
 * used so the caller can stash it for a matching check_output_struct
 * call after the syscall returns.
 */
uint64_t poison_output_struct(void *buf, size_t sz, uint64_t seed);

/*
 * Return true iff every byte of `buf[0..sz)` still equals the byte the
 * matching poison_output_struct(seed) would have written there.
 */
bool check_output_struct(const void *buf, size_t sz, uint64_t seed);

/*
 * Guarded variant of check_output_struct() for user pointers.  Snapshots
 * sz bytes from `user` into a stack-local copy via post_snapshot_or_skip
 * -- the same readability + sigsetjmp bracket the other post handlers
 * use for user reads -- then runs check_output_struct on the copy.  A
 * post handler calling check_output_struct() directly on snap->field
 * TOCTOU-faults on the buffer it inspects when a sibling munmap of the
 * writable-pool page slips in between syscall return and the compare;
 * this helper degrades that window to a skipped sample.
 *
 * Returns true iff the snapshot succeeded AND every byte matches the
 * poison pattern for `seed` -- the "kernel returned success but wrote
 * zero bytes" signal callers bump against shm->stats.post_handler_
 * untouched_out_buf.  Returns false on an unprovable-readable user
 * range, a sigsetjmp-recovered fault, or a genuine mismatch; the
 * caller cannot distinguish skip from mismatch, and must not deref
 * `user` on a false return.
 *
 * `sz` is capped at CHECK_OUTPUT_STRUCT_SNAP_MAX; a larger request
 * returns false rather than truncating the check.  The cap is set well
 * above every poison-oracle out-buffer in the tree today.
 */
#define CHECK_OUTPUT_STRUCT_SNAP_MAX 512
bool check_output_struct_user_or_skip(const void *user, size_t sz,
				      uint64_t seed);
