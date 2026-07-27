#pragma once

/*
 * Internal contract shared across the blob-mutator TU family in
 * args/pools/blob_mutator*.c.  Public callers use include/blob_mutator.h;
 * everything here is engine-internal (arm functions, splat helpers,
 * static-magic table) split out of the original single blob_mutator.c
 * for readability.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Cap on the run length of the block-scoped HAVOC arms (memset run,
 * splice copy, region swap).  Kept small so total worst-case bytes
 * touched per blob_fill() stays O(BLOB_HAVOC_MAX_OPS *
 * BLOB_HAVOC_BLOCK_MAX) -- 64 * 64 = 4 KiB, comfortably below any
 * ARG_BUF_SIZED allocation.  Bounded independent of len.
 */
#define BLOB_HAVOC_BLOCK_MAX	64u

/*
 * Splat-form arms drawn per iteration inside the CMPDICT loop.  See
 * apply_splat_form() / pick_splat_form() in blob_mutator_helpers.c for
 * the per-arm rationale and the majority-LE arm-selection weighting.
 */
enum blob_splat_form {
	BLOB_SPLAT_LE_PLAIN,
	BLOB_SPLAT_BE,
	BLOB_SPLAT_PLUS_ONE,
	BLOB_SPLAT_MINUS_ONE,
};

/*
 * Well-known FS / binary-format header magics that the CMPDICT arm
 * splats into the buffer prefix ahead of any learned cmp_hints pull.
 * See blob_mutator_helpers.c for the table and the on-disk-encoding
 * notes per entry.
 */
struct blob_static_magic {
	uint64_t value;
	unsigned int width;
};

extern const struct blob_static_magic blob_static_magics[];
extern const size_t blob_static_magics_count;

/* Position / value helpers.  pick_pos draws one RNG value; pick_splat_form
 * draws one; the splat_* value transforms are RNG-neutral. */
size_t pick_pos(size_t len);
enum blob_splat_form pick_splat_form(void);
uint64_t apply_splat_form(uint64_t v, unsigned int width,
			  enum blob_splat_form form);

/* Byte + bit flipper arms (blob_mutator_flip.c). */
void havoc_bit_flip(unsigned char *buf, size_t len);
void havoc_byte_flip(unsigned char *buf, size_t len);
void havoc_set_interesting(unsigned char *buf, size_t len, unsigned int width);

/* Block-scoped arms (blob_mutator_block.c). */
void havoc_memset_block(unsigned char *buf, size_t len);
void havoc_splice_copy(unsigned char *buf, size_t len);
void havoc_swap_regions(unsigned char *buf, size_t len);
