/*
 * Block-scoped HAVOC arms.  Moved from blob_mutator.c.
 * See args/pools/blob_mutator-internal.h for the shared contract and
 * the BLOB_HAVOC_BLOCK_MAX cap on the per-arm run length.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blob_mutator-internal.h"
#include "rnd.h"

/*
 * HAVOC arm: memset a bounded run to 0x00 or 0xff.  All-zero clears
 * an optional-field TLV to its terminator; all-ones is the classic
 * "unset" pattern (-1 as a signed length, MAX as a bitmap) that
 * parsers often special-case.  Run length is clamped so start + run
 * <= len and run <= BLOB_HAVOC_BLOCK_MAX.
 */
void havoc_memset_block(unsigned char *buf, size_t len)
{
	size_t pos;
	size_t max_run;
	size_t run;
	unsigned char val;

	if (len == 0)
		return;

	val = (rnd_u32() & 1u) ? 0xffu : 0x00u;
	pos = pick_pos(len);

	max_run = len - pos;
	if (max_run > BLOB_HAVOC_BLOCK_MAX)
		max_run = BLOB_HAVOC_BLOCK_MAX;
	/* max_run is at least 1 here: pos < len from pick_pos, so
	 * len - pos >= 1. */
	run = 1u + rnd_modulo_u32((uint32_t) max_run);

	memset(buf + pos, val, run);
}

/*
 * HAVOC arm: copy a bounded region over another region inside the
 * same buffer (self-splice).  Builds the repeated / nested structure
 * that fresh-random FILL never produces on its own -- repeating a
 * header field, duplicating a TLV entry, or aliasing a length field
 * to a body field.  memmove() handles overlap safely; when src and
 * dst are the same position the write is a no-op which is harmless.
 * Run length is clamped so both src + run <= len and dst + run <= len
 * and run <= BLOB_HAVOC_BLOCK_MAX.
 */
void havoc_splice_copy(unsigned char *buf, size_t len)
{
	size_t max_run;
	size_t run;
	size_t src;
	size_t dst;

	/* Need at least two bytes to have a meaningful copy target that
	 * differs from the source; splice on a one-byte buffer collapses
	 * to a no-op at best. */
	if (len < 2)
		return;

	max_run = len;
	if (max_run > BLOB_HAVOC_BLOCK_MAX)
		max_run = BLOB_HAVOC_BLOCK_MAX;
	run = 1u + rnd_modulo_u32((uint32_t) max_run);
	if (run > len)
		run = len;

	/* pos in [0, len - run]; +1 makes the range inclusive. */
	src = (size_t) rnd_modulo_u32((uint32_t)(len - run) + 1u);
	dst = (size_t) rnd_modulo_u32((uint32_t)(len - run) + 1u);

	memmove(buf + dst, buf + src, run);
}

/*
 * HAVOC arm: swap two non-overlapping regions inside the buffer.
 * Different from splice-copy: swap preserves both original byte
 * sequences (just at different offsets), so it builds the "same
 * bytes, wrong position" mutation class (mis-ordered TLV entries,
 * transposed header fields) rather than the "same bytes duplicated"
 * class.  Byte-by-byte with a scratch byte -- no hot-path heap.
 * Overlapping picks are skipped rather than fixed up: the swap
 * semantic is only well-defined when a and b are disjoint, and any
 * fix-up here would just re-roll into a distribution the caller
 * already samples on the next iteration.
 */
void havoc_swap_regions(unsigned char *buf, size_t len)
{
	size_t max_run;
	size_t run;
	size_t a;
	size_t b;
	size_t i;

	/* Two disjoint one-byte regions require len >= 2. */
	if (len < 2)
		return;

	max_run = len / 2u;
	if (max_run > BLOB_HAVOC_BLOCK_MAX)
		max_run = BLOB_HAVOC_BLOCK_MAX;
	run = 1u + rnd_modulo_u32((uint32_t) max_run);

	a = (size_t) rnd_modulo_u32((uint32_t)(len - run) + 1u);
	b = (size_t) rnd_modulo_u32((uint32_t)(len - run) + 1u);
	if (a == b)
		return;
	if (a < b) {
		if (a + run > b)
			return;
	} else {
		if (b + run > a)
			return;
	}

	for (i = 0; i < run; i++) {
		unsigned char t = buf[a + i];

		buf[a + i] = buf[b + i];
		buf[b + i] = t;
	}
}
