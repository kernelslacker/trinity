/*
 * Byte + bit flipper HAVOC arms.
 * See args/pools/blob_mutator-internal.h for the shared contract.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator-internal.h"
#include "rnd.h"
#include "sanitise.h"

/* HAVOC arm: flip exactly one bit somewhere in [0, len). */
void havoc_bit_flip(unsigned char *buf, size_t len)
{
	size_t pos = pick_pos(len);
	unsigned int bit = rnd_modulo_u32(8);

	buf[pos] ^= (unsigned char) (1u << bit);
}

/* HAVOC arm: replace one byte with a fresh random byte. */
void havoc_byte_flip(unsigned char *buf, size_t len)
{
	size_t pos = pick_pos(len);

	buf[pos] = (unsigned char) rnd_u32();
}

/*
 * HAVOC arm: stamp an interesting byte / word / dword / qword at a
 * bounded position.  width is the operand size in bytes (1, 2, 4, or
 * 8) -- the four sizes the KCOV_TRACE_CMP collector records, so the
 * stamp lands at a width the kernel's cmp instruction actually reads
 * against.  The stamp is clamped so that pos + width <= len -- a
 * width that does not fit is degraded to a single-byte stamp.
 */
void havoc_set_interesting(unsigned char *buf, size_t len,
			   unsigned int width)
{
	unsigned long val;
	size_t pos;
	size_t max_pos;

	/* An empty buffer has nothing to mutate; returning also avoids the
	 * len - width underflow to SIZE_MAX below. */
	if (len == 0)
		return;

	if (width != 1 && width != 2 && width != 4 && width != 8)
		width = 1;
	if (width > len)
		width = 1;

	max_pos = len - width;
	/* Full-width u64 draw so any pos in [0, max_pos] is reachable; an
	 * earlier version clamped to rnd_modulo_u32(UINT32_MAX) on the
	 * max_pos > UINT32_MAX branch, silently biasing away from the tail.
	 * +1 because the position is inclusive of max_pos. */
	pos = (size_t) rnd_modulo_u64((uint64_t) max_pos + 1u);

	/* Mix the two interesting-numbers pools so HAVOC reaches both
	 * the boundary table (ULONG_MAX, INT_MIN, ...) and the broader
	 * interesting-values table. */
	val = (rnd_u32() & 1u) ? get_boundary_value() : get_interesting_value();

	blob_store_le(buf + pos, width, (uint64_t) val);
}
