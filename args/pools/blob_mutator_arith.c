/*
 * Arithmetic / length-oriented HAVOC arms.  Moved from blob_mutator.c.
 * See args/pools/blob_mutator-internal.h for the shared contract.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator-internal.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * HAVOC arm: add or subtract a small magnitude (1..35) to a byte /
 * word / dword at a bounded position, wrapping at width.  Targets
 * length / counter / index fields the plain byte-flip arms tend to
 * push far outside any parser-accepted range; small deltas walk the
 * boundary neighbourhood of whatever value is already there.  Width
 * must be one of {1, 2, 4}; the little-endian in-place read/modify/
 * write matches the LE splat style the CMPDICT arm uses.
 */
void havoc_arith(unsigned char *buf, size_t len,
		 unsigned int width, bool sub)
{
	uint64_t v;
	unsigned int mag;
	size_t pos;
	size_t max_pos;

	if (len == 0)
		return;

	if (width != 1 && width != 2 && width != 4)
		width = 1;
	if (width > len)
		width = 1;

	max_pos = len - width;
	if (max_pos == 0)
		pos = 0;
	else if (max_pos > UINT32_MAX)
		pos = (size_t) rnd_modulo_u32(UINT32_MAX);
	else
		pos = (size_t) rnd_modulo_u32((uint32_t) max_pos + 1u);

	/* AFL-style [1..35] magnitude keeps the delta below the size of
	 * any single byte and inside the "off-by-a-few" neighbourhood of
	 * length / counter fields. */
	mag = 1u + rnd_modulo_u32(35);

	switch (width) {
	case 1:
		v = buf[pos];
		break;
	case 2:
		v = (uint64_t) buf[pos]
		  | ((uint64_t) buf[pos + 1] << 8);
		break;
	case 4:
	default:
		v = (uint64_t) buf[pos]
		  | ((uint64_t) buf[pos + 1] << 8)
		  | ((uint64_t) buf[pos + 2] << 16)
		  | ((uint64_t) buf[pos + 3] << 24);
		break;
	}

	if (sub)
		v -= (uint64_t) mag;
	else
		v += (uint64_t) mag;

	switch (width) {
	case 1:
		buf[pos] = (unsigned char) (v & 0xffu);
		break;
	case 2:
		buf[pos]     = (unsigned char) (v & 0xffu);
		buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
		break;
	case 4:
	default:
		buf[pos]     = (unsigned char) (v & 0xffu);
		buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
		buf[pos + 2] = (unsigned char) ((v >> 16) & 0xffu);
		buf[pos + 3] = (unsigned char) ((v >> 24) & 0xffu);
		break;
	}
}

/*
 * HAVOC arm: stamp a plausible length / size value at the buffer
 * prefix (offset 0).  Many kernel parsers gate on a leading length or
 * size field at offset 0 (TLV entry length, netlink attribute nla_len,
 * on-wire packet-header size fields).  The uniform per-byte havoc arms
 * almost never land a plausible length there, so the length-gated
 * parse path downstream of that check stays cold.  This arm writes a
 * width w in {1, 2, 4, 8} (clamped so w <= len) at offset 0, choosing
 * a candidate biased toward buffer-relative values (len itself, len±1,
 * len/2, 0, a small int, or a draw from the interesting-numbers pool
 * for the classic ULONG_MAX / INT_MIN / INT_MAX boundary sentinels)
 * so the prefix satisfies the "length matches or bounds the buffer"
 * contract at least some of the time.  Endianness is coin-flipped
 * LE/BE per iteration -- the on-wire surface is a mix of both, and a
 * plain LE arm alone would miss every BE-gated parser.  Bounded, in-
 * place, O(1): writes only within [0, w) which is inside [0, len) by
 * construction, so a broken bound trips the same guard-byte
 * self-check the other block-scoped arms are covered by.
 */
void havoc_prefix_len(unsigned char *buf, size_t len)
{
	unsigned int width;
	uint64_t v;
	bool be;

	if (len == 0)
		return;

	switch (rnd_modulo_u32(4)) {
	case 0:  width = 1; break;
	case 1:  width = 2; break;
	case 2:  width = 4; break;
	default: width = 8; break;
	}
	if ((size_t) width > len)
		width = 1;

	/* Uniform pick over eight length candidates.  The first four are
	 * buffer-relative (satisfy the "length matches the buffer" gate);
	 * the small-int and interesting-numbers arms cover the "length
	 * field is a sentinel" gate parsers use as a terminator or
	 * unbounded marker. */
	switch (rnd_modulo_u32(8)) {
	case 0:  v = (uint64_t) len; break;
	case 1:  v = (uint64_t) len + 1u; break;
	case 2:  v = (uint64_t) len - 1u; break;
	case 3:  v = (uint64_t) len / 2u; break;
	case 4:  v = 0; break;
	case 5:  v = 1u + (uint64_t) rnd_modulo_u32(16u); break;
	case 6:  v = (uint64_t) get_boundary_value(); break;
	default: v = (uint64_t) get_interesting_value(); break;
	}

	be = (rnd_u32() & 1u) != 0u;

	switch (width) {
	case 1:
		buf[0] = (unsigned char) (v & 0xffu);
		break;
	case 2: {
		uint16_t x = (uint16_t) v;

		if (be) {
			buf[0] = (unsigned char) ((x >> 8) & 0xffu);
			buf[1] = (unsigned char) (x & 0xffu);
		} else {
			buf[0] = (unsigned char) (x & 0xffu);
			buf[1] = (unsigned char) ((x >> 8) & 0xffu);
		}
		break;
	}
	case 4: {
		uint32_t x = (uint32_t) v;

		if (be) {
			buf[0] = (unsigned char) ((x >> 24) & 0xffu);
			buf[1] = (unsigned char) ((x >> 16) & 0xffu);
			buf[2] = (unsigned char) ((x >> 8) & 0xffu);
			buf[3] = (unsigned char) (x & 0xffu);
		} else {
			buf[0] = (unsigned char) (x & 0xffu);
			buf[1] = (unsigned char) ((x >> 8) & 0xffu);
			buf[2] = (unsigned char) ((x >> 16) & 0xffu);
			buf[3] = (unsigned char) ((x >> 24) & 0xffu);
		}
		break;
	}
	case 8: {
		uint64_t x = v;

		if (be) {
			buf[0] = (unsigned char) ((x >> 56) & 0xffu);
			buf[1] = (unsigned char) ((x >> 48) & 0xffu);
			buf[2] = (unsigned char) ((x >> 40) & 0xffu);
			buf[3] = (unsigned char) ((x >> 32) & 0xffu);
			buf[4] = (unsigned char) ((x >> 24) & 0xffu);
			buf[5] = (unsigned char) ((x >> 16) & 0xffu);
			buf[6] = (unsigned char) ((x >> 8) & 0xffu);
			buf[7] = (unsigned char) (x & 0xffu);
		} else {
			buf[0] = (unsigned char) (x & 0xffu);
			buf[1] = (unsigned char) ((x >> 8) & 0xffu);
			buf[2] = (unsigned char) ((x >> 16) & 0xffu);
			buf[3] = (unsigned char) ((x >> 24) & 0xffu);
			buf[4] = (unsigned char) ((x >> 32) & 0xffu);
			buf[5] = (unsigned char) ((x >> 40) & 0xffu);
			buf[6] = (unsigned char) ((x >> 48) & 0xffu);
			buf[7] = (unsigned char) ((x >> 56) & 0xffu);
		}
		break;
	}
	}
}
