/*
 * Helpers for the blob-mutator engine.  Moved from blob_mutator.c:
 * position picker, splat-form value transforms, and the well-known
 * static-magic table the CMPDICT arm layers before its learned pull.
 * See args/pools/blob_mutator-internal.h for the shared contract.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator-internal.h"
#include "rnd.h"

/*
 * Pick one bounded byte position inside [0, len).  Returns 0 when
 * len == 0 (caller already gates on len, but the guard keeps a future
 * caller from tripping the rnd_modulo_u32(0) early return into a
 * silent always-zero position).
 */
size_t pick_pos(size_t len)
{
	if (len == 0)
		return 0;
	/*
	 * rnd_modulo_u32 takes a u32 bound; size_t can be wider but
	 * trinity ARG_BUF_SIZED sizes top out around 64 KiB so the
	 * cast is loss-free in practice.  Clamp to UINT32_MAX
	 * defensively in case a future caller passes a larger len.
	 */
	if (len > UINT32_MAX)
		return (size_t) rnd_modulo_u32(UINT32_MAX);
	return (size_t) rnd_modulo_u32((uint32_t) len);
}

/*
 * Well-known FS / binary-format header magics that a kernel parser
 * checks BEFORE the KCOV_TRACE_CMP-instrumented compare in the deeper
 * arm (ext4 / XFS / BTRFS / squashfs super-block sanity, ELF eident,
 * gzip member header).  The learned cmp_hints pool cannot bootstrap
 * these: the pre-parser gate rejects the buffer and the instrumented
 * compare downstream is never reached, so no learned constant ever
 * flows back into the pool for the arm to draw from.
 *
 * All entries are stored so that a little-endian splat of value at
 * width bytes reproduces the on-disk byte sequence the kernel checks
 * -- values for headers that are big-endian on disk (XFS) are pre-
 * byteswapped in the table so the same LE splat helper in
 * blob_cmpdict() consumes the entry unchanged.  Widths are restricted
 * to {1, 2, 4, 8} to fit that helper without a new byte-path.
 */
const struct blob_static_magic blob_static_magics[] = {
	/* EXT2/3/4 s_magic (include/uapi/linux/magic.h) -- LE on disk. */
	{ 0xEF53ULL,             2 },
	/* XFS_SB_MAGIC "XFSB" (fs/xfs/libxfs/xfs_format.h) -- big-endian
	 * on disk; byteswapped here so an LE splat writes the on-disk
	 * bytes 0x58 0x46 0x53 0x42. */
	{ 0x42534658ULL,         4 },
	/* BTRFS_MAGIC "_BHRfS_M" (include/uapi/linux/btrfs_tree.h) --
	 * LE splat writes 0x5F 0x42 0x48 0x52 0x66 0x53 0x5F 0x4D. */
	{ 0x4D5F53665248425FULL, 8 },
	/* SQUASHFS_MAGIC "hsqs" (include/uapi/linux/magic.h) -- LE. */
	{ 0x73717368ULL,         4 },
	/* ELF eident (include/uapi/linux/elf.h ELFMAG) -- LE splat writes
	 * 0x7f 'E' 'L' 'F'. */
	{ 0x464C457FULL,         4 },
	/* gzip member header (RFC 1952) -- LE splat writes 0x1f 0x8b. */
	{ 0x8B1FULL,             2 },
};

const size_t blob_static_magics_count =
	sizeof(blob_static_magics) / sizeof(blob_static_magics[0]);

/*
 * Draw one splat form for this iteration.  Eight-slot roll keeps
 * plain LE the majority arm (5/8 = 62.5%) with the three transform
 * arms sharing the remaining 3/8 (12.5% each).  The LE-plain slot
 * count is a deliberate choice: transforms are additive coverage,
 * not a replacement, and the well-known-magic table entries in
 * blob_static_magics[] are curated to satisfy the on-disk check
 * under an LE splat -- shifting the majority away from plain would
 * regress the static-magic hit-rate for a marginal gain elsewhere.
 */
enum blob_splat_form pick_splat_form(void)
{
	switch (rnd_modulo_u32(8)) {
	case 5:  return BLOB_SPLAT_BE;
	case 6:  return BLOB_SPLAT_PLUS_ONE;
	case 7:  return BLOB_SPLAT_MINUS_ONE;
	default: return BLOB_SPLAT_LE_PLAIN;
	}
}

/*
 * Width-bounded mask so ±1 arithmetic wraps in the operand size and
 * the BE arm ignores the upper bytes of an over-wide hint.  Width is
 * always one of {1, 2, 4, 8} on this path; width == 8 dodges the
 * 1<<64 undefined shift by returning all-ones directly.
 */
static uint64_t splat_width_mask(unsigned int width)
{
	if (width >= 8)
		return ~(uint64_t) 0;
	return (((uint64_t) 1) << (width * 8u)) - 1u;
}

/* Byte-reverse the low `width` bytes of v; upper bytes are dropped. */
static uint64_t splat_bswap(uint64_t v, unsigned int width)
{
	switch (width) {
	case 2:  return (uint64_t) __builtin_bswap16((uint16_t) v);
	case 4:  return (uint64_t) __builtin_bswap32((uint32_t) v);
	case 8:  return __builtin_bswap64(v);
	default: return v & 0xffu;
	}
}

uint64_t apply_splat_form(uint64_t v, unsigned int width,
			  enum blob_splat_form form)
{
	uint64_t mask = splat_width_mask(width);

	switch (form) {
	case BLOB_SPLAT_BE:
		return splat_bswap(v & mask, width);
	case BLOB_SPLAT_PLUS_ONE:
		return (v + 1u) & mask;
	case BLOB_SPLAT_MINUS_ONE:
		return (v - 1u) & mask;
	case BLOB_SPLAT_LE_PLAIN:
	default:
		return v & mask;
	}
}
