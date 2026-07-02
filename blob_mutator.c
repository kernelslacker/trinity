/*
 * --blob-mutator: content-authoring lane for opaque ARG_BUF_SIZED args.
 *
 * See include/blob_mutator.h for the per-mode contract.  This TU is
 * the engine implementation -- the parse / wire-up sites are in
 * params.c and generate-args.c.
 *
 * RNG discipline: every random draw routes through rnd_u32 /
 * rnd_modulo_u32 (Lemire-debiased, splitmix64-backed) declared in
 * include/rnd.h.  libc rand() is forbidden on this path -- enforced
 * by scripts/check-static/no-libc-rand.sh.
 *
 * OFF (engine-level off, no write), FILL (generate_rand_bytes into
 * the owned buffer), HAVOC (FILL plus a bounded byte-mutation pass:
 * bit-flip / byte-flip / set-interesting byte+word+dword, capped at
 * BLOB_HAVOC_MAX_OPS), CMPDICT (HAVOC plus a bounded buffer-redqueen
 * pass capped at BLOB_CMPDICT_MAX_INSERTS: each iteration coin-flips
 * between a built-in well-known-magic table and the learned per-nr
 * cmp-hint pool via cmp_hints_try_get, then applies one of four
 * splat forms -- plain little-endian in the majority, plus three
 * transform arms {big-endian, value+1, value-1} for endian and
 * boundary coverage -- and writes the result into the buffer at a
 * random offset).
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator.h"
#include "cmp_hints.h"
#include "debug.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

enum blob_mutator_mode blob_mutator_mode = BLOB_MUTATOR_OFF;

/*
 * Pick one bounded byte position inside [0, len).  Returns 0 when
 * len == 0 (caller already gates on len, but the guard keeps a future
 * caller from tripping the rnd_modulo_u32(0) early return into a
 * silent always-zero position).
 */
static size_t pick_pos(size_t len)
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

/* HAVOC arm: flip exactly one bit somewhere in [0, len). */
static void havoc_bit_flip(unsigned char *buf, size_t len)
{
	size_t pos = pick_pos(len);
	unsigned int bit = rnd_modulo_u32(8);

	buf[pos] ^= (unsigned char) (1u << bit);
}

/* HAVOC arm: replace one byte with a fresh random byte. */
static void havoc_byte_flip(unsigned char *buf, size_t len)
{
	size_t pos = pick_pos(len);

	buf[pos] = (unsigned char) rnd_u32();
}

/*
 * HAVOC arm: stamp an interesting byte / word / dword at a bounded
 * position.  width is the operand size in bytes (1, 2, or 4); the
 * stamp is clamped so that pos + width <= len -- a width that does
 * not fit is degraded to a single-byte stamp.
 */
static void havoc_set_interesting(unsigned char *buf, size_t len,
				  unsigned int width)
{
	unsigned long val;
	size_t pos;
	size_t max_pos;

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
		/* +1 because the position is inclusive of max_pos. */
		pos = (size_t) rnd_modulo_u32((uint32_t) max_pos + 1u);

	/* Mix the two interesting-numbers pools so HAVOC reaches both
	 * the boundary table (ULONG_MAX, INT_MIN, ...) and the broader
	 * interesting-values table. */
	val = (rnd_u32() & 1u) ? get_boundary_value() : get_interesting_value();

	switch (width) {
	case 1:
		buf[pos] = (unsigned char) val;
		break;
	case 2: {
		uint16_t v = (uint16_t) val;
		buf[pos]     = (unsigned char) (v & 0xffu);
		buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		buf[pos]     = (unsigned char) (v & 0xffu);
		buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
		buf[pos + 2] = (unsigned char) ((v >> 16) & 0xffu);
		buf[pos + 3] = (unsigned char) ((v >> 24) & 0xffu);
		break;
	}
	}
}

/*
 * Bounded havoc pass.  Op count is drawn from [1, BLOB_HAVOC_MAX_OPS]
 * so the worst case is bounded independent of len.  Each iteration
 * picks one of the five arms with uniform probability.  Returns the
 * number of ops applied so the caller can attribute the count to the
 * blob_havoc_ops shadow counter.
 */
static unsigned int blob_havoc(unsigned char *buf, size_t len)
{
	unsigned int n_ops;
	unsigned int i;

	if (len == 0)
		return 0;

	n_ops = 1u + rnd_modulo_u32(BLOB_HAVOC_MAX_OPS);

	for (i = 0; i < n_ops; i++) {
		switch (rnd_modulo_u32(5)) {
		case 0:
			havoc_bit_flip(buf, len);
			break;
		case 1:
			havoc_byte_flip(buf, len);
			break;
		case 2:
			havoc_set_interesting(buf, len, 1);
			break;
		case 3:
			havoc_set_interesting(buf, len, 2);
			break;
		default:
			havoc_set_interesting(buf, len, 4);
			break;
		}
	}
	return n_ops;
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
struct blob_static_magic {
	uint64_t value;
	unsigned int width;
};

static const struct blob_static_magic blob_static_magics[] = {
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

/*
 * Splat-form arms drawn per iteration inside the CMPDICT loop.  The
 * majority draw stays plain little-endian; the three transform arms
 * are additive coverage for the {LE-only, exact-value} blind spot the
 * baseline splat has:
 *
 *   BE          -- byte-reverse to width.  The heavy netlink / socket
 *                  / on-wire surface trinity fuzzes checks big-endian
 *                  fields (family/version u16, port u16, netlink
 *                  attribute headers), so a raw LE splat of an ORed-
 *                  in-from-the-cmp-pool constant can never satisfy a
 *                  BE compare.
 *   PLUS_ONE    -- (value + 1) at width, wrapping.  Off-by-one over
 *                  a length/size/offset constant is a well-known
 *                  boundary that the exact splat misses by
 *                  construction.
 *   MINUS_ONE   -- (value - 1) at width, wrapping.  Symmetric
 *                  boundary neighbour; on unsigned constants that
 *                  hit zero this wraps to the width-full UINT_MAX
 *                  which is itself an interesting boundary value.
 *
 * A width-1 BE splat is arithmetically the same as the LE-plain
 * splat; it is still selected and still bumps the transform counter
 * so the arm-selection distribution stays observable.
 */
enum blob_splat_form {
	BLOB_SPLAT_LE_PLAIN,
	BLOB_SPLAT_BE,
	BLOB_SPLAT_PLUS_ONE,
	BLOB_SPLAT_MINUS_ONE,
};

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
static enum blob_splat_form pick_splat_form(void)
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

static uint64_t apply_splat_form(uint64_t v, unsigned int width,
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

/*
 * CMPDICT arm: splat one bounded cmp-source into the buffer per
 * iteration, at a random offset.  Insert count is drawn from
 * [1, BLOB_CMPDICT_MAX_INSERTS] so the worst case is bounded
 * independent of len and of how rich the source is.
 *
 * Two sources.  Each iteration coin-flips (rnd_u32() & 1u) between
 * (a) the built-in blob_static_magics[] table -- one uniformly-picked
 * entry with a fixed width baked into the entry -- and (b) the
 * learned per-nr cmp_hints pool -- one cmp_hints_try_get(nr, do32,
 * ...) pull with a width drawn from {1, 2, 4, 8}.  A static draw
 * whose baked width does not fit len falls back to the learned path
 * silently; a learned pull that misses (empty pool, chaos-
 * suppressed, corrupted) is skipped silently.  Neither miss bumps a
 * counter so both blob_dict_inserts and blob_static_magic_inserts
 * measure committed splats, not attempts.
 *
 * Every commit then draws one splat form via pick_splat_form(): the
 * majority arm is plain little-endian (matches the baseline that
 * blob_static_magics[] is curated against); the minority arms are
 * big-endian byte-swap and value ± 1 at width for endian coverage
 * on wire-format surface and off-by-one boundary neighbours.  The
 * transform is applied AFTER the width ladder resolves, so the
 * bounds contract (pos + width <= len) is unaffected.  A transform
 * commit bumps blob_dict_transform_inserts in addition to the
 * source-side counter, giving the transform-vs-plain ratio without
 * disturbing the existing static-vs-learned ratio.
 *
 * Every write is clamped so pos + width <= len; on the learned arm,
 * widths that do not fit in len degrade down the {8, 4, 2, 1} ladder
 * until they do (a len of 0 is rejected by the caller, so the worst
 * case here is len == 1 which forces a single-byte splat).  The
 * static arm does not degrade because the baked width is part of the
 * magic -- a truncated header magic would not satisfy the pre-parser
 * check the entry exists to satisfy.  Returns the number of committed
 * learned-pool inserts through the return value, the number of
 * committed static-table inserts through *static_committed_out, and
 * the count of committed splats that used a non-plain transform
 * arm (across both sources) through *transform_committed_out so the
 * caller can credit blob_dict_inserts, blob_static_magic_inserts,
 * and blob_dict_transform_inserts respectively.
 */
static unsigned int blob_cmpdict(unsigned char *buf, size_t len,
				 unsigned int nr, bool do32,
				 unsigned int *static_committed_out,
				 unsigned int *transform_committed_out)
{
	unsigned int n_inserts;
	unsigned int committed = 0;
	unsigned int static_committed = 0;
	unsigned int transform_committed = 0;
	unsigned int i;

	*static_committed_out = 0;
	*transform_committed_out = 0;
	if (len == 0)
		return 0;

	n_inserts = 1u + rnd_modulo_u32(BLOB_CMPDICT_MAX_INSERTS);

	for (i = 0; i < n_inserts; i++) {
		unsigned long hint;
		uint64_t v;
		unsigned int width;
		size_t pos;
		size_t max_pos;
		enum blob_splat_form form;
		bool from_static = false;

		/* Source coin-flip.  When the static arm is picked and
		 * the entry fits, take it; otherwise (arm not picked, or
		 * baked width > len) fall through to the learned pool so
		 * short buffers still get some coverage. */
		if (rnd_u32() & 1u) {
			const struct blob_static_magic *m =
				&blob_static_magics[rnd_modulo_u32(
					ARRAY_SIZE(blob_static_magics))];

			if (m->width <= len) {
				hint = (unsigned long) m->value;
				width = m->width;
				from_static = true;
			}
		}

		if (!from_static) {
			if (!cmp_hints_try_get(nr, do32, &hint))
				continue;

			/* Width ladder: pick uniformly from {1, 2, 4, 8}
			 * then degrade if the chosen width does not fit
			 * in len.  The degrade walks down the same ladder
			 * so a len=3 buffer accepts width 2 or 1, never
			 * the constructed-mid value of 3 (which would
			 * expose a partial 32-bit stamp). */
			switch (rnd_modulo_u32(4)) {
			case 0:  width = 1; break;
			case 1:  width = 2; break;
			case 2:  width = 4; break;
			default: width = 8; break;
			}
			while (width > len)
				width >>= 1;
		}
		/* width is now in {1, 2, 4, 8} and <= len. */

		max_pos = len - width;
		if (max_pos == 0)
			pos = 0;
		else if (max_pos > UINT32_MAX)
			pos = (size_t) rnd_modulo_u32(UINT32_MAX);
		else
			pos = (size_t) rnd_modulo_u32((uint32_t) max_pos + 1u);

		/* Apply the splat-form transform (plain LE in the
		 * majority, else BE / ±1 at width).  Transform is
		 * value-only; bounds are already resolved above. */
		form = pick_splat_form();
		v = apply_splat_form((uint64_t) hint, width, form);

		/* Little-endian splat of the (possibly transformed) value.
		 * Safe by construction: width is <= len and pos <=
		 * len - width, so pos + width <= len. */
		switch (width) {
		case 1:
			buf[pos] = (unsigned char) (v & 0xffu);
			break;
		case 2:
			buf[pos]     = (unsigned char) (v & 0xffu);
			buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
			break;
		case 4:
			buf[pos]     = (unsigned char) (v & 0xffu);
			buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
			buf[pos + 2] = (unsigned char) ((v >> 16) & 0xffu);
			buf[pos + 3] = (unsigned char) ((v >> 24) & 0xffu);
			break;
		case 8:
			buf[pos]     = (unsigned char) (v & 0xffu);
			buf[pos + 1] = (unsigned char) ((v >> 8) & 0xffu);
			buf[pos + 2] = (unsigned char) ((v >> 16) & 0xffu);
			buf[pos + 3] = (unsigned char) ((v >> 24) & 0xffu);
			buf[pos + 4] = (unsigned char) ((v >> 32) & 0xffu);
			buf[pos + 5] = (unsigned char) ((v >> 40) & 0xffu);
			buf[pos + 6] = (unsigned char) ((v >> 48) & 0xffu);
			buf[pos + 7] = (unsigned char) ((v >> 56) & 0xffu);
			break;
		}
		if (from_static)
			static_committed++;
		else
			committed++;
		if (form != BLOB_SPLAT_LE_PLAIN)
			transform_committed++;
	}
	*static_committed_out = static_committed;
	*transform_committed_out = transform_committed;
	return committed;
}

void blob_fill(unsigned char *buf, size_t len, unsigned int nr, bool do32)
{
	enum blob_mutator_mode mode;
	unsigned int n;

	if (buf == NULL || len == 0)
		return;

	mode = __atomic_load_n(&blob_mutator_mode, __ATOMIC_RELAXED);
	if (mode == BLOB_MUTATOR_OFF)
		return;

	/* FILL is the floor for every non-OFF mode.  generate_rand_bytes
	 * takes unsigned int; cap defensively (ARG_BUF_SIZED sizes are
	 * <= ~64 KiB today so the cap is a future-proofing guard). */
	n = (len > UINT32_MAX) ? UINT32_MAX : (unsigned int) len;
	generate_rand_bytes(buf, n);

	/* Attribute one fill invocation regardless of which non-OFF mode
	 * we resolved to -- this is the gate the stat-category emitter
	 * suppresses on when zero (render-gap-aware). */
	__atomic_fetch_add(&shm->stats.blob_fills, 1UL, __ATOMIC_RELAXED);

	/* HAVOC is the floor for CMPDICT: a missed cmp-hint pull still
	 * leaves the bounded byte-mutation pass on top of FILL, so the
	 * CMPDICT arm never authors less surface area than HAVOC for the
	 * same blob.  Fall through into the cmpdict splat below when the
	 * mode is CMPDICT. */
	if (mode == BLOB_MUTATOR_HAVOC || mode == BLOB_MUTATOR_CMPDICT) {
		unsigned int ops = blob_havoc(buf, len);

		if (ops > 0)
			__atomic_fetch_add(&shm->stats.blob_havoc_ops,
					   (unsigned long) ops,
					   __ATOMIC_RELAXED);
	}

	if (mode == BLOB_MUTATOR_CMPDICT) {
		unsigned int static_inserts = 0;
		unsigned int transform_inserts = 0;
		unsigned int inserts = blob_cmpdict(buf, len, nr, do32,
						    &static_inserts,
						    &transform_inserts);

		if (inserts > 0)
			__atomic_fetch_add(&shm->stats.blob_dict_inserts,
					   (unsigned long) inserts,
					   __ATOMIC_RELAXED);
		if (static_inserts > 0)
			__atomic_fetch_add(&shm->stats.blob_static_magic_inserts,
					   (unsigned long) static_inserts,
					   __ATOMIC_RELAXED);
		if (transform_inserts > 0)
			__atomic_fetch_add(&shm->stats.blob_dict_transform_inserts,
					   (unsigned long) transform_inserts,
					   __ATOMIC_RELAXED);
	}
}

void blob_mutator_self_check(void)
{
	/*
	 * Invariant 1: the enum ordering OFF=0 < FILL < HAVOC < CMPDICT
	 * underpins both the parser (params.c stores by name) and the
	 * hook gate (mode == OFF short-circuits before any RNG draw).
	 * A future reordering that breaks the OFF=0 contract would make
	 * a zero-initialised global silently engage the mutator.
	 */
	if (BLOB_MUTATOR_OFF != 0)
		BUG("BLOB_MUTATOR_OFF must be 0 for zero-init no-op contract");
	if (!(BLOB_MUTATOR_OFF < BLOB_MUTATOR_FILL &&
	      BLOB_MUTATOR_FILL < BLOB_MUTATOR_HAVOC &&
	      BLOB_MUTATOR_HAVOC < BLOB_MUTATOR_CMPDICT))
		BUG("blob_mutator_mode enum ordering broken");

	/*
	 * Invariant 2: BLOB_HAVOC_MAX_OPS must be representable inside
	 * the rnd_modulo_u32(BLOB_HAVOC_MAX_OPS) draw and non-zero so
	 * the bounded havoc loop is reachable.  Same contract for
	 * BLOB_CMPDICT_MAX_INSERTS: a cap that drops to zero would
	 * silently skip the entire CMPDICT splat loop.
	 */
	if (BLOB_HAVOC_MAX_OPS == 0 || BLOB_HAVOC_MAX_OPS > UINT32_MAX)
		BUG("BLOB_HAVOC_MAX_OPS out of bounds");
	if (BLOB_CMPDICT_MAX_INSERTS == 0 ||
	    BLOB_CMPDICT_MAX_INSERTS > UINT32_MAX)
		BUG("BLOB_CMPDICT_MAX_INSERTS out of bounds");

	/*
	 * Invariant 3: blob_fill() must be a true no-op when OFF.  Run
	 * blob_fill on a small canary with mode forced OFF; a regression
	 * that, e.g., drops the early return would scribble the pattern.
	 */
	{
		unsigned char canary[16];
		size_t i;
		enum blob_mutator_mode saved =
			__atomic_load_n(&blob_mutator_mode, __ATOMIC_RELAXED);

		for (i = 0; i < sizeof(canary); i++)
			canary[i] = (unsigned char) (0xa5u ^ (i * 7u));

		__atomic_store_n(&blob_mutator_mode, BLOB_MUTATOR_OFF,
				 __ATOMIC_RELAXED);
		blob_fill(canary, sizeof(canary), 0, false);
		for (i = 0; i < sizeof(canary); i++) {
			if (canary[i] != (unsigned char) (0xa5u ^ (i * 7u)))
				BUG("blob_fill(OFF) scribbled buffer");
		}
		__atomic_store_n(&blob_mutator_mode, saved, __ATOMIC_RELAXED);
	}

	/*
	 * Invariant 4: blob_fill() must reject NULL / zero-length without
	 * touching memory.  A loud check here keeps a refactor from
	 * sneaking a deref past the guard.
	 */
	blob_fill(NULL, 0, 0, false);
	blob_fill(NULL, 16, 0, false);
	{
		unsigned char buf[4] = { 0, 0, 0, 0 };
		blob_fill(buf, 0, 0, false);
		if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0)
			BUG("blob_fill(len=0) scribbled buffer");
	}
}
