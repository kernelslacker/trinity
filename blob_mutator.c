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
 * BLOB_HAVOC_MAX_OPS).  CMPDICT is parsed but no-ops to FILL until
 * Build 2.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator.h"
#include "debug.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"

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

void blob_fill(unsigned char *buf, size_t len, unsigned int nr, bool do32)
{
	enum blob_mutator_mode mode;
	unsigned int n;

	(void) nr;
	(void) do32;

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

	if (mode == BLOB_MUTATOR_HAVOC) {
		unsigned int ops = blob_havoc(buf, len);

		if (ops > 0)
			__atomic_fetch_add(&shm->stats.blob_havoc_ops,
					   (unsigned long) ops,
					   __ATOMIC_RELAXED);
	}

	/* CMPDICT is reserved for Build 2; treat as FILL for now.  The
	 * blob_dict_inserts counter is declared in struct stats_s so the
	 * rendered schema is stable across the planned row -- it stays
	 * at zero until the dict-insert arm is wired. */
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
	 * the bounded havoc loop is reachable.
	 */
	if (BLOB_HAVOC_MAX_OPS == 0 || BLOB_HAVOC_MAX_OPS > UINT32_MAX)
		BUG("BLOB_HAVOC_MAX_OPS out of bounds");

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
