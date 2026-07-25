/*
 * Fixed-seed RNG-stream golden hashes.
 *
 * The help text carries 33 separate "byte-identical when off" /
 * "pick stream stays identical to off for a given seed" / "byte-
 * identical to today" promises across the shadow-lane knob rows.
 * Every one of them rests on the same load-bearing invariant: a
 * fixed seed reproduces the exact same sequence of rnd_u32() /
 * rnd_u64() / rnd_modulo_u{32,64}() draws that a pre-row build
 * produced.  A single stray rnd_u32() slipped into an off-path
 * branch desynchronises the stream and silently invalidates every
 * A/B comparison the operator ever runs with that knob.
 *
 * The RNG contract itself is the floor beneath those promises --
 * if the splitmix64 mixer / seed-mix constants / helper shapes
 * shift, every downstream byte-identical claim collapses in one
 * sweep and nothing in the tree today catches the shift.  This
 * suite pins the raw stream: seed the RNG, draw a fixed count of
 * values through each public helper, and hash the result against a
 * golden constant.  A drift shows up as a hash mismatch on the
 * first CI run after the change, not as a corrupted A/B months
 * later.
 *
 * The knob-by-knob byte-identical promises (each of the 33 rows
 * asserting that its off-path issues zero incremental draws) still
 * need a per-knob runtime check.  That check has to run through the
 * option-parse -> hot-path chain, which is not on the PURE-module
 * test seam yet -- it needs the picker migrated onto the arena test
 * infra first.  This row lands the floor; per-knob rows come after
 * that migration.
 *
 * Hashing shape: FNV-1a 64-bit over the raw byte layout of the
 * draw buffer, little-endian on the platforms trinity is built for
 * (x86_64 / aarch64), so the golden is stable across those hosts
 * without an explicit swap.
 *
 * Blessing: the golden constants below were produced by running
 * the test once with placeholder 0s, capturing the observed hashes
 * from the FAIL diagnostic, and pasting them back.  If the splitmix
 * mixer or seed-mix constants change on purpose, do the same one-
 * shot regen and update every EXPECTED_* below in one commit --
 * that regen is the deliberate act that justifies the churn, and
 * the same commit should carry the "why" in its Summary.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rnd.h"
#include "rnd_stream_golden.h"

#define STREAM_LEN	1024u

/*
 * FNV-1a 64-bit: single-byte-at-a-time streaming hash.  Picked over
 * a cryptographic digest because this file has zero external deps
 * (fits the tests/ scaffold's linked-set) and because the property
 * under test is "did the byte layout of the draw buffer change",
 * which FNV catches every bit as well as SHA-256 at 1/50 the code.
 */
static uint64_t fnv1a64(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint64_t h = 0xcbf29ce484222325ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= (uint64_t) p[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

static void fail_hash(const char *what, uint64_t got, uint64_t expected)
{
	fprintf(stderr,
		"\nFAIL: %s: got=0x%016llx expected=0x%016llx\n"
		"  If the RNG mixer or seed-mix constants changed on\n"
		"  purpose, regen every EXPECTED_* golden in\n"
		"  tests/rnd_stream_golden.c in a single commit.\n"
		"  If not, hunt the stray rnd_u32() draw a shadow-lane\n"
		"  row leaked into an OFF branch.\n",
		what,
		(unsigned long long) got,
		(unsigned long long) expected);
	exit(1);
}

static void check_u32_stream(uint64_t seed, const char *label,
			     uint64_t expected)
{
	uint32_t buf[STREAM_LEN];
	uint64_t got;
	unsigned int i;

	rnd_seed(seed);
	for (i = 0; i < STREAM_LEN; i++)
		buf[i] = rnd_u32();
	got = fnv1a64(buf, sizeof(buf));
	if (got != expected)
		fail_hash(label, got, expected);
}

static void check_u64_stream(uint64_t seed, const char *label,
			     uint64_t expected)
{
	uint64_t buf[STREAM_LEN];
	uint64_t got;
	unsigned int i;

	rnd_seed(seed);
	for (i = 0; i < STREAM_LEN; i++)
		buf[i] = rnd_u64();
	got = fnv1a64(buf, sizeof(buf));
	if (got != expected)
		fail_hash(label, got, expected);
}

/*
 * rnd_modulo_u32(bound) exercises the Lemire debiased-bound path
 * in rnd.h: same rnd_u32() feeder, but the rejection loop's
 * residue-band branch is what makes the bound value observable to
 * the stream.  Two bounds cover the two rejection regimes -- an
 * odd tiny bound (7) hits the rejection more often, a moderate
 * near-power-of-two bound (100) hits it rarely -- so a helper
 * change that shifts either regime is caught.
 */
static void check_modulo_u32_stream(uint64_t seed, uint32_t bound,
				    const char *label, uint64_t expected)
{
	uint32_t buf[STREAM_LEN];
	uint64_t got;
	unsigned int i;

	rnd_seed(seed);
	for (i = 0; i < STREAM_LEN; i++)
		buf[i] = rnd_modulo_u32(bound);
	got = fnv1a64(buf, sizeof(buf));
	if (got != expected)
		fail_hash(label, got, expected);
}

static void check_modulo_u64_stream(uint64_t seed, uint64_t bound,
				    const char *label, uint64_t expected)
{
	uint64_t buf[STREAM_LEN];
	uint64_t got;
	unsigned int i;

	rnd_seed(seed);
	for (i = 0; i < STREAM_LEN; i++)
		buf[i] = rnd_modulo_u64(bound);
	got = fnv1a64(buf, sizeof(buf));
	if (got != expected)
		fail_hash(label, got, expected);
}

/*
 * Interleaved draw pattern: alternate rnd_u32() and rnd_u64()
 * against a single seeded stream.  Catches a hypothetical helper-
 * shape regression where u32 stops sharing the same underlying
 * state advance as u64 -- e.g. a partial refactor that inlined u32
 * as an independent stream and passed the isolated golden checks
 * above.
 */
static void check_interleaved_stream(uint64_t seed, const char *label,
				     uint64_t expected)
{
	uint64_t buf[STREAM_LEN];
	uint64_t got;
	unsigned int i;

	rnd_seed(seed);
	for (i = 0; i < STREAM_LEN; i++) {
		if ((i & 1u) == 0u)
			buf[i] = (uint64_t) rnd_u32();
		else
			buf[i] = rnd_u64();
	}
	got = fnv1a64(buf, sizeof(buf));
	if (got != expected)
		fail_hash(label, got, expected);
}

/*
 * Blob-state contract: rnd_blob_seed() seeds the secondary stream
 * with a distinct mix constant.  A regression that folded the blob
 * seed into rnd_state (or swapped the mix constant) would let a
 * --blob-ab-mode run leak into the main pick stream, breaking the
 * shadow-lane byte-identical promise from the other direction.
 * The blob helpers do not export a u32/u64 draw of their own (the
 * hot-path caller in blob_fill() swaps rnd_state around the call),
 * so the check reads rnd_blob_state directly after seeding to pin
 * the seed-mix contract.
 */
static void check_blob_seed_mix(uint64_t seed, uint64_t expected)
{
	uint64_t got;

	rnd_blob_seed(seed);
	got = rnd_blob_state;
	if (got != expected)
		fail_hash("rnd_blob_state/seed-mix", got, expected);
}

/*
 * Golden hashes.  Seed 0xa17e57 matches the test-bin default so a
 * "-s <same>" repro of a hash-drift report reproduces every row
 * here bit-for-bit; the second seed (0x2a) covers a distinct seed
 * class (small integer, low bit density) so a mixer change that
 * happens to preserve one seed's stream would still fail on the
 * other.
 */
#define SEED_A		0xa17e57ULL
#define SEED_B		0x2aULL

#define EXPECTED_U32_A			0xfa9f8b9cd75af7beULL
#define EXPECTED_U64_A			0xb8adebf6340d45a8ULL
#define EXPECTED_MODULO_U32_7_A		0xf6814adda0cd63f7ULL
#define EXPECTED_MODULO_U32_100_A	0x1e0b630b81a1d200ULL
#define EXPECTED_MODULO_U64_7_A		0x07217e10d680dd47ULL
#define EXPECTED_MODULO_U64_100_A	0xbf557f7f6df07c99ULL
#define EXPECTED_INTERLEAVED_A		0x58e94e2f2295f649ULL
#define EXPECTED_U32_B			0xb35f9b0d878422bbULL
#define EXPECTED_U64_B			0x9037281da1601735ULL
#define EXPECTED_BLOB_SEED_A		0xd1b54a32d1339354ULL
#define EXPECTED_BLOB_SEED_B		0xd1b54a32d192ed29ULL

void rnd_stream_golden_check(void)
{
	check_u32_stream(SEED_A, "rnd_u32/seed=A/N=1024",
			 EXPECTED_U32_A);
	check_u64_stream(SEED_A, "rnd_u64/seed=A/N=1024",
			 EXPECTED_U64_A);
	check_modulo_u32_stream(SEED_A, 7,
				"rnd_modulo_u32(7)/seed=A/N=1024",
				EXPECTED_MODULO_U32_7_A);
	check_modulo_u32_stream(SEED_A, 100,
				"rnd_modulo_u32(100)/seed=A/N=1024",
				EXPECTED_MODULO_U32_100_A);
	check_modulo_u64_stream(SEED_A, 7,
				"rnd_modulo_u64(7)/seed=A/N=1024",
				EXPECTED_MODULO_U64_7_A);
	check_modulo_u64_stream(SEED_A, 100,
				"rnd_modulo_u64(100)/seed=A/N=1024",
				EXPECTED_MODULO_U64_100_A);
	check_interleaved_stream(SEED_A,
				 "rnd_u32/u64 interleaved/seed=A/N=1024",
				 EXPECTED_INTERLEAVED_A);
	check_u32_stream(SEED_B, "rnd_u32/seed=B/N=1024",
			 EXPECTED_U32_B);
	check_u64_stream(SEED_B, "rnd_u64/seed=B/N=1024",
			 EXPECTED_U64_B);
	check_blob_seed_mix(SEED_A, EXPECTED_BLOB_SEED_A);
	check_blob_seed_mix(SEED_B, EXPECTED_BLOB_SEED_B);
}
