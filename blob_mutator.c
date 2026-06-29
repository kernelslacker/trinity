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
 * Build 1 commit 1: OFF (engine-level off, no write), FILL
 * (generate_rand_bytes into the owned buffer).  HAVOC is parsed but
 * behaves as FILL until the follow-up commit adds the bounded
 * byte-mutation pass; CMPDICT is reserved for Build 2.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob_mutator.h"
#include "debug.h"
#include "random.h"

enum blob_mutator_mode blob_mutator_mode = BLOB_MUTATOR_OFF;

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

	/* HAVOC and CMPDICT degrade to FILL in this commit. */
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
	 * Invariant 2: blob_fill() must be a true no-op when OFF.  Run
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
	 * Invariant 3: blob_fill() must reject NULL / zero-length without
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
