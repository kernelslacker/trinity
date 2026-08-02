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
 * bit-flip / byte-flip / set-interesting at the four recorded cmp
 * widths {1,2,4,8} / ±1..±35 arithmetic on a byte/word/dword field /
 * prefix-len stamp of a plausible length/size at offset 0 /
 * memset a bounded run to 0x00 or 0xff / self-splice copy a bounded
 * region over another / swap two non-overlapping bounded regions,
 * capped at BLOB_HAVOC_MAX_OPS ops per invocation regardless of arm
 * cost), CMPDICT (HAVOC plus a bounded buffer-redqueen
 * pass capped at BLOB_CMPDICT_MAX_INSERTS: each iteration coin-flips
 * between a built-in well-known-magic table and the learned per-nr
 * cmp-hint pool via cmp_hints_try_get_sized -- which returns both
 * the constant AND the operand width the kernel's cmp instruction
 * recorded, so a learned magic is splatted at the width the kernel
 * actually compares against -- then applies one of four splat forms
 * -- plain little-endian in the majority, plus three transform arms
 * {big-endian, value+1, value-1} for endian and boundary coverage --
 * and writes the result into the buffer at a random offset).
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blob_corpus.h"
#include "blob_mutator.h"
#include "blob_mutator-internal.h"
#include "child.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "debug.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"

enum blob_mutator_mode blob_mutator_mode = BLOB_MUTATOR_OFF;

bool blob_ab_mode = false;

/*
 * Bounded havoc pass.  Op count is drawn from [1, BLOB_HAVOC_MAX_OPS]
 * so the worst case is bounded independent of len and independent of
 * per-arm cost (block-scoped arms cap their run at
 * BLOB_HAVOC_BLOCK_MAX bytes).  Each iteration picks one of the
 * sixteen arms with uniform probability -- single-position arms
 * (bit-flip, byte-flip, set-interesting at four widths, ±1..±35
 * arith at three widths) plus block-scoped arms (memset run, self-
 * splice copy, region swap) plus the prefix-len arm that stamps a
 * plausible length / size at offset 0 to reach length-gated parsers.
 * Returns the number of ops applied so the caller can attribute the
 * count to the blob_havoc_ops shadow counter; the number of ops the
 * prefix-len arm was picked for is returned through
 * *prefix_len_ops_out so the caller can credit
 * blob_havoc_prefix_len_ops for arm-selection observability.
 */
static unsigned int blob_havoc(unsigned char *buf, size_t len,
			       unsigned int *prefix_len_ops_out)
{
	unsigned int n_ops;
	unsigned int i;
	unsigned int prefix_len_ops = 0;

	*prefix_len_ops_out = 0;
	if (len == 0)
		return 0;

	n_ops = 1u + rnd_modulo_u32(BLOB_HAVOC_MAX_OPS);

	for (i = 0; i < n_ops; i++) {
		switch (rnd_modulo_u32(16)) {
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
		case 4:
			havoc_set_interesting(buf, len, 4);
			break;
		case 5:
			havoc_set_interesting(buf, len, 8);
			break;
		case 6:
			havoc_arith(buf, len, 1, false);
			break;
		case 7:
			havoc_arith(buf, len, 1, true);
			break;
		case 8:
			havoc_arith(buf, len, 2, false);
			break;
		case 9:
			havoc_arith(buf, len, 2, true);
			break;
		case 10:
			havoc_arith(buf, len, 4, false);
			break;
		case 11:
			havoc_arith(buf, len, 4, true);
			break;
		case 12:
			havoc_memset_block(buf, len);
			break;
		case 13:
			havoc_splice_copy(buf, len);
			break;
		case 15:
			havoc_prefix_len(buf, len);
			prefix_len_ops++;
			break;
		default:
			havoc_swap_regions(buf, len);
			break;
		}
	}
	*prefix_len_ops_out = prefix_len_ops;
	return n_ops;
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
 * learned per-nr cmp_hints pool -- one cmp_hints_try_get_sized(nr,
 * do32, ...) pull that returns both the constant and its RECORDED
 * operand width from the cmp record ({1, 2, 4, 8}).  Honoring the
 * pool entry's own width matches the width the kernel's cmp
 * instruction reads -- a magic learned at a 2-byte compare is
 * written as two bytes, not blindly widened to eight bytes of
 * surrounding garbage the downstream compare then rejects.  A static
 * draw whose baked width does not fit len falls back to the learned
 * path silently; a learned pull that misses (empty pool, chaos-
 * suppressed, corrupted) or whose recorded width does not fit in
 * len is skipped silently.  Neither miss bumps a counter so both
 * blob_dict_inserts and blob_static_magic_inserts measure committed
 * splats, not attempts.
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
 * Every write is clamped so pos + width <= len.  On the learned arm
 * the pool entry's recorded width is honored verbatim -- if that
 * width does not fit in len (e.g. a 4-byte cmp constant against a
 * 3-byte buffer) the iteration is skipped rather than truncated,
 * because a narrowed splat writes a partial constant the kernel's
 * cmp instruction cannot match at its actual width, and the
 * substituted low bytes would be indistinguishable from noise.  The
 * static arm likewise does not degrade because the baked width is
 * part of the magic -- a truncated header magic would not satisfy
 * the pre-parser check the entry exists to satisfy.  Returns the number of committed
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
					(uint32_t) blob_static_magics_count)];

			if (m->width <= len) {
				hint = (unsigned long) m->value;
				width = m->width;
				from_static = true;
			}
		}

		if (!from_static) {
			unsigned int recorded_width = 0;

			/* CMP_HINT_CALLSITE_NR: the CMPDICT arm is a byte-
			 * splat consumer with no argtype-handler callsite --
			 * the drain gates on < NR so the pull is not
			 * attributed to any callsite bucket. */
			if (!cmp_hints_try_get_sized(nr, do32,
						     CMP_HINT_CALLSITE_NR,
						     &hint, &recorded_width))
				continue;

			/* Honor the pool entry's recorded operand width
			 * verbatim.  The cmp_hints collector only stores
			 * KCOV_TRACE_CMP records whose size is in
			 * {1, 2, 4, 8}, but guard defensively: a torn
			 * lockless read of a freshly-evicted entry or a
			 * future collector change outside the invariant
			 * would otherwise splat at a width the LE stamp
			 * helper below cannot handle.  Skip on both an
			 * unsupported width AND a recorded width that
			 * does not fit len -- a narrowed splat writes a
			 * partial constant the kernel's cmp cannot match
			 * at its true width. */
			if (recorded_width != 1 && recorded_width != 2 &&
			    recorded_width != 4 && recorded_width != 8)
				continue;
			if ((size_t) recorded_width > len)
				continue;
			width = recorded_width;
		}
		/* width is now in {1, 2, 4, 8} and <= len. */

		max_pos = len - width;
		/* Full-width u64 draw so any pos in [0, max_pos] is reachable;
		 * an earlier version clamped to rnd_modulo_u32(UINT32_MAX) on
		 * the max_pos > UINT32_MAX branch, silently biasing away from
		 * the tail. */
		pos = (size_t) rnd_modulo_u64((uint64_t) max_pos + 1u);

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
	bool ab;
	uint64_t saved_rnd_state = 0;

	if (buf == NULL || len == 0)
		return;

	ab = blob_ab_mode;
	if (ab) {
		/* Route every blob-mutator draw for this fill -- the
		 * HAVOC-vs-CMPDICT coin-flip, the havoc arms, the
		 * cmpdict pulls, the nested generate_rand_bytes and
		 * cmp_hints_try_get -- through the dedicated blob rng
		 * stream by swapping rnd_state.  The main syscall-
		 * selection stream is preserved verbatim across the
		 * fill so both A/B arms see the same syscall sequence
		 * and args; only the blob CONTENT differs.  Restored on
		 * exit; without the restore the main stream would
		 * absorb the blob's draws and the per-fill new-edges
		 * comparison would leak. */
		saved_rnd_state = rnd_state;
		rnd_state = rnd_blob_state;

		/* Coin-flip mode for THIS fill.  Uses the blob stream so
		 * the mode-assignment itself does not perturb the main
		 * selection stream. */
		mode = (rnd_u32() & 1u) ? BLOB_MUTATOR_HAVOC
					: BLOB_MUTATOR_CMPDICT;

		/* Stash the picked mode on the current child so the
		 * dispatch-side novelty-gate credit block can attribute
		 * this call's new_edges to the mode that produced them.
		 * Reset at the top of generate_syscall_args() alongside
		 * cmp_hint_injected_this_call.  Multiple blob_fills in
		 * one call resolve to latest-wins semantics -- rare on
		 * the ARG_BUF_SIZED surface and the design accepts
		 * that. */
		{
			struct childdata *child = this_child();

			if (child != NULL)
				child->blob_ab_mode_last =
					(mode == BLOB_MUTATOR_HAVOC)
					? BLOB_AB_MODE_HAVOC
					: BLOB_AB_MODE_CMPDICT;
		}
	} else {
		mode = __atomic_load_n(&blob_mutator_mode, __ATOMIC_RELAXED);
		if (mode == BLOB_MUTATOR_OFF)
			return;
	}

	/* FILL is the floor for every non-OFF mode.  generate_rand_bytes
	 * takes unsigned int; cap defensively (ARG_BUF_SIZED sizes are
	 * <= ~64 KiB today so the cap is a future-proofing guard). */
	n = (len > UINT32_MAX) ? UINT32_MAX : (unsigned int) len;

	/* Prefer a productive base from the per-(nr, do32) blob corpus
	 * when one exists so HAVOC/CMPDICT lay their bounded pass on top
	 * of a known-productive byte pattern instead of on top of fresh
	 * random noise.  On a miss (empty pool, no key match), fall back
	 * to the original generate_rand_bytes() floor so the FILL contract
	 * is preserved.  The try_get_base call bumps
	 * blob_base_from_corpus on hit / blob_base_from_random on miss;
	 * the ratio is the observable "how often did we get a productive
	 * base?" gauge without disturbing any existing counter. */
	if (!blob_corpus_try_get_base(nr, do32, buf, (size_t) n))
		generate_rand_bytes(buf, n);

	/* Attribute one fill invocation regardless of which non-OFF mode
	 * we resolved to -- this is the gate the stat-category emitter
	 * suppresses on when zero (render-gap-aware). */
	__atomic_fetch_add(&shm->stats.blob.fills, 1UL, __ATOMIC_RELAXED);

	/* Per-group shadow of blob_fills.  Looked up via the (nr, do32)
	 * pair the caller passed in so the attribution stays correct
	 * regardless of any dispatch-side state.  entry / group defensive
	 * gate mirrors account_fd_and_group() in strategy-accounting.c. */
	{
		struct syscallentry *entry = get_syscall_entry(nr, do32);

		if (entry != NULL && entry->group < NR_GROUPS)
			__atomic_fetch_add(&shm->stats.blob.fills_by_group[entry->group],
					   1UL, __ATOMIC_RELAXED);
	}

	/* HAVOC is the floor for CMPDICT: a missed cmp-hint pull still
	 * leaves the bounded byte-mutation pass on top of FILL, so the
	 * CMPDICT arm never authors less surface area than HAVOC for the
	 * same blob.  Fall through into the cmpdict splat below when the
	 * mode is CMPDICT. */
	if (mode == BLOB_MUTATOR_HAVOC || mode == BLOB_MUTATOR_CMPDICT) {
		unsigned int prefix_len_ops = 0;
		unsigned int ops = blob_havoc(buf, len, &prefix_len_ops);

		if (ops > 0)
			__atomic_fetch_add(&shm->stats.blob.havoc_ops,
					   (unsigned long) ops,
					   __ATOMIC_RELAXED);
		if (prefix_len_ops > 0)
			__atomic_fetch_add(&shm->stats.blob.havoc_prefix_len_ops,
					   (unsigned long) prefix_len_ops,
					   __ATOMIC_RELAXED);
	}

	if (mode == BLOB_MUTATOR_CMPDICT) {
		unsigned int static_inserts = 0;
		unsigned int transform_inserts = 0;
		unsigned int inserts = blob_cmpdict(buf, len, nr, do32,
						    &static_inserts,
						    &transform_inserts);

		if (inserts > 0)
			__atomic_fetch_add(&shm->stats.blob.dict_inserts,
					   (unsigned long) inserts,
					   __ATOMIC_RELAXED);
		if (static_inserts > 0)
			__atomic_fetch_add(&shm->stats.blob.static_magic_inserts,
					   (unsigned long) static_inserts,
					   __ATOMIC_RELAXED);
		if (transform_inserts > 0)
			__atomic_fetch_add(&shm->stats.blob.dict_transform_inserts,
					   (unsigned long) transform_inserts,
					   __ATOMIC_RELAXED);
	}

	/* Stash the just-authored bytes as a pending candidate for the
	 * next minicorpus_save promotion.  Deferred to the caller's
	 * post-syscall novelty gate so only PRODUCTIVE blobs enter the
	 * shared corpus -- an unpromoted pending is cleared at the top of
	 * the next generate_syscall_args() without ever hitting shared
	 * memory. */
	blob_corpus_stash_pending(nr, do32, buf, (size_t) n);

	if (ab) {
		/* Persist blob-stream advance and hand rnd_state back to
		 * the main syscall-selection stream verbatim. */
		rnd_blob_state = rnd_state;
		rnd_state = saved_rnd_state;
	}
}

void blob_mutator_self_check(void)
{
	bool saved_ab = blob_ab_mode;

	/*
	 * The invariants below force blob_mutator_mode to exercise specific
	 * arms.  --blob-ab-mode authors content independent of
	 * blob_mutator_mode (the gen_arg_time.c caller gate and the ab
	 * branch in blob_fill), so a --blob-ab-mode run would trip
	 * Invariant 3's OFF=no-op check against that intended enable.
	 * Force the flag off across the whole check so each invariant
	 * tests the mode contract it is about; restored before return.
	 * init_shm runs single-threaded pre-fork, so the write is
	 * race-free.
	 */
	blob_ab_mode = false;

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

	/*
	 * Invariant 5: the HAVOC arms -- including the block-scoped ones
	 * (memset run, self-splice copy, region swap) that walk past the
	 * mutation origin -- must not scribble outside [buf, buf+len).
	 * Frame the mutation region with sentinel bytes and drive a full
	 * blob_fill(HAVOC) pass; a broken bound-check on any arm trips
	 * the guard bytes.  BLOB_HAVOC_BLOCK_MAX (64) exceeds the 32-byte
	 * mutation region, so the run-clamp path in the block arms is
	 * exercised too.
	 */
	{
		unsigned char guarded[48];
		size_t g;
		enum blob_mutator_mode saved =
			__atomic_load_n(&blob_mutator_mode, __ATOMIC_RELAXED);

		for (g = 0; g < 8; g++)
			guarded[g] = (unsigned char) (0xa5u ^ g);
		for (g = 0; g < 8; g++)
			guarded[40 + g] = (unsigned char) (0x5au ^ g);

		__atomic_store_n(&blob_mutator_mode, BLOB_MUTATOR_HAVOC,
				 __ATOMIC_RELAXED);
		blob_fill(guarded + 8, 32, 0, false);
		__atomic_store_n(&blob_mutator_mode, saved, __ATOMIC_RELAXED);

		for (g = 0; g < 8; g++)
			if (guarded[g] != (unsigned char) (0xa5u ^ g))
				BUG("blob_fill(HAVOC) scribbled below buf");
		for (g = 0; g < 8; g++)
			if (guarded[40 + g] != (unsigned char) (0x5au ^ g))
				BUG("blob_fill(HAVOC) scribbled past len bound");
	}

	blob_ab_mode = saved_ab;
}
