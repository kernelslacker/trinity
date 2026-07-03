#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		// BUG
#include "minicorpus.h"		// minicorpus_struct_field_attrib
#include "random.h"
#include "rnd.h"
#include "struct_catalog.h"
#include "syscall.h"

/*
 * Structure-aware post-fill mutation gate.  After
 * struct_field_fill_schema_aware() writes a schema-valid struct into
 * buf, struct_field_mutate_one() rolls this percentage and, on hit,
 * picks one field and applies a tag-respecting neighbour mutation.
 *
 * 12% (~1-in-8) keeps schema-fill's validator-passing intent dominant
 * while still exploring valid neighbours every few calls; tuned next to
 * OPTIONAL_PRESENT_PCT so the two probability-driven fill knobs live
 * side-by-side.
 */
#define STRUCT_FIELD_MUTATE_PCT		12U

/*
 * True for tags the post-fill mutator may touch.  The skip-list (PTR_*,
 * LEN_*, ADDRESS, FD, BPF_PROGRAM, TAGGED_UNION) is enforced at
 * candidate-collection time so a skip-listed field is never picked --
 * the load-bearing safety property for the whole phase.  FT_MAGIC /
 * FT_VERSION_MAGIC are deliberately excluded today; folding them in is
 * a future curated-tag lift once the per-tag counters confirm we want
 * them.  Other future tags default to non-mutable so the skip-list
 * grows by allow-list, not by deny-list.
 */
static bool field_tag_is_mutable_c2b(enum field_tag tag)
{
	switch (tag) {
	case FT_FLAGS:
	case FT_ENUM:
	case FT_VOCAB:
	case FT_RANGE:
	case FT_SRANGE:
	case FT_RAW:
		return true;
	default:
		return false;
	}
}

/*
 * FT_FLAGS post-fill primitive: single-bit flip within the valid-bits
 * mask.  Unlike fill_field_flags()'s whole-mask 50%-each redraw, this
 * walks exactly one bit -- the kernel sees the same value the schema
 * fill produced with one in-mask bit toggled, so a coverage win
 * attributes to that one bit instead of the eight or sixteen the
 * fill's redraw would have churned in parallel.  Bits outside the mask
 * are never touched, preserving the kernel's "unknown flags reject"
 * guarantee.
 */
static void mutate_field_flags(unsigned char *buf, const struct struct_field *f)
{
	uint64_t mask = f->u.flags.mask;
	uint64_t val;
	unsigned int pop, pick, seen;
	unsigned int i;

	if (mask == 0)
		return;

	pop = (unsigned int) __builtin_popcountll(mask);
	pick = (unsigned int) rnd_modulo_u32(pop);

	val = read_field_uint(buf, f);
	seen = 0;
	for (i = 0; i < 64; i++) {
		uint64_t bit = (uint64_t) 1 << i;

		if ((mask & bit) == 0)
			continue;
		if (seen == pick) {
			val ^= bit;
			break;
		}
		seen++;
	}
	write_field_uint(buf, f, val);
}

/*
 * FT_ENUM post-fill primitive: replace with a different draw from
 * u.enum_.vals so the kernel sees a real "swap to another vocab entry"
 * neighbour move instead of either the same value or a wholly random
 * one.  Reject-samples until a different index is drawn; with n == 1
 * there is no different value to swap to, so the field is left alone.
 * A bounded retry cap guards against pathological vocabs that contain
 * the same value repeated (effective n == 1 with formal n > 1) without
 * spinning the rng forever.
 */
static void mutate_field_enum(unsigned char *buf, const struct struct_field *f)
{
	const unsigned long *vals = f->u.enum_.vals;
	unsigned int n = f->u.enum_.n;
	uint64_t current;
	unsigned int retries;

	if (vals == NULL || n <= 1)
		return;

	current = read_field_uint(buf, f);
	for (retries = 0; retries < 8; retries++) {
		uint64_t cand = (uint64_t) vals[rnd_modulo_u32(n)];

		if (cand != current) {
			write_field_uint(buf, f, cand);
			return;
		}
	}

	/*
	 * All 8 random draws collided with the current value (small vocab).
	 * Deterministic scan guarantees a swap whenever any value differs --
	 * the enum selftest and callers require the value to actually change.
	 */
	for (retries = 0; retries < n; retries++) {
		if ((uint64_t) vals[retries] != current) {
			write_field_uint(buf, f, (uint64_t) vals[retries]);
			return;
		}
	}
}

/*
 * FT_VOCAB post-fill primitive: pick a different curated string and
 * splat it NUL-padded across element_stride bytes, mirroring exactly
 * the shape fill_field_vocab() lands in pass 1 -- memset(stride, 0),
 * memcpy(min(strlen, stride - 1)).  Reject-sample on the just-filled
 * string so the kernel sees a fresh entry rather than the same one
 * twice; bounded retries handle the n == 1 / duplicate-vocab cases
 * without burning rng.  String comparison is over the stride-bounded
 * pad to match what's actually written into the buffer (anything
 * beyond stride-1 is truncated identically by both writers, so the
 * "different" check would be a false negative if it compared past the
 * truncation point).
 */
static void mutate_field_vocab(unsigned char *buf, const struct struct_field *f)
{
	const char *const *vocab = f->u.vocab.vocab;
	unsigned int nv = f->u.vocab.vocab_len;
	unsigned int stride = f->u.vocab.element_stride;
	unsigned int retries;

	if (vocab == NULL || nv <= 1 || stride == 0)
		return;
	if (stride > f->size)
		stride = f->size;
	if (stride == 0)
		return;

	for (retries = 0; retries < 8; retries++) {
		const char *pick = vocab[rnd_modulo_u32(nv)];
		size_t plen = strnlen(pick, stride - 1);

		if (memcmp(buf + f->offset, pick, plen) == 0 &&
		    plen == strnlen((const char *) (buf + f->offset),
				    stride - 1))
			continue;

		memset(buf + f->offset, 0, stride);
		memcpy(buf + f->offset, pick, plen);
		return;
	}
}

/*
 * FT_RANGE post-fill primitive: step by ±1 within [lo, hi], clamped at
 * the bounds.  The "small adjacent step" is what makes FT_RANGE
 * mutable distinct from the fill's uniform redraw -- the kernel sees a
 * value one neighbour away from a known-valid base, so size-sensitive
 * branches that the schema fill jumps across uniformly get walked one
 * step at a time.  Out-of-range or degenerate ranges (hi <= lo) are
 * no-ops: there is no neighbour to step to.  Saturating at the bounds
 * rather than wrapping preserves the lo/hi invariant the fill writes.
 */
static void mutate_field_range(unsigned char *buf, const struct struct_field *f)
{
	unsigned long lo = f->u.range.lo;
	unsigned long hi = f->u.range.hi;
	uint64_t current;
	uint64_t next;

	if (hi <= lo)
		return;

	current = read_field_uint(buf, f);
	if (current < lo || current > hi)
		return;

	if (current == lo)
		next = current + 1;
	else if (current == hi)
		next = current - 1;
	else if (rnd_u32() & 1)
		next = current + 1;
	else
		next = current - 1;

	write_field_uint(buf, f, next);
}

/*
 * FT_SRANGE post-fill primitive: signed sibling of mutate_field_range.
 * read_field_uint() zero-extends the raw bytes, so a negative in-range
 * value would compare above hi as unsigned and the step would be
 * skipped; sign-extend through f->size before the bound check so a
 * field holding -3 is recognised as in [-5, 5].  Step arithmetic is
 * done in int64_t so lo == LONG_MIN and hi == LONG_MAX edges don't
 * overflow; write_field_uint() truncates to the field width identically
 * to the unsigned path.
 */
static void mutate_field_srange(unsigned char *buf, const struct struct_field *f)
{
	long lo = f->u.srange.lo;
	long hi = f->u.srange.hi;
	int64_t current;
	int64_t next;
	uint64_t raw;
	unsigned int sh;

	if (hi <= lo)
		return;
	if (f->size == 0 || f->size > 8)
		return;

	raw = read_field_uint(buf, f);
	sh = (unsigned int) (64 - f->size * 8);
	current = (int64_t) (raw << sh) >> sh;

	if (current < lo || current > hi)
		return;

	if (current == lo)
		next = current + 1;
	else if (current == hi)
		next = current - 1;
	else if (rnd_u32() & 1)
		next = current + 1;
	else
		next = current - 1;

	write_field_uint(buf, f, (uint64_t) next);
}

/*
 * FT_RAW post-fill primitive: single-bit flip scoped to a random byte
 * inside [f->offset, f->offset + f->size).  The "scoped" part is
 * load-bearing -- a stray byte outside the field would clobber its
 * neighbour, which is precisely the sort of cross-field contamination
 * schema fill exists to prevent.  Width-gated to <= 4 bytes (1/2/4) so
 * the splat shape matches fill_field_raw()'s; wider FT_RAW (pointers,
 * u64 cookies) is left alone, the same conservative shape the fill
 * walks past.
 */
static void mutate_field_raw(unsigned char *buf, const struct struct_field *f)
{
	unsigned int byte_off;
	unsigned int bit;

	if (f->size == 0 || f->size > 4)
		return;

	byte_off = rnd_modulo_u32(f->size);
	bit = rnd_modulo_u32(8);
	buf[f->offset + byte_off] ^= (unsigned char) (1U << bit);
}

/*
 * Build a candidate list of mutable fields reachable from buf via the
 * cataloged struct descriptor, walking FT_PTR_STRUCT children up to a
 * fixed depth.  Skip-list discipline lives here: any tag for which
 * field_tag_is_mutable_c2b() returns false (PTR/LEN/FD/ADDRESS/
 * BPF_PROGRAM/TAGGED_UNION as well as the not-yet-mutable future tags)
 * never becomes a candidate, so the picker can't waste a trial on a
 * "selected then bailed" field.
 *
 * Each candidate remembers the buffer it lives in alongside the field
 * pointer -- after the cross-depth weighted pick, the dispatch needs
 * to know which buffer to mutate.  Bounds-checked at each level
 * against that buffer's size for the same reason struct_fill_passes
 * is: a field whose end lies past the local buffer cannot be safely
 * read or written.  Candidate weights default to one when the catalog
 * leaves mutate_weight at zero so the early scaffolding stays
 * pickable.
 */
struct mutate_candidate {
	unsigned char *buf;
	const struct struct_field *field;
	unsigned int weight;
};

/*
 * Depth cap for the recursive walk: parent + two child levels (depths
 * 0, 1, 2).  Each level can in principle contribute STRUCT_FILL_MAX_FIELDS
 * candidates; multiply for the upper bound on the candidate array.
 * Catalog structs today reach at most 2 levels (msghdr -> iovec); the
 * extra slot is a forward-compat safety margin for future deeper
 * nests.  Bounded recursion is also the cyclic-catalog safety net --
 * a future cyclic entry can't trap the collector beyond the cap.
 */
#define STRUCT_MUTATE_DEPTH_CAP		3U
#define STRUCT_MUTATE_MAX_CANDIDATES	(STRUCT_FILL_MAX_FIELDS * \
					 STRUCT_MUTATE_DEPTH_CAP)

/*
 * Test-only lookup override.  Trinity has no separate unit-test
 * binary, so the depth-walk self-test must drive collect_candidates
 * over a sandbox catalog without polluting the real struct_catalog
 * lookup table.  Setting this pointer redirects the FT_PTR_STRUCT
 * child-desc resolution path; cleared after the test so production
 * callers see struct_catalog_lookup unchanged.  Never set outside the
 * self-test.
 */
static const struct struct_desc *(*mutate_struct_lookup_override)(const char *);

static const struct struct_desc *mutate_lookup_desc(const char *name)
{
	if (mutate_struct_lookup_override != NULL)
		return mutate_struct_lookup_override(name);
	return struct_catalog_lookup(name);
}

static unsigned int collect_mutable_candidates(unsigned char *buf,
					       unsigned int size,
					       const struct struct_desc *desc,
					       struct syscallrecord *rec,
					       unsigned int depth,
					       struct mutate_candidate *out,
					       unsigned int out_max)
{
	const struct union_variant *variant;
	const struct struct_field *fields;
	unsigned int n_fields;
	unsigned int collected = 0;
	unsigned int i;

	if (buf == NULL || desc == NULL)
		return 0;
	if (depth >= STRUCT_MUTATE_DEPTH_CAP)
		return 0;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		fields = variant->fields;
		n_fields = variant->num_fields;
	} else {
		fields = desc->fields;
		n_fields = desc->num_fields;
	}
	if (n_fields > STRUCT_FILL_MAX_FIELDS)
		n_fields = STRUCT_FILL_MAX_FIELDS;

	for (i = 0; i < n_fields && collected < out_max; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		if (field_tag_is_mutable_c2b(f->tag)) {
			out[collected].buf = buf;
			out[collected].field = f;
			out[collected].weight =
				f->mutate_weight ? f->mutate_weight : 1U;
			collected++;
			continue;
		}

		/*
		 * Walk FT_PTR_STRUCT children to depth STRUCT_MUTATE_DEPTH_CAP.
		 * NULL child pointer (optional rolled absent at fill time)
		 * has nothing to mutate; uncataloged or zero-sized target
		 * has no schema to walk.  Both skip silently rather than
		 * fail loud -- a depth-walk that aborts on a single
		 * missing leaf would starve every other reachable field.
		 */
		if (f->tag == FT_PTR_STRUCT) {
			const struct struct_desc *child_desc;
			unsigned char *child_buf;

			child_desc = mutate_lookup_desc(f->u.ptr_struct.struct_name);
			if (child_desc == NULL || child_desc->struct_size == 0)
				continue;

			child_buf = (unsigned char *)(uintptr_t)
				read_field_uint(buf, f);
			if (child_buf == NULL)
				continue;

			collected += collect_mutable_candidates(
				child_buf, child_desc->struct_size,
				child_desc, rec, depth + 1,
				out + collected, out_max - collected);
		}
	}
	return collected;
}

/*
 * Weighted pick over the collected candidate set.  Same uniform-falls-
 * out-when-equal-weights behaviour as the other weighted pickers in the
 * codebase; an all-zero weight set is impossible because the collector
 * substitutes 1 for an unset mutate_weight.  Returns a pointer into the
 * caller's candidate array; the (buf, field) pair both come from there.
 */
static const struct mutate_candidate *
weighted_pick_candidate(const struct mutate_candidate *cands, unsigned int n)
{
	unsigned long total = 0;
	unsigned long r, accum;
	unsigned int i;

	for (i = 0; i < n; i++)
		total += cands[i].weight;
	if (total == 0)
		return NULL;

	r = (unsigned long) rnd_modulo_u32((uint32_t) total);
	accum = 0;
	for (i = 0; i < n; i++) {
		accum += cands[i].weight;
		if (r < accum)
			return &cands[i];
	}
	return &cands[n - 1];
}

/*
 * Apply one per-tag primitive to one already-picked field.  Split out
 * from the gated public entry point so the self-test can drive the
 * dispatch deterministically without rolling against
 * STRUCT_FIELD_MUTATE_PCT thousands of times to land enough trials.
 */
static void mutate_dispatch_one(unsigned char *buf,
				const struct struct_field *winner)
{
	switch (winner->tag) {
	case FT_FLAGS:
		mutate_field_flags(buf, winner);
		break;
	case FT_ENUM:
		mutate_field_enum(buf, winner);
		break;
	case FT_VOCAB:
		mutate_field_vocab(buf, winner);
		break;
	case FT_RANGE:
		mutate_field_range(buf, winner);
		break;
	case FT_SRANGE:
		mutate_field_srange(buf, winner);
		break;
	case FT_RAW:
		mutate_field_raw(buf, winner);
		break;
	default:
		/*
		 * Skip-listed and not-yet-mutable tags should never reach
		 * the dispatch -- collect_mutable_candidates filters them
		 * upstream.  A stray dispatch here is a bug in the filter,
		 * not a write to attempt; stay silent.
		 */
		break;
	}
}

/*
 * Variant-resolve at each level, collect mutable candidates across the
 * nested struct chain (depth cap STRUCT_MUTATE_DEPTH_CAP), weight-pick
 * one, dispatch against the winning candidate's buffer (which may be a
 * child sub-buffer reachable via FT_PTR_STRUCT, not the top-level buf).
 * Bumps the per-tag attribution stash before returning so the next
 * minicorpus_mut_attrib_commit folds the trial into the per-tag
 * histogram.  No gate roll -- callers own the gating decision.
 */
static void
mutate_one_unconditional(unsigned char *buf, unsigned int size,
			 const struct struct_desc *desc,
			 struct syscallrecord *rec)
{
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	const struct mutate_candidate *winner;
	unsigned int n_cands;

	n_cands = collect_mutable_candidates(buf, size, desc, rec, 0,
					     cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n_cands == 0)
		return;

	winner = weighted_pick_candidate(cands, n_cands);
	if (winner == NULL)
		return;

	mutate_dispatch_one(winner->buf, winner->field);
	minicorpus_struct_field_attrib(winner->field->tag);
}

/*
 * Post-fill struct-buffer mutation.  Called immediately after
 * struct_field_fill_schema_aware() at the two top-level ARG_STRUCT
 * call sites; runs at most one tag-respecting neighbour mutation per
 * invocation.  Variant resolution receives the live post-fill buf so
 * buffer-derived discriminators (sockaddr_storage's ss_family,
 * bpf_attr's cmd) scope to the correct variant -- passing NULL would
 * silently mis-scope every tagged-union mutation.
 *
 * One field per call keeps the change atomic so a coverage win
 * attributes to a single (tag, field) pair instead of being smeared
 * across a whole-buffer re-roll.  Candidate collection recurses through
 * FT_PTR_STRUCT children up to STRUCT_MUTATE_DEPTH_CAP, so the winning
 * field may live in a sub-buffer rather than the top-level buf.
 */
void struct_field_mutate_one(unsigned char *buf, unsigned int size,
			     const struct struct_desc *desc,
			     struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) >= STRUCT_FIELD_MUTATE_PCT)
		return;
	mutate_one_unconditional(buf, size, desc, rec);
}

/*
 * Self-test for the per-tag primitives and the skip-list discipline.
 *
 * Trinity has no separate unit-test binary -- the harness only runs on
 * an isolated fuzz host, so structural and behavioural invariants
 * shipped with new code have to be asserted at process start instead.
 * Same pattern as shared_bitmap_self_check(): one-shot, called from
 * the parent before any child forks, BUG() on failure so a regression
 * fails the run loudly instead of silently producing wrong outputs.
 *
 * Each primitive is exercised with a hand-built struct_field over a
 * sandbox buffer (i.e. zero coupling to the production catalog) so the
 * assertions don't depend on catalog field choices that may shift.
 * Iteration counts are large enough that reject-sampling primitives
 * (FT_ENUM / FT_VOCAB) get many independent draws; rng coverage of
 * sub-byte cases (FT_RAW bit picks, FT_RANGE direction) is hit by the
 * same loop count without needing a separate sweep.
 */
#define STRUCT_MUTATE_SELFTEST_ITERS	256U

static void selftest_flags(void)
{
	uint64_t mask = 0x0000000000ABCDEFULL;
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_flags",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_FLAGS,
		.mutate_weight	= 1,
		.u.flags	= { .mask = (unsigned long) mask },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) (rnd_u32() & (uint32_t) mask);
		uint32_t after;
		uint32_t diff;
		uint32_t bits;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_flags(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if ((after & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags wrote outside mask");

		diff = before ^ after;
		bits = (uint32_t) __builtin_popcount(diff);
		if (bits != 1)
			BUG("mutate_field_flags toggled != 1 bit");
		if ((diff & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags toggled out-of-mask bit");
	}
}

static void selftest_enum(void)
{
	static const unsigned long vals[] = { 1, 7, 42, 100, 9999 };
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_enum",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_ENUM,
		.mutate_weight	= 1,
		.u.enum_	= { .vals = vals, .n = ARRAY_SIZE(vals) },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) vals[rnd_modulo_u32(ARRAY_SIZE(vals))];
		uint32_t after;
		unsigned int j;
		bool in_vocab = false;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_enum(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after == before)
			BUG("mutate_field_enum failed to swap value");
		for (j = 0; j < ARRAY_SIZE(vals); j++) {
			if ((uint32_t) vals[j] == after) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_enum wrote non-vocab value");
	}
}

static void selftest_vocab(void)
{
	static const char *const vocab[] = { "alpha", "beta", "gamma", "delta" };
	unsigned char field_buf[16];
	struct struct_field f = {
		.name		= "selftest_vocab",
		.offset		= 0,
		.size		= sizeof(field_buf),
		.tag		= FT_VOCAB,
		.mutate_weight	= 1,
		.u.vocab	= {
			.vocab		= vocab,
			.vocab_len	= ARRAY_SIZE(vocab),
			.element_stride	= sizeof(field_buf),
		},
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		const char *start = vocab[rnd_modulo_u32(ARRAY_SIZE(vocab))];
		unsigned int j;
		bool in_vocab = false;

		memset(field_buf, 0, sizeof(field_buf));
		memcpy(field_buf, start, strlen(start));
		mutate_field_vocab(field_buf, &f);

		if (field_buf[sizeof(field_buf) - 1] != 0)
			BUG("mutate_field_vocab dropped trailing NUL");

		for (j = 0; j < ARRAY_SIZE(vocab); j++) {
			if (strcmp((const char *) field_buf, vocab[j]) == 0) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_vocab wrote non-vocab string");
	}
}

static void selftest_range(void)
{
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_range",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_RANGE,
		.mutate_weight	= 1,
		.u.range	= { .lo = 10, .hi = 20 },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = 10 + rnd_modulo_u32(11);
		uint32_t after;
		int32_t delta;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_range(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after < 10 || after > 20)
			BUG("mutate_field_range stepped outside [lo, hi]");
		delta = (int32_t) after - (int32_t) before;
		if (delta < -1 || delta > 1 || delta == 0)
			BUG("mutate_field_range step != +/- 1");
	}
}

static void selftest_raw(void)
{
	unsigned char ring[8];
	struct struct_field f = {
		.name		= "selftest_raw",
		.offset		= 2,
		.size		= 4,
		.tag		= FT_RAW,
		.mutate_weight	= 1,
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		unsigned char before[sizeof(ring)];
		unsigned int j;
		unsigned int touched = 0;

		for (j = 0; j < sizeof(ring); j++)
			ring[j] = (unsigned char) rnd_u32();
		memcpy(before, ring, sizeof(ring));

		mutate_field_raw(ring, &f);

		/*
		 * Bytes outside [f->offset, f->offset + f->size) must be
		 * byte-identical -- the field-scope guarantee is the whole
		 * point of FT_RAW's "do not contaminate the neighbour" rule.
		 */
		for (j = 0; j < sizeof(ring); j++) {
			if (j >= f.offset && j < f.offset + f.size)
				continue;
			if (ring[j] != before[j])
				BUG("mutate_field_raw touched out-of-field byte");
		}
		for (j = f.offset; j < f.offset + f.size; j++)
			if (ring[j] != before[j])
				touched++;
		if (touched != 1)
			BUG("mutate_field_raw flipped != 1 byte");
	}
}

/*
 * Skip-list invariant: a struct whose only fields carry skip-listed
 * tags must round-trip byte-identical across many gated invocations
 * of struct_field_mutate_one().  The candidate collector should yield
 * zero candidates and the gated entry point should short-circuit; any
 * regression that promoted a coupled tag (PTR_*, LEN_*, ADDRESS, FD,
 * BPF_PROGRAM) into the candidate set would re-introduce the
 * (ptr, len) / address / fd desync the schema fill exists to prevent.
 *
 * The mutation rate is high enough that 10k * STRUCT_FIELD_MUTATE_PCT
 * gate passes is on the order of 1200 -- a single mistakenly-allowed
 * skip-list candidate would flip a byte with overwhelming probability.
 */
static void selftest_skiplist(void)
{
	unsigned char buf[64];
	unsigned char snapshot[sizeof(buf)];
	struct struct_field skiplist_fields[] = {
		{
			.name		= "ptr",
			.offset		= 0,
			.size		= 8,
			.tag		= FT_PTR_BYTES,
			.mutate_weight	= 100,
			.u.ptr_bytes	= { .max_bytes = 16 },
		},
		{
			.name		= "len",
			.offset		= 8,
			.size		= 4,
			.tag		= FT_LEN_BYTES,
			.mutate_weight	= 100,
			.u.len_of	= { .buf_field = "ptr" },
		},
		{
			.name		= "fd",
			.offset		= 16,
			.size		= 4,
			.tag		= FT_FD,
			.mutate_weight	= 100,
		},
		{
			.name		= "addr",
			.offset		= 24,
			.size		= 8,
			.tag		= FT_ADDRESS,
			.mutate_weight	= 100,
		},
	};
	struct struct_desc desc = {
		.name		= "selftest_skiplist",
		.struct_size	= sizeof(buf),
		.fields		= skiplist_fields,
		.num_fields	= ARRAY_SIZE(skiplist_fields),
	};
	unsigned int i;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char) rnd_u32();
	memcpy(snapshot, buf, sizeof(buf));

	for (i = 0; i < 10000U; i++)
		struct_field_mutate_one(buf, sizeof(buf), &desc, NULL);

	if (memcmp(buf, snapshot, sizeof(buf)) != 0)
		BUG("struct_field_mutate_one mutated a skip-listed field");
}

/*
 * Variant-scope invariant: when the resolved desc carries variants
 * keyed off a buffer-derived discriminator, collect_mutable_candidates
 * must only emit fields from the resolved variant -- never the parent's
 * shared field list, never sibling variants.  A regression that
 * forgot to resolve the variant (passing NULL buf, or skipping the
 * resolver entirely) would silently splatter mutations across the
 * dead union envelope.
 *
 * Builds a sandbox tagged-union desc with two variants keyed on byte
 * zero (1 -> "alpha" variant, 2 -> "beta" variant); flips the
 * discriminator and asserts the candidate set names the matching
 * field exclusively.
 */
static void selftest_variant_scope(void)
{
	static const struct struct_field alpha_fields[] = {
		{
			.name		= "alpha",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct struct_field beta_fields[] = {
		{
			.name		= "beta",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct union_variant variants[] = {
		{
			.discrim_value	= 1,
			.name		= "alpha_v",
			.fields		= alpha_fields,
			.num_fields	= ARRAY_SIZE(alpha_fields),
		},
		{
			.discrim_value	= 2,
			.name		= "beta_v",
			.fields		= beta_fields,
			.num_fields	= ARRAY_SIZE(beta_fields),
		},
	};
	struct struct_desc desc = {
		.name			= "selftest_variant",
		.struct_size		= 16,
		.variants		= variants,
		.num_variants		= ARRAY_SIZE(variants),
		.buffer_discrim_offset	= 0,
		.buffer_discrim_size	= 1,
	};
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned char buf[16];
	unsigned int n;

	memset(buf, 0, sizeof(buf));
	buf[0] = 1;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "alpha") != 0)
		BUG("variant scope failed for alpha discriminator");

	buf[0] = 2;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "beta") != 0)
		BUG("variant scope failed for beta discriminator");

	/*
	 * Unknown discriminator: no variant resolves, the collector
	 * falls back to desc->fields[] -- which is empty here -- so
	 * the candidate set must be zero.  Catches a regression that
	 * leaked sibling variant fields into the no-match arm.
	 */
	buf[0] = 99;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 0)
		BUG("variant no-match leaked candidates");
}

/*
 * Depth-cap invariant: the recursive walk reaches the parent and its
 * first two FT_PTR_STRUCT descendants (depths 0, 1, 2) and stops
 * before depth 3.  Catches a regression that lifted or removed the
 * cap (unbounded recursion) or applied it off-by-one (only depths
 * 0/1 contribute).
 *
 * Builds a 4-deep sandbox chain via the mutate_struct_lookup_override
 * hook so the test desc resolves without polluting the production
 * struct_catalog.  Each level has one FT_FLAGS leaf; a working depth
 * cap of 3 yields exactly 3 candidates.
 */
struct selftest_depth_chain {
	unsigned char *next;
	uint32_t       leaf;
} __attribute__((packed));

static const struct struct_field selftest_depth_fields[4][2] = {
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_1" },
		},
		{
			.name		= "leaf0",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_2" },
		},
		{
			.name		= "leaf1",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_3" },
		},
		{
			.name		= "leaf2",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_unreached" },
		},
		{
			.name		= "leaf3",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
};

static const struct struct_desc selftest_depth_descs[4] = {
	{
		.name		= "selftest_depth_0",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[0],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_1",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[1],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_2",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[2],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_3",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[3],
		.num_fields	= 2,
	},
};

static const struct struct_desc *selftest_depth_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(selftest_depth_descs); i++)
		if (strcmp(selftest_depth_descs[i].name, name) == 0)
			return &selftest_depth_descs[i];
	return NULL;
}

static void selftest_depth_cap(void)
{
	struct selftest_depth_chain chain[4];
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned int n;
	unsigned int i;
	unsigned int leaf_seen = 0;

	memset(chain, 0, sizeof(chain));
	chain[0].next = (unsigned char *) &chain[1];
	chain[1].next = (unsigned char *) &chain[2];
	chain[2].next = (unsigned char *) &chain[3];
	chain[3].next = NULL;
	for (i = 0; i < 4; i++)
		chain[i].leaf = 0;

	mutate_struct_lookup_override = selftest_depth_lookup;
	n = collect_mutable_candidates((unsigned char *) &chain[0],
				       sizeof(chain[0]),
				       &selftest_depth_descs[0], NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	mutate_struct_lookup_override = NULL;

	if (n != 3)
		BUG("depth-walk did not contribute exactly 3 candidates");

	for (i = 0; i < n; i++) {
		if (strncmp(cands[i].field->name, "leaf", 4) != 0)
			BUG("depth-walk emitted a non-leaf candidate");
		/*
		 * leaf3 lives in chain[3], which is depth 3 -- past the
		 * cap.  Its name must never appear in the candidate set.
		 */
		if (strcmp(cands[i].field->name, "leaf3") == 0)
			BUG("depth-walk reached depth-3 field");
		leaf_seen |= 1U << (cands[i].field->name[4] - '0');
	}
	/* leaf0 (bit 0), leaf1 (bit 1), leaf2 (bit 2) all present. */
	if (leaf_seen != 0x7U)
		BUG("depth-walk did not visit all three reachable leaves");
}

/*
 * Variant-aware reachability gate: struct_desc_has_address_field()
 * powers the nested-address-scrub mask, which decides whether the
 * runtime scrub walks a given (syscall, arg) slot at all.  Before the
 * variant walk landed, an FT_ADDRESS that lived only inside a variant
 * (e.g. perf_event_attr.bp_addr on the BREAKPOINT arm) was invisible
 * to the reachability gate -- the mask stayed zero, the scrub never
 * ran, and an in-struct kernel-deref pointer was free to alias the
 * shared sibling buffer.
 *
 * This selftest pins the three variant locations the walker must now
 * follow (variant->fields, variant->base->fields, nested_variant->
 * fields) plus a negative case where no FT_ADDRESS is reachable.  The
 * runtime scrub in scrub_struct_addresses() mirrors the same
 * traversal shape, so guarding the reachability walker also guards
 * the live scrub against the same regression class.
 */
static void selftest_variant_address_walk(void)
{
	static const struct struct_field fields_with_addr[] = {
		{
			.name	= "va_addr",
			.offset	= 8,
			.size	= sizeof(unsigned long),
			.tag	= FT_ADDRESS,
		},
	};
	static const struct struct_field fields_no_addr[] = {
		{
			.name		= "va_flags",
			.offset		= 8,
			.size		= 4,
			.tag		= FT_FLAGS,
			.u.flags	= { .mask = 0xFFU },
		},
	};

	/* Case A: FT_ADDRESS lives only in variant->fields[]. */
	{
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "addr_v",
				.fields		= fields_with_addr,
				.num_fields	= ARRAY_SIZE(fields_with_addr),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_variant_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("variant-only FT_ADDRESS missed by reachability walker");
	}

	/* Case B: FT_ADDRESS lives only in variant->base->fields[]. */
	{
		static const struct union_variant base = {
			.name		= "addr_base",
			.fields		= fields_with_addr,
			.num_fields	= ARRAY_SIZE(fields_with_addr),
		};
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "outer_v",
				.fields		= fields_no_addr,
				.num_fields	= ARRAY_SIZE(fields_no_addr),
				.base		= &base,
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_base_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("variant->base FT_ADDRESS missed by reachability walker");
	}

	/* Case C: FT_ADDRESS lives only in nested_variants[k]->fields[]. */
	{
		static const struct union_variant nested[] = {
			{
				.discrim_value	= 7,
				.name		= "nested_addr_v",
				.fields		= fields_with_addr,
				.num_fields	= ARRAY_SIZE(fields_with_addr),
			},
		};
		static const struct union_variant variants[] = {
			{
				.discrim_value		= 1,
				.name			= "outer_v",
				.fields			= fields_no_addr,
				.num_fields		= ARRAY_SIZE(fields_no_addr),
				.nested_discrim_offset	= 4,
				.nested_discrim_size	= 1,
				.nested_variants	= nested,
				.num_nested_variants	= ARRAY_SIZE(nested),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_nested_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("nested_variant FT_ADDRESS missed by reachability walker");
	}

	/* Case D: no FT_ADDRESS anywhere -- walker must return false. */
	{
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "noaddr_v",
				.fields		= fields_no_addr,
				.num_fields	= ARRAY_SIZE(fields_no_addr),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_no_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (struct_desc_has_address_field(&desc))
			BUG("reachability walker false-positive on variant without FT_ADDRESS");
	}
}

void struct_field_mutate_self_check(void)
{
	selftest_flags();
	selftest_enum();
	selftest_vocab();
	selftest_range();
	selftest_raw();
	selftest_skiplist();
	selftest_variant_scope();
	selftest_depth_cap();
	selftest_variant_address_walk();
}
