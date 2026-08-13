#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		// BUG
#include "minicorpus.h"		// minicorpus_struct_field_attrib
#include "random.h"
#include "rnd.h"
#include "struct_catalog.h"
#include "struct_mutate-internal.h"
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
void mutate_field_flags(unsigned char *buf, const struct struct_field *f)
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
void mutate_field_enum(unsigned char *buf, const struct struct_field *f)
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
void mutate_field_vocab(unsigned char *buf, const struct struct_field *f)
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
void mutate_field_range(unsigned char *buf, const struct struct_field *f)
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
void mutate_field_srange(unsigned char *buf, const struct struct_field *f)
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
void mutate_field_raw(unsigned char *buf, const struct struct_field *f)
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
 *
 * struct mutate_candidate, STRUCT_MUTATE_DEPTH_CAP, and
 * STRUCT_MUTATE_MAX_CANDIDATES live in include/struct_mutate-internal.h
 * so the selftest TU can drive collect_mutable_candidates over a
 * sandbox catalog with the same layout production uses.
 */
const struct struct_desc *(*mutate_struct_lookup_override)(const char *);

static const struct struct_desc *mutate_lookup_desc(const char *name)
{
	if (mutate_struct_lookup_override != NULL)
		return mutate_struct_lookup_override(name);
	return struct_catalog_lookup(name);
}

unsigned int collect_mutable_candidates(unsigned char *buf,
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

		if (f->offset > size || f->size > size - f->offset)
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
		} else if (f->tag == FT_EMBEDDED_STRUCT) {
			/*
			 * Child lives in-place at buf + offset within the
			 * parent's own backing buffer -- no pointer to deref,
			 * no NULL-check.  Bounds against the parent's size
			 * still gate before recursing.
			 */
			const struct struct_desc *child_desc;

			child_desc = mutate_lookup_desc(
				f->u.embedded_struct.elem_struct_name);
			if (child_desc == NULL || child_desc->struct_size == 0)
				continue;
			if (f->offset > size || child_desc->struct_size > size - f->offset)
				continue;

			collected += collect_mutable_candidates(
				buf + f->offset, child_desc->struct_size,
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

