#include "arch.h"
#include "args-internal.h"
#include "argtype-ops.h"
#include "blob_corpus.h"
#include "blob_mutator.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "minicorpus.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "utils-alloc.h"


/*
 * Map a slot's argtype to a coarse default ownership/direction descriptor.
 * Broad best-effort seed: the structurally clear argtypes (curated input
 * buffers, the in/out/inout struct pointer trio, fd-backed handles) get a
 * non-default classification; the truly generic address-family slots
 * (ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE) and bare scalars stay at
 * dir/owner == NONE so the central-generator-coverage row above this one
 * can attribute the slots it fills.  SHADOW: no caller of arg_meta_init
 * consults the result for a decision.
 */
static void argtype_default_meta(enum argtype t, uint8_t *dir, uint8_t *owner,
				 uint32_t *flags)
{
	*dir = ARG_DIR_NONE;
	*owner = ARG_OWNER_NONE;
	*flags = 0;

	switch (t) {
	case ARG_STRUCT_PTR_IN:
	case ARG_IOVEC_IN:
	case ARG_PATHNAME:
	case ARG_XATTR_NAME:
	case ARG_FSTYPE_NAME:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_NODEMASK:
	case ARG_CPUMASK:
		*dir = ARG_DIR_IN;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_STRUCT_PTR_OUT:
		*dir = ARG_DIR_OUT;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_STRUCT_PTR_INOUT:
	case ARG_IOVEC:
	case ARG_BUF_SIZED:
		*dir = ARG_DIR_INOUT;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_SOCKADDR:
		*dir = ARG_DIR_OPTIONAL_IN;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED | ARG_META_FLAG_ALLOW_NULL;
		break;
	default:
		if (is_fdarg(t))
			*owner = ARG_OWNER_EXTERNAL;
		break;
	}
}

void arg_meta_init(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint32_t generation = ++rec->arg_meta_gen;
	uint32_t prev_generation = generation - 1;
	unsigned int i;

	for (i = 0; i < 6; i++) {
		enum argtype t = (i < entry->num_args)
				? entry->argtype[i] : ARG_UNDEFINED;
		struct arg_slot_meta *m = &rec->arg_meta[i];
		uint32_t stored_gen = m->generation;
		uint8_t dir, owner;
		uint32_t flags;
		bool prestamped = (stored_gen == generation);

		/* Stale-sidecar tripwire: a non-zero stored generation that
		 * is neither the previous dispatch's value nor this dispatch's
		 * own generation (which fill_arg stamps when its central-
		 * generator coverage classifies an address-family slot) means
		 * an init pass was skipped (missed reset) or the rec was
		 * wholesale-stomped. */
		if (stored_gen != 0 && stored_gen != prev_generation &&
		    !prestamped)
			__atomic_add_fetch(&shm->stats.arg.meta_argtype_stale,
					   1, __ATOMIC_RELAXED);

		argtype_default_meta(t, &dir, &owner, &flags);

		/* Adopt fill_arg's central-generator stamp for the address-
		 * family argtypes when the prestamp signal proves the slot's
		 * dir/owner came from this dispatch's mint, not stale residue
		 * from a prior dispatch's argtype.  ARG_RANGE is in the gate
		 * for symmetry with the credit set below; fill_arg never
		 * stamps it (returns a numeric value, not an address) so the
		 * prestamped branch is never taken. */
		if (prestamped &&
		    (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS ||
		     t == ARG_RANGE)) {
			dir = m->dir;
			owner = m->owner;
		}

		*m = (struct arg_slot_meta){
			.dir = dir,
			.owner = owner,
			.flags = flags,
			.generation = generation,
		};

		if (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS ||
		    t == ARG_RANGE) {
			if (dir != ARG_DIR_NONE || owner != ARG_OWNER_NONE ||
			    flags != 0)
				__atomic_add_fetch(&shm->stats.arg.meta_addr_with_meta,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.arg.meta_addr_without_meta,
						   1, __ATOMIC_RELAXED);
		}
	}
}

void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint8_t mask = entry->address_scrub_mask;

	/* Most syscalls have no scrub-eligible slots; skip the walk entirely
	 * via the cached mask instead of running argtype_get_ops() per arg. */
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		unsigned long *slot;

		switch (i) {
		case 1: slot = &rec->a1; break;
		case 2: slot = &rec->a2; break;
		case 3: slot = &rec->a3; break;
		case 4: slot = &rec->a4; break;
		case 5: slot = &rec->a5; break;
		case 6: slot = &rec->a6; break;
		default: slot = NULL; break;
		}
		if (slot != NULL)
			avoid_shared_buffer_out(slot, page_size);
		__atomic_add_fetch(&shm->stats.arg.blanket_address_scrub_slots_walked,
				   1, __ATOMIC_RELAXED);
		mask &= (uint8_t)(mask - 1);
	}

	/* SHADOW: contradiction census between the blanket's coverage
	 * (entry->address_scrub_mask) and the per-slot sidecar dir seeded
	 * by arg_meta_init().  Telemetry only -- the live walk above is
	 * byte-unchanged. */
	for (unsigned int s = 0; s < entry->num_args && s < 6; s++) {
		uint8_t dir = rec->arg_meta[s].dir;

		if (entry->address_scrub_mask & (uint8_t)(1u << s)) {
			if (dir == ARG_DIR_IN || dir == ARG_DIR_INOUT)
				__atomic_add_fetch(&shm->stats.arg.meta_scrub_would_destroy_in,
						   1, __ATOMIC_RELAXED);
		} else if (dir == ARG_DIR_OUT) {
			__atomic_add_fetch(&shm->stats.arg.meta_scrub_would_preserve_out,
					   1, __ATOMIC_RELAXED);
		}
	}

	nested_address_scrub(entry, rec);
}

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec)
{
	/* Defensive: zero arg slots so any ARG_UNDEFINED entry doesn't
	 * inherit stale values from the previous syscall's record.  Also
	 * zero the post_state snapshot slot — sanitisers that use it
	 * allocate fresh in this dispatch, and a stale value left by a
	 * previous syscall (e.g. one whose post handler did not reach the
	 * deferred_freeptr) would otherwise survive into a post handler
	 * that now reads it as a live pointer.
	 *
	 * Only zero the slots that won't be overwritten below by fill_arg();
	 * the bulk memset of all six was wasted work for the common case of
	 * 4-6 argument syscalls. Switch fall-through unrolls the per-slot
	 * zero so the compiler can pick an efficient sequence. */
	switch (entry->num_args) {
	case 0: rec->a1 = 0; /* fall through */
	case 1: rec->a2 = 0; /* fall through */
	case 2: rec->a3 = 0; /* fall through */
	case 3: rec->a4 = 0; /* fall through */
	case 4: rec->a5 = 0; /* fall through */
	case 5: rec->a6 = 0; /* fall through */
	default: break;
	}
	rec->post_state = 0;

	/* num_args is the authority for which slots are present.
	 * Don't gate on argtype[i] != 0 — ARG_UNDEFINED is enum value 0,
	 * which would silently skip filling those slots even though
	 * fill_arg() handles ARG_UNDEFINED by returning a random value. */
	if (entry->num_args >= 1)
		rec->a1 = fill_arg(entry, rec, 1);
	if (entry->num_args >= 2)
		rec->a2 = fill_arg(entry, rec, 2);
	if (entry->num_args >= 3)
		rec->a3 = fill_arg(entry, rec, 3);
	if (entry->num_args >= 4)
		rec->a4 = fill_arg(entry, rec, 4);
	if (entry->num_args >= 5)
		rec->a5 = fill_arg(entry, rec, 5);
	if (entry->num_args >= 6)
		rec->a6 = fill_arg(entry, rec, 6);
}

void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint8_t mask;

	BUG_ON(entry == NULL);

	/* Most syscalls own no freeable resources in any slot; the cached
	 * cleanup_arg_mask lets us skip the per-arg argtype_get_ops() walk
	 * outright in that common case. */
	mask = entry->cleanup_arg_mask;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		enum argtype t = get_argtype(entry, i);
		const struct argtype_ops *ops = argtype_get_ops(t);

		deferred_free_set_cleanup_argtype(t);
		ops->cleanup(rec, i);
		deferred_free_set_cleanup_argtype(ARG_UNDEFINED);
		mask &= (uint8_t)(mask - 1);
	}
}

/*
 * Post-replay perturbation: on a bounded fraction of replays, replace
 * one cataloged ARG_STRUCT_PTR_{IN,INOUT} arg with a freshly schema-
 * filled buffer whose single FT_FLAGS or FT_RANGE field has been
 * nudged one neighbour away.  Verbatim replay is the dominant path;
 * this is a shadow-measured exploration knob, not a rewrite.
 *
 * Tag discipline: FT_FLAGS/FT_RANGE only.  Every coupled tag
 * (FT_PTR_*, FT_LEN_*, FT_FD, FT_ADDRESS, ...) is never picked -- a
 * blind flip on a length or a pointer just steers the syscall onto
 * the reject-path and burns iterations for no coverage.
 *
 * At most one field mutated per replay by construction, so the
 * replay_perturbed_wins signal attributes to a single (arg, field)
 * neighbourhood step rather than to a whole-buffer re-roll.
 */
struct perturb_cand {
	unsigned int argnum;			/* 1-based */
	const struct struct_desc *desc;
	const struct struct_field *field;
};

#define PERTURB_MAX_CANDS	32U

static void perturb_flags_field(unsigned char *buf, const struct struct_field *f)
{
	uint64_t mask = f->u.flags.mask;
	uint64_t val, bit;
	unsigned int pop, pick, seen, flips, k, i;

	if (mask == 0)
		return;

	pop = (unsigned int) __builtin_popcountll(mask);
	val = read_field_uint(buf, f);

	/* Flip 1 bit unconditionally; on wide masks (>=2 in-mask bits) roll
	 * a second flip so the neighbour move is either 1 or 2 bits.  Both
	 * flips are drawn from the mask, so the invariant "no out-of-mask
	 * bit set" holds. */
	flips = (pop >= 2 && ONE_IN(2)) ? 2U : 1U;

	for (k = 0; k < flips; k++) {
		pick = rnd_modulo_u32(pop);
		seen = 0;
		for (i = 0; i < 64; i++) {
			bit = (uint64_t) 1 << i;
			if ((mask & bit) == 0)
				continue;
			if (seen == pick) {
				val ^= bit;
				break;
			}
			seen++;
		}
	}

	write_field_uint(buf, f, val);
}

static void perturb_range_field(unsigned char *buf, const struct struct_field *f)
{
	uint64_t lo = f->u.range.lo;
	uint64_t hi = f->u.range.hi;
	uint64_t cur, next;

	if (hi <= lo)
		return;

	cur = read_field_uint(buf, f);

	/* Snap out-of-range into the interval before stepping so the
	 * clamp invariant [lo, hi] holds without needing a "give up"
	 * branch on a torn / stale value. */
	if (cur < lo)
		cur = lo;
	else if (cur > hi)
		cur = hi;

	if (cur == lo)
		next = cur + 1;
	else if (cur == hi)
		next = cur - 1;
	else if (rnd_u32() & 1)
		next = cur + 1;
	else
		next = cur - 1;

	write_field_uint(buf, f, next);
}

static bool field_is_perturbable(const struct struct_field *f)
{
	switch (f->tag) {
	case FT_FLAGS:
		return f->u.flags.mask != 0;
	case FT_RANGE:
		return f->u.range.hi > f->u.range.lo;
	default:
		return false;
	}
}

static unsigned int collect_perturb_candidates(struct syscallentry *entry,
					       struct syscallrecord *rec,
					       struct perturb_cand *out,
					       unsigned int out_max)
{
	unsigned int i, k;
	unsigned int n = 0;

	for (i = 0; i < entry->num_args && i < 6 && n < out_max; i++) {
		enum argtype t = entry->argtype[i];
		const struct struct_desc *desc;
		const struct struct_field *fields;
		unsigned int n_fields;

		if (t != ARG_STRUCT_PTR_IN && t != ARG_STRUCT_PTR_INOUT)
			continue;

		desc = struct_arg_lookup(rec->nr, i + 1, rec->do32bit, rec);
		if (desc == NULL || desc->struct_size == 0)
			continue;

		fields = desc->fields;
		n_fields = desc->num_fields;
		if (fields == NULL || n_fields == 0)
			continue;
		if (n_fields > STRUCT_FILL_MAX_FIELDS)
			n_fields = STRUCT_FILL_MAX_FIELDS;

		for (k = 0; k < n_fields && n < out_max; k++) {
			const struct struct_field *f = &fields[k];

			if ((unsigned long) f->offset + f->size > desc->struct_size)
				continue;
			if (!field_is_perturbable(f))
				continue;

			out[n].argnum = i + 1;
			out[n].desc = desc;
			out[n].field = f;
			n++;
		}
	}
	return n;
}

static void perturb_replayed_struct_field(struct syscallentry *entry,
					  struct syscallrecord *rec)
{
	struct perturb_cand cands[PERTURB_MAX_CANDS];
	const struct perturb_cand *pick;
	unsigned int n;
	unsigned char *buf;
	unsigned long *slot;

	if (!ONE_IN(MINICORPUS_PERTURB_DENOM))
		return;

	n = collect_perturb_candidates(entry, rec, cands, PERTURB_MAX_CANDS);
	if (n == 0)
		return;

	pick = &cands[rnd_modulo_u32(n)];

	buf = zmalloc_tracked(pick->desc->struct_size);
	struct_field_fill_schema_aware(buf, pick->desc->struct_size,
				       pick->desc, rec);

	if (pick->field->tag == FT_FLAGS)
		perturb_flags_field(buf, pick->field);
	else
		perturb_range_field(buf, pick->field);

	deferred_free_enqueue_or_leak(buf);

	switch (pick->argnum) {
	case 1: slot = &rec->a1; break;
	case 2: slot = &rec->a2; break;
	case 3: slot = &rec->a3; break;
	case 4: slot = &rec->a4; break;
	case 5: slot = &rec->a5; break;
	case 6: slot = &rec->a6; break;
	default: return;
	}
	*slot = (unsigned long) buf;

	__atomic_fetch_add(&minicorpus_shm->replay_perturbed_count, 1UL,
			   __ATOMIC_RELAXED);
	minicorpus_replay_perturbation_mark();
}

void generate_syscall_args(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	struct childdata *child;

	srec_publish_begin(rec);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL) {
		srec_publish_end(rec);
		return;
	}
	__atomic_store_n(&rec->state, PREP, __ATOMIC_RELAXED);

	/* reset the per-call cmp-hint latch so each new
	 * call starts with a fresh "no hint injected yet" state.  Any of
	 * the five argtype-handler callsites below that pulls a hint via
	 * cmp_hints_try_get() sets the flag through credit_cmp_hint_injection
	 * before the dispatch lands; kcov_collect()'s found_new branch then
	 * reads it to credit per_syscall_cmp_hint_pc_wins[nr].  Parent-
	 * context this_child()==NULL skips the clear -- the flag has no
	 * parent-side consumer. */
	child = this_child();
	if (child != NULL) {
		child->cmp_hint_injected_this_call = false;
		/* --blob-ab-mode per-call stamp: each call starts with
		 * no blob-fill mode recorded, so the dispatch-site
		 * credit block short-circuits when the flag is absent
		 * or when a call happened not to fire any blob_fill().
		 * Set by blob_fill()'s ab-mode branch to the HAVOC or
		 * CMPDICT coin-flip outcome and drained at the credit
		 * block in random_syscall/dispatch.c. */
		child->blob_ab_mode_last = BLOB_AB_MODE_NONE;
		/* SHADOW feedback scoring stash starts each call empty
		 * ([11-feedback-loop]).  cmp_hints_try_get_ex pushes; the
		 * dispatch_step tail drains and credits via one of the
		 * cmp_hints_feedback_credit_* helpers.  Resetting here too
		 * means a parent dispatch that bailed before reaching the
		 * credit drain cannot leak its stash into the next call. */
		cmp_hints_feedback_reset_stash();
	}

	/* Reset post_state on every syscall step, before any branch.
	 * generic_sanitise() also clears it, but the minicorpus-replay
	 * path below skips generic_sanitise entirely; without this hoist,
	 * a sanitise-less syscall whose prior post handler did not reach
	 * deferred_freeptr would leave a stale pointer in post_state for
	 * the next syscall's post handler to dereference. */
	rec->post_state = 0;
	/* Same hoist for the per-rec owned-pointer list: rec_owned_drain
	 * zeros owned_count after every dispatched call, but the drain
	 * site is in handle_syscall_ret -- a minicorpus-replay step that
	 * inherits a rec where the previous dispatch never reached the
	 * drain (e.g. the child died between BEFORE and AFTER and the
	 * rec is re-used after fork) could otherwise see a stale owned[]
	 * entry and free a pointer the new caller never owned.  Hoisting
	 * the reset here matches the post_state contract above. */
	rec->owned_count = 0;
	/* Drop any pending blob-corpus stash left over from a previous
	 * dispatch that never reached the minicorpus_save promotion path
	 * (no novelty signal fired).  Same rationale as the post_state /
	 * owned_count hoists above: without this clear a stale pending
	 * from the prior call could be promoted by this call's save. */
	blob_corpus_clear_pending();
	/* Same hoist for arg_snapshot_mask: defaults to "nothing shadowed"
	 * so get_arg_snapshot() in any unrelated handler that somehow gets
	 * called against this rec (e.g. an early validate_arg_coupling
	 * rejection in __do_syscall before the dispatch-time snapshot
	 * runs) sees the live slot instead of a stale shadow from a
	 * previous dispatch.  The real snapshot is taken in __do_syscall
	 * after the second blanket_address_scrub, from the local a1..a6
	 * values that are actually passed to the kernel. */
	rec->arg_snapshot_mask = 0;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		if (minicorpus_shm != NULL)
			perturb_replayed_struct_field(entry, rec);
		arg_meta_init(entry, rec);
		blanket_address_scrub(entry, rec);
		srec_publish_end(rec);
		return;
	}

	generic_sanitise(entry, rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);
	arg_meta_init(entry, rec);
	blanket_address_scrub(entry, rec);

	srec_publish_end(rec);
}
