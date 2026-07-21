/*
 * Per-child ring of small-integer return values captured from recent
 * syscall returns, available for re-injection as input arguments to
 * later syscalls.  See include/prop_ring.h for the data shape and
 * Documentation/architecture or the constant-propagation design note
 * for the motivation.
 *
 * Capture side runs in handle_syscall_ret() after register_returned_fd.
 * Consume side runs in gen_undefined_arg() at low probability so the
 * raw-random exploration path keeps its share of the mutation budget.
 *
 * Single-writer / single-reader from the owning child only.  No
 * atomics, no cross-process visibility.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "child.h"
#include "kcov.h"
#include "objects.h"
#include "prop_ring.h"
#include "rnd.h"
#include "shm.h"

/* Slots older than this (measured in child->op_nr ticks) are skipped
 * by the consumer -- the win is chaining values into multi-step
 * protocols within a short window, not resurrecting stale state from
 * thousands of syscalls ago. */
#define PROP_RING_RECENCY_MAX	64

/* Capture-side acceptance window for "small int that looks like a
 * cookie / id / count, not a kernel pointer or an error code".  The
 * upper bound is well under the lowest plausible userspace address on
 * any supported arch, so a returned address can't slip through this
 * filter and become input to a later syscall -- the wild-write channel
 * that default_address_scrub exists to break stays broken. */
#define PROP_RING_HIGH_PTR	0x40000000UL

/* Baseline inject probability denominator.  Matches the design note's
 * "meaningful share without crowding out random exploration" target --
 * roughly the same per-call injection rate as the cmp_hints case in
 * gen_undefined_arg's mod-9 switch. */
#define PROP_RING_INJECT_MOD		12

/* Per-injection recency-filter probe budget.  If every slot we touch
 * inside the loop is stale (older than PROP_RING_RECENCY_MAX), the ring
 * as a whole is treated as stale and the caller falls back to
 * raw-random generation. */
#define PROP_RING_RECENCY_PROBE_TRIES	4

/* Inverse probability of the typed-consumer escape hatch.  When a
 * typed callsite asks for kind K but no fresh kind-K slot is found
 * (or even before the same-kind walk), with ~1-in-N we accept any
 * slot regardless of tag.  Keeps a chaos contribution alive when the
 * same-kind population is empty / stale, and lets a SCALAR_UNTYPED
 * value occasionally land in a typed arg slot the way it would today
 * under the kind-agnostic prop_ring_try_get(). */
#define PROP_RING_KIND_ESCAPE_MOD	8

static unsigned int ring_prev(unsigned int head)
{
	return (head - 1) & (CHILD_PROP_RING_SIZE - 1);
}

/*
 * Shared filter + dedup + slot-fill body for the public push variants.
 * Returns true iff a new slot was published.  Callers gate the OBJ_NONE
 * check (or deliberately bypass it for typed scalar returns that have
 * their own external registrar) before reaching here, and pass the
 * KIND tag the published slot should carry.
 */
static bool prop_ring_push_filtered(struct childdata *child,
				    unsigned int src_nr,
				    bool do32bit,
				    unsigned long value,
				    enum scalar_kind kind)
{
	struct child_prop_ring *ring;
	struct prop_slot *prev;
	struct prop_slot *slot;
	long sret = (long) value;

	/* -1 is the failure sentinel; small negative values just outside
	 * it (errno-encoded returns from syscalls that don't go through
	 * libc's errno indirection, signal numbers, etc.) are legitimate
	 * cookies and stay in the window. */
	if (sret == -1)
		return false;
	if (sret < -32 || sret > INT32_MAX)
		return false;

	/* Pointer-shape firewall for positive returns.  Negatives in
	 * [-32, -2] survive the unsigned cast as huge values and would
	 * otherwise be rejected here -- exempt them explicitly. */
	if (sret > 0 && (unsigned long) sret > PROP_RING_HIGH_PTR)
		return false;

	/* The fd pool already biases live fds back into ARG_FD slots.
	 * If a generic scalar return happens to alias a registered fd,
	 * skip capture so we don't double-bias. */
	if (sret > 2 && fd_hash_lookup((int) sret) != NULL)
		return false;

	ring = &child->prop_ring;

	/* Dedup against the most recent slot so an open/close loop
	 * that keeps returning the same fd doesn't fill the whole ring
	 * with one value.  Kind is part of the dedup key so a value
	 * pushed first untyped and then typed (or vice-versa) is not
	 * folded into one slot -- the typed consumer needs to find a
	 * tagged copy. */
	prev = &ring->slots[ring_prev(ring->head)];
	if (prev->valid &&
	    prev->value == value &&
	    prev->src_nr == src_nr &&
	    prev->do32bit == do32bit &&
	    prev->kind == kind)
		return false;

	slot = &ring->slots[ring->head & (CHILD_PROP_RING_SIZE - 1)];
	slot->value = value;
	slot->captured_at = child->op_nr;
	slot->src_nr = src_nr;
	slot->kind = kind;
	slot->do32bit = do32bit;
	slot->valid = true;
	ring->head++;
	return true;
}

void prop_ring_push(struct childdata *child,
		    const struct syscallentry *entry,
		    const struct syscallrecord *rec)
{
	if (child == NULL || entry == NULL || rec == NULL)
		return;

	/* Typed returns own their own propagation paths (fd pool, key
	 * serial registrar, pid registrar).  Only general scalars land
	 * here, tagged SCALAR_UNTYPED so the kind-aware consumers can
	 * distinguish them from typed cookies that arrived via
	 * prop_ring_push_scalar(). */
	if (entry->ret_objtype != OBJ_NONE)
		return;

	prop_ring_push_filtered(child, rec->nr, rec->do32bit,
				rec->retval, SCALAR_UNTYPED);
}

/*
 * Variant for typed scalar returns whose own registrar (key serial,
 * etc.) has already accepted the value and we additionally want it
 * mirrored into the propagation ring so consumers can replay it.
 * Bypasses the OBJ_NONE gate by design -- the caller must guarantee
 * the value is a non-fd / non-pid scalar, since the in-line pointer-
 * shape / fd-alias filters cannot tell typed integer cookies apart
 * from raw scalars.  The OBJ_NONE gate on prop_ring_push() above
 * stays intact so the fd/pid leakage vector it was added to close
 * stays closed.  The slot lands tagged with KIND so kind-aware
 * consumers in generate-args.c can prefer same-type cookies.
 */
void prop_ring_push_scalar(unsigned int nr, long scalar_val,
			   enum scalar_kind kind)
{
	struct childdata *child = this_child();

	if (child == NULL)
		return;
	/* Defensive: a SCALAR_UNTYPED tag here would silently fold the
	 * typed push into the OBJ_NONE pool the consumer is trying to
	 * keep separate.  Reject rather than misclassify. */
	if (kind == SCALAR_UNTYPED || kind >= SCALAR_NR_KINDS)
		return;

	if (prop_ring_push_filtered(child, nr, false,
				    (unsigned long) scalar_val, kind))
		__atomic_add_fetch(&shm->stats.diag.propagation_injected_key_scalar,
				   1, __ATOMIC_RELAXED);
}

bool prop_ring_try_get(struct childdata *child,
		       const struct syscallrecord *rec,
		       unsigned long *out)
{
	struct child_prop_ring *ring;
	unsigned int populated;
	unsigned int tries;
	unsigned long now;

	if (child == NULL || rec == NULL || out == NULL)
		return false;

	if (rnd_modulo_u32(PROP_RING_INJECT_MOD) != 0)
		return false;

	ring = &child->prop_ring;
	populated = ring->head < CHILD_PROP_RING_SIZE
		    ? ring->head : CHILD_PROP_RING_SIZE;
	if (populated == 0)
		return false;

	now = child->op_nr;

	/* Uniform pick over the populated range, with a recency filter.
	 * Up to a handful of probes -- if every slot we touch is stale,
	 * the ring as a whole is stale and the caller falls back to
	 * raw-random generation. */
	for (tries = 0; tries < PROP_RING_RECENCY_PROBE_TRIES; tries++) {
		unsigned int idx = rnd_modulo_u32(populated);
		struct prop_slot *slot = &ring->slots[idx];

		if (!slot->valid)
			continue;
		if (now - slot->captured_at > PROP_RING_RECENCY_MAX)
			continue;

		*out = slot->value;
		return true;
	}

	return false;
}

bool prop_ring_try_get_kind(struct childdata *child,
			    const struct syscallrecord *rec,
			    enum scalar_kind kind,
			    unsigned long *out)
{
	struct child_prop_ring *ring;
	unsigned int populated;
	unsigned int tries;
	unsigned long now;
	bool escape_hatch;

	if (child == NULL || rec == NULL || out == NULL)
		return false;
	if (kind == SCALAR_UNTYPED || kind >= SCALAR_NR_KINDS)
		return false;

	if (rnd_modulo_u32(PROP_RING_INJECT_MOD) != 0)
		return false;

	ring = &child->prop_ring;
	populated = ring->head < CHILD_PROP_RING_SIZE
		    ? ring->head : CHILD_PROP_RING_SIZE;
	if (populated == 0)
		return false;

	/* Roll the escape hatch up-front so the per-call RNG sequence
	 * is stable regardless of whether the same-kind walk below
	 * finds a hit -- a downstream A/B comparison needs the same
	 * draw count whether or not the ring is populated with our
	 * kind on a given call. */
	escape_hatch = (rnd_modulo_u32(PROP_RING_KIND_ESCAPE_MOD) == 0);

	now = child->op_nr;

	for (tries = 0; tries < PROP_RING_RECENCY_PROBE_TRIES; tries++) {
		unsigned int idx = rnd_modulo_u32(populated);
		struct prop_slot *slot = &ring->slots[idx];

		if (!slot->valid)
			continue;
		if (now - slot->captured_at > PROP_RING_RECENCY_MAX)
			continue;

		if (slot->kind == kind) {
			*out = slot->value;
			if (kcov_shm != NULL)
				__atomic_fetch_add(
				    &kcov_shm->cohorts.prop_ring_kind_consumed[kind],
				    1UL, __ATOMIC_RELAXED);
			return true;
		}

		/* Same-kind miss this probe.  If the escape hatch is
		 * armed for this call we take the slot anyway, counted
		 * separately so the kind-discipline signal is not
		 * polluted by chaos contributions. */
		if (escape_hatch) {
			*out = slot->value;
			if (kcov_shm != NULL)
				__atomic_fetch_add(
				    &kcov_shm->cohorts.prop_ring_kind_escape_fires,
				    1UL, __ATOMIC_RELAXED);
			return true;
		}
	}

	return false;
}
