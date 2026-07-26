#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_hyp_shadow.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_hyp_shadow {
unsigned long cmp_hyp_pow2_derive_would_fire;
unsigned long cmp_hyp_pow2_derive_would_win;

/* Shadow measurement of BITMASK combination probe classes in the
 * typed-hypothesis derive.  The live BITMASK lane today emits
 * only single-bit values chosen uniformly from picked->mask
 * (the accumulated OR of all single-bit constants observed at
 * this (nr, cmp_ip, width)); two natural combination probes
 * carry information single-bit picks structurally cannot:
 *
 *  FULL_OR: emit picked->mask itself once popcount(mask) >= 2.
 *  Reaches `(flags & A) && (flags & B)` gates the single-bit
 *  lane cannot converge on -- the two arms need both bits set
 *  simultaneously, and a lane that only ever fires ONE bit at a
 *  time hits AT MOST one arm per probe.
 *
 *  ANDNOT_TOGGLE: gated on popcount(~mask & width_mask) small
 *  enough (1..8 bits) that the complement forms a plausible
 *  disallowed-bit set for an `x & ~c` allow-mask check.  Emits
 *  candidates of the form (mask | (1<<b)) for each disallowed
 *  bit b -- flipping one at a time surfaces WHICH disallowed
 *  bit trips the gate.
 *
 * would_fire counts every derive at a BITMASK-picked hypothesis
 * whose accumulated mask makes the respective combo eligible;
 * would_win counts the subset where the combo candidate differs
 * from the value the live BITMASK lane just emitted (a single
 * bit picked from the mask), so a live promotion would surface
 * a value the existing lane did not.  Nothing on the live pick /
 * inject / credit path reads these counters; ratio in per-mille
 * sizes the delta a live promotion would open up.  Append-only
 * at the tail per convention so consumer offsets stay stable. */
unsigned long cmp_hyp_bitmask_full_or_would_fire;
unsigned long cmp_hyp_bitmask_full_or_would_win;
unsigned long cmp_hyp_bitmask_andnot_toggle_would_fire;
unsigned long cmp_hyp_bitmask_andnot_toggle_would_win;

/* Shadow measurement of a signed / unsigned SIGN-SWITCH probe class
 * in the typed-hypothesis derive.  KCOV cmp words carry no sign bit,
 * so the class is strictly ARGTYPE-GATED: only fires where the
 * argtype callsite plus the picked hypothesis together yield a known
 * signedness verdict.  Two verdicts are wired in this row --
 * CMP_HINT_CALLSITE_ARG_STRUCT_SIZE is inherently unsigned
 * (size_t / u32 argtype family), and CMP_HINT_CALLSITE_ARG_RANGE
 * with a CMP_HYP_RANGE-kind pick inherits the observer's already-
 * inferred range_signedness; every other callsite / kind stays
 * UNKNOWN and the probe is silent (further inference slices are
 * follow-ups per the derive-lane plan).
 *
 * would_fire counts every derive at an argtype-gated signedness-
 * known callsite whose picked exemplar has the sign bit of the
 * operand width set -- i.e. sits in the ambiguous "signed-negative
 * vs unsigned-large" region where reinterpretation carries
 * information.  Below the sign boundary both interpretations agree
 * and the class has no candidate to add.
 *
 * would_win counts the subset where at least one candidate from the
 * {two's-complement negation, sign-bit XOR, sign_bit,
 * sign_bit - 1} ladder (all masked to the operand width) differs
 * from the value the live derive lane just emitted, so a live
 * promotion would surface a value the existing lanes did not.  The
 * live derive is byte-for-byte unchanged; the ratio in per-mille
 * sizes the coverage headroom of promoting the class.  Append-only
 * at the tail per convention so consumer offsets stay stable. */
unsigned long cmp_hyp_sign_switch_would_fire;
unsigned long cmp_hyp_sign_switch_would_win;
};
