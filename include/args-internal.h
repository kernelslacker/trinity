#pragma once

/*
 * Internal header for the args/ cluster.  Holds prototypes and shared
 * constants for helpers that cross cluster boundaries within the
 * generate-args carve but are not part of the public argtype-ops /
 * sanitise API.
 *
 * The public API lives in include/argtype-ops.h, include/sanitise.h,
 * and include/arg-len-semantics.h; anything callers outside args/
 * need continues to be declared there.  This header is private to the
 * args/ subdirectory and the generate-args driver.
 */

#include <stdbool.h>
#include <stdint.h>

#include "kcov.h"		/* enum cmp_hint_callsite */
#include "syscall.h"		/* struct syscallentry, struct syscallrecord, enum argtype */

/*
 * cmp-hint injection rate + credit-stamp helpers.  Definitions live in
 * args/cmp_hint_inject.c.
 *
 * cmp_hint_inject_denom() resolves the ONE_IN denom for a callsite's
 * baseline (16 for the ARG_RANGE/OP/LIST callsites, 9 for the
 * gen_undefined_arg case-0 shortcut, 10 for the ARG_STRUCT_SIZE
 * fallback), amplifying to 4 during a plateau-driven rescue.
 *
 * cmp_hint_baseline_should_inject() folds the per-child A/B baseline
 * gate around cmp_hint_inject_denom().  Used only at the three
 * BASELINE callsites; the AMPLIFIED callsites keep calling
 * cmp_hint_inject_denom() directly.
 *
 * credit_cmp_hint_injection() runs at every callsite that commits an
 * injected hint, keeping the observability counters and the per-call
 * latch in lock-step.
 */
unsigned int cmp_hint_inject_denom(unsigned int baseline);
bool cmp_hint_baseline_should_inject(void);
void credit_cmp_hint_injection(struct syscallrecord *rec,
			       enum cmp_hint_callsite callsite);
