/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef STATS_ARM_VERDICT_H
#define STATS_ARM_VERDICT_H

/*
 * Shared dead-arm verdict status tokens.
 *
 * Both the text emitter (stats/dump/subsystems.c) and the JSON emitter
 * (stats/json/tail.c) report dead-arm detection results using these
 * tokens.  Keeping the strings in one place prevents the emitters from
 * drifting apart silently (the historical hyphen-vs-underscore class).
 *
 * Usage:
 *   arm_verdict_to_str(ARM_VERDICT_DEAD)
 *   arm_verdict_to_str(ARM_VERDICT_INSUFFICIENT_SAMPLES)
 *   arm_verdict_to_str(ARM_VERDICT_UNSUPPORTED)
 *   arm_verdict_to_str(ARM_VERDICT_RAN_NO_EFFECT)
 */

enum arm_verdict {
	ARM_VERDICT_DEAD,
	ARM_VERDICT_INSUFFICIENT_SAMPLES,
	ARM_VERDICT_UNSUPPORTED,
	ARM_VERDICT_RAN_NO_EFFECT,
	/* RUNTIME_DEAD: arm is config-live (compiled in, F_OK visible) but
	 * dead at runtime due to capability or device-access constraints
	 * discovered after cap-drop.  Distinct from UNSUPPORTED (feature
	 * absent from kernel) and DEAD (selector-unreachable arm). */
	ARM_VERDICT_RUNTIME_DEAD,
	ARM_VERDICT__COUNT,
};

static const char * const arm_verdict_str[] = {
	[ARM_VERDICT_DEAD]                 = "dead",
	[ARM_VERDICT_INSUFFICIENT_SAMPLES] = "insufficient_samples",
	[ARM_VERDICT_UNSUPPORTED]          = "unsupported",
	[ARM_VERDICT_RAN_NO_EFFECT]        = "ran_no_effect",
	[ARM_VERDICT_RUNTIME_DEAD]         = "runtime_dead",
};

_Static_assert(sizeof(arm_verdict_str) / sizeof(arm_verdict_str[0]) == ARM_VERDICT__COUNT,
	       "arm_verdict_str[] out of sync with enum arm_verdict");

static inline const char *arm_verdict_to_str(enum arm_verdict v)
{
	return arm_verdict_str[v];
}

#endif /* STATS_ARM_VERDICT_H */
