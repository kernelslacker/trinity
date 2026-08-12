/*
 * SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)
 */
#include <linux/ioprio.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

#ifndef IOPRIO_NR_LEVELS
#define IOPRIO_NR_LEVELS	8
#endif

#ifndef IOPRIO_CLASS_INVALID
#define IOPRIO_CLASS_INVALID	7
#endif

#ifndef IOPRIO_HINT_SHIFT
#define IOPRIO_HINT_SHIFT	3
#endif

#ifndef IOPRIO_NR_HINTS
#define IOPRIO_NR_HINTS		1024
#endif

#ifndef IOPRIO_HINT_NONE
#define IOPRIO_HINT_NONE			0
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_1
#define IOPRIO_HINT_DEV_DURATION_LIMIT_1	1
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_2
#define IOPRIO_HINT_DEV_DURATION_LIMIT_2	2
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_3
#define IOPRIO_HINT_DEV_DURATION_LIMIT_3	3
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_4
#define IOPRIO_HINT_DEV_DURATION_LIMIT_4	4
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_5
#define IOPRIO_HINT_DEV_DURATION_LIMIT_5	5
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_6
#define IOPRIO_HINT_DEV_DURATION_LIMIT_6	6
#endif
#ifndef IOPRIO_HINT_DEV_DURATION_LIMIT_7
#define IOPRIO_HINT_DEV_DURATION_LIMIT_7	7
#endif

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

/*
 * The kernel's ioprio_check_cap() / sys_ioprio_set() validates the
 * (class, level, hint) triple against a narrow per-class matrix:
 *
 *   IOPRIO_CLASS_RT   level in [0, IOPRIO_NR_LEVELS) (== 0..7)
 *   IOPRIO_CLASS_BE   level in [0, IOPRIO_NR_LEVELS) (== 0..7)
 *   IOPRIO_CLASS_IDLE level == 0 (ignored, kernel forces 7 historically;
 *                                 v6.x accepts 0 explicitly)
 *   IOPRIO_CLASS_NONE level == 0 (kernel resets to default)
 *
 * The 10-bit hint field (bits 3..12) carries IOPRIO_HINT_* values; hints
 * in [0, IOPRIO_NR_HINTS) pass the ioprio_value() range check.
 *
 * Random `ioprio` ints almost never land on a legal (class, level, hint)
 * triple: a uniform 32-bit draw clears the class field 7/8 of the time,
 * and the level field exceeds IOPRIO_NR_LEVELS most of the time too.
 * Seed the legal-combos bucket so the kernel actually reaches the
 * per-class io_priority_install() path, and vary the hint dimension so
 * the hint-decode path is exercised too.
 */

struct ioprio_valid_combo {
	unsigned int class;
	unsigned int level;
	unsigned int hint;
};

static const struct ioprio_valid_combo ioprio_valid_combos[] = {
	/* IOPRIO_CLASS_RT covers level 0..7 with any legal hint. */
	{ IOPRIO_CLASS_RT,   0, IOPRIO_HINT_NONE },
	{ IOPRIO_CLASS_RT,   3, IOPRIO_HINT_DEV_DURATION_LIMIT_1 },
	{ IOPRIO_CLASS_RT,   7, IOPRIO_HINT_DEV_DURATION_LIMIT_7 },
	/* IOPRIO_CLASS_BE covers level 0..7 with any legal hint. */
	{ IOPRIO_CLASS_BE,   0, IOPRIO_HINT_NONE },
	{ IOPRIO_CLASS_BE,   4, IOPRIO_HINT_DEV_DURATION_LIMIT_3 },
	{ IOPRIO_CLASS_BE,   7, IOPRIO_HINT_DEV_DURATION_LIMIT_5 },
	/* IOPRIO_CLASS_IDLE / NONE require level == 0. */
	{ IOPRIO_CLASS_IDLE, 0, IOPRIO_HINT_NONE },
	{ IOPRIO_CLASS_IDLE, 0, IOPRIO_HINT_DEV_DURATION_LIMIT_2 },
	{ IOPRIO_CLASS_NONE, 0, IOPRIO_HINT_NONE },
};

static const unsigned int ioprio_hint_values[] = {
	IOPRIO_HINT_NONE,
	IOPRIO_HINT_DEV_DURATION_LIMIT_1,
	IOPRIO_HINT_DEV_DURATION_LIMIT_2,
	IOPRIO_HINT_DEV_DURATION_LIMIT_3,
	IOPRIO_HINT_DEV_DURATION_LIMIT_4,
	IOPRIO_HINT_DEV_DURATION_LIMIT_5,
	IOPRIO_HINT_DEV_DURATION_LIMIT_6,
	IOPRIO_HINT_DEV_DURATION_LIMIT_7,
};

static void sanitise_ioprio_set(struct syscallrecord *rec)
{
	unsigned int bucket = rnd_modulo_u32(10);
	unsigned int class, level, hint;

	if (bucket < 7) {
		/* 70%: known-valid (class, level, hint) combo from the table. */
		const struct ioprio_valid_combo *c =
			&ioprio_valid_combos[rnd_modulo_u32(
				sizeof(ioprio_valid_combos) /
				sizeof(ioprio_valid_combos[0]))];
		class = c->class;
		level = c->level;
		/* Keep the combo's known-valid class/level anchor, but half
		 * the time vary the hint across the full legal IOPRIO_HINT_*
		 * set (still a valid triple) so the hint-decode path is
		 * exercised beyond the single hint paired in the table. */
		if (rnd_modulo_u32(2))
			hint = c->hint;
		else
			hint = ioprio_hint_values[rnd_modulo_u32(
				sizeof(ioprio_hint_values) /
				sizeof(ioprio_hint_values[0]))];
		rec->a3 = ((class & 0x7) << IOPRIO_CLASS_SHIFT) |
			  ((hint & 0x3ff) << IOPRIO_HINT_SHIFT) |
			  (level & 0x7);
	} else if (bucket < 9) {
		/* 20%: real class with deliberately invalid level and/or hint
		 * so the kernel's per-class range check stays exercised.
		 * Include IOPRIO_CLASS_INVALID here — the kernel treats it as
		 * a class the caller cannot request, which drives a distinct
		 * rejection path from a valid class with an out-of-range
		 * level. */
		switch (rnd_modulo_u32(5)) {
		case 0: class = IOPRIO_CLASS_RT; break;
		case 1: class = IOPRIO_CLASS_BE; break;
		case 2: class = IOPRIO_CLASS_IDLE; break;
		case 3: class = IOPRIO_CLASS_NONE; break;
		default: class = IOPRIO_CLASS_INVALID; break;
		}
		/* level > IOPRIO_NR_LEVELS-1 so the per-class check fires;
		 * hint drawn from the full 10-bit space so both legal-hint and
		 * out-of-range-hint rejection paths are hit. Pack the word by
		 * hand — the upstream IOPRIO_PRIO_VALUE() macro is a
		 * validating inline that collapses every out-of-range triple
		 * to IOPRIO_CLASS_INVALID<<IOPRIO_CLASS_SHIFT (0xe000),
		 * which would flatten this whole bucket to a single word. */
		level = IOPRIO_NR_LEVELS + rnd_modulo_u32(8184);
		hint = rnd_modulo_u32(IOPRIO_NR_HINTS * 2);
		rec->a3 = ((class & 0x7) << IOPRIO_CLASS_SHIFT) |
			  ((hint & 0x3ff) << IOPRIO_HINT_SHIFT) |
			  (level & 0x1fff);
	} else {
		/* 10%: pure random 13-bit (class << 13 | data) word. */
		rec->a3 = rand32();
	}

	/*
	 * who-arg bias.  The framework already picked rec->a1 (which) from
	 * ioprio_who[] and rec->a2 (who) via ARG_PID.  Refine:
	 *
	 *   ~50% IOPRIO_WHO_PROCESS, who left to ARG_PID (self/child).
	 *   ~30% IOPRIO_WHO_PGRP / IOPRIO_WHO_USER targeting our own
	 *        pgrp / uid so the lookup actually finds a task we own.
	 *   ~20% leave the framework's pick alone for the random tail.
	 */
	{
		unsigned int who_bucket = rnd_modulo_u32(10);

		if (who_bucket < 5) {
			rec->a1 = IOPRIO_WHO_PROCESS;
			/* a2 (ARG_PID) already biased self/child by get_pid(). */
		} else if (who_bucket < 8) {
			if (RAND_BOOL()) {
				rec->a1 = IOPRIO_WHO_PGRP;
				rec->a2 = (unsigned long) getpgrp();
			} else {
				rec->a1 = IOPRIO_WHO_USER;
				rec->a2 = (unsigned long) getuid();
			}
		}
	}
}

struct syscallentry syscall_ioprio_set = {
	.name = "ioprio_set",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who", [2] = "ioprio" },
	.arg_params[0].list = ARGLIST(ioprio_who),
	.sanitise = sanitise_ioprio_set,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
	.flags = REEXEC_SANITISE_OK,
};
