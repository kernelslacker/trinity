/*
 * SYSCALL_DEFINE3(ioprio_set, int, which, int, who, int, ioprio)
 */
#include <linux/ioprio.h>
#include <sys/types.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

#ifndef IOPRIO_NR_LEVELS
#define IOPRIO_NR_LEVELS	8
#endif

#ifndef IOPRIO_PRIO_VALUE
#define IOPRIO_PRIO_VALUE(class, data) \
	((((class) & 0x7) << IOPRIO_CLASS_SHIFT) | ((data) & 0x1fff))
#endif

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

/*
 * The kernel's ioprio_check_cap() / sys_ioprio_set() validates the
 * (class, data) pair against a narrow per-class matrix:
 *
 *   IOPRIO_CLASS_RT   data in [0, IOPRIO_NR_LEVELS) (== 0..7)
 *   IOPRIO_CLASS_BE   data in [0, IOPRIO_NR_LEVELS) (== 0..7)
 *   IOPRIO_CLASS_IDLE data == 0 (ignored, kernel forces 7 historically;
 *                                v6.x accepts 0 explicitly)
 *   IOPRIO_CLASS_NONE data == 0 (kernel resets to default)
 *
 * Random `ioprio` ints almost never land on a legal (class, data) pair:
 * a uniform 32-bit draw clears the class field 7/8 of the time, and
 * the level field exceeds IOPRIO_NR_LEVELS most of the time too.  Seed
 * the legal-combos bucket so the kernel actually reaches the per-class
 * io_priority_install() path.
 */

struct ioprio_valid_combo {
	unsigned int class;
	unsigned int data;
};

static const struct ioprio_valid_combo ioprio_valid_combos[] = {
	/* IOPRIO_CLASS_RT covers data 0..7. */
	{ IOPRIO_CLASS_RT,   0 },
	{ IOPRIO_CLASS_RT,   3 },
	{ IOPRIO_CLASS_RT,   7 },
	/* IOPRIO_CLASS_BE covers data 0..7. */
	{ IOPRIO_CLASS_BE,   0 },
	{ IOPRIO_CLASS_BE,   4 },
	{ IOPRIO_CLASS_BE,   7 },
	/* IOPRIO_CLASS_IDLE / NONE require data == 0. */
	{ IOPRIO_CLASS_IDLE, 0 },
	{ IOPRIO_CLASS_NONE, 0 },
};

static void sanitise_ioprio_set(struct syscallrecord *rec)
{
	unsigned int bucket = rnd_modulo_u32(10);
	unsigned int class, data;

	if (bucket < 7) {
		/* 70%: known-valid (class, data) combo from the table. */
		const struct ioprio_valid_combo *c =
			&ioprio_valid_combos[rnd_modulo_u32(
				sizeof(ioprio_valid_combos) /
				sizeof(ioprio_valid_combos[0]))];
		class = c->class;
		data = c->data;
	} else if (bucket < 9) {
		/* 20%: real class with deliberately invalid data so the
		 * kernel's per-class data-range check stays exercised. */
		switch (rnd_modulo_u32(4)) {
		case 0: class = IOPRIO_CLASS_RT; break;
		case 1: class = IOPRIO_CLASS_BE; break;
		case 2: class = IOPRIO_CLASS_IDLE; break;
		default: class = IOPRIO_CLASS_NONE; break;
		}
		/* data > IOPRIO_NR_LEVELS-1: NONE/IDLE+nonzero or RT/BE
		 * with an out-of-range level. */
		data = IOPRIO_NR_LEVELS + rnd_modulo_u32(8184);
	} else {
		/* 10%: pure random 13-bit (class << 13 | data) word. */
		rec->a3 = rand32();
		goto pick_who;
	}

	rec->a3 = IOPRIO_PRIO_VALUE(class, data);

pick_who:
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
};
