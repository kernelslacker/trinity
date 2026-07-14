/*
 * SYSCALL_DEFINE2(getpriority, int, which, int, who)
 */

#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long getpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

/*
 * getpriority(which, who): the kernel rejects an unknown `which` with
 * -EINVAL and an unresolvable `who` with -ESRCH before the actual
 * priority lookup runs.  Without a sanitiser the framework's curated
 * `which` pick always lands in {PRIO_PROCESS, PRIO_PGRP, PRIO_USER}
 * so the EINVAL arm is never hit, and a raw random `who` almost never
 * resolves for the PGRP/USER classes — most calls short-circuit on
 * ESRCH without exercising the lookup path.
 *
 * Bias toward valid pairs that resolve for the chosen `which` 70% of
 * the time, keep random-`who` pressure with a curated `which` 20%,
 * and reserve 10% for an out-of-range `which` to reach the EINVAL arm.
 */
static void sanitise_getpriority(struct syscallrecord *rec)
{
	unsigned int bucket = rnd_modulo_u32(10);

	if (bucket < 7) {
		/* 70%: valid which+who pair that resolves. */
		switch (rnd_modulo_u32(3)) {
		case 0:
			rec->a1 = PRIO_PROCESS;
			rec->a2 = RAND_BOOL() ? 0 : (unsigned long) mypid();
			break;
		case 1:
			rec->a1 = PRIO_PGRP;
			rec->a2 = RAND_BOOL() ? 0 : (unsigned long) getpgrp();
			break;
		case 2:
			rec->a1 = PRIO_USER;
			rec->a2 = RAND_BOOL() ? 0 : (unsigned long) getuid();
			break;
		}
	} else if (bucket < 9) {
		/* 20%: valid which, random who — keeps ESRCH fuzz pressure. */
		rec->a1 = RAND_ARRAY(getpriority_which);
		/* leave rec->a2 from generic arg gen. */
	} else {
		/* 10%: out-of-range which to exercise the EINVAL arm. */
		rec->a1 = 3 + rnd_modulo_u32(29);
		rec->a2 = 0;
	}
}

static void post_getpriority(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 1 || ret > 40)
		output(0, "getpriority oracle: returned %ld is out of range (must be 1..40 or -1)\n",
			ret);
}

struct syscallentry syscall_getpriority = {
	.name = "getpriority",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg_params[0].list = ARGLIST(getpriority_which),
	.sanitise = sanitise_getpriority,
	.group = GROUP_SCHED,
	.post = post_getpriority,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
};
