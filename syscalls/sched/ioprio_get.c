/*
 * SYSCALL_DEFINE2(ioprio_get, int, which, int, who)
 */
#include <linux/ioprio.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ioprio_who[] = {
	IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER,
};

/*
 * ARG_PID delivers a raw pid for rec->a2, which resolves for
 * IOPRIO_WHO_PROCESS but is meaningless as a pgid or uid.  Marry the
 * framework's 'which' pick to a 'who' value the kernel can actually look
 * up, so calls reach get_task_ioprio() instead of bouncing off -ESRCH.
 * Keep a minority arm that leaves the framework's random pick alone so
 * the EINVAL / ESRCH paths still get hit.
 */
static void sanitise_ioprio_get(struct syscallrecord *rec)
{
	unsigned int bucket = rnd_modulo_u32(10);

	if (bucket >= 8)
		return;

	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a1 = IOPRIO_WHO_PROCESS;
		rec->a2 = RAND_BOOL() ? 0 : (unsigned long) mypid();
		break;
	case 1:
		rec->a1 = IOPRIO_WHO_PGRP;
		rec->a2 = RAND_BOOL() ? 0 : (unsigned long) getpgrp();
		break;
	default:
		rec->a1 = IOPRIO_WHO_USER;
		rec->a2 = (unsigned long) getuid();
		break;
	}
}

static void post_ioprio_get(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 0 || ret > 0xFFFF) {
		output(0, "ioprio_get oracle: returned %ld is out of range (must fit in 16 bits or be -1)\n",
			ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_ioprio_get = {
	.name = "ioprio_get",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who" },
	.arg_params[0].list = ARGLIST(ioprio_who),
	.sanitise = sanitise_ioprio_get,
	.group = GROUP_SCHED,
	.post = post_ioprio_get,
};
