/*
 * SYSCALL_DEFINE5(kcmp, pid_t, pid1, pid_t, pid2, int, type,
 *               unsigned long, idx1, unsigned long, idx2)
 *
 */
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"

static unsigned long kcmp_types[] = {
	KCMP_FILE, KCMP_VM, KCMP_FILES, KCMP_FS,
	KCMP_SIGHAND, KCMP_IO, KCMP_SYSVSEM,
};

/* For KCMP_FILE, idx1/idx2 are fd numbers to compare. */
static void sanitise_kcmp(struct syscallrecord *rec)
{
	if (rec->a3 == KCMP_FILE) {
		rec->a4 = get_random_fd();
		rec->a5 = get_random_fd();
	} else {
		rec->a4 = 0;
		rec->a5 = 0;
	}
}

static void post_kcmp(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret > 3)
		output(0, "kcmp oracle: returned %ld is out of range (must be 0..3 or -1)\n",
			ret);
}

struct syscallentry syscall_kcmp = {
	.name = "kcmp",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID, [2] = ARG_OP },
	.argname = { [0] = "pid1", [1] = "pid2", [2] = "type", [3] = "idx1", [4] = "idx2" },
	.arg_params[2].list = ARGLIST(kcmp_types),
	.sanitise = sanitise_kcmp,
	.post = post_kcmp,
};
