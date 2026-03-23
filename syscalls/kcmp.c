/*
 * SYSCALL_DEFINE5(kcmp, pid_t, pid1, pid_t, pid2, int, type,
 *               unsigned long, idx1, unsigned long, idx2)
 *
 */
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"

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
	}
}

struct syscallentry syscall_kcmp = {
	.name = "kcmp",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.arg1name = "pid1",
	.arg1type = ARG_PID,
	.arg2name = "pid2",
	.arg2type = ARG_PID,
	.arg3name = "type",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(kcmp_types),
	.arg4name = "idx1",
	.arg5name = "idx2",
	.sanitise = sanitise_kcmp,
};
