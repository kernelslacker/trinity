/*
 * SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
	 unsigned long, arg4, unsigned long, arg5)
 */

#include <stdlib.h>
#ifdef USE_SECCOMP
#include <linux/seccomp.h>
#endif
#include <sys/prctl.h>
#include <sys/socket.h>

#include "net.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static int prctl_opts[] = {
	PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_GET_DUMPABLE, PR_SET_DUMPABLE,
	PR_GET_UNALIGN, PR_SET_UNALIGN, PR_GET_KEEPCAPS, PR_SET_KEEPCAPS,
	PR_GET_FPEMU, PR_SET_FPEMU, PR_GET_FPEXC, PR_SET_FPEXC,
	PR_GET_TIMING, PR_SET_TIMING, PR_SET_NAME, PR_GET_NAME,
	PR_GET_ENDIAN, PR_SET_ENDIAN, PR_GET_SECCOMP, PR_SET_SECCOMP,
	PR_CAPBSET_READ, PR_CAPBSET_DROP, PR_GET_TSC, PR_SET_TSC,
	PR_GET_SECUREBITS, PR_SET_SECUREBITS, PR_SET_TIMERSLACK, PR_GET_TIMERSLACK,
	PR_TASK_PERF_EVENTS_DISABLE, PR_TASK_PERF_EVENTS_ENABLE, PR_MCE_KILL, PR_MCE_KILL_GET,
	PR_SET_MM, PR_SET_CHILD_SUBREAPER, PR_GET_CHILD_SUBREAPER, PR_SET_NO_NEW_PRIVS,
	PR_GET_NO_NEW_PRIVS, PR_GET_TID_ADDRESS, PR_SET_THP_DISABLE, PR_GET_THP_DISABLE,
	PR_MPX_ENABLE_MANAGEMENT, PR_MPX_DISABLE_MANAGEMENT,
	PR_GET_SPECULATION_CTRL, PR_SET_SPECULATION_CTRL,
#ifdef __mips__
	PR_GET_FP_MODE, PR_SET_FP_MODE,
#endif
#ifdef __arm64__
	PR_SVE_SET_VL, PR_SVE_GET_VL, PR_PAC_RESET_KEYS,
#endif
	PR_CAP_AMBIENT,
};
#define NR_PRCTL_OPTS ARRAY_SIZE(prctl_opts)


#ifdef USE_SECCOMP
static void do_set_seccomp(struct syscallrecord *rec)
{
	unsigned long *optval = NULL, __unused__ optlen = 0;

#ifdef USE_BPF
	bpf_gen_seccomp(&optval, &optlen);
#endif

	rec->a2 = SECCOMP_MODE_FILTER;
	rec->a3 = (unsigned long) optval;
	rec->a4 = 0;
	rec->a5 = 0;
}
#else
static void do_set_seccomp(__unused__ struct syscallrecord *rec) { }
#endif

/* We already got a generic_sanitise at this point */
static void sanitise_prctl(struct syscallrecord *rec)
{
	int option = prctl_opts[rnd() % NR_PRCTL_OPTS];

// For now, just do SECCOMP, the other options need some attention.
	option = PR_SET_SECCOMP;

	rec->a1 = option;

	switch (option) {
	case PR_SET_SECCOMP:
		do_set_seccomp(rec);
		break;

	default:
		break;
	}
}

struct syscallentry syscall_prctl = {
	.name = "prctl",
	.num_args = 5,
	.arg1name = "option",
	.arg2name = "arg2",
	.arg3name = "arg3",
	.arg4name = "arg4",
	.arg5name = "arg5",
	.sanitise = sanitise_prctl,
	//TODO: .post that free's bpf & bpf->filter
};
