/*
 * SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
	 unsigned long, arg4, unsigned long, arg5)
 */

#include <stdlib.h>
#include <linux/capability.h>
#include <linux/filter.h>
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
#include "trinity.h"
#include "compat.h"
#include "utils.h"

/* ARM pointer authentication (added in 5.8) */
#ifndef PR_PAC_SET_ENABLED_KEYS
#define PR_PAC_SET_ENABLED_KEYS		60
#define PR_PAC_GET_ENABLED_KEYS		61
#endif
/* ARM SME vector length (added in 5.18) */
#ifndef PR_SME_SET_VL
#define PR_SME_SET_VL			63
#define PR_SME_GET_VL			64
#endif
/* RISC-V vector/cache control (added in 6.5-6.7) */
#ifndef PR_RISCV_V_SET_CONTROL
#define PR_RISCV_V_SET_CONTROL		69
#define PR_RISCV_V_GET_CONTROL		70
#define PR_RISCV_SET_ICACHE_FLUSH_CTX	71
#endif
/* PowerPC DEXCR (added in 6.6) */
#ifndef PR_PPC_GET_DEXCR
#define PR_PPC_GET_DEXCR		72
#define PR_PPC_SET_DEXCR		73
#endif

/* Capabilities added after Linux 5.8/5.9 — guard for older build systems. */
#ifndef CAP_PERFMON
#define CAP_PERFMON		38
#endif
#ifndef CAP_BPF
#define CAP_BPF			39
#endif
#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE	40
#endif

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
	PR_GET_SPECULATION_CTRL, PR_SET_SPECULATION_CTRL,
	PR_GET_FP_MODE, PR_SET_FP_MODE,
	PR_SVE_SET_VL, PR_SVE_GET_VL, PR_PAC_RESET_KEYS,
	PR_PAC_SET_ENABLED_KEYS, PR_PAC_GET_ENABLED_KEYS,
	PR_SME_SET_VL, PR_SME_GET_VL,
	PR_CAP_AMBIENT,
	PR_SET_TAGGED_ADDR_CTRL, PR_GET_TAGGED_ADDR_CTRL,
	PR_SET_IO_FLUSHER, PR_GET_IO_FLUSHER,
	PR_SET_SYSCALL_USER_DISPATCH, PR_SCHED_CORE,
	PR_SET_MDWE, PR_GET_MDWE,
	PR_SET_MEMORY_MERGE, PR_GET_MEMORY_MERGE,
	PR_GET_SHADOW_STACK_STATUS, PR_SET_SHADOW_STACK_STATUS, PR_LOCK_SHADOW_STACK_STATUS,
	PR_TIMER_CREATE_RESTORE_IDS, PR_FUTEX_HASH, PR_RSEQ_SLICE_EXTENSION,
	PR_GET_CFI, PR_SET_CFI,
	PR_RISCV_V_SET_CONTROL, PR_RISCV_V_GET_CONTROL, PR_RISCV_SET_ICACHE_FLUSH_CTX,
	PR_PPC_GET_DEXCR, PR_PPC_SET_DEXCR,
	PR_SET_PTRACER, PR_SET_VMA, PR_GET_AUXV,
};
#define NR_PRCTL_OPTS ARRAY_SIZE(prctl_opts)

static unsigned long cfi_ops[] = {
	PR_CFI_ENABLE, PR_CFI_DISABLE, PR_CFI_LOCK,
};

static unsigned long cap_values[] = {
	CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
	CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID,
	CAP_SETPCAP, CAP_LINUX_IMMUTABLE, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST,
	CAP_NET_ADMIN, CAP_NET_RAW, CAP_IPC_LOCK, CAP_IPC_OWNER,
	CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_CHROOT, CAP_SYS_PTRACE,
	CAP_SYS_PACCT, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_NICE,
	CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYS_TTY_CONFIG, CAP_MKNOD,
	CAP_LEASE, CAP_AUDIT_WRITE, CAP_AUDIT_CONTROL, CAP_SETFCAP,
	CAP_MAC_OVERRIDE, CAP_MAC_ADMIN, CAP_SYSLOG, CAP_WAKE_ALARM,
	CAP_BLOCK_SUSPEND, CAP_AUDIT_READ, CAP_PERFMON, CAP_BPF,
	CAP_CHECKPOINT_RESTORE,
};


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
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_prctl() runs, leaving a real-but-wrong heap
	 * pointer that the corruption guard cannot distinguish from the
	 * original sock_fprog. */
	rec->post_state = (unsigned long) optval;
}
#else
static void do_set_seccomp(__unused__ struct syscallrecord *rec) { }
#endif

/* We already got a generic_sanitise at this point */
static void sanitise_prctl(struct syscallrecord *rec)
{
	int option = prctl_opts[rand() % NR_PRCTL_OPTS];

	rec->a1 = option;

	switch (option) {
	case PR_SET_SECCOMP:
		do_set_seccomp(rec);
		break;

	case PR_CAPBSET_READ:
	case PR_CAPBSET_DROP:
		rec->a2 = RAND_ARRAY(cap_values);
		break;

	case PR_CAP_AMBIENT:
		rec->a2 = RAND_RANGE(1, 4);
		rec->a3 = RAND_ARRAY(cap_values);
		break;

	case PR_SET_CFI:
		rec->a2 = PR_CFI_BRANCH_LANDING_PADS;
		rec->a3 = RAND_ARRAY(cfi_ops);
		break;

	default:
		break;
	}
}

static void post_prctl(struct syscallrecord *rec)
{
	struct sock_fprog *bpf;
	long got;

	switch (rec->a1) {
	case PR_SET_SECCOMP:
		bpf = (struct sock_fprog *) rec->post_state;
		if (bpf == NULL)
			return;
		/*
		 * post_state is private to the post handler, but the whole
		 * syscallrecord can still be wholesale-stomped, so keep the
		 * corruption guard as a backstop.
		 */
		if (looks_like_corrupted_ptr(bpf)) {
			outputerr("post_prctl: rejected suspicious bpf=%p (pid-scribbled?)\n",
				  (void *) bpf);
			shm->stats.post_handler_corrupt_ptr++;
			rec->a3 = 0;
			rec->post_state = 0;
			return;
		}
		free(bpf->filter);
		free(bpf);
		rec->a3 = 0;
		rec->post_state = 0;
		return;

	case PR_SET_NO_NEW_PRIVS:
		/*
		 * Oracle: PR_SET_NO_NEW_PRIVS is sticky and one-way.  After a
		 * successful set the read-back via PR_GET_NO_NEW_PRIVS must
		 * return 1.  A different value is silent corruption of a
		 * security-critical task flag — this is the bit that gates
		 * suid-binary execve and seccomp filter installation.
		 */
		if ((long) rec->retval != 0)
			return;
		if (!ONE_IN(20))
			return;
		got = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		if (got != 1) {
			output(0, "cred oracle: prctl(PR_SET_NO_NEW_PRIVS) "
			       "succeeded but PR_GET_NO_NEW_PRIVS=%ld\n", got);
			__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
		return;
	}
}

struct syscallentry syscall_prctl = {
	.name = "prctl",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argname = { [0] = "option", [1] = "arg2", [2] = "arg3", [3] = "arg4", [4] = "arg5" },
	.sanitise = sanitise_prctl,
	.post = post_prctl,
};
