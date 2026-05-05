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

#include "deferred-free.h"
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


/*
 * Snapshot of the dispatch option and the (PR_SET_SECCOMP-only) heap
 * sock_fprog the post handler reads, captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose, so the post path is immune to a sibling
 * syscall scribbling rec->a1 (option) or rec->a3 (sock_fprog pointer)
 * between the syscall returning and the post handler running.  The old
 * post handler dispatched off rec->a1 directly: a flip to PR_SET_SECCOMP
 * from any other option would deref a NULL post_state's bpf->filter, and
 * a flip away from PR_SET_SECCOMP would leak the sock_fprog and its
 * filter; a flip to PR_SET_NO_NEW_PRIVS would fire the cred oracle on
 * an unrelated retval and report bogus divergences.
 */
struct prctl_post_state {
	int option;
	struct sock_fprog *bpf;
};

#ifdef USE_SECCOMP
static struct sock_fprog *do_set_seccomp(struct syscallrecord *rec)
{
	unsigned long *optval = NULL, __unused__ optlen = 0;

#ifdef USE_BPF
	bpf_gen_seccomp(&optval, &optlen);
#endif

	rec->a2 = SECCOMP_MODE_FILTER;
	rec->a3 = (unsigned long) optval;
	rec->a4 = 0;
	rec->a5 = 0;
	return (struct sock_fprog *) optval;
}
#else
static struct sock_fprog *do_set_seccomp(__unused__ struct syscallrecord *rec)
{
	return NULL;
}
#endif

/* We already got a generic_sanitise at this point */
static void sanitise_prctl(struct syscallrecord *rec)
{
	int option = prctl_opts[rand() % NR_PRCTL_OPTS];
	struct sock_fprog *bpf = NULL;

	rec->post_state = 0;
	rec->a1 = option;

	switch (option) {
	case PR_SET_SECCOMP:
		bpf = do_set_seccomp(rec);
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

	/*
	 * Options with post-handler work get a snapshot of the option (and
	 * the heap sock_fprog, for PR_SET_SECCOMP) so the post path can
	 * dispatch off snap->option (immune to a sibling scribble of
	 * rec->a1) and read bpf from snap->bpf (immune to a scribble of
	 * rec->a3).  Two SET options have side-effects to handle:
	 * PR_SET_SECCOMP frees the heap sock_fprog and PR_SET_NO_NEW_PRIVS
	 * runs the sticky-flag oracle.  The PR_GET_* family below carries
	 * per-option STRONG-VAL retval bounds: each getter has a tight ABI
	 * (a single bit, a small enum, a sub-byte bitmask) that is much
	 * narrower than the generic 64-bit return slot, and any value
	 * outside the listed set on the success path is a corruption shape
	 * worth catching (a -errno leak, a sign-extension tear, a torn read
	 * of the source field, or a dispatch into the wrong getter).
	 * Options with no post-handler work skip the snap entirely -- their
	 * post path is empty and a sibling-induced flip into them simply
	 * returns early on snap == NULL.
	 */
	switch (option) {
	case PR_SET_SECCOMP:
	case PR_SET_NO_NEW_PRIVS:
	case PR_GET_PDEATHSIG:
	case PR_GET_KEEPCAPS:
	case PR_GET_DUMPABLE:
	case PR_GET_NAME:
	case PR_GET_NO_NEW_PRIVS:
	case PR_CAPBSET_READ:
	case PR_GET_TIMING:
	case PR_GET_FPEXC:
	case PR_GET_FPEMU:
	case PR_GET_TSC:
	case PR_GET_THP_DISABLE:
	case PR_GET_CHILD_SUBREAPER:
	case PR_GET_SECCOMP: {
		struct prctl_post_state *snap = zmalloc(sizeof(*snap));

		snap->option = option;
		snap->bpf = bpf;
		rec->post_state = (unsigned long) snap;
		break;
	}
	default:
		break;
	}
}

static void post_prctl(struct syscallrecord *rec)
{
	struct prctl_post_state *snap = (struct prctl_post_state *) rec->post_state;
	struct sock_fprog *bpf;
	long got;

	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_prctl: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner bpf pointer may no longer reference our heap
	 * allocation.  NULL is a legitimate value here (PR_SET_NO_NEW_PRIVS
	 * does not allocate), so only flag a non-NULL value that fails
	 * the heuristic.  Leak rather than hand garbage to free().
	 */
	if (snap->bpf != NULL && looks_like_corrupted_ptr(rec, snap->bpf)) {
		outputerr("post_prctl: rejected suspicious snap bpf=%p (post_state-scribbled?)\n",
			  snap->bpf);
		deferred_freeptr(&rec->post_state);
		return;
	}

	switch (snap->option) {
	case PR_SET_SECCOMP:
		bpf = snap->bpf;
		if (bpf != NULL) {
			if (inner_ptr_ok_to_free(rec, bpf->filter,
						 "post_prctl/bpf_filter"))
				free(bpf->filter);
			deferred_free_enqueue(bpf, NULL);
		}
		break;

	case PR_SET_NO_NEW_PRIVS:
		/*
		 * Oracle: PR_SET_NO_NEW_PRIVS is sticky and one-way.  After a
		 * successful set the read-back via PR_GET_NO_NEW_PRIVS must
		 * return 1.  A different value is silent corruption of a
		 * security-critical task flag — this is the bit that gates
		 * suid-binary execve and seccomp filter installation.
		 */
		if ((long) rec->retval != 0)
			break;
		if (!ONE_IN(20))
			break;
		got = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		if (got != 1) {
			output(0, "cred oracle: prctl(PR_SET_NO_NEW_PRIVS) "
			       "succeeded but PR_GET_NO_NEW_PRIVS=%ld\n", got);
			__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
		break;

	case PR_GET_PDEATHSIG:
		/*
		 * Kernel ABI: writes the parent-death signal number to the
		 * out-arg at arg2; the syscall return slot itself is just
		 * 0/-1.  Anything else on the return path is a -errno leak
		 * or a copy_to_user retval tear bleeding into the slot.
		 */
		if (rec->retval != 0 && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_PDEATHSIG retval 0x%lx outside {0, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_KEEPCAPS:
		/*
		 * Kernel ABI: returns task->keep_capabilities — a single bit,
		 * value 0 or 1.  A larger value is a torn read of the cred
		 * flags word or a dispatch into the wrong getter.
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_KEEPCAPS retval 0x%lx outside {0, 1, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_DUMPABLE:
		/*
		 * Kernel ABI: returns mm->flags & MMF_DUMPABLE_MASK — value 0
		 * (SUID_DUMP_DISABLE), 1 (SUID_DUMP_USER) or 2 (SUID_DUMP_ROOT).
		 * A larger value is a torn read of mm_struct->flags or a leak
		 * of the upper MMF_* bits past the dumpable mask.
		 */
		if (rec->retval > 2UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_DUMPABLE retval 0x%lx outside {0, 1, 2, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_NAME:
		/*
		 * Kernel ABI: copies task->comm into the out-arg at arg2; the
		 * return slot is just 0/-1.  Anything else on the return path
		 * is a -errno leak or a bytes-copied count bleeding into the
		 * slot from a wrong copy_to_user dispatch.
		 */
		if (rec->retval != 0 && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_NAME retval 0x%lx outside {0, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_NO_NEW_PRIVS:
		/*
		 * Kernel ABI: returns task->no_new_privs — a single bit,
		 * value 0 or 1.  A larger value is silent corruption of a
		 * security-critical task flag (suid-binary execve gating).
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_NO_NEW_PRIVS retval 0x%lx outside {0, 1, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_CAPBSET_READ:
		/*
		 * Kernel ABI: returns whether the queried capability bit is
		 * set in cred->cap_bset — value 0 or 1.  A larger value is a
		 * torn read of the kernel_cap_t bitmask or a leak of the
		 * underlying word past the queried bit.
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_CAPBSET_READ retval 0x%lx outside {0, 1, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_TIMING:
		/*
		 * Kernel ABI: returns one of PR_TIMING_STATISTICAL (0) or
		 * PR_TIMING_TIMESTAMP (1).  Anything else is a torn read of
		 * the timing mode or a dispatch into the wrong getter.
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_TIMING retval 0x%lx outside {STATISTICAL, TIMESTAMP, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_FPEXC:
	case PR_GET_FPEMU:
		/*
		 * Kernel ABI (PowerPC / IA-64): returns a small bitmask of
		 * PR_FP_EXC_* / PR_FP_EMU_* flags, all of which fit in a byte.
		 * Anything above 0xff is a sign-extension tear or a leak of
		 * upper bits from the source field.
		 */
		if (rec->retval > 0xffUL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_FP{EXC,EMU} retval 0x%lx above byte-wide bitmask\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_TSC:
		/*
		 * Kernel ABI (x86): returns one of PR_TSC_ENABLE (1) or
		 * PR_TSC_SIGSEGV (2).  Note 0 is NOT valid here -- the TSC
		 * mode field is initialised to PR_TSC_ENABLE.  Any other
		 * value is a torn read of thread->flags or a dispatch into
		 * the wrong getter.
		 */
		if (rec->retval != 1UL && rec->retval != 2UL &&
		    rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_TSC retval 0x%lx outside {ENABLE, SIGSEGV, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_THP_DISABLE:
		/*
		 * Kernel ABI: returns the MMF_DISABLE_THP bit from mm->flags
		 * -- a single bit, value 0 or 1.  A larger value is a torn
		 * read of mm_struct->flags or a leak of adjacent MMF_* bits
		 * past the THP-disable mask.
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_THP_DISABLE retval 0x%lx outside {0, 1, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_CHILD_SUBREAPER:
		/*
		 * Kernel ABI: returns task->signal->is_child_subreaper -- a
		 * single bit, value 0 or 1.  A larger value is a torn read
		 * of signal_struct or a dispatch into the wrong getter.
		 */
		if (rec->retval > 1UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_CHILD_SUBREAPER retval 0x%lx outside {0, 1, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;

	case PR_GET_SECCOMP:
		/*
		 * Kernel ABI: returns task->seccomp.mode -- one of
		 * SECCOMP_MODE_DISABLED (0), SECCOMP_MODE_STRICT (1) or
		 * SECCOMP_MODE_FILTER (2).  A larger value is silent
		 * corruption of a security-critical task field that gates
		 * filter installation and syscall dispatch.
		 */
		if (rec->retval > 2UL && rec->retval != (unsigned long)-1L) {
			output(0, "post_prctl: rejected PR_GET_SECCOMP retval 0x%lx outside {DISABLED, STRICT, FILTER, -1}\n",
			       rec->retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
		}
		break;
	}

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_prctl = {
	.name = "prctl",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argname = { [0] = "option", [1] = "arg2", [2] = "arg3", [3] = "arg4", [4] = "arg5" },
	.sanitise = sanitise_prctl,
	.post = post_prctl,
};
