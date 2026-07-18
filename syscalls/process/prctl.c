/*
 * SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
	 unsigned long, arg4, unsigned long, arg5)
 */

#include <signal.h>
#include <linux/const.h>
#include <linux/capability.h>
#include <linux/filter.h>
#ifdef USE_SECCOMP
#include <linux/seccomp.h>
#endif
#include <sys/prctl.h>
#include <string.h>

#include "deferred-free.h"
#include "net.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/prctl.h"
#include "kernel/seccomp.h"
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
/* arm64 MTE store-only checking (added in 6.17) */
#ifndef PR_MTE_STORE_ONLY
#define PR_MTE_STORE_ONLY		(1UL << 19)
#endif
/* RISC-V pointer-masking tag length (added in 6.13) */
#ifndef PR_PMLEN_MASK
#define PR_PMLEN_MASK			(0x7fUL << 24)
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
	/*
	 * PR_SET_MDWE is intentionally omitted: MDWE is irreversible
	 * per-process and enforces W^X.  Once the long-lived fuzz child
	 * sets PR_MDWE_REFUSE_EXEC_GAIN on itself, trinity's deferred-free
	 * allocator can no longer mprotect its tracked arenas back to
	 * writable -- the next re-protect returns EACCES and the child
	 * SIGSEGVs.  PR_GET_MDWE is read-only and stays.
	 */
	PR_GET_MDWE,
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
#define PRCTL_POST_STATE_MAGIC	0x50524354UL	/* "PRCT" */
struct prctl_post_state {
	unsigned long magic;
	int option;
	struct sock_fprog *bpf;
	/*
	 * Snapshot of the SET-side argument captured at sanitise time so
	 * the 1-in-20 SET/GET roundtrip oracles can compare the GET
	 * readback against what we asked the kernel to store -- immune
	 * to sibling-thread scribbles of rec->a2 or the writable buffer
	 * it pointed at.  set_arg is the literal arg2 for the scalar
	 * SET options; set_name is a content snapshot for PR_SET_NAME,
	 * truncated and NUL-terminated like the kernel will do.
	 */
	unsigned long set_arg;
	unsigned char set_name[16];
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

static void sanitise_set_syscall_user_dispatch(struct syscallrecord *rec)
{
	/*
	 * Pin SUD to PR_SYS_DISPATCH_OFF.  ON installs a per-task
	 * selector that traps every syscall whose PC is outside
	 * [offset, offset+len) -- or inside the range with the
	 * selector byte != ALLOW -- to SIGSYS.  The generic
	 * arg-fill can land mode=PR_SYS_DISPATCH_ON via the
	 * boundary-value pool (which includes 1) paired with a
	 * writable selector address from get_writable_address()
	 * (one branch of gen_undefined_arg), at which point the
	 * next syscall the fuzz child issues -- libc PC, random
	 * range, random selector byte -- traps SIGSYS and the
	 * child dies before the post handler can run.  OFF mode
	 * requires offset/len/selector all zero per the kernel's
	 * task_set_syscall_user_dispatch input validation; pinning
	 * them keeps that input-validation path exercised without
	 * the ON-side self-break.
	 */
	rec->a2 = PR_SYS_DISPATCH_OFF;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;
}

static void sanitise_set_tsc(struct syscallrecord *rec)
{
	/*
	 * Pin TSC mode to PR_TSC_ENABLE.  The other legal value,
	 * PR_TSC_SIGSEGV (2), is reachable from the boundary-value
	 * pool the generic arg-fill draws from.  Landing it sets
	 * CR4.TSD on the task, after which any user-mode rdtsc /
	 * rdtscp raises #GP and the kernel turns it into SIGSEGV
	 * per the prctl ABI.  The fuzz child calls clock_gettime
	 * (CLOCK_MONOTONIC) from its inner loop and elsewhere;
	 * glibc 2.17+ routes that through the vDSO's
	 * __vdso_clock_gettime fast path, which reads the TSC in
	 * user mode.  A landed PR_TSC_SIGSEGV therefore SIGSEGV-
	 * kills the child on its next clock_gettime call, before
	 * the post handler can run, and the death is mis-
	 * attributed by the reaper.  Setting one's own TSC mode
	 * requires no capability, so the child's cap-clear does
	 * not defang this the way it does PR_SET_MM /
	 * PR_SET_SECUREBITS.  PR_TSC_ENABLE is the boot default
	 * and matches the task's initial state, so pinning it
	 * keeps the input-validation path exercised (the kernel
	 * still walks the legal-mode switch) without flipping the
	 * self-breaking bit.  Zero a3-a5; prctl ignores them for
	 * PR_SET_TSC but the kernel ABI reserves them for
	 * possible future use.
	 */
	rec->a2 = PR_TSC_ENABLE;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;
}

static void sanitise_set_shadow_stack_status(struct syscallrecord *rec)
{
	/*
	 * Pin shadow-stack status to 0 (all feature bits clear).
	 * The argument is a bitmask of PR_SHADOW_STACK_ENABLE
	 * (1<<0), PR_SHADOW_STACK_WRITE (1<<1) and
	 * PR_SHADOW_STACK_PUSH (1<<2); the generic arg-fill draws
	 * a2 from the boundary-value pool and from rnd_u64(), so
	 * any combination of those bits -- crucially the ENABLE
	 * bit -- is reachable.  Setting ENABLE installs a shadow
	 * stack for the calling thread and turns on CET CALL/RET
	 * enforcement: the very next RET checks SSP against the
	 * shadow copy, and trinity's own call frames -- pushed
	 * before the prctl returned -- have no matching shadow
	 * entries, so the child takes a control-protection
	 * exception (SIGSEGV with si_code=SEGV_CPERR on x86) on
	 * the first RET out of the syscall wrapper.  The WRITE
	 * and PUSH bits widen the attack surface further by
	 * exposing WRSS / shadow-stack-PUSH to userspace, both of
	 * which can scribble the shadow stack and produce the
	 * same self-break on a later RET.  Setting one's own
	 * shadow-stack status requires no capability, so the
	 * child's unconditional cap-clear does not defang this --
	 * same shape as the recent PR_SET_TSC and
	 * PR_SET_SYSCALL_USER_DISPATCH pins.  Zero is a legal
	 * argument (all features disabled, matching the task's
	 * initial state when CET is not in use) and exercises the
	 * kernel's input-validation path without flipping any
	 * self-breaking bit.  Zero a3-a5; prctl ignores them for
	 * this option but the ABI reserves them.
	 */
	rec->a2 = 0;
	rec->a3 = 0;
	rec->a4 = 0;
	rec->a5 = 0;
}

#ifdef PR_TAGGED_ADDR_ENABLE
static void sanitise_set_tagged_addr_ctrl(struct syscallrecord *rec)
{
	static const unsigned long tagged_addr_flags[] = {
		0,
		PR_TAGGED_ADDR_ENABLE,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC  | PR_MTE_TAG_MASK,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | PR_MTE_TAG_MASK,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC  | PR_MTE_STORE_ONLY,
		PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | PR_MTE_STORE_ONLY,
		PR_TAGGED_ADDR_ENABLE | (PR_PMLEN_MASK & (7UL << 24)),
	};
	rec->a2 = tagged_addr_flags[rnd_modulo_u32(ARRAY_SIZE(tagged_addr_flags))];
}
#endif

#ifdef PR_PAC_APIAKEY
static void sanitise_pac_set_enabled_keys(struct syscallrecord *rec)
{
	static const unsigned long pac_keys[] = {
		PR_PAC_APIAKEY, PR_PAC_APIBKEY, PR_PAC_APDAKEY,
		PR_PAC_APDBKEY, PR_PAC_APGAKEY,
	};
	unsigned long mask = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pac_keys); i++)
		if (RAND_BOOL())
			mask |= pac_keys[i];
	rec->a2 = mask;
	rec->a3 = mask & rnd_u64();
}
#endif

static void sanitise_get_auxv(struct syscallrecord *rec)
{
	if (rec->a3 == 0 || rec->a3 > page_size)
		rec->a3 = page_size;
	avoid_shared_buffer_out(&rec->a2, rec->a3);
}

/* We already got a generic_sanitise at this point */
static void sanitise_prctl(struct syscallrecord *rec)
{
	int option = prctl_opts[rnd_modulo_u32(NR_PRCTL_OPTS)];
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

	case PR_SET_TIMERSLACK:
		/* 0 means "use task default 50us"; values >0 set slack ns. */
		rec->a2 = RAND_RANGE(0, 1000000);
		break;

	case PR_SET_PDEATHSIG:
		rec->a2 = RAND_RANGE(0, _NSIG);
		rec->a3 = rec->a4 = rec->a5 = 0;
		break;

	case PR_SET_SYSCALL_USER_DISPATCH:
		sanitise_set_syscall_user_dispatch(rec);
		break;

	case PR_SET_TSC:
		sanitise_set_tsc(rec);
		break;

	case PR_SET_SHADOW_STACK_STATUS:
		sanitise_set_shadow_stack_status(rec);
		break;

	case PR_SET_NAME:
		/*
		 * Kernel reads up to 16 bytes from userspace and truncates.
		 * Leave content random; the kernel only validates the pointer.
		 */
		rec->a2 = (unsigned long) get_writable_address(16);
		break;

#ifdef PR_TAGGED_ADDR_ENABLE
	case PR_SET_TAGGED_ADDR_CTRL:
		sanitise_set_tagged_addr_ctrl(rec);
		break;
#endif

#ifdef PR_PAC_APIAKEY
	case PR_PAC_SET_ENABLED_KEYS:
		sanitise_pac_set_enabled_keys(rec);
		break;
#endif

#ifdef PR_SVE_VL_INHERIT
	case PR_SVE_SET_VL:
		/* legal vl: 16..8192 in steps of 16; with optional flags. */
		rec->a2 = (RAND_RANGE(1, 512) * 16) |
			  (RAND_BOOL() ? PR_SVE_VL_INHERIT : 0) |
			  (RAND_BOOL() ? PR_SVE_SET_VL_ONEXEC : 0);
		break;
#endif

#ifdef PR_SME_VL_INHERIT
	case PR_SME_SET_VL:
		rec->a2 = (RAND_RANGE(1, 512) * 16) |
			  (RAND_BOOL() ? PR_SME_VL_INHERIT : 0) |
			  (RAND_BOOL() ? PR_SME_SET_VL_ONEXEC : 0);
		break;
#endif

	case PR_GET_PDEATHSIG:
	case PR_GET_UNALIGN:
	case PR_GET_FPEMU:
	case PR_GET_FPEXC:
	case PR_GET_TSC:
	case PR_GET_ENDIAN:
	case PR_GET_CHILD_SUBREAPER:
		avoid_shared_buffer_out(&rec->a2, sizeof(int));
		break;

	case PR_GET_NAME:
		avoid_shared_buffer_out(&rec->a2, 16);
		break;

	case PR_GET_TID_ADDRESS:
	case PR_GET_SHADOW_STACK_STATUS:
		avoid_shared_buffer_out(&rec->a2, sizeof(unsigned long));
		break;

	case PR_GET_AUXV:
		sanitise_get_auxv(rec);
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
	case PR_SET_NAME:
	case PR_SET_DUMPABLE:
	case PR_SET_KEEPCAPS:
	case PR_SET_PDEATHSIG:
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
		struct prctl_post_state *snap = zmalloc_tracked(sizeof(*snap));

		snap->magic = PRCTL_POST_STATE_MAGIC;
		snap->option = option;
		snap->bpf = bpf;
		snap->set_arg = rec->a2;
		if (option == PR_SET_NAME && rec->a2 != 0) {
			const unsigned char *src =
				(const unsigned char *) rec->a2;
			size_t i;

			/*
			 * Mirror what the kernel stores in task->comm:
			 * copy bytes until first NUL or 15 chars, then
			 * NUL-terminate.  zmalloc_tracked already zeroed
			 * the trailing bytes.
			 */
			for (i = 0; i < 15; i++) {
				snap->set_name[i] = src[i];
				if (src[i] == '\0')
					break;
			}
		}
		rec->post_state = (unsigned long) snap;
		post_state_register(snap);
		break;
	}
	default:
		break;
	}
}

static void post_set_seccomp(struct prctl_post_state *snap)
{
	struct sock_fprog *bpf = snap->bpf;

	if (bpf == NULL)
		return;

	/*
	 * Wrapper-side gate before reading bpf->filter:
	 * looks_like_corrupted_ptr() above is shape-only
	 * (heap-band + alignment), so a heap-shaped but
	 * unmapped snap->bpf survives and the bpf->filter
	 * read here would fault the post handler before the
	 * inner-free dispatch ever runs.  Require the
	 * wrapper to be a tracked allocation (one we
	 * produced via do_set_seccomp) or readable for a
	 * sock_fprog-sized window.  When neither holds,
	 * skip the inner-free dispatch; the outer wrapper
	 * still enqueues.  Mirrors the bpf_free_filter()
	 * inner-filter gate.
	 *
	 * Inner-filter free is alloc_track_lookup()-gated
	 * and routed through deferred_free_enqueue() rather
	 * than a shape-only gate + direct free().  A
	 * scribbled bpf->filter that aliases a chunk
	 * admitted to the deferred ring by another site
	 * passes any shape check (the alias is a valid
	 * aligned heap address) but misses the ownership
	 * check -- ring admission drained the chunk from
	 * alloc_track -- so the inner free is skipped.  A
	 * shape-only gate would have landed an out-of-band
	 * free on the ring-pinned chunk, and the original
	 * site's later ring_evict_oldest_safe would surface
	 * as an ASAN bad-free.  Mirrors bpf_free_filter()
	 * and syscalls/bpf.c BPF_PROG_LOAD eBPF cleanup.
	 */
	if (alloc_track_lookup(bpf) ||
	    range_readable_user(bpf, sizeof(struct sock_fprog))) {
		if (bpf->filter != NULL &&
		    alloc_track_lookup(bpf->filter))
			deferred_free_enqueue(bpf->filter);
	}
	deferred_free_enqueue(bpf);
}

static void post_set_no_new_privs(unsigned long retval)
{
	long got;

	/*
	 * Oracle: PR_SET_NO_NEW_PRIVS is sticky and one-way.  After a
	 * successful set the read-back via PR_GET_NO_NEW_PRIVS must
	 * return 1.  A different value is silent corruption of a
	 * security-critical task flag — this is the bit that gates
	 * suid-binary execve and seccomp filter installation.
	 */
	if ((long) retval != 0)
		return;
	if (!ONE_IN(20))
		return;
	got = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (got != 1) {
		output(0, "cred oracle: prctl(PR_SET_NO_NEW_PRIVS) "
		       "succeeded but PR_GET_NO_NEW_PRIVS=%ld\n", got);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_set_name(const struct prctl_post_state *snap,
			  unsigned long retval)
{
	/*
	 * Oracle: PR_SET_NAME stores into task->comm; PR_GET_NAME
	 * reads it back.  Compare against the byte snapshot we took
	 * at sanitise time -- not the userspace buffer at rec->a2,
	 * which a sibling thread may have scribbled between the SET
	 * and the readback.
	 */
	char readback[16] = { 0 };

	if ((long) retval != 0)
		return;
	if (!ONE_IN(20))
		return;
	if (prctl(PR_GET_NAME, (unsigned long) readback, 0, 0, 0) != 0)
		return;
	if (strncmp(readback, (const char *) snap->set_name, 16) != 0) {
		output(0, "cred oracle: prctl(PR_SET_NAME) succeeded "
		       "but PR_GET_NAME readback differs from snapshot\n");
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_set_dumpable(const struct prctl_post_state *snap,
			      unsigned long retval)
{
	long got;

	/*
	 * Oracle: PR_SET_DUMPABLE only accepts SUID_DUMP_DISABLE (0)
	 * or SUID_DUMP_USER (1); a successful SET means the kernel
	 * stored that value.  PR_GET_DUMPABLE must read it back.
	 */
	if ((long) retval != 0)
		return;
	if (!ONE_IN(20))
		return;
	got = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	if ((unsigned long) got != snap->set_arg) {
		output(0, "cred oracle: prctl(PR_SET_DUMPABLE %lu) "
		       "succeeded but PR_GET_DUMPABLE=%ld\n",
		       snap->set_arg, got);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_set_keepcaps(const struct prctl_post_state *snap,
			      unsigned long retval)
{
	long got;

	/*
	 * Oracle: PR_SET_KEEPCAPS only accepts 0 or 1.  A successful
	 * SET means the kernel stored that single bit;
	 * PR_GET_KEEPCAPS must read it back.
	 */
	if ((long) retval != 0)
		return;
	if (!ONE_IN(20))
		return;
	got = prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
	if ((unsigned long) got != snap->set_arg) {
		output(0, "cred oracle: prctl(PR_SET_KEEPCAPS %lu) "
		       "succeeded but PR_GET_KEEPCAPS=%ld\n",
		       snap->set_arg, got);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_set_pdeathsig(const struct prctl_post_state *snap,
			       unsigned long retval)
{
	/*
	 * Oracle: PR_SET_PDEATHSIG accepts 0 or a valid signal
	 * number.  PR_GET_PDEATHSIG writes the stored value to the
	 * int* at arg2; compare against the snapshot.
	 */
	int sig = -1;

	if ((long) retval != 0)
		return;
	if (!ONE_IN(20))
		return;
	if (prctl(PR_GET_PDEATHSIG, (unsigned long) &sig, 0, 0, 0) != 0)
		return;
	if ((unsigned long) sig != snap->set_arg) {
		output(0, "cred oracle: prctl(PR_SET_PDEATHSIG %lu) "
		       "succeeded but PR_GET_PDEATHSIG=%d\n",
		       snap->set_arg, sig);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_get_pdeathsig(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: writes the parent-death signal number to the
	 * out-arg at arg2; the syscall return slot itself is just
	 * 0/-1.  Anything else on the return path is a -errno leak
	 * or a copy_to_user retval tear bleeding into the slot.
	 */
	if (retval != 0 && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_PDEATHSIG retval 0x%lx outside {0, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_keepcaps(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns task->keep_capabilities — a single bit,
	 * value 0 or 1.  A larger value is a torn read of the cred
	 * flags word or a dispatch into the wrong getter.
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_KEEPCAPS retval 0x%lx outside {0, 1, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_dumpable(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns mm->flags & MMF_DUMPABLE_MASK — value 0
	 * (SUID_DUMP_DISABLE), 1 (SUID_DUMP_USER) or 2 (SUID_DUMP_ROOT).
	 * A larger value is a torn read of mm_struct->flags or a leak
	 * of the upper MMF_* bits past the dumpable mask.
	 */
	if (retval > 2UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_DUMPABLE retval 0x%lx outside {0, 1, 2, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_name(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: copies task->comm into the out-arg at arg2; the
	 * return slot is just 0/-1.  Anything else on the return path
	 * is a -errno leak or a bytes-copied count bleeding into the
	 * slot from a wrong copy_to_user dispatch.
	 */
	if (retval != 0 && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_NAME retval 0x%lx outside {0, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_no_new_privs(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns task->no_new_privs — a single bit,
	 * value 0 or 1.  A larger value is silent corruption of a
	 * security-critical task flag (suid-binary execve gating).
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_NO_NEW_PRIVS retval 0x%lx outside {0, 1, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_capbset_read(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns whether the queried capability bit is
	 * set in cred->cap_bset — value 0 or 1.  A larger value is a
	 * torn read of the kernel_cap_t bitmask or a leak of the
	 * underlying word past the queried bit.
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_CAPBSET_READ retval 0x%lx outside {0, 1, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_timing(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns one of PR_TIMING_STATISTICAL (0) or
	 * PR_TIMING_TIMESTAMP (1).  Anything else is a torn read of
	 * the timing mode or a dispatch into the wrong getter.
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_TIMING retval 0x%lx outside {STATISTICAL, TIMESTAMP, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_fp_exc_emu(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI (PowerPC): returns a small bitmask of
	 * PR_FP_EXC_* / PR_FP_EMU_* flags, all of which fit in a byte.
	 * Anything above 0xff is a sign-extension tear or a leak of
	 * upper bits from the source field.
	 */
	if (retval > 0xffUL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_FP{EXC,EMU} retval 0x%lx above byte-wide bitmask\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_tsc(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI (x86): returns one of PR_TSC_ENABLE (1) or
	 * PR_TSC_SIGSEGV (2).  Note 0 is NOT valid here -- the TSC
	 * mode field is initialised to PR_TSC_ENABLE.  Any other
	 * value is a torn read of thread->flags or a dispatch into
	 * the wrong getter.
	 */
	if (retval != 1UL && retval != 2UL &&
	    retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_TSC retval 0x%lx outside {ENABLE, SIGSEGV, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_thp_disable(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns the MMF_DISABLE_THP bit from mm->flags
	 * -- a single bit, value 0 or 1.  A larger value is a torn
	 * read of mm_struct->flags or a leak of adjacent MMF_* bits
	 * past the THP-disable mask.
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_THP_DISABLE retval 0x%lx outside {0, 1, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_child_subreaper(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns task->signal->is_child_subreaper -- a
	 * single bit, value 0 or 1.  A larger value is a torn read
	 * of signal_struct or a dispatch into the wrong getter.
	 */
	if (retval > 1UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_CHILD_SUBREAPER retval 0x%lx outside {0, 1, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_get_seccomp(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns task->seccomp.mode -- one of
	 * SECCOMP_MODE_DISABLED (0), SECCOMP_MODE_STRICT (1) or
	 * SECCOMP_MODE_FILTER (2).  A larger value is silent
	 * corruption of a security-critical task field that gates
	 * filter installation and syscall dispatch.
	 */
	if (retval > 2UL && retval != (unsigned long)-1L) {
		output(0, "post_prctl: rejected PR_GET_SECCOMP retval 0x%lx outside {DISABLED, STRICT, FILTER, -1}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_prctl(struct syscallrecord *rec)
{
	struct prctl_post_state *snap = (struct prctl_post_state *) rec->post_state;
	unsigned long retval;

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
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * prctl_post_state.  A cookie mismatch means snap does not point
	 * at our struct -- abandon rather than dispatch off snap->option
	 * (which steers into the PR_SET_SECCOMP bpf->filter free path and
	 * the per-PR_GET_* strong-val retval bound checks) or free()
	 * snap->bpf as a sock_fprog.
	 */
	/*
	 * Ownership-table check: shape passed but the magic cookie only
	 * proves "looks like struct prctl_post_state", not "is the snapshot
	 * we produced for this attempt".  A sibling scribble that redirects
	 * rec->post_state at a stale same-type snap still resident on the
	 * deferred-free queue carries the matching cookie by construction,
	 * so a cookie-only gate would trust it and dispatch off snap->option
	 * -- driving the PR_SET_SECCOMP arm into tracked_free_now() on an
	 * attacker-influenced bpf->filter (an arbitrary free on a tracking-
	 * table miss).  sanitise_prctl() registers each snap in the post_state
	 * ownership table immediately after the rec->post_state assignment;
	 * a value that fails the lookup is not the live snap for this record
	 * and must not be dereferenced.  Mirrors execve.c / pipe.c.  Bail
	 * without freeing -- the pointer is suspect.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_prctl: rejected post_state=%p not in ownership "
			  "table (post_state-redirected?)\n", snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if (snap->magic != PRCTL_POST_STATE_MAGIC) {
		outputerr("post_prctl: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
		post_state_release(rec, snap);
		return;
	}

	retval = rec->retval;

	switch (snap->option) {
	case PR_SET_SECCOMP:
		post_set_seccomp(snap);
		break;
	case PR_SET_NO_NEW_PRIVS:
		post_set_no_new_privs(retval);
		break;
	case PR_SET_NAME:
		post_set_name(snap, retval);
		break;
	case PR_SET_DUMPABLE:
		post_set_dumpable(snap, retval);
		break;
	case PR_SET_KEEPCAPS:
		post_set_keepcaps(snap, retval);
		break;
	case PR_SET_PDEATHSIG:
		post_set_pdeathsig(snap, retval);
		break;
	case PR_GET_PDEATHSIG:
		post_get_pdeathsig(rec, retval);
		break;
	case PR_GET_KEEPCAPS:
		post_get_keepcaps(rec, retval);
		break;
	case PR_GET_DUMPABLE:
		post_get_dumpable(rec, retval);
		break;
	case PR_GET_NAME:
		post_get_name(rec, retval);
		break;
	case PR_GET_NO_NEW_PRIVS:
		post_get_no_new_privs(rec, retval);
		break;
	case PR_CAPBSET_READ:
		post_capbset_read(rec, retval);
		break;
	case PR_GET_TIMING:
		post_get_timing(rec, retval);
		break;
	case PR_GET_FPEXC:
	case PR_GET_FPEMU:
		post_get_fp_exc_emu(rec, retval);
		break;
	case PR_GET_TSC:
		post_get_tsc(rec, retval);
		break;
	case PR_GET_THP_DISABLE:
		post_get_thp_disable(rec, retval);
		break;
	case PR_GET_CHILD_SUBREAPER:
		post_get_child_subreaper(rec, retval);
		break;
	case PR_GET_SECCOMP:
		post_get_seccomp(rec, retval);
		break;
	}

	post_state_release(rec, snap);
}

struct syscallentry syscall_prctl = {
	.name = "prctl",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argname = { [0] = "option", [1] = "arg2", [2] = "arg3", [3] = "arg4", [4] = "arg5" },
	.sanitise = sanitise_prctl,
	.post = post_prctl,
};
