/*
 * Process / signal / rlimit / futex struct-catalog registrations.
 *
 * Covers clone3, {set,get}rlimit / prlimit64, perf_event_open, all
 * sigaction / siginfo / sigaltstack / sigqueue rows, capset / capget,
 * keyctl, rseq, set_robust_list, process_vm_{read,write}v, the futex
 * family (futex_wait, futex_waitv, futex_requeue, futex with its
 * timeout-op discriminator), the sigset_t rows on rt_sigsuspend /
 * rt_sigtimedwait, and (X86) modify_ldt.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <linux/futex.h>

#include "config.h"

#include "arch.h"

#include "struct_catalog.h"

/*
 * futex_timeout_ops: the op subset where a4 (utime) is a struct
 * timespec pointer rather than the val2 integer overload.  Mirrors
 * the kernel's futex_cmd_has_timeout() switch (kernel/futex/syscalls.c).
 * Matched against rec->a2 masked by FUTEX_CMD_MASK so the PRIVATE /
 * CLOCK_REALTIME / ROBUST flag bits don't perturb the dispatch.
 */
static const unsigned long futex_timeout_ops[] = {
	FUTEX_WAIT,
	FUTEX_LOCK_PI,
	FUTEX_WAIT_BITSET,
	FUTEX_WAIT_REQUEUE_PI,
	FUTEX_LOCK_PI2,
};

const struct syscall_struct_arg struct_catalog_registry_process[] = {
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[SC_CLONE_ARGS] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[SC_RLIMIT] },
	{ "prlimit64",		4, &struct_catalog[SC_RLIMIT] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[SC_PERF_EVENT_ATTR] },
	/* rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t) */
	{ "rt_sigaction",	2, &struct_catalog[SC_SIGACTION] },
	{ "rt_sigaction",	3, &struct_catalog[SC_SIGACTION] },
	/* sigaction(int, const struct old_sigaction *, struct old_sigaction *) */
	{ "sigaction",		2, &struct_catalog[SC_SIGACTION] },
	{ "sigaction",		3, &struct_catalog[SC_SIGACTION] },
	/* capset(cap_user_header_t hdr, const cap_user_data_t data) */
	{ "capset",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	{ "capset",		2, &struct_catalog[SC_USER_CAP_DATA] },
	/* capget(cap_user_header_t hdr, cap_user_data_t data) */
	{ "capget",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	/* futex_waitv(struct futex_waitv *waiters, unsigned int nr, unsigned int flags, struct timespec *timo, clockid_t clockid) */
	{ "futex_waitv",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* futex_requeue(struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue) */
	{ "futex_requeue",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* sigaltstack(const stack_t *ss, stack_t *old_ss) */
	{ "sigaltstack",	1, &struct_catalog[SC_STACK_T] },
	/*
	 * rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo)
	 * rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
	 *                   siginfo_t __user *uinfo)
	 *
	 * Attribution-only registration -- argtype[*] for the siginfo
	 * slot is not ARG_STRUCT_PTR_*, so the schema-aware fill never
	 * runs against rec->a3 (rt_sigqueueinfo) / rec->a4
	 * (rt_tgsigqueueinfo).  The bespoke sanitisers keep owning the
	 * live fill (fill_siginfo_by_class on rt_sigqueueinfo, a fixed
	 * SI_QUEUE shape on rt_tgsigqueueinfo), and this entry lets
	 * struct_field_for_cmp() steer CMP-learned constants at the
	 * named si_signo / si_code / si_pid / si_uid / si_value slots
	 * rather than at coincidentally-same-width slots.  Variants in
	 * the descriptor scope the candidate field pool to the live
	 * _kill / _rt arm whenever struct_desc_resolve_variant is
	 * called with the post-fill buf (CMP-time callers that pass
	 * buf == NULL fall through to the shared head).
	 *
	 * Not mapped here on purpose: waitid's a3 is a kernel-written
	 * OUTPUT (mirrors the gettimeofday / get_robust_list /
	 * cachestat-output skips above) and registering it would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  pidfd_send_signal's a3
	 * IS mapped (attribution-only, same as rt_sigqueueinfo /
	 * rt_tgsigqueueinfo -- the bespoke sanitisers keep owning the
	 * live fill).
	 */
	{ "rt_sigqueueinfo",	3, &struct_catalog[SC_SIGINFO_T] },
	{ "rt_tgsigqueueinfo",	4, &struct_catalog[SC_SIGINFO_T] },
	{ "pidfd_send_signal",	3, &struct_catalog[SC_SIGINFO_T] },
	/*
	 * keyctl(int cmd, unsigned long a2, unsigned long a3,
	 *        unsigned long a4, unsigned long a5)
	 * The a2 slot's shape is cmd-selected: DH_COMPUTE points it at a
	 * struct keyctl_dh_params, the four PKEY_{ENCRYPT,DECRYPT,SIGN,
	 * VERIFY} ops at a struct keyctl_pkey_params; the remaining cmds
	 * put a scalar (key_serial_t, mask, or opaque flag) there and
	 * match no variant.  argtype[1] is left at the syscall's default
	 * (ARG_UNDEFINED) and sanitise_keyctl() owns the live fill for
	 * every cmd, so this is an attribution-only row -- the schema-
	 * aware fill path never resolves rec->a2 through the catalog, and
	 * struct_field_for_cmp() gets to name the specific struct field
	 * (keyctl_dh_params.prime, keyctl_pkey_params.in_len, ...) that a
	 * KCOV-CMP-learned constant fell out of.  The variants dispatch
	 * off rec->a1 (discrim_arg_idx=1 on the descriptor itself, same
	 * shape bpf_attr uses for its per-cmd tagged union).
	 */
	{ "keyctl",		2, &struct_catalog[SC_KEYCTL_PAYLOAD] },
	/*
	 * rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
	 *                 const struct timespec *uts, size_t sigsetsize)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitiser (build_timeout stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (uthese,
	 * sigset_t) and a2 (uinfo, siginfo_t) are not timespecs and are
	 * intentionally unregistered here.
	 */
	{ "rt_sigtimedwait",	3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex_wait(void *uaddr, unsigned long val, unsigned long mask,
	 *            unsigned int flags, struct timespec *timeout,
	 *            clockid_t clockid)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_wait (stamps the slot via get_writable_struct)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "futex_wait",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex(u32 *uaddr, int op, u32 val, struct timespec *utime,
	 *       u32 *uaddr2, u32 val3)
	 * a4 (utime) is a struct timespec pointer only for the WAIT-family
	 * and LOCK_PI / LOCK_PI2 ops (kernel: futex_cmd_has_timeout); for
	 * every other cmd it carries the val2 integer overload instead.
	 * Discriminate on a2 masked by FUTEX_CMD_MASK so the row matches
	 * only the timeout-taking ops, mirroring the kernel's own
	 * `cmd = op & FUTEX_CMD_MASK` dispatch.  Attribution-only: the
	 * bespoke sanitise_futex still owns the a4 fill via &utime_clamp;
	 * this row only lets schema-aware CMP attribution name the
	 * tv_sec / tv_nsec fields for the matching ops.
	 */
	{
		"futex", 4, &struct_catalog[SC_TIMESPEC],
		.discrim_arg_idx	= 2,
		.discrim_mask		= FUTEX_CMD_MASK,
		.discrim_values		= futex_timeout_ops,
		.num_discrim_values	= ARRAY_SIZE(futex_timeout_ops),
	},
	/*
	 * futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
	 *             unsigned int flags, struct timespec *timeout,
	 *             clockid_t clockid)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_waitv (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (waiters)
	 * is mapped to SC_FUTEX_WAITV above and is unaffected.
	 */
	{ "futex_waitv",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * process_vm_readv(pid_t pid, const struct iovec *lvec,
	 *                  unsigned long liovcnt, const struct iovec *rvec,
	 *                  unsigned long riovcnt, unsigned long flags)
	 * process_vm_writev(pid_t pid, const struct iovec *lvec,
	 *                   unsigned long liovcnt, const struct iovec *rvec,
	 *                   unsigned long riovcnt, unsigned long flags)
	 * Both lvec (a2) and rvec (a4) are iovec arrays; map each
	 * separately so attribution covers both slots.
	 */
	{ "process_vm_readv",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_readv",	4, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	4, &struct_catalog[SC_IOVEC] },
	/*
	 * set_robust_list(struct robust_list_head __user *head, size_t len)
	 * a1 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_set_robust_list() keeps owning the live (list.next,
	 * futex_offset, list_op_pending) layout.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned constants
	 * at the named fields.  get_robust_list's robust_list_head is an
	 * output (a2 is a double pointer the kernel writes), so only
	 * set_robust_list's a1 is mapped.
	 */
	{ "set_robust_list",	1, &struct_catalog[SC_ROBUST_LIST_HEAD] },
	/*
	 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
	 * a1 is the INPUT struct rseq pointer; the bespoke sanitise_rseq()
	 * keeps owning the live fill (32-byte-aligned allocation, zero-
	 * init, a2 length-bucket distribution, a4 signature pin).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at the named fields rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "rseq",		1, &struct_catalog[SC_RSEQ] },
	/*
	 * Signals-primary sigset_t rows.  The FS-primary consumers
	 * (signalfd, signalfd4, ppoll a4, epoll_pwait, epoll_pwait2)
	 * live with the fs group.
	 */
	{ "rt_sigsuspend",	1, &struct_catalog[SC_SIGSET_T] },
	{ "rt_sigtimedwait",	1, &struct_catalog[SC_SIGSET_T] },
#ifdef X86
	/*
	 * modify_ldt(int func, void __user *ptr, unsigned long bytecount)
	 * a2 is a struct user_desc pointer only on the write_ldt arm
	 * (func == 1); the read arm (func == 0) hands the kernel a
	 * plain user buffer to splat the live LDT into.  The bespoke
	 * sanitise_modify_ldt() arm keeps owning the live fill (per-bit
	 * RAND_BOOL pickers for the seg_32bit / contents / read_exec_only
	 * / limit_in_pages / seg_not_present / useable / lm bitfields,
	 * rec->a3 pinned to sizeof(struct user_desc));  attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named entry_number / base_addr / limit slots
	 * rather than at a coincidentally-same-width slot.
	 *
	 * Discriminator pool is the single value {1}; func == 0 / 2 fall
	 * through to NULL and the bespoke arm continues to own them.
	 */
	{
		"modify_ldt", 2, &struct_catalog[SC_USER_DESC],
		.discrim_arg_idx	= 1,
		.discrim_value		= 1,
	},
#endif
	/* sentinel */
	{ NULL, 0, NULL },
};
