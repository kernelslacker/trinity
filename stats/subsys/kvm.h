#ifndef _TRINITY_STATS_SUBSYS_KVM_H
#define _TRINITY_STATS_SUBSYS_KVM_H

/*
 * KVM ioctl fuzzing counters -- per-vCPU / per-VM ioctl dispatches,
 * KVM_RUN churn (invocations + exit_reason histogram + errors), and
 * the gpc-memslot-race sub-mode gauges.  See ioctls/kvm-vcpu.c,
 * ioctls/kvm-vm.c, childops/misc/kvm-run-churn.c.  The surrounding
 * struct stats_s composes an instance of struct kvm_stats as its
 * "kvm" member.
 *
 * Member naming: the run_* / gpc_memslot_race_* prefixes are the
 * historical JSON keys emitted under the kvm_run_churn category, and
 * are preserved verbatim so the fleet dashboards keep working.
 * vcpu_ / vm_ prefixes come from the ioctl-dispatch counters which
 * emit under the kvm category itself.
 */
struct kvm_stats {
	/* Per-vCPU ioctl dispatches into kvm_vcpu_grp.  Bumped from
	 * kvm_vcpu_sanitise() each time pick_random_ioctl() lands on an ioctl
	 * destined for an OBJ_FD_KVM_VCPU fd.  Distinct from the flat KVM
	 * ioctl group so a zero count here while the flat KVM group stat ticks
	 * means the per-vCPU fd_test path is dropping the fd and the dispatch
	 * is still bouncing off /dev/kvm with ENOTTY.  Surfaced via
	 * periodic_counter_rates_dump() so an operator sees the per-window
	 * dispatch rate without waiting for the end-of-run summary. */
	unsigned long vcpu_ioctls_dispatched;

	/* Per-VM ioctl dispatches into kvm_vm_grp.  Bumped from
	 * kvm_vm_sanitise() each time pick_random_ioctl() lands on an ioctl
	 * destined for an OBJ_FD_KVM_VM fd.  Same diagnostic role as
	 * vcpu_ioctls_dispatched for the per-vCPU group: a flat counter
	 * while VM fds exist in the pool means kvm_vm_fd_test isn't winning
	 * arbitration and the dispatch is still bouncing off /dev/kvm with
	 * ENOTTY. */
	unsigned long vm_ioctls_dispatched;

	/* kvm_run_churn childop counters (emitted under kvm_run_churn) */
	unsigned long invocations;		/* total KVM_RUN ioctls issued */
	unsigned long exit_io;			/* exit_reason == KVM_EXIT_IO */
	unsigned long exit_mmio;		/* exit_reason == KVM_EXIT_MMIO */
	unsigned long exit_hlt;			/* exit_reason == KVM_EXIT_HLT */
	unsigned long exit_shutdown;		/* exit_reason == KVM_EXIT_SHUTDOWN */
	unsigned long exit_fail_entry;		/* exit_reason == KVM_EXIT_FAIL_ENTRY */
	unsigned long exit_internal_error;	/* exit_reason == KVM_EXIT_INTERNAL_ERROR */
	unsigned long exit_intr;		/* exit_reason == KVM_EXIT_INTR (alarm-induced) */
	unsigned long exit_other;		/* every other exit_reason value */
	unsigned long errors;			/* KVM_RUN ioctl returned -1 */
	unsigned long gpc_memslot_race_runs;	/* memslot-race sub-mode invocations */
	unsigned long gpc_memslot_race_deletes;	/* KVM_SET_USER_MEMORY_REGION{,2} delete ioctls issued by writer */
	unsigned long gpc_memslot_race_unsupported; /* sub-mode latched off (cap absent or ENODEV/EOPNOTSUPP) */

	/* kvm_mmu_reclaim_race childop ioctl accounting.
	 * Counters are incremented from multiple threads via __atomic_add_fetch
	 * directly into shm, so they accumulate across child respawns.
	 *
	 * KVM_PRE_FAULT_MEMORY (vcpu ioctl, Lane 1):
	 *   returns 0 on success; -EOPNOTSUPP when the vCPU's page_fault handler
	 *   is not kvm_tdp_page_fault (e.g. TDP MMU active, tdp_mmu=1) or when
	 *   vcpu->arch.mmu->pre_fault_allowed is not set; other errors are rare.
	 *   A nonzero reclaim_prefault_eopnotsupp-to-total ratio while
	 *   reclaim_prefault_ok stays zero confirms the oracle is structurally
	 *   inert on this kernel config (kvm.tdp_mmu not cleared at boot).
	 *
	 * KVM_SET_NR_MMU_PAGES (vm ioctl, Lane 2):
	 *   returns 0 on success; -EINVAL if the value is below
	 *   KVM_MIN_FREE_MMU_PAGES (10) or the VM is not x86.
	 *
	 * KVM_SET_USER_MEMORY_REGION (vm ioctl, setup / Lane 3 / teardown):
	 *   returns 0 on success; errors here indicate a broken memslot
	 *   state that would prevent the churn lane from opening the race
	 *   window -- surfaced so a silent-failure harness is detectable. */
	unsigned long reclaim_prefault_ok;		/* KVM_PRE_FAULT_MEMORY succeeded (rc == 0) */
	unsigned long reclaim_prefault_eopnotsupp;	/* KVM_PRE_FAULT_MEMORY → -EOPNOTSUPP */
	unsigned long reclaim_prefault_err;		/* KVM_PRE_FAULT_MEMORY → other error */
	unsigned long reclaim_set_nr_mmu_ok;		/* KVM_SET_NR_MMU_PAGES succeeded */
	unsigned long reclaim_set_nr_mmu_err;		/* KVM_SET_NR_MMU_PAGES failed */
	unsigned long reclaim_memslot_ok;		/* KVM_SET_USER_MEMORY_REGION succeeded */
};

#endif	/* _TRINITY_STATS_SUBSYS_KVM_H */
