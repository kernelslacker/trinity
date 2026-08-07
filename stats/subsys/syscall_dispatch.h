#ifndef _TRINITY_STATS_SUBSYS_SYSCALL_DISPATCH_H
#define _TRINITY_STATS_SUBSYS_SYSCALL_DISPATCH_H

/*
 * Aggregate syscall-dispatch accounting -- total per-syscall wall
 * time and per-source dispatch counters (childop-attributed random
 * calls, random_syscall walker's direct dispatches).  Feeds the
 * childop-split periodic dump so an operator can compare "syscalls
 * driven by structured childops" vs "syscalls the random dispatcher
 * fired directly".  The surrounding struct stats_s composes an
 * instance of struct syscall_dispatch_stats as its "syscall_dispatch"
 * member.
 */
struct syscall_dispatch_stats {
	unsigned long walltime_ns;
	unsigned long in_childops;
	unsigned long random;
	unsigned long random_dispatches;

	/* Untraced dispatch-shape counters -- the raw denominators the
	 * child hot-path optimizations need to price cost-per-completed-
	 * syscall without ptrace distortion.  Four counters, all
	 * RELAXED add-fetch:
	 * cumulative diagnostic, single-writer-per-child, lost-update
	 * races tolerated.
	 *
	 *   random_syscall_attempts:
	 *     Bumped once at the entry of random_syscall_step BEFORE
	 *     set_syscall_nr(), so an out-of-range or table-declined
	 *     NR pick still counts.  Denominator for "how many times
	 *     did the child try to fire a random syscall".
	 *
	 *   random_syscall_completions:
	 *     Bumped once at random_syscall_step's tail after
	 *     dispatch_step returned, i.e. do_syscall() ran (regardless
	 *     of the syscall's own return value or validator reject
	 *     status).  Together with _attempts this surfaces the
	 *     attempt/completion ratio: a big gap means many NR picks
	 *     bailed before dispatch (deactivated syscall, missing
	 *     capability, biased-consumer rejects).
	 *
	 *   childop_dispatches:
	 *     Bumped once per child_process() outer-loop iteration that
	 *     dispatched an alt-op (is_alt_op == true), measured at the
	 *     same site the wall_ns[op] bracket closes.  Complements
	 *     random_dispatches (the syscall-path parallel already
	 *     wired one field above) so the childop_split ratio has a
	 *     matched dispatch denominator without dragging in the
	 *     per-op childop.invocations[] arrays.
	 *
	 *   childop_iterations:
	 *     Bumped once per child_process() outer-loop iteration
	 *     regardless of op_type.  Denominator for the child hot-
	 *     path cost model: total iterations vs completed syscalls
	 *     vs childop dispatches.  One iteration can represent
	 *     dozens of kernel calls when it lands on a chatty childop
	 *     (pipe_thrash averages ~28 pipe2/close per outer alarm),
	 *     so an iteration count alone cannot price the loop --
	 *     pairing it with the syscall and childop denominators
	 *     lets the operator see the true call-per-iteration ratio.
	 *
	 *   seal_fail_ops:
	 *     Bumped at dispatch/syscall.c when deferred_free_seal_all()
	 *     returns false (mprotect sweep failed, usually vma
	 *     exhaustion).  Distinct from the arg-validator counter
	 *     (validator_rejected in stats_aggregate) which is a
	 *     normal, high-volume infrastructure counter.  A non-zero
	 *     seal_fail_ops rate flags a fuzzer-infrastructure fault
	 *     (persistent mprotect failures) that would otherwise be
	 *     invisible in fleet throughput stats. */
	unsigned long random_syscall_attempts;
	unsigned long random_syscall_completions;
	unsigned long childop_dispatches;
	unsigned long childop_iterations;
	unsigned long seal_fail_ops;
};

#endif	/* _TRINITY_STATS_SUBSYS_SYSCALL_DISPATCH_H */
