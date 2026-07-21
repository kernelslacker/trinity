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
};

#endif	/* _TRINITY_STATS_SUBSYS_SYSCALL_DISPATCH_H */
