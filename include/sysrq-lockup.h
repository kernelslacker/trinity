#pragma once

/*
 * Opt-in (--sysrq-on-lockup) wedge diagnostic invoked by the parent
 * watchdog once per tick.  With sysrq_on_lockup==false the entire
 * trigger path is unreachable and this call is a single
 * branch-predicted `if` test on the caller side.
 *
 * When the flag is on and stall_count crosses the threshold
 * max(3, running_childs/2), write SysRq 'w' (blocked task list) and
 * 'l' (backtrace all active CPUs) to /proc/sysrq-trigger and drain the
 * resulting kernel post-mortem from /dev/kmsg to the run's diagnostic
 * output.  Fires once per wedge event; re-arms when stall_count drops
 * back below the threshold so a subsequent event can also fire.
 */
void sysrq_lockup_check_and_fire(unsigned int stall_count,
				 unsigned int running_childs);
