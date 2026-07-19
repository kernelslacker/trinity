/*
 * SYSCALL_DEFINE0(uretprobe)
 *
 * Called directly (not from the kernel-installed return-probe trampoline),
 * the kernel does force_sig(SIGILL) on the caller. There is no reachable
 * code path with useful coverage from a raw syscall invocation, so mark
 * AVOID_SYSCALL. The real uprobe/uretprobe surface is exercised via
 * tracefs uprobe_events, not this entry point.
 */
#include "sanitise.h"

struct syscallentry syscall_uretprobe = {
	.name = "uretprobe",
	.num_args = 0,
	.flags = AVOID_SYSCALL, // out-of-trampoline call force_sig(SIGILL)s the caller — no coverage, floods logs
	.group = GROUP_PROCESS,
};
