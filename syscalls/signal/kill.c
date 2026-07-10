/*
 * SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
 */
#include <signal.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "signals-safelist.h"

static void sanitise_kill(struct syscallrecord *rec)
{
	unsigned int draw;

	/*
	 * Bias toward sig==0 (existence-probe, no delivery) and the
	 * child-safe set so a self/sibling-targeted delivery does not
	 * tear down a healthy fuzz child.  A small slice picks from the
	 * crash-probe (child-fatal) bucket so the kernel-side delivery
	 * path for the obviously-fatal signals still sees traffic
	 * without dominating the run with teardowns.  kill has no
	 * siginfo path so there is no realtime branch to exercise here.
	 */
	draw = rnd_modulo_u32(20);
	if (draw < 6)
		rec->a2 = 0;
	else if (draw < 19)
		rec->a2 = child_safe_signals[rnd_modulo_u32(child_safe_signals_count)];
	else
		rec->a2 = child_fatal_signals[rnd_modulo_u32(child_fatal_signals_count)];
}

struct syscallentry syscall_kill = {
	.name = "kill",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "sig" },
	.sanitise = sanitise_kill,
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,
};
