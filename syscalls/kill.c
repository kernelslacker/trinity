/*
 * SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
 */
#include <signal.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Drop the synchronous-fault signals (SIGILL/SIGTRAP/SIGABRT/SIGBUS/
 * SIGSEGV) and the lifecycle-fatal trio (SIGKILL/SIGSTOP/SIGTERM) from
 * the default path -- a self-targeted or sibling-targeted deliver will
 * re-enter trinity's own fault handlers or tear down a healthy child.
 * sig==0 is the kernel's existence-probe and is covered by the dedicated
 * path in sanitise_kill().
 */
static unsigned long safe_signals[] = {
	SIGHUP, SIGQUIT, SIGFPE, SIGUSR1, SIGUSR2, SIGPIPE,
	SIGALRM, SIGCHLD, SIGCONT, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static void sanitise_kill(struct syscallrecord *rec)
{
	unsigned int draw;

	/*
	 * Bias toward sig==0 (existence-probe, no delivery) and the
	 * ignorable safe set.  kill has no siginfo path so there is no
	 * realtime branch to exercise here.
	 */
	draw = rnd_modulo_u32(10);
	if (draw < 3)
		rec->a2 = 0;
	else
		rec->a2 = RAND_ARRAY(safe_signals);
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
