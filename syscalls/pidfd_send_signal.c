/*
 *   SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig, siginfo_t __user *, info, unsigned int, flags)
 */
#include <signal.h>
#include <string.h>
#include <linux/pidfd.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "pids.h"

/*
 * Drop the synchronous-fault signals (SIGILL/SIGTRAP/SIGABRT/SIGBUS/
 * SIGSEGV) and the lifecycle-fatal trio (SIGKILL/SIGSTOP/SIGTERM) from
 * the default path -- a self- or sibling-targeted deliver will re-enter
 * trinity's own fault handlers or tear down a healthy child.  sig==0 is
 * the kernel's existence-probe and is covered by the dedicated path in
 * sanitise_pidfd_send_signal().
 */
static unsigned long pidfd_signals[] = {
	SIGHUP, SIGQUIT, SIGFPE, SIGUSR1, SIGUSR2, SIGPIPE,
	SIGALRM, SIGCHLD, SIGCONT, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static unsigned long pidfd_send_signal_flags[] = {
	PIDFD_SIGNAL_THREAD, PIDFD_SIGNAL_THREAD_GROUP, PIDFD_SIGNAL_PROCESS_GROUP,
};

static void sanitise_pidfd_send_signal(struct syscallrecord *rec)
{
	unsigned int draw;

	/*
	 * Bias toward sig==0 (existence-probe, no delivery) and the
	 * ignorable safe set.  pidfd_send_signal does not accept a
	 * realtime signo with arbitrary siginfo from unprivileged callers
	 * any differently, so no separate realtime branch is needed.
	 */
	draw = rnd_modulo_u32(10);
	if (draw < 3)
		rec->a2 = 0;
	else
		rec->a2 = RAND_ARRAY(pidfd_signals);

#ifdef PIDFD_SELF_THREAD
	/* Sometimes pass a self-referencing sentinel instead of a real pidfd. */
	if (rnd_modulo_u32(4) == 0) {
		rec->a1 = RAND_BOOL() ? (unsigned long)PIDFD_SELF_THREAD
				      : (unsigned long)PIDFD_SELF_THREAD_GROUP;
		return;
	}
#endif

	/* Half the time pass NULL — kernel fills in default siginfo. */
	if (RAND_BOOL()) {
		rec->a3 = 0;
		return;
	}

	/* Otherwise allocate a valid siginfo_t with SI_QUEUE. */
	siginfo_t *info = (siginfo_t *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	info->si_code = SI_QUEUE;
	info->si_pid = mypid();
	info->si_uid = getuid();

	rec->a3 = (unsigned long) info;
}

struct syscallentry syscall_pidfd_send_signal = {
	.name = "pidfd_send_signal",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIDFD, [3] = ARG_OP },
	.argname = { [0] = "pidfd", [1] = "sig", [2] = "info", [3] = "flags" },
	.arg_params[3].list = ARGLIST(pidfd_send_signal_flags),
	.sanitise = sanitise_pidfd_send_signal,
};
