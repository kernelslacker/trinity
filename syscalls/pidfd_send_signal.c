/*
 *   SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig, siginfo_t __user *, info, unsigned int, flags)
 */
#include <signal.h>
#include <string.h>
#include <linux/pidfd.h>
#include "random.h"
#include "sanitise.h"

static unsigned long pidfd_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGTERM, SIGCHLD, SIGCONT,
	SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM,
	SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static unsigned long pidfd_send_signal_flags[] = {
	PIDFD_SIGNAL_THREAD, PIDFD_SIGNAL_THREAD_GROUP, PIDFD_SIGNAL_PROCESS_GROUP,
};

static void sanitise_pidfd_send_signal(struct syscallrecord *rec)
{
#ifdef PIDFD_SELF_THREAD
	/* Sometimes pass a self-referencing sentinel instead of a real pidfd. */
	if (rand() % 4 == 0) {
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
	info->si_pid = getpid();
	info->si_uid = getuid();

	rec->a3 = (unsigned long) info;
}

struct syscallentry syscall_pidfd_send_signal = {
	.name = "pidfd_send_signal",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_OP, [3] = ARG_OP },
	.argname = { [0] = "pidfd", [1] = "sig", [2] = "info", [3] = "flags" },
	.arg_params[1].list = ARGLIST(pidfd_signals),
	.arg_params[3].list = ARGLIST(pidfd_send_signal_flags),
	.sanitise = sanitise_pidfd_send_signal,
};
