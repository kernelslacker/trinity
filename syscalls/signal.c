/*
 * SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
 */
#include <signal.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/* Real signals we are willing to install a handler for via the legacy
 * signal(2) installer's default bucket below.  The synchronous-fault
 * class (SIGILL/SIGTRAP/SIGABRT/SIGBUS/SIGFPE/SIGSEGV) is excluded
 * here for the same reason it is excluded from rt_sigaction's settable
 * pool in syscalls/sigaction.c (see f4a04186fa66): the handler arg is
 * an ARG_ADDRESS draw that frequently resolves to a wild rand-shaped
 * pointer, and pairing one of the fault signos with that draw
 * permanently replaces trinity's per-child child_fault_handler
 * (installed exactly once per child in signals.c::mask_signals_child,
 * never re-armed).  The next benign self-fault is then either killed
 * uncaught or mis-attributed by the parent's reaper as a kernel crash.
 * The fault signals stay reachable via the small fault_class_signals[]
 * bucket in pick_signal_target() so install-path coverage for those
 * signos is preserved at a rate low enough not to dominate runs with
 * mis-attributed deaths.
 *
 * SIGKILL/SIGSTOP are rejected by the kernel; the forbidden bucket
 * targets them explicitly to keep the EINVAL gate exercised.
 */
static const unsigned long settable_signals[] = {
	SIGHUP, SIGINT, SIGQUIT, SIGUSR1, SIGUSR2,
	SIGPIPE, SIGALRM, SIGCHLD, SIGCONT, SIGTSTP,
	SIGTTIN, SIGTTOU, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGPWR,
	SIGSYS,
};

/* Synchronous-fault class -- excluded from settable_signals[] above to
 * avoid wiping trinity's child_fault_handler.  Drawn at low rate in
 * pick_signal_target() so sys_signal() coverage for these signos stays
 * warm without the per-call handler-clobber probability that the
 * pre-curation full-range signo carried.
 */
static const unsigned long fault_class_signals[] = {
	SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV,
};

static unsigned long pick_signal_target(void)
{
	unsigned int draw = rnd_modulo_u32(100);
	int rtcount = SIGRTMAX - SIGRTMIN + 1;

	if (draw < 5) {
		/* Intentionally-uninstallable bucket -- keeps EINVAL gate
		 * for SIGKILL/SIGSTOP warm. */
		static const unsigned long forbidden[] = { SIGKILL, SIGSTOP };
		return RAND_ARRAY(forbidden);
	}
	if (draw < 10)
		/* Synchronous-fault class: kept reachable at low rate so
		 * sys_signal() coverage for these signos stays warm; see
		 * settable_signals[] for why this is not folded into the
		 * default bucket. */
		return RAND_ARRAY(fault_class_signals);
	if (draw < 70)
		return RAND_ARRAY(settable_signals);
	if (rtcount > 0)
		return SIGRTMIN + rnd_modulo_u32(rtcount);
	return RAND_ARRAY(settable_signals);
}

static void sanitise_signal(struct syscallrecord *rec)
{
	rec->a1 = pick_signal_target();
}

struct syscallentry syscall_signal = {
	.name = "signal",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.sanitise = sanitise_signal,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "sig", [1] = "handler" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = _NSIG,
	.flags = AVOID_SYSCALL,
};
