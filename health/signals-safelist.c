#include <signal.h>

#include "signals-safelist.h"
#include "utils.h"	/* ARRAY_SIZE */

/*
 * CHILD-NON-FATAL set.  Derived from the policy mask_signals_child() in
 * signals.c installs on every fuzz child:
 *
 *   SIGFPE, SIGTSTP, SIGWINCH, SIGIO, SIGPIPE, SIGXFSZ
 *     Explicitly SIG_IGN'd by mask_signals_child() -- kernel discards
 *     the delivery and the child runs on.
 *
 *   SIGALRM, SIGXCPU
 *     Wired to dedicated flag-setting handlers (sigalrm_handler /
 *     sigxcpu_handler); the child's main loop notices the flag on the
 *     next iteration -- no teardown.
 *
 *   SIGCHLD
 *     SIG_DFL, whose kernel default action is Ignore -- harmless.
 *
 *   SIGCONT, SIGURG
 *     No explicit override, so the catch-all sighandler runs and
 *     reduces to the kernel default action: Continue and Ignore
 *     respectively.  A non-stopped fuzz child takes neither as a
 *     teardown.
 *
 * Edits to this list MUST be matched by an audit of mask_signals_child()
 * (or vice versa).  Otherwise the "safe" bias re-acquires the exact
 * ability it exists to remove: kill(self, X) tearing down a healthy
 * fuzz child via the catch-all sighandler -> SIG_DFL -> raise default-
 * action path.
 */
const unsigned long child_safe_signals[] = {
	SIGALRM, SIGCHLD, SIGCONT, SIGFPE, SIGIO,
	SIGPIPE, SIGTSTP, SIGURG, SIGWINCH, SIGXCPU,
	SIGXFSZ,
};
const unsigned int child_safe_signals_count = ARRAY_SIZE(child_safe_signals);

/*
 * CHILD-FATAL crash-probe bucket.  No explicit override in
 * mask_signals_child(), so the catch-all sighandler runs and reduces
 * each one to the kernel default action: Term for SIGHUP / SIGUSR1 /
 * SIGUSR2 / SIGVTALRM / SIGPROF, Core for SIGQUIT / SIGSYS.  Self- or
 * sibling-targeted delivery WILL reap a healthy fuzz child -- that is
 * the noise the safe-list rework removed from the default path -- so
 * the delivery sanitisers pick from this set at a small fixed rate to
 * keep kernel-side coverage of the signal-delivery / permission /
 * group-leader paths warm without dominating the run.
 *
 * Deliberately omitted:
 *
 *   SIGKILL, SIGSTOP, SIGTERM
 *     Lifecycle-fatal trio.  SIGKILL / SIGSTOP cannot be caught;
 *     SIGTERM goes through the catch-all to default-Term.  Each pick
 *     would deterministically reap a sibling fuzz child rather than
 *     merely exercising the delivery path.
 *
 *   SIGSEGV, SIGABRT, SIGBUS, SIGILL
 *     Wired to child_fault_handler().  A sibling-spoofed pick is
 *     dropped silently, but a self-targeted pick lands on the
 *     in_do_syscall self-fuzz gate that _exit()s the child -- so a
 *     fraction proportional to ARG_PID's self-pid bias still reaps the
 *     caller, defeating the purpose.
 *
 *   SIGTTIN, SIGTTOU
 *     Default action Stop.  No teardown but the child sits idle until
 *     SIGCONT, wasting a worker slot.
 */
const unsigned long child_fatal_signals[] = {
	SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
	SIGVTALRM, SIGPROF, SIGSYS,
};
const unsigned int child_fatal_signals_count = ARRAY_SIZE(child_fatal_signals);
