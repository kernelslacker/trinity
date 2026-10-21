/*
 * The wait-then-kill that ends do_extrafork()'s throwaway grandchild.
 * The grandchild is signalled only after a timeout, never once the wait
 * has failed: its pid may be someone else's by then.  Nothing here
 * reaches into the rest of trinity, which lets the test binary link it
 * and drive it with bare forked children.
 */

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include "syscall-internal.h"
#include "trinity.h"
#include "utils.h"

/* Reap the throwaway grandchild @extrapid: poll for its exit, then kill
 * whatever is still running.  @polls is the number of 1ms polls to wait.
 */
void extrafork_reap(pid_t extrapid, unsigned int polls)
{
	pid_t pid = 0;

	/* Bound the loop to @polls * 1ms (~1 second for do_extrafork) so a
	 * D-state grandchild can't stall us forever.  A stopped or
	 * continued grandchild is still alive, so ask for neither report;
	 * a ptrace-stop is reported whatever the flags, so skip that too.
	 */
	for (unsigned int i = 0; pid == 0 && i < polls; i++) {
		int childstatus;

		pid = waitpid_eintr(extrapid, &childstatus, WNOHANG);
		if (pid > 0 && WIFSTOPPED(childstatus))
			pid = 0;
		usleep(1000);
	}

	/* Only a timeout may signal the grandchild: it was still our
	 * unreaped child at the last poll.  After ECHILD (SIGCHLD ignored
	 * or SA_NOCLDWAIT: the kernel reaped it at exit) its pid may belong
	 * to someone else by now.
	 *
	 * Force-kill, then try a bounded WNOHANG reap. A D-state grandchild
	 * survives SIGKILL, and a blocking waitpid here would pin the worker
	 * past the ~1s budget claimed above. If the grandchild still hasn't
	 * exited after a few short polls, log and continue -- leave it as a
	 * zombie for the eventual SIGCHLD path rather than wedging the worker.
	 */
	if (pid == 0) {
		pid_t rp = 0;

		kill(extrapid, SIGKILL);
		for (int i = 0; i < 5; i++) {
			rp = waitpid_eintr(extrapid, NULL, WNOHANG);
			if (rp != 0)
				break;
			usleep(1000);
		}
		if (rp == 0)
			output(1, "extrafork: grandchild %d unreapable after SIGKILL, leaving zombie\n",
			       extrapid);
	}
}
