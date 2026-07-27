/*
 * Periodic maintenance work carved out of child.c: the every-16-ops
 * periodic_work() tick and its parent-pid watchdog helper.  Split out
 * so make -j can compile the periodic-tick path concurrently with the
 * childop dispatch arm and the watchdog / stall detector helpers.
 *
 * periodic_work sheds its `static` linkage here so the child_process()
 * main loop (still in child.c) can reach it across the TU boundary;
 * declaration is in include/child-internal.h.  check_parent_pid stays
 * static -- periodic_work is its lone caller and both live here.
 */

#include <stdlib.h>
#include <unistd.h>

#include "child.h"
#include "child-internal.h"
#include "fd.h"
#include "maps.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "vma-pressure.h"

/*
 * Sanity check to make sure that the main process is still around
 * to wait for us.
 */
static void check_parent_pid(void)
{
	pid_t pid, ppid;

	ppid = getppid();
	if (ppid == mainpid)
		return;

	pid = mypid();

	/*
	 * Inside a PID namespace our parent may legitimately be pid 1
	 * (the namespace init) or we ourselves may be pid 1.  Either
	 * case is expected when CLONE_NEWPID is in play — just bail
	 * out of this child quietly rather than triggering a panic.
	 */
	if (pid == 1 || ppid == 1) {
		debugf("pidns detected (pid=%d ppid=%d), exiting child.\n", pid, ppid);
		_exit(EXIT_REPARENT_PROBLEM);
	}

	if (pid == ppid) {
		debugf("pid became ppid! exiting child.\n");
		_exit(EXIT_REPARENT_PROBLEM);
	}

	if (ppid < 2) {
		debugf("ppid == %d. pidns? exiting child.\n", ppid);
		_exit(EXIT_REPARENT_PROBLEM);
	}

	lock(&shm->buglock);

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_REPARENT_PROBLEM)
		goto out;

	output(0, "BUG!: CHILD (pid:%d) GOT REPARENTED! "
		"main pid:%d. ppid=%d\n",
		pid, mainpid, ppid);

	if (pid_alive(mainpid) == false)
		output(0, "main pid %d is dead.\n", mainpid);

	panic(EXIT_REPARENT_PROBLEM);

out:
	unlock(&shm->buglock);
	_exit(EXIT_REPARENT_PROBLEM);
}

/*
 * Here we call various functions that perform checks/changes that
 * we don't want to happen on every iteration of the child loop.
 *
 * The caller gates entry on (op_nr & 15) == 0, so reaching here is
 * already the "every 16 iterations" event — check_parent_pid and the
 * divergence sentinel run unconditionally.  The deeper 128-iteration
 * gate is folded into the op_nr argument so this function carries no
 * static state at all.
 */
void periodic_work(struct childdata *child, unsigned long op_nr)
{
	check_parent_pid();

	divergence_sentinel_tick(child);

	/* Sampled invariant asserting the init_child_setup_sandbox()
	 * capset()-to-empty drop held.  Self-gates on ONE_IN(N) so the
	 * four bare-syscall probes (bpf, mount, setsockopt, capget) pay
	 * their cost only on the sample tick.  See child-capdrop-oracle.c. */
	capdrop_oracle_tick();

	/* Global VMA-pressure watchdog: sample the child's live VMA count
	 * every VMA_PRESSURE_SAMPLE_PERIOD ops and latch a per-child
	 * flag the heavy-VMA childops poll at iteration top.  Cadence and
	 * cost are documented in mm/vma-pressure.c; cheap when latched
	 * LOW, bounded when latched HIGH (only the backoff regime pays). */
	vma_pressure_sample_maybe(op_nr);

	/* Every 128 iterations.  Skip the maps-dirty + fd-provider fuzzing
	 * passes under -c/-r/-g so a targeted-syscall run stays isolated to
	 * the syscall set the user asked for; the picker gate in
	 * child_process() handles the per-iteration alt-op leak, this
	 * handles the periodic-work leak that lives outside that picker.
	 * check_parent_pid + divergence_sentinel + vma_pressure stay
	 * unconditional -- those are watchdog / diagnostic work, not
	 * fuzzing. */
	if ((op_nr & 127) == 0 &&
	    !do_specific_syscall && !random_selection &&
	    desired_group == GROUP_NONE) {
		dirty_random_mapping();
		run_fd_provider_child_ops();
	}
}
