/*
 * Per-child stdio + controlling-terminal isolation: redirect fd
 * 0/1/2 to /dev/null, drop the inherited parent-only fds
 * (--stats-log-file, self-cgroup, /proc/<pid>/stat), and setsid()
 * away from the controlling tty.  Split out of child-init.c so make
 * -j can compile the isolation contract concurrently with the freeze
 * / sandbox / runtime setup helpers.
 *
 * init_child_isolate_io sheds its static linkage so init_child
 * (in child-init-core.c) can call it across the TU boundary;
 * declaration added to include/child-internal.h.
 */

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "child-internal.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "rnd.h"
#include "self_cgroup.h"
#include "shm.h"
#include "signals.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "trinity.h"	// ARRAY_SIZE
#include "writer-watch.h"
#include "uid.h"
#include "utils.h"	// zmalloc

#include "kernel/sched.h"

/*
 * Isolate this child's stdio + controlling terminal before any
 * syscall fuzzing starts.  Three steps, all about keeping fuzzed
 * I/O off the operator's terminal: redirect fd 0/1/2 to /dev/null
 * so splice/sendfile/vmsplice/write can't spew to the tty, drop the
 * inherited --stats-log-file fd so a fuzzed fchmod/ftruncate/write
 * can't smash the operator's log, and setsid() to sever the
 * controlling terminal so a later open("/dev/tty") can't re-acquire
 * it.  Bundled here so the I/O-isolation contract is self-contained
 * -- subsequent init phases assume stderr is /dev/null and rely on
 * the no-controlling-tty invariant.
 */
void init_child_isolate_io(void)
{
	int devnull;

	/* Redirect stdin/stdout/stderr to /dev/null so no syscall
	 * (splice, sendfile, vmsplice, write to fd 0, etc.) can spew to
	 * the operator's terminal.  fd 0 must be redirected too: ptys
	 * are bidirectional and writing to the inherited stdin (which
	 * is the operator's pty) lands on their shell.  Open O_RDWR so
	 * fuzzed reads against fd 0 also succeed (with EOF) instead of
	 * EBADF'ing — keeps the syscall behaviour realistic. */
	/* If /dev/null can't be opened (absent, inaccessible, EMFILE,
	 * chroot without /dev bind-mounted) fd 0/1/2 would remain pointed
	 * at the operator tty / inherited log fd -- exactly the hazard
	 * this redirect exists to prevent -- so bail hard rather than
	 * proceed to fuzzing with poisoned stdio. */
	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0)
		_exit(EXIT_FAILURE);

	/* On dup2 failure the std fd would remain pointing at the
	 * operator tty or an inherited log fd -- exactly the hazard
	 * this redirect exists to prevent -- so bail hard rather than
	 * proceed to fuzzing with a poisoned fd 0/1/2. */
	while (dup2(devnull, STDIN_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	while (dup2(devnull, STDOUT_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	while (dup2(devnull, STDERR_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	if (devnull > STDERR_FILENO)
		close(devnull);

	/* Drop the inherited --stats-log-file fd before any syscall fuzzing
	 * starts: it's a parent-only writer, but children would otherwise
	 * reach it numerically via fchmod / ftruncate / write at random
	 * offset, smashing the operator's log mid-run. */
	stats_log_drop_in_child();
	stats_timeseries_drop_in_child();

	/* Same hazard, different fds: the parent's self-cgroup fds (the
	 * memory.events file fd, its inotify watch fd, and the workload
	 * cgroup O_DIRECTORY fd handed to clone3(CLONE_INTO_CGROUP)) were
	 * created IN_CLOEXEC, but CLOEXEC only fires on exec(), and our
	 * children fork-and-fuzz without exec.  A fuzzed fcntl on the
	 * inherited inotify fd can clear O_NONBLOCK on the shared OFD,
	 * wedging the parent's drain-read in self_cgroup_events_check()
	 * and stalling the main loop (no child reap -> zombie pileup).  A
	 * fuzzed dup2 onto the workload-cgroup dirfd redirects subsequent
	 * spawns into the wrong cgroup, breaking memory.max + oom.group
	 * containment.  Drop all three. */
	self_cgroup_drop_fds_in_child();

	/* And the parent's /proc/<pid>/stat fds for liveness polling.  They
	 * are opened post-fork as each child is spawned, so every later
	 * child inherits earlier slots' fds.  Only the parent reads them;
	 * leaving them open in the child lets a fuzzed close/dup2 corrupt
	 * the parent's get_pid_state view and blind stuck-detection. */
	pidstatfiles_drop_in_child();

	/* Detach from the controlling terminal so a fuzzed
	 * open("/dev/tty", O_WRONLY) followed by write() can't reach the
	 * operator's shell.  The dup2 above only covers fds 0/1/2; this
	 * closes the wider class of paths that re-acquire the tty (open of
	 * /dev/tty itself, ioctl(TIOCSCTTY), etc.).  setsid() makes us our
	 * own session leader without a controlling terminal — subsequent
	 * /dev/tty opens fail with ENXIO.  A failure here (typically EPERM
	 * because we are already a process-group leader) leaves the child
	 * attached to the parent's session, so a fuzzed /dev/tty write can
	 * still reach the operator's terminal — log it and continue; the
	 * dup2 of 0/1/2 above still covers the common path. */
	if (setsid() == (pid_t) -1)
		outputerr("setsid failed! (%s)\n", strerror(errno));
}
