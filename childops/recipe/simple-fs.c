/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "syscall-gate.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe/internal.h"

#include "kernel/eventfd.h"
#include "kernel/fcntl.h"
#include "kernel/timerfd.h"
#include "kernel/memfd.h"
/*
 * Recipe 3: pipe lifecycle (no-fork variant).
 *
 * Trinity already exercises pipe() heavily, but the typical kernel
 * path is "create, then random fcntl/ioctl noise" because fork is too
 * disruptive to inject into the child loop.  This recipe drives the
 * whole pipe through a deliberate sequence: create, write, read
 * back, flip O_NONBLOCK on each end, close.
 */
bool recipe_pipe(bool *unsupported __unused__)
{
	/* Snapshot the recipe-runner childop under which we're executing
	 * so the direct-syscall reporter attributes this invocation's
	 * per-attempt raw kernel entries to the parent op's per-childop
	 * tally.  Bounds-check matches the surrounding valid_op gate in
	 * recipe_runner. */
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int pfd[2] = { -1, -1 };
	char buf[16];
	bool ok = false;
	int flags;

	if (pipe(pfd) < 0)
		goto out;

	if (write(pfd[1], "trinity-recipe", 14) != 14)
		goto out;

	if (read(pfd[0], buf, sizeof(buf)) <= 0)
		goto out;

	flags = fcntl(pfd[0], F_GETFL);
	if (flags >= 0)
		(void)fcntl(pfd[0], F_SETFL, flags | O_NONBLOCK);

	flags = fcntl(pfd[1], F_GETFL);
	if (flags >= 0)
		(void)fcntl(pfd[1], F_SETFL, flags | O_NONBLOCK);

	ok = true;
out:
	if (pfd[0] >= 0)
		close(pfd[0]);
	if (pfd[1] >= 0)
		close(pfd[1]);
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}

/*
 * Recipe 8: inotify watch lifecycle.
 *
 * Init an inotify fd, add a watch on /tmp (always exists, attribute
 * changes are common enough to trigger occasional events but the
 * recipe doesn't rely on one firing), perform a non-blocking read
 * (typically EAGAIN), remove the watch, close.  Exercises the
 * inotify_handle_event / fsnotify_destroy_marks teardown paths.
 */
bool recipe_inotify(bool *unsupported __unused__)
{
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	char buf[1024];
	ssize_t r __unused__;
	int fd = -1;
	int wd = -1;
	bool ok = false;

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		goto out;

	wd = inotify_add_watch(fd, "/tmp",
			       IN_CREATE | IN_DELETE | IN_ATTRIB);
	if (wd < 0)
		goto out;

	r = read(fd, buf, sizeof(buf));

	if (inotify_rm_watch(fd, wd) < 0)
		goto out;
	wd = -1;

	ok = true;
out:
	if (wd >= 0)
		(void)inotify_rm_watch(fd, wd);
	if (fd >= 0)
		close(fd);
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}

/*
 * Recipe 15: fanotify watch lifecycle.
 *
 * fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK) → fanotify_mark(ADD)
 * on /tmp → non-blocking read (typically EAGAIN) → fanotify_mark
 * (REMOVE) → close.  Requires CAP_SYS_ADMIN on most kernels — first
 * EPERM/ENOSYS latches the recipe off.
 */
bool recipe_fanotify(bool *unsupported)
{
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	char buf[1024];
	int fd = -1;
	bool marked = false;
	ssize_t r __unused__;
	bool ok = false;

	fd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_CLOEXEC,
			   O_RDONLY);
	if (fd < 0) {
		if (errno == EPERM || errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe.unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (fanotify_mark(fd, FAN_MARK_ADD,
			  FAN_MODIFY | FAN_ACCESS, AT_FDCWD, "/tmp") < 0)
		goto out;
	marked = true;

	r = read(fd, buf, sizeof(buf));

	if (fanotify_mark(fd, FAN_MARK_REMOVE,
			  FAN_MODIFY | FAN_ACCESS, AT_FDCWD, "/tmp") < 0)
		goto out;
	marked = false;

	ok = true;
out:
	if (marked)
		(void)fanotify_mark(fd, FAN_MARK_REMOVE,
				    FAN_MODIFY | FAN_ACCESS,
				    AT_FDCWD, "/tmp");
	if (fd >= 0)
		close(fd);
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}

/*
 * Recipe 17: file-lease lifecycle.
 *
 * Open a fresh per-pid file under /tmp → unlink immediately so the
 * fd is the sole reference → fcntl(F_SETLEASE, F_RDLCK) to install a
 * read lease → F_GETLEASE to read it back → upgrade to F_WRLCK →
 * release with F_UNLCK → close.
 *
 * Drives the file_lock alloc/free path and the lm_setup / lm_change
 * vfs_setlease callbacks.  F_WRLCK upgrade requires no other openers
 * of the inode, which is guaranteed because the file is anonymous
 * (already unlinked) and the fd lives only in this process.
 *
 * F_SETLEASE may fail with EACCES (caller lacks CAP_LEASE and isn't
 * the owner — shouldn't happen since we just created the file but
 * not impossible under exotic credential setups), ENOLCK (kernel lock
 * cache exhausted), or EAGAIN (lease conflict raced).  Any of those
 * latches the recipe off via *unsupported.
 */
bool recipe_vfs_leases(bool *unsupported)
{
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	char path[64];
	int fd = -1;
	int lease;
	bool ok = false;

	snprintf(path, sizeof(path), "%s/trinity-recipe-lease-%d-%u", trinity_tmpdir_abs(),
		 (int)mypid(), rnd_u32());

	fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;

	/* Unlink immediately — the file lives only via this fd, so
	 * concurrent recipe runs in sibling children can't race to open
	 * it and break the F_WRLCK upgrade preconditions. */
	(void)unlink(path);

	if (fcntl(fd, F_SETLEASE, F_RDLCK) < 0) {
		if (errno == EACCES || errno == ENOLCK || errno == EAGAIN) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe.unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	lease = fcntl(fd, F_GETLEASE);
	if (lease < 0)
		goto out;

	if (fcntl(fd, F_SETLEASE, F_WRLCK) < 0)
		goto out;

	if (fcntl(fd, F_SETLEASE, F_UNLCK) < 0)
		goto out;

	ok = true;
out:
	if (fd >= 0)
		close(fd);
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}
