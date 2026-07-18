#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "child-api.h"
#include "fd.h"
#include "fd-event.h"
#include "kcov.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

static void post_dup(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	struct stat st_old, st_new;

	if ((long) retval < 0 || (long) retval >= (1 << 20))
		return;

	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);

	/*
	 * Oracle: dup(oldfd) must produce a new fd pointing at the same inode.
	 * A dev/ino mismatch means the fd-table was corrupted by the kernel.
	 * post hooks run in child context where init_child has redirected
	 * stderr to /dev/null, so the previous output() here was lost.  The
	 * fd_oracle_anomalies counter is the survivor signal.
	 */
	if (fstat((int) rec->a1, &st_old) == 0 &&
	    fstat((int) retval, &st_new) == 0) {
		if (st_old.st_dev != st_new.st_dev ||
		    st_old.st_ino != st_new.st_ino) {
			__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

struct syscallentry syscall_dup = {
	.name = "dup",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fildes" },
	.rettype = RET_FD,
	.post = post_dup,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * dup2/dup3 silently close newfd if it was open, then dup oldfd to newfd.
 * Enqueue a CLOSE event for newfd if it was tracked.
 */

/*
 * Target-fd category buckets for dup2 / dup3 newfd.  ARG_FD only
 * picks from the trinity-tracked fd pool, which misses the kernel
 * code paths that key off newfd's relation to the current fd table
 * and rlimit: expand_files() on a sparse high slot, the
 * RLIMIT_NOFILE boundary EMFILE arm, the oldfd == newfd short-
 * circuit in __do_dup2(), and the out-of-range EBADF reject.
 * Shape rec->a2 across those classes before the stdio safety net
 * runs; rec->a1 (oldfd) is left to ARG_FD.
 */
static void sanitise_dup2(struct syscallrecord *rec)
{
	static __thread int rl_initialised;
	static __thread struct rlimit rl;
	unsigned int pick;
	unsigned int tries;
	unsigned int kcov_tries;

	if (!rl_initialised) {
		if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
			rl.rlim_cur = 1024;
			rl.rlim_max = 1024;
		}
		rl_initialised = 1;
	}

	/*
	 * gen_arg_fd() filters protected fds out of ARG_FD picks (kcov
	 * PC/cmp, STDERR_FILENO, the stderr capture memfd), but the rlimit
	 * / RAND_RANGE buckets below pick fresh integers that can land on
	 * any of those slots.  A successful dup2(oldfd, protected_fd)
	 * atomically replaces the slot: the kcov case silently disables
	 * coverage for the rest of the child's life (next ioctl(KCOV_*,
	 * ...) returns -ENOTTY); the stderr-capture case loses the
	 * buffered pre-crash glibc malloc_printerr text the fault handler
	 * was relying on to drain into the bug log.  Reroll on collision
	 * (match the bounded-retry pattern in gen_arg_fd), and on the
	 * unlikely case where every attempt collides, fall back to rec->a1:
	 * it was picked by ARG_FD so it is already filtered, and
	 * dup2(oldfd, oldfd) is the documented kernel no-op short-circuit
	 * the bucket already exercises with pick < 90.
	 */
	for (kcov_tries = 0; kcov_tries < 4; kcov_tries++) {
		pick = rnd_modulo_u32(100);
		if (pick < 35) {
			/* occupied: leave the ARG_FD pick. */
		} else if (pick < 50) {
			rec->a2 = (unsigned long) RAND_RANGE(256, 4095);
		} else if (pick < 60) {
			if (rl.rlim_cur > 0)
				rec->a2 = (unsigned long) (rl.rlim_cur - 1);
		} else if (pick < 65) {
			rec->a2 = (unsigned long) (rl.rlim_cur + 1);
		} else if (pick < 70) {
			if (rl.rlim_max > 0)
				rec->a2 = (unsigned long) (rl.rlim_max - 1);
		} else if (pick < 80) {
			rec->a2 = (unsigned long) RAND_RANGE(3, 5);
		} else if (pick < 90) {
			rec->a2 = rec->a1;
		} else if (pick < 95) {
			rec->a2 = 0x7fffffffUL;
		}
		/* pick >= 95: reserved gap; leave the ARG_FD pick untouched. */

		tries = 0;
		/* Don't let newfd clobber stdin/stdout/stderr. */
		while (rec->a2 <= 2 && tries++ < 32)
			rec->a2 = get_random_fd();
		if (rec->a2 <= 2)
			rec->a2 = (unsigned long) RAND_RANGE(256, 4095);

		if (!fd_is_protected((int) rec->a2))
			return;
	}
	rec->a2 = rec->a1;
}

static void post_dup2(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	unsigned long a1 = rec->a1;
	unsigned long a2 = rec->a2;
	struct childdata *child;
	struct stat st_old, st_new;

	if ((long) retval < 0 || (long) retval >= (1 << 20))
		return;

	/*
	 * dup2(oldfd, oldfd) is a documented kernel no-op success: it
	 * returns oldfd without closing anything.  sanitise_dup2() picks
	 * rec->a2 == rec->a1 about 10% of the time to exercise the
	 * oldfd == newfd short-circuit in __do_dup2(); emitting a CLOSE
	 * event for rec->a2 in that case makes the parent destroy a
	 * still-live tracked object and close its copy of the fd, which
	 * degrades fd provider coverage over long runs.  dup3(oldfd,
	 * oldfd, flags) returns EINVAL, so the negative-retval guard
	 * above already keeps that case out of the post path.
	 */
	if (a1 != a2) {
		/* Publish the implicit close of newfd to the parent and
		 * drop this child's local snapshots.  Without the
		 * live_fds ring eviction the next arg-generation pick
		 * could still surface newfd from the 16-slot live-fd
		 * cache and burn an fcntl() validating a slot whose old
		 * file description the kernel may have already replaced
		 * under dup2()'s atomic swap. */
		child = this_child();
		if (child != NULL)
			notify_child_fd_closed(child, (int) a2);
	}

	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);

	/*
	 * Oracle: dup2(oldfd, newfd) must produce two fds pointing at the same
	 * inode.  A dev/ino mismatch means the fd-table was corrupted by the
	 * kernel -- silent data-corruption, not a crash.  post hooks run in
	 * child context where init_child has redirected stderr to /dev/null,
	 * so the previous output() here was lost.  The fd_oracle_anomalies
	 * counter is the survivor signal.
	 */
	if (fstat((int) a1, &st_old) == 0 &&
	    fstat((int) retval, &st_new) == 0) {
		if (st_old.st_dev != st_new.st_dev ||
		    st_old.st_ino != st_new.st_ino) {
			__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

/*
 * SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_dup2 = {
	.name = "dup2",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD },
	.argname = { [0] = "oldfd", [1] = "newfd" },
	.rettype = RET_FD,
	.sanitise = sanitise_dup2,
	.post = post_dup2,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

static unsigned long dup3_flags[] = {
	O_CLOEXEC,
};

struct syscallentry syscall_dup3 = {
	.name = "dup3",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "oldfd", [1] = "newfd", [2] = "flags" },
	.arg_params[2].list = ARGLIST(dup3_flags),
	.rettype = RET_FD,
	.sanitise = sanitise_dup2,
	.post = post_dup2,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
