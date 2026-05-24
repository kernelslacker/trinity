#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "child.h"
#include "fd.h"
#include "fd-event.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"

/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

static void post_dup(struct syscallrecord *rec)
{
	struct stat st_old, st_new;

	if ((long) rec->retval < 0 || (long) rec->retval >= (1 << 20))
		return;

	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);

	/*
	 * Oracle: dup(oldfd) must produce a new fd pointing at the same inode.
	 * A dev/ino mismatch means the fd-table was corrupted by the kernel.
	 */
	if (fstat((int) rec->a1, &st_old) == 0 &&
	    fstat((int) rec->retval, &st_new) == 0) {
		if (st_old.st_dev != st_new.st_dev ||
		    st_old.st_ino != st_new.st_ino) {
			output(0, "fd oracle: dup(%lu->%lu) inode mismatch "
			       "dev=%lu:%lu ino=%lu:%lu\n",
			       rec->a1, rec->retval,
			       (unsigned long) st_old.st_dev,
			       (unsigned long) st_new.st_dev,
			       (unsigned long) st_old.st_ino,
			       (unsigned long) st_new.st_ino);
			__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
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
	unsigned int tries = 0;

	if (!rl_initialised) {
		if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
			rl.rlim_cur = 1024;
			rl.rlim_max = 1024;
		}
		rl_initialised = 1;
	}

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

	/* Don't let newfd clobber stdin/stdout/stderr. */
	while (rec->a2 <= 2 && tries++ < 32)
		rec->a2 = get_random_fd();
	if (rec->a2 <= 2)
		rec->a2 = (unsigned long) RAND_RANGE(256, 4095);
}

static void post_dup2(struct syscallrecord *rec)
{
	struct childdata *child;
	struct stat st_old, st_new;

	if ((long)rec->retval < 0 || (long)rec->retval >= (1 << 20))
		return;

	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL)
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
				 (int) rec->a2);

	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);

	/*
	 * Oracle: dup2(oldfd, newfd) must produce two fds pointing at the same
	 * inode.  A dev/ino mismatch means the fd-table was corrupted by the
	 * kernel — silent data-corruption, not a crash.
	 */
	if (fstat((int) rec->a1, &st_old) == 0 &&
	    fstat((int) rec->retval, &st_new) == 0) {
		if (st_old.st_dev != st_new.st_dev ||
		    st_old.st_ino != st_new.st_ino) {
			output(0, "fd oracle: dup2(%lu->%lu) inode mismatch "
			       "dev=%lu:%lu ino=%lu:%lu\n",
			       rec->a1, rec->retval,
			       (unsigned long) st_old.st_dev,
			       (unsigned long) st_new.st_dev,
			       (unsigned long) st_old.st_ino,
			       (unsigned long) st_new.st_ino);
			__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
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
