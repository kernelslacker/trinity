/*
 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */
#include <linux/ioctl.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include "arch.h"
#include "fd.h"
#include "ioctls.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/*
 * One call in this many draws the group before the fd.  find_ioctl_group()
 * starts from the fd, so a group whose fds are a small share of the pool
 * gets a small share of the calls; this is the way round that.  It runs
 * after the random-group draw, which keeps its one in a hundred, and
 * only the groups that name a typed-fd class can take it.  A sixteenth
 * moves about 6% of the calls off the fd pick: enough for
 * ioctl_group_first to show whether it pays off, few enough that the
 * rest keep the distribution they have.
 */
#define IOCTL_GROUP_FIRST_ODDS	16

/*
 * Draw a group that names an fd class and put an fd of that class in a1.
 * NULL leaves the call to the fd pick.  get_typed_fd() hands back any fd
 * when its pool is empty, so the group has to claim the one it returns;
 * a protected fd is refused as gen_arg_fd() refuses it.
 */
static const struct ioctl_group *pick_group_first(struct syscallrecord *rec)
{
	const struct ioctl_group *grp = get_random_fd_class_ioctl_group();
	struct stat st;
	int fd;

	if (grp == NULL)
		return NULL;

	fd = get_typed_fd(grp->fd_class);
	if (fd < 0 || fd_is_protected(fd) || fstat(fd, &st) < 0 ||
	    grp->fd_test(fd, &st) != 0)
		return NULL;

	rec->a1 = (unsigned long) fd;
	return grp;
}

static void sanitise_ioctl(struct syscallrecord *rec)
{
	const struct ioctl_group *grp;
	bool fd_claimed = false;

	if (ONE_IN(100)) {
		grp = get_random_ioctl_group();
		__atomic_add_fetch(&shm->stats.ioctl_group_random, 1,
				   __ATOMIC_RELAXED);
	} else if (ONE_IN(IOCTL_GROUP_FIRST_ODDS) &&
		   (grp = pick_group_first(rec)) != NULL) {
		fd_claimed = true;
		__atomic_add_fetch(&shm->stats.ioctl_group_first, 1,
				   __ATOMIC_RELAXED);
	} else {
		grp = find_ioctl_group(rec->a1);
		if (grp) {
			fd_claimed = true;
			__atomic_add_fetch(&shm->stats.ioctl_group_match, 1,
					   __ATOMIC_RELAXED);
		} else
			__atomic_add_fetch(&shm->stats.ioctl_group_miss, 1,
					   __ATOMIC_RELAXED);
	}

	if (grp)
		grp->sanitise(grp, rec);
	else {
		/* if we don't know about this ioctl, the argument could mean anything,
		 * because ioctl sucks like that. Make some shit up.
		 */
		switch (rnd_modulo_u32(3)) {
		case 0:	rec->a3 = rand32();
			break;
		case 1:	rec->a3 = (unsigned long) get_non_null_address();
			break;
		case 2:	grp = get_random_ioctl_group();
			if (grp)
				grp->sanitise(grp, rec);
			break;
		}
	}

	/*
	 * pick_random_ioctl() scrubs rec->a3 against shared_regions[], but
	 * most custom sanitisers run pick_random_ioctl() and then overwrite
	 * a3 with a get_writable_struct()/get_writable_address() pointer.
	 * Those allocators legitimately return addresses inside the global
	 * shared tracker (childdata, stats, kcov buffers, the obj/str
	 * heaps), so a read/write-direction ioctl would copy_to_user back
	 * onto our own bookkeeping.  Re-run the scrub here so the post-
	 * sanitise a3 cannot land in shared_regions[] regardless of which
	 * group ran.
	 */
	avoid_shared_buffer_out(&rec->a3, page_size);

	/*
	 * A group publishes RET_FD for the cmds that return the fd they
	 * create, which holds for an fd the group claims.  Drawn without
	 * regard to the fd, its cmd lands on whichever driver owns the fd,
	 * and that driver decides what the call returns.
	 */
	if (!fd_claimed)
		rec->rettype = RET_NONE;
}

#ifndef NSFS_MAGIC
#define NSFS_MAGIC	0x6e736673
#endif

/*
 * A pidfs namespace getter returns the nsfd it made, and nothing else owns
 * it: pool it, so the pool's cap closes it in time.  Left alone, every
 * getter that succeeds would leak one in the child.  The vfio, vduse and
 * i915 cmds that publish RET_FD cannot succeed as generated, and stay
 * unowned.
 *
 * rec->rettype is what the sanitiser drew, and the cmd slot is rewritten
 * after it (a RedQueen pin, a chain substitution), so the return value may
 * be a plain integer, 0 for most ioctls.  Nothing is pooled or closed unless
 * the number is verified as the fd a getter made: the cmd is a getter and
 * the number is a file on nsfs.  A stdio or protected number is no new fd
 * either, since the kernel only hands out a free one.  What
 * pool_returned_fd() refuses after that is the getter's and has no owner:
 * it is closed.
 */
static void post_ioctl(struct syscallrecord *rec)
{
	struct statfs sfs;
	int fd = rec->retval;

	if (rec->rettype != RET_FD || !pidfd_ns_getter(rec->a2) ||
	    (long) rec->retval < 0 || (long) rec->retval >= (1 << 20))
		return;

	if (fd <= 2 || fd_is_protected(fd) ||
	    fstatfs(fd, &sfs) != 0 || sfs.f_type != NSFS_MAGIC)
		return;

	if (!pool_returned_fd(fd))
		close(fd);
}

struct syscallentry syscall_ioctl = {
	.name = "ioctl",
	.num_args = 3,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "arg" },
	.sanitise = sanitise_ioctl,
	.post = post_ioctl,
	.flags = NEED_ALARM | IGNORE_ENOSYS | REEXEC_SANITISE_OK,
	.group = GROUP_VFS_IO,
};
