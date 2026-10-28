/*
 * SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */
#include <linux/ioctl.h>
#include <linux/major.h>
#include <sys/stat.h>
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

/*
 * The cmd a group that holds its cmd drew (struct ioctl_group's cmd_held),
 * for vet_final_ioctl().  Lives in rec->post_state, a slot the syscall ABI
 * does not expose.
 */
#define IOCTL_POST_STATE_MAGIC	0x494F43544C5F4344UL	/* "IOCTL_CD" */
struct ioctl_post_state {
	unsigned long magic;
	unsigned long cmd;
};

/*
 * A group that holds its cmd builds valid args only for the cmds it means
 * to see work, so a final cmd other than the one it drew, which a RedQueen
 * pin on the cmd slot or a chain substitution can supply, would reach the
 * driver with args built for another: the call is refused.  The kernel
 * reads the cmd as an unsigned int.  A call with no snapshot drew its cmd
 * from a group that holds none; one whose snapshot fails the shape,
 * ownership or magic check, in post_state_claim_owned()'s order, is
 * refused too.
 */
static int vet_final_ioctl(struct syscallrecord *rec,
			   const struct syscallentry *entry)
{
	struct ioctl_post_state *snap =
		(struct ioctl_post_state *) rec->post_state;

	if (rec->post_state == 0)
		return 0;
	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == IOCTL_POST_STATE_MAGIC &&
	    (unsigned int) rec->a2 == (unsigned int) snap->cmd)
		return 0;

	outputerr("arg-coupling: %s rejected: the cmd is not the one its group drew\n",
		  entry->name);
	return -1;
}

static void sanitise_ioctl(struct syscallrecord *rec)
{
	const struct ioctl_group *grp;
	bool fd_claimed = false;

	/*
	 * Clear post_state up front so the final-slot hook and the cleanup
	 * see no snapshot rather than a stale pointer carried over from an
	 * earlier syscall on this record.
	 */
	rec->post_state = 0;

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

	if (grp != NULL && grp->cmd_held) {
		struct ioctl_post_state *snap = zmalloc_tracked(sizeof(*snap));

		snap->magic = IOCTL_POST_STATE_MAGIC;
		snap->cmd = rec->a2;
		post_state_install(rec, snap);
	}
}

/*
 * A pidfs or nsfs namespace getter returns the nsfd it made, and nothing
 * else owns it: pool it, so the pool's cap closes it in time.  Left alone,
 * every getter that succeeds would leak one in the child.  The vfio, vduse
 * and i915 cmds that publish RET_FD cannot succeed as generated, and stay
 * unowned.
 *
 * rec->rettype is not consulted.  A rewrite of any slot after the sanitiser
 * (a RedQueen pin, a chain substitution) resets it to the entry's own,
 * RET_NONE, and a getter that succeeds after one, a chain step threading a
 * fresh pidfd into a1 for one, still returns an nsfd nothing else owns.
 * What keeps a plain integer return, 0 for most ioctls, from being taken for
 * that fd is the check on the number: nothing is pooled or closed unless it
 * is verified as the fd a getter made, the cmd being a getter of either
 * group and the number a file on nsfs.  A stdio or protected number is no
 * new fd either, since the kernel only hands out a free one.  What
 * pool_returned_fd() refuses after that is the getter's and has no owner: it
 * is closed.
 */
static void post_ioctl(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if ((!pidfd_ns_getter(rec->a2) && !nsfs_getter(rec->a2)) ||
	    (long) rec->retval < 0 || (long) rec->retval >= (1 << 20))
		return;

	if (fd <= 2 || fd_is_protected(fd) || !fd_is_nsfs(fd))
		return;

	if (!pool_returned_fd(fd))
		close(fd);
}

/* The snapshot is the final-slot hook's alone, so it goes on every path. */
static void cleanup_ioctl(struct syscallrecord *rec)
{
	struct ioctl_post_state *snap;

	snap = post_state_claim_owned(rec, IOCTL_POST_STATE_MAGIC, __func__);
	post_state_release(rec, snap);
}

struct syscallentry syscall_ioctl = {
	.name = "ioctl",
	.num_args = 3,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "arg" },
	.sanitise = sanitise_ioctl,
	.vet_final = vet_final_ioctl,
	.post = post_ioctl,
	.cleanup = cleanup_ioctl,
	.flags = NEED_ALARM | IGNORE_ENOSYS | REEXEC_SANITISE_OK,
	.group = GROUP_VFS_IO,
};
