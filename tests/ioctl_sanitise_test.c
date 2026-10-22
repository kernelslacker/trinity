/*
 * Self-check for what sanitise_ioctl() hands the dispatcher.  A group's
 * sanitiser publishes RET_FD for the cmds whose return value is the new
 * fd, and for those alone: a cmd that writes the fd into its arg
 * returns 0.  sanitise_ioctl() withdraws the claim when the group was
 * drawn without regard to the fd, since the cmd then reaches a driver
 * that owns the return value.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "objects.h"		/* get_objhead */
#include "random.h"		/* rand64 */
#include "rnd.h"
#include "sanitise.h"		/* writable pool */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_ioctl */
#include "utils-macros.h"	/* ARRAY_SIZE */

#define ROUNDS		3
#define PICK_ROUNDS	4000

/*
 * The cmds whose return value is the new fd, by table name.  Each was
 * read in the kernel: open_namespace() for the pidfs getters,
 * vfio_group_ioctl_get_device_fd(), receive_fd() for the vduse iotlb
 * cmds and i915_perf_open_ioctl().  The cmds that hand the fd back
 * through their arg and return 0 stay out: DRM prime and syncobj
 * handle-to-fd, the DRM lease, the gpio line requests, the iommufd queue
 * allocs and VIDIOC_EXPBUF.  So does VFIO_DEVICE_GET_GFX_DMABUF, whose
 * request number VFIO_IOMMU_ENABLE shares.
 */
static const char *const returns_fd[] = {
	"PIDFD_GET_CGROUP_NAMESPACE",
	"PIDFD_GET_IPC_NAMESPACE",
	"PIDFD_GET_MNT_NAMESPACE",
	"PIDFD_GET_NET_NAMESPACE",
	"PIDFD_GET_PID_NAMESPACE",
	"PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE",
	"PIDFD_GET_TIME_NAMESPACE",
	"PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE",
	"PIDFD_GET_USER_NAMESPACE",
	"PIDFD_GET_UTS_NAMESPACE",
	"VFIO_GROUP_GET_DEVICE_FD",
	"VDUSE_IOTLB_GET_FD",
	"VDUSE_IOTLB_GET_FD2",
	"DRM_IOCTL_I915_PERF_OPEN",
};

/*
 * What the linked groups reach beyond the fake registry.  Only the
 * pidfd group's fd_test touches the object pools, and nothing here
 * calls it.  Its info sanitiser asks for set_rand_bitmask(), which
 * genl_ops_test.c fakes.
 */
struct objhead *get_objhead(enum obj_scope scope, enum objecttype type)
{
	(void)scope;
	(void)type;
	BUG("ioctl rettype: a group walked an object pool");
	return NULL;
}

void __for_each_obj_init(struct objhead *head, struct __for_each_obj_state *s)
{
	(void)head;
	(void)s;
	BUG("ioctl rettype: a group walked an object pool");
}

u64 rand64(void)
{
	return rnd_u64();
}

static bool names_fd(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(returns_fd); i++)
		if (strcmp(name, returns_fd[i]) == 0)
			return true;
	return false;
}

/* Every cmd of every linked group, picked in turn.  The sanitiser of a
 * cmd can branch at random, so each runs a few times. */
static void groups_publish_only_fd_cmds(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *const *groups;
	unsigned int ngroups, g, published = 0, wrong = 0;
	size_t i;
	int round;

	groups = fake_ioctl_groups(&ngroups);
	for (g = 0; g < ngroups; g++) {
		const struct ioctl_group *grp = groups[g];

		for (i = 0; i < grp->ioctls_cnt; i++) {
			const struct ioctl *ioc = &grp->ioctls[i];
			int want = names_fd(ioc->name) ? RET_FD : RET_NONE;

			for (round = 0; round < ROUNDS; round++) {
				/* generate_syscall_args() starts a call
				 * from the entry's own rettype. */
				memset(&rec, 0, sizeof(rec));
				fake_ioctl_request = ioc->request;

				grp->sanitise(grp, &rec);

				if (rec.rettype != want) {
					fprintf(stderr, "%s (%#x): published rettype %d, want %d\n",
						ioc->name, ioc->request,
						rec.rettype, want);
					wrong++;
					break;
				}
			}
			if (want == RET_FD)
				published++;
		}
	}
	if (wrong != 0)
		BUG("ioctl rettype: a group published the wrong return type");
	if (published == 0)
		BUG("ioctl rettype: no linked group has a cmd that returns an fd");
}

/*
 * The group lookup sanitise_ioctl() reaches.  The group find_ioctl_group()
 * claims for the fd and the one a random draw hands back both publish
 * RET_FD, and count the calls that ran them.
 */
static unsigned int claimed_runs;
static unsigned int random_runs;
static bool fd_claimed;

static void claimed_sanitise(const struct ioctl_group *grp,
			     struct syscallrecord *rec)
{
	(void)grp;
	claimed_runs++;
	rec->rettype = RET_FD;
}

static void random_sanitise(const struct ioctl_group *grp,
			    struct syscallrecord *rec)
{
	(void)grp;
	random_runs++;
	rec->rettype = RET_FD;
}

static const struct ioctl_group claimed_grp = {
	.name = "claimed",
	.sanitise = claimed_sanitise,
};

static const struct ioctl_group random_grp = {
	.name = "random",
	.sanitise = random_sanitise,
};

const struct ioctl_group *find_ioctl_group(int fd)
{
	(void)fd;
	return fd_claimed ? &claimed_grp : NULL;
}

const struct ioctl_group *get_random_ioctl_group(void)
{
	return &random_grp;
}

/* RET_FD survives only a group that claimed the fd. */
static void withdrawn_off_the_fd(void)
{
	static struct syscallrecord rec;
	unsigned int claimed = 0, foreign = 0, none = 0;
	int pass, i;

	for (pass = 0; pass < 2; pass++) {
		fd_claimed = pass != 0;

		for (i = 0; i < PICK_ROUNDS; i++) {
			unsigned int c = claimed_runs, r = random_runs;

			memset(&rec, 0, sizeof(rec));
			syscall_ioctl.sanitise(&rec);

			if (claimed_runs != c) {
				claimed++;
				if (rec.rettype != RET_FD)
					BUG("ioctl rettype: the group that claimed the fd lost its RET_FD");
			} else if (random_runs != r) {
				foreign++;
				if (rec.rettype != RET_NONE)
					BUG("ioctl rettype: a group drawn without the fd kept its RET_FD");
			} else {
				none++;
				if (rec.rettype != RET_NONE)
					BUG("ioctl rettype: a call with no group published a return type");
			}
		}
	}

	/* Each way a group is chosen has to have been taken. */
	if (claimed == 0 || foreign == 0 || none == 0)
		BUG("ioctl rettype: a group pick was never exercised");
}

void ioctl_sanitise_self_check(void);
void ioctl_sanitise_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	groups_publish_only_fd_cmds();
	withdrawn_off_the_fd();
}
