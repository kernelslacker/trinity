/*
 * Self-check for what sanitise_ioctl() hands the dispatcher: RET_FD only for
 * cmds whose return value is the new fd, withdrawn when the group was drawn
 * without regard to the fd; the group-first draw (one call in sixteen) that
 * swaps in an fd of the group's class; the zero arg of the pidfs namespace
 * getters; and typed-fd groups claiming the fds the child made itself.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arg_coupling.h"	/* validate_arg_coupling */
#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "fd.h"			/* get_typed_fd */
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/nsfs.h"
#include "objects.h"		/* get_objhead */
#include "random.h"		/* rand64 */
#include "rnd.h"
#include "sanitise.h"		/* writable pool */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_ioctl */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct object *(*fake_find_local_object_by_fd)(enum objecttype type,
						       int fd);	/* fake_objects.c */
extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

#define ROUNDS		3
#define PICK_ROUNDS	4000
#define FIRST_ROUNDS	8000

/*
 * The cmds whose return value is the new fd, by table name.  Each was
 * read in the kernel: open_namespace() for the pidfs getters,
 * open_related_ns() for the nsfs ones that open a related namespace,
 * FD_PREPARE() and fd_publish() for the two that step to the next and the
 * previous mount namespace, vfio_group_ioctl_get_device_fd(), receive_fd()
 * for the vduse iotlb cmds and i915_perf_open_ioctl().  The cmds that hand the fd back
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
	"NS_GET_USERNS",
	"NS_GET_PARENT",
	"NS_MNT_GET_NEXT",
	"NS_MNT_GET_PREV",
	"VFIO_GROUP_GET_DEVICE_FD",
	"VDUSE_IOTLB_GET_FD",
	"VDUSE_IOTLB_GET_FD2",
	"DRM_IOCTL_I915_PERF_OPEN",
};

/*
 * What the linked groups reach beyond the fake registry.  Only the fd_test
 * of the groups that name a typed-fd class touches the object pools, and
 * only the claim case calls them, with get_objhead() and
 * find_local_object_by_fd() hooked in fake_objects.c; their for_each_obj
 * walks run through objects/registry.c.  The pidfd group's info sanitiser
 * asks for set_rand_bitmask(), which genl_ops_test.c fakes, and the perf
 * group's for a bpf prog fd, which fake_fds.c fakes.
 */
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

/* A group that holds its cmd, which its sanitiser draws as held_cmd. */
#define HELD_CMD	0x40044a01UL
static bool fd_held;

static void held_sanitise(const struct ioctl_group *grp,
			  struct syscallrecord *rec)
{
	(void)grp;
	rec->a2 = HELD_CMD;
}

static const struct ioctl_group held_grp = {
	.name = "held",
	.sanitise = held_sanitise,
	.cmd_held = true,
};

static const struct ioctl_group random_grp = {
	.name = "random",
	.sanitise = random_sanitise,
};

const struct ioctl_group *find_ioctl_group(int fd)
{
	(void)fd;
	if (fd_held)
		return &held_grp;
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

/*
 * A group that holds its cmd refuses a final cmd other than the one its
 * sanitiser drew, read as the unsigned int the kernel takes: a rewrite to
 * another is refused, the drawn one with any upper bits passes.  A cmd
 * from a group that holds none is left alone.
 */
static void cmd_held_to_the_one_drawn(void)
{
	static struct syscallrecord rec;
	unsigned int held = 0, other = 0;
	int i;

	fd_held = true;
	for (i = 0; i < PICK_ROUNDS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_ioctl;
		syscall_ioctl.sanitise(&rec);
		if (rec.a2 == HELD_CMD) {
			held++;
			rec.a2 = HELD_CMD | (1UL << 32);
			if (validate_arg_coupling(&rec, &syscall_ioctl) != 0)
				BUG("ioctl: the cmd a held group drew was refused");
			rec.a2 = HELD_CMD + 1;
			if (validate_arg_coupling(&rec, &syscall_ioctl) != -1)
				BUG("ioctl: a held group's cmd was rewritten and kept");
		} else {
			other++;
			rec.a2 = HELD_CMD + 1;
			if (validate_arg_coupling(&rec, &syscall_ioctl) != 0)
				BUG("ioctl: a cmd from a group that holds none was refused");
		}
		syscall_ioctl.cleanup(&rec);
		if (rec.post_state != 0)
			BUG("ioctl: the cleanup left a held group's snapshot behind");
	}
	fd_held = false;
	if (held == 0 || other == 0)
		BUG("ioctl: a held group, or one that holds none, was never drawn");
}

/*
 * The group-first draw.  The class group claims the one fd in
 * class_claims, publishes RET_FD like the groups that return an fd, and
 * records the a1 its sanitiser ran with.  get_typed_fd() answers
 * typed_fd whatever the class, as it does when the pool is empty and it
 * falls back to an fd of any kind.
 */
static bool class_registered;
static int typed_fd = -1;
static int class_claims = -1;
static enum argtype class_asked;
static unsigned int class_runs;
static unsigned long class_a1;

static int class_fd_test(int fd, const struct stat *st)
{
	(void)st;
	return fd == class_claims ? 0 : -1;
}

static void class_sanitise(const struct ioctl_group *grp,
			   struct syscallrecord *rec)
{
	(void)grp;
	class_runs++;
	class_a1 = rec->a1;
	rec->rettype = RET_FD;
}

static const struct ioctl_group class_grp = {
	.name = "classed",
	.fd_test = class_fd_test,
	.fd_class = ARG_FD_PIDFD,
	.sanitise = class_sanitise,
};

const struct ioctl_group *get_random_fd_class_ioctl_group(void)
{
	return class_registered ? &class_grp : NULL;
}

int get_typed_fd(enum argtype type)
{
	class_asked = type;
	return typed_fd;
}

/* The a1 the generator left, and what a call that does not take the
 * group-first pick must still carry. */
#define GENERATED_FD	7

/*
 * Run FIRST_ROUNDS calls and return how many took the group-first pick,
 * leaving the random-group count in @random.  A call that took it has
 * the typed fd in a1 when the class group's sanitiser runs, and keeps
 * its RET_FD; any other call keeps the a1 it started with.
 */
static unsigned long run_first_picks(unsigned long *random)
{
	static struct syscallrecord rec;
	unsigned long first = 0;
	int i;

	*random = 0;
	for (i = 0; i < FIRST_ROUNDS; i++) {
		unsigned long first0 = shm->stats.ioctl_group_first;
		unsigned long random0 = shm->stats.ioctl_group_random;
		unsigned int runs = class_runs;

		memset(&rec, 0, sizeof(rec));
		rec.a1 = GENERATED_FD;
		syscall_ioctl.sanitise(&rec);

		*random += shm->stats.ioctl_group_random - random0;
		if (shm->stats.ioctl_group_first == first0) {
			if (rec.a1 != GENERATED_FD)
				BUG("ioctl group first: a call off the group-first pick lost its a1");
			continue;
		}

		first++;
		if (shm->stats.ioctl_group_first != first0 + 1)
			BUG("ioctl group first: one call counted twice");
		if (class_runs != runs + 1)
			BUG("ioctl group first: the drawn group did not run");
		if (class_a1 != (unsigned long) typed_fd ||
		    rec.a1 != (unsigned long) typed_fd)
			BUG("ioctl group first: the class fd did not reach a1 before the group ran");
		if (rec.rettype != RET_FD)
			BUG("ioctl group first: a group drawn with its fd lost its RET_FD");
	}
	return first;
}

/* Of FIRST_ROUNDS calls, one in a hundred draws a group at random and
 * one in sixteen of the rest draws first: about 6%.  The bounds sit many
 * standard deviations out. */
static void group_first_pick(void)
{
	unsigned long first, random;
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		BUG("ioctl group first: cannot open /dev/null");
	fd_claimed = false;
	class_registered = true;

	/* A claimed fd of the class: the pick runs at its rate, asks for the
	 * group's class, and the random draw keeps its own. */
	typed_fd = fd;
	class_claims = fd;
	class_asked = ARG_UNDEFINED;
	first = run_first_picks(&random);
	if (first < FIRST_ROUNDS * 4 / 100 || first > FIRST_ROUNDS * 8 / 100) {
		fprintf(stderr, "%lu of %d calls drew the group first\n",
			first, FIRST_ROUNDS);
		BUG("ioctl group first: the pick is not taken one call in sixteen");
	}
	if (class_asked != ARG_FD_PIDFD)
		BUG("ioctl group first: the fd was not asked for by the group's class");
	if (random < FIRST_ROUNDS * 4 / 1000 || random > FIRST_ROUNDS * 18 / 1000) {
		fprintf(stderr, "%lu of %d calls drew a group at random\n",
			random, FIRST_ROUNDS);
		BUG("ioctl group first: the random-group draw lost its one in a hundred");
	}

	/* No fd of the class: the lookup returns -1. */
	typed_fd = -1;
	if (run_first_picks(&random) != 0)
		BUG("ioctl group first: picked a group with no fd of its class");

	/* An fd the group does not claim, as when the class pool is empty
	 * and the lookup hands back any fd. */
	typed_fd = fd;
	class_claims = -1;
	if (run_first_picks(&random) != 0)
		BUG("ioctl group first: picked an fd its group does not claim");

	/* An fd the group claims that must not be fuzzed. */
	typed_fd = STDERR_FILENO;
	class_claims = STDERR_FILENO;
	if (run_first_picks(&random) != 0)
		BUG("ioctl group first: picked a protected fd");

	/* No group names a class. */
	typed_fd = fd;
	class_claims = fd;
	class_registered = false;
	if (run_first_picks(&random) != 0)
		BUG("ioctl group first: picked a group when none names a class");

	close(fd);
}

/*
 * The namespace getters.  fs/pidfs.c refuses a non-zero arg with EINVAL
 * once it has the task, so the arg the picker made, which is never zero,
 * can only reach that refusal.  Most calls pass zero and so can succeed;
 * the rest keep the picker's arg and exercise the refusal.  PIDFD_GET_INFO
 * takes a struct.
 */
#define ARG_ROUNDS	400

static void ns_getters_get_a_zero_arg(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = fake_ioctl_group("pidfd");
	size_t i;
	int round;

	if (grp == NULL)
		BUG("ioctl ns arg: the pidfd group is not linked");

	for (i = 0; i < grp->ioctls_cnt; i++) {
		const struct ioctl *ioc = &grp->ioctls[i];
		unsigned int zero = 0, junk = 0, other = 0;

		for (round = 0; round < ARG_ROUNDS; round++) {
			memset(&rec, 0, sizeof(rec));
			fake_ioctl_request = ioc->request;
			grp->sanitise(grp, &rec);

			if (rec.a3 == 0)
				zero++;
			else if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
				junk++;
			else
				other++;
		}

		if (strcmp(ioc->name, "PIDFD_GET_INFO") == 0) {
			if (zero != 0 || junk != 0)
				BUG("ioctl ns arg: PIDFD_GET_INFO lost its struct");
			continue;
		}

		if (other != 0) {
			fprintf(stderr, "%s: %u calls got an arg that is neither 0 nor the picked one\n",
				ioc->name, other);
			BUG("ioctl ns arg: a getter's arg was rewritten to something else");
		}
		/* Three in four pass zero: 300 of 400, 8.7 deviations wide. */
		if (zero < ARG_ROUNDS * 5 / 8 || zero > ARG_ROUNDS * 7 / 8 + 25) {
			fprintf(stderr, "%s: %u of %d calls passed a zero arg\n",
				ioc->name, zero, ARG_ROUNDS);
			BUG("ioctl ns arg: a getter does not pass zero three times in four");
		}
		if (junk == 0)
			BUG("ioctl ns arg: a getter never keeps the picked arg, so pidfs's refusal is unreachable");
	}
}

/*
 * What post_ioctl() asks before it owns a return value: the ten getters of
 * the pidfd group are the cmds whose return value is a namespace file, and
 * no other cmd of any linked group is.  The kernel reads the cmd as an
 * unsigned int, so the bits above it do not matter.
 */
static void only_the_ns_getters_are_getters(void)
{
	const struct ioctl_group *const *groups;
	unsigned int ngroups, g, getters = 0;
	size_t i;

	groups = fake_ioctl_groups(&ngroups);
	for (g = 0; g < ngroups; g++) {
		const struct ioctl_group *grp = groups[g];

		for (i = 0; i < grp->ioctls_cnt; i++) {
			const char *name = grp->ioctls[i].name;
			unsigned long req = grp->ioctls[i].request;
			bool want = grp->name != NULL &&
				    strcmp(grp->name, "pidfd") == 0 &&
				    strncmp(name, "PIDFD_GET_", 10) == 0 &&
				    strcmp(name, "PIDFD_GET_INFO") != 0;

			if (pidfd_ns_getter(req) != want) {
				fprintf(stderr, "%s: pidfd_ns_getter() says %d\n",
					name, !want);
				BUG("ioctl ns getter: the predicate and the pidfd group disagree");
			}
			if (want) {
				getters++;
				if (!pidfd_ns_getter(req | (1UL << 40)))
					BUG("ioctl ns getter: the predicate reads bits the kernel drops");
			}
		}
	}
	if (getters != 10)
		BUG("ioctl ns getter: the pidfd group does not have ten getters");
	if (pidfd_ns_getter(0))
		BUG("ioctl ns getter: cmd 0 is a getter");
}

/*
 * What post_ioctl() asks of the nsfs cmds, as of the pidfs ones: the four that
 * return a namespace file are the getters, whatever struct size the two mount
 * namespace ones carry from 16 bytes up, which the kernel takes
 * (nsfs_ioctl_valid()) and the bits above the cmd it does not read, and no
 * other cmd of any linked group is.  A smaller size, another direction or
 * another type is not the kernel's request.
 */
static void only_the_nsfs_cmds_that_return_an_fd_are_getters(void)
{
	const struct ioctl_group *const *groups;
	unsigned int ngroups, g, getters = 0;
	size_t i;

	groups = fake_ioctl_groups(&ngroups);
	for (g = 0; g < ngroups; g++) {
		const struct ioctl_group *grp = groups[g];

		for (i = 0; i < grp->ioctls_cnt; i++) {
			const char *name = grp->ioctls[i].name;
			unsigned long req = grp->ioctls[i].request;
			bool want = grp->name != NULL &&
				    strcmp(grp->name, "nsfs") == 0 &&
				    (strcmp(name, "NS_GET_USERNS") == 0 ||
				     strcmp(name, "NS_GET_PARENT") == 0 ||
				     strcmp(name, "NS_MNT_GET_NEXT") == 0 ||
				     strcmp(name, "NS_MNT_GET_PREV") == 0);

			if (nsfs_getter(req) != want) {
				fprintf(stderr, "%s: nsfs_getter() says %d\n",
					name, !want);
				BUG("nsfs getter: the predicate and the nsfs group disagree");
			}
			if (want) {
				getters++;
				if (!nsfs_getter(req | (1UL << 40)))
					BUG("nsfs getter: the predicate reads bits the kernel drops");
			}
		}
	}
	if (getters != 4)
		BUG("nsfs getter: the nsfs group does not have four getters");

	if (nsfs_getter(0))
		BUG("nsfs getter: cmd 0 is a getter");
	if (!nsfs_getter(_IOC(_IOC_READ, NSIO, _IOC_NR(NS_MNT_GET_NEXT), 4096)) ||
	    !nsfs_getter(_IOC(_IOC_READ, NSIO, _IOC_NR(NS_MNT_GET_PREV), 16)))
		BUG("nsfs getter: a mount namespace step with a larger struct is not a getter");
	if (nsfs_getter(_IOC(_IOC_READ, NSIO, _IOC_NR(NS_MNT_GET_NEXT), 15)) ||
	    nsfs_getter(_IOC(_IOC_WRITE, NSIO, _IOC_NR(NS_MNT_GET_NEXT), 16)) ||
	    nsfs_getter(_IOC(_IOC_READ, NSIO + 1, _IOC_NR(NS_MNT_GET_NEXT), 16)))
		BUG("nsfs getter: a cmd the kernel does not know is a getter");
	if (nsfs_getter(NS_MNT_GET_INFO) || nsfs_getter(NS_GET_NSTYPE))
		BUG("nsfs getter: a cmd that returns no fd is a getter");
	if (pidfd_ns_getter(NS_GET_USERNS) ||
	    nsfs_getter(fake_ioctl_group("pidfd")->ioctls[0].request))
		BUG("nsfs getter: the two predicates overlap");
}

/*
 * A group that names a typed-fd class claims the fds of it the child made
 * itself, which sit in its own pool and which get_typed_fd() never reads,
 * as well as the ones the parent opened.  The pidfd group needs them: the
 * namespace getters only succeed on a task the child may ptrace-read, and
 * the parent's pidfd names pid 1.  The ioctls of the socket, epoll and
 * perf groups apply to any fd of their class.
 *
 * Each class in turn puts one fd in a pool, the parent's or the child's.
 * The group of that class claims it, the others do not, and none claims
 * the number next to it.
 */
#define POOLED_FD	7

static const struct {
	enum argtype fd_class;
	enum objecttype type;
} fd_classes[] = {
	{ ARG_FD_PIDFD,  OBJ_FD_PIDFD },
	{ ARG_FD_SOCKET, OBJ_FD_SOCKET },
	{ ARG_FD_EPOLL,  OBJ_FD_EPOLL },
	{ ARG_FD_PERF,   OBJ_FD_PERF },
};

static enum objecttype pooled_type;
static bool pooled_in_child;
static struct object pooled_obj;
static struct object *pooled_array[] = { &pooled_obj };
static struct objhead parent_pool = { .array = pooled_array, .num_entries = 1 };
static struct objhead no_pool;

static struct objhead *the_pools(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_GLOBAL && !pooled_in_child && type == pooled_type)
		return &parent_pool;
	return &no_pool;
}

static struct object *the_childs_pool(enum objecttype type, int fd)
{
	if (pooled_in_child && type == pooled_type && fd == POOLED_FD)
		return &pooled_obj;
	return NULL;
}

static void fd_class_groups_claim_the_childs_own_fds(void)
{
	const struct ioctl_group *const *groups;
	unsigned int ngroups, g, c, classed = 0;
	struct stat st;
	int pass;

	memset(&st, 0, sizeof(st));
	groups = fake_ioctl_groups(&ngroups);
	for (g = 0; g < ngroups; g++)
		if (groups[g]->fd_class != ARG_UNDEFINED &&
		    groups[g]->fd_test != NULL)
			classed++;
	if (classed != ARRAY_SIZE(fd_classes))
		BUG("ioctl fd claim: the linked groups that name a class are not the ones covered here");

	fake_get_objhead = the_pools;
	fake_find_local_object_by_fd = the_childs_pool;

	for (c = 0; c < ARRAY_SIZE(fd_classes); c++) {
		pooled_type = fd_classes[c].type;
		memset(&pooled_obj, 0, sizeof(pooled_obj));
		switch (pooled_type) {
		case OBJ_FD_PIDFD:	pooled_obj.pidfdobj.fd = POOLED_FD; break;
		case OBJ_FD_SOCKET:	pooled_obj.sockinfo.fd = POOLED_FD; break;
		case OBJ_FD_EPOLL:	pooled_obj.epollobj.fd = POOLED_FD; break;
		case OBJ_FD_PERF:	pooled_obj.perfobj.fd = POOLED_FD; break;
		default:		BUG("ioctl fd claim: a class the test cannot pool");
		}

		for (pass = 0; pass < 2; pass++) {
			pooled_in_child = pass != 0;

			for (g = 0; g < ngroups; g++) {
				const struct ioctl_group *grp = groups[g];
				bool want = grp->fd_class == fd_classes[c].fd_class;
				bool got;

				if (grp->fd_class == ARG_UNDEFINED ||
				    grp->fd_test == NULL)
					continue;

				got = grp->fd_test(POOLED_FD, &st) == 0;
				if (got != want) {
					fprintf(stderr, "group %s (class %d), fd of class %d in the %s pool: claimed %d, want %d\n",
						grp->name ? grp->name : "(unnamed)",
						grp->fd_class,
						fd_classes[c].fd_class,
						pooled_in_child ? "child's" : "parent's",
						got, want);
					BUG("ioctl fd claim: a group's claim on a pooled fd is wrong");
				}
				if (grp->fd_test(POOLED_FD + 1, &st) == 0)
					BUG("ioctl fd claim: an fd in no pool was claimed");
			}
		}
	}

	fake_find_local_object_by_fd = NULL;
	fake_get_objhead = NULL;
}

void ioctl_sanitise_self_check(void);
void ioctl_sanitise_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	groups_publish_only_fd_cmds();
	withdrawn_off_the_fd();
	group_first_pick();
	ns_getters_get_a_zero_arg();
	only_the_ns_getters_are_getters();
	only_the_nsfs_cmds_that_return_an_fd_are_getters();
	fd_class_groups_claim_the_childs_own_fds();
	cmd_held_to_the_one_drawn();
}
