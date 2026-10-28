/*
 * Self-check for the nsfs ioctl group: the files it claims, that the args it
 * builds are held to a model of ns_ioctl() (fs/nsfs.c), written from the
 * kernel, that the cmds that return an fd say so, and that the group is kept
 * out of the EFAULT probe.  No ioctl is issued against a namespace file, so
 * what the kernel under the test would answer does not matter.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "efault_cache.h"	/* ioctl_efault_classify */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/nsfs.h"
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

/* Calls per cmd: a draw one time in 32 is seen 125 times or so. */
#define ROUNDS		4000

static const struct ioctl_group *group(void)
{
	const struct ioctl_group *grp = fake_ioctl_group("nsfs");

	if (grp == NULL)
		BUG("nsfs: the group is not linked");
	return grp;
}

/* A fraction of whole that part is, held to [lo, hi]. */
static void expect_fraction(unsigned int part, unsigned int whole, double lo,
			    double hi, const char *what, const char *bug)
{
	if (whole < 500 || part < whole * lo || part > whole * hi) {
		fprintf(stderr, "%s: %u of %u, want a fraction in [%.2f, %.2f]\n",
			what, part, whole, lo, hi);
		BUG(bug);
	}
}

/* ---------- Which files the group claims -------------------------------- */

/*
 * A file on nsfs, and nothing else.  The namespace files have no size and are
 * regular files, as is a file of procfs or a memfd, so what the claim has to
 * tell apart is the filesystem, not the shape of the inode.
 */
static void claims_only_namespace_files(void)
{
	static const char *const ns_files[] = {
		"cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
		"time", "time_for_children", "user", "uts",
	};
	static const char *const others[] = {
		"/proc/self/maps", "/proc/self/exe", "/dev/null", "/",
	};
	const struct ioctl_group *grp = group();
	unsigned int i, claimed = 0;
	int fd, pipefd[2];
	struct stat st;

	for (i = 0; i < ARRAY_SIZE(ns_files); i++) {
		char path[64];

		snprintf(path, sizeof(path), "/proc/self/ns/%s", ns_files[i]);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) != 0)
			BUG("nsfs: cannot stat a file it just opened");
		if (grp->fd_test(fd, &st) != 0 || !fd_is_nsfs(fd)) {
			fprintf(stderr, "%s\n", path);
			BUG("nsfs: a namespace file is not claimed");
		}
		close(fd);
		claimed++;
	}
	if (claimed == 0)
		printf("(no namespace files, skipping the claim) ");

	for (i = 0; i < ARRAY_SIZE(others); i++) {
		fd = open(others[i], O_RDONLY);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) != 0)
			BUG("nsfs: cannot stat a file it just opened");
		if (grp->fd_test(fd, &st) == 0 || fd_is_nsfs(fd)) {
			fprintf(stderr, "%s\n", others[i]);
			BUG("nsfs: claimed a file that is not on nsfs");
		}
		close(fd);
	}

	/* A regular file with no size on tmpfs, which a stat does not tell
	 * from a namespace file. */
	fd = memfd_create("nsfs-claim", 0);
	if (fd >= 0) {
		if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 0)
			BUG("nsfs: a memfd is not a regular file with no size");
		if (grp->fd_test(fd, &st) == 0 || fd_is_nsfs(fd))
			BUG("nsfs: claimed a memfd");
		close(fd);
	}

	if (pipe(pipefd) != 0)
		BUG("nsfs: no pipe");
	if (fstat(pipefd[0], &st) != 0 || grp->fd_test(pipefd[0], &st) == 0)
		BUG("nsfs: claimed a pipe");
	close(pipefd[0]);
	close(pipefd[1]);
}

/* ---------- The args ---------------------------------------------------- */

/* Pids the model's pid namespace has: this process, and init. */
static bool model_has_pid(unsigned long arg)
{
	int pid = (int) arg;

	return pid == getpid() || pid == 1;
}

/*
 * nsfs_ioctl_valid() (fs/nsfs.c): a cmd it knows exactly, or one of the
 * extensible mount namespace requests with the direction, type and number
 * of the kernel's and an encoded struct of 16 bytes or more
 * (extensible_ioctl_valid()).  The model lists every request ns_ioctl()
 * answers, not the ones the group draws.
 */
static bool nsfs_ioctl_valid(unsigned int cmd)
{
	static const unsigned int mnt[] = {
		NS_MNT_GET_INFO, NS_MNT_GET_NEXT, NS_MNT_GET_PREV,
	};
	unsigned int i;

	switch (cmd) {
	case NS_GET_USERNS:
	case NS_GET_PARENT:
	case NS_GET_NSTYPE:
	case NS_GET_OWNER_UID:
	case NS_GET_MNTNS_ID:
	case NS_GET_PID_FROM_PIDNS:
	case NS_GET_TGID_FROM_PIDNS:
	case NS_GET_PID_IN_PIDNS:
	case NS_GET_TGID_IN_PIDNS:
	case NS_GET_ID:
		return true;
	}

	for (i = 0; i < ARRAY_SIZE(mnt); i++)
		if (_IOC_DIR(cmd) == _IOC_DIR(mnt[i]) &&
		    _IOC_TYPE(cmd) == _IOC_TYPE(mnt[i]) &&
		    _IOC_NR(cmd) == _IOC_NR(mnt[i]) &&
		    _IOC_SIZE(cmd) >= MNT_NS_INFO_SIZE_VER0)
			return true;
	return false;
}

/*
 * What ns_ioctl() returns an fd for: open_related_ns() for NS_GET_USERNS and
 * NS_GET_PARENT, and the fd FD_PREPARE() makes for the next and the previous
 * mount namespace.  The rest return a type, a pid, a uid's 0 or 0.
 */
static bool model_returns_fd(unsigned int cmd)
{
	if (!nsfs_ioctl_valid(cmd))
		return false;
	return cmd == NS_GET_USERNS || cmd == NS_GET_PARENT ||
	       _IOC_NR(cmd) == _IOC_NR(NS_MNT_GET_NEXT) ||
	       _IOC_NR(cmd) == _IOC_NR(NS_MNT_GET_PREV);
}

struct tally {
	unsigned int calls;
	unsigned int valid;		/* the kernel knows the cmd as drawn */
	unsigned int null;		/* the arg is NULL */
	unsigned int in_pool;		/* a pointer the kernel may write through */
	unsigned int translates;	/* a pid the model's namespace has */
	unsigned int own_pid;
	unsigned int exact, small, large;	/* the encoded struct size */
};

/* The bytes the kernel writes through a request's arg, 0 when the arg is no pointer. */
static size_t arg_len(unsigned int cmd)
{
	switch (cmd) {
	case NS_GET_OWNER_UID:	return sizeof(unsigned int);
	case NS_GET_MNTNS_ID:
	case NS_GET_ID:		return sizeof(unsigned long long);
	}
	switch (_IOC_NR(cmd)) {
	case _IOC_NR(NS_MNT_GET_INFO):
	case _IOC_NR(NS_MNT_GET_NEXT):
	case _IOC_NR(NS_MNT_GET_PREV):
		return MNT_NS_INFO_SIZE_VER0;
	}
	return 0;
}

static void tally_call(struct tally *t, unsigned long request,
		       const struct syscallrecord *rec)
{
	unsigned int cmd = (unsigned int) rec->a2;
	size_t len = arg_len(cmd);

	t->calls++;
	t->valid += nsfs_ioctl_valid(cmd);

	/*
	 * The cmd the picker drew says what the call returns, whatever struct
	 * size is drawn for it afterwards; and the predicate the post handler
	 * asks of the cmd as the kernel reads it is the kernel's.
	 */
	if ((rec->rettype == RET_FD) != model_returns_fd((unsigned int) request)) {
		fprintf(stderr, "request %#lx, rettype %d\n", request,
			rec->rettype);
		BUG("nsfs: the type a cmd publishes is not whether it returns an fd");
	}
	if (nsfs_getter(rec->a2) != model_returns_fd(cmd)) {
		fprintf(stderr, "cmd %#x\n", cmd);
		BUG("nsfs: nsfs_getter() and the kernel disagree about a cmd");
	}

	if (len != 0) {
		if (rec->a3 == FAKE_IOCTL_JUNK_ARG)
			BUG("nsfs: a request that takes a pointer got none");
		if (rec->a3 == 0)
			t->null++;
		else if (range_in_writable_pool(rec->a3, len))
			t->in_pool++;
		else
			BUG("nsfs: the arg is not in the writable pool");
	}

	switch (request) {
	case NS_GET_PID_FROM_PIDNS:
	case NS_GET_TGID_FROM_PIDNS:
	case NS_GET_PID_IN_PIDNS:
	case NS_GET_TGID_IN_PIDNS:
		t->translates += model_has_pid(rec->a3);
		t->own_pid += (int) rec->a3 == getpid();
		break;
	case NS_MNT_GET_INFO:
	case NS_MNT_GET_NEXT:
	case NS_MNT_GET_PREV:
		if (_IOC_SIZE(cmd) == MNT_NS_INFO_SIZE_VER0)
			t->exact++;
		else if (_IOC_SIZE(cmd) < MNT_NS_INFO_SIZE_VER0)
			t->small++;
		else
			t->large++;
		break;
	}
}

/*
 * A request that takes a pointer is handed one, in the writable pool, and
 * NULL one call in 32.  A pid translation is handed a pid number, never a
 * pointer: this process's four times in eight, 1 once, the rest a number the
 * model has no task for.  The mount namespace requests carry the kernel's
 * 16 byte struct 28 times in 32, a larger one three and a smaller one, which
 * the kernel does not know, one.  Over 4000 calls the fractions have
 * deviations under 0.008 and the bounds are many of them out.
 */
static void expect_request(const char *name, unsigned long request,
			   const struct tally *t)
{
	if (arg_len((unsigned int) request) != 0)
		expect_fraction(t->null, t->calls, 0.012, 0.06, name,
				"nsfs: an arg is not NULL one time in 32");

	switch (request) {
	case NS_GET_PID_FROM_PIDNS:
	case NS_GET_TGID_FROM_PIDNS:
	case NS_GET_PID_IN_PIDNS:
	case NS_GET_TGID_IN_PIDNS:
		expect_fraction(t->own_pid, t->calls, 0.44, 0.56, name,
				"nsfs: a pid translation is not asked for this process's pid half the time");
		expect_fraction(t->translates, t->calls, 0.56, 0.69, name,
				"nsfs: a pid translation is not asked for a pid the namespace has five times in eight");
		break;
	case NS_MNT_GET_INFO:
	case NS_MNT_GET_NEXT:
	case NS_MNT_GET_PREV:
		expect_fraction(t->exact, t->calls, 0.82, 0.92, name,
				"nsfs: a mount namespace request does not carry the kernel's struct size 28 times in 32");
		expect_fraction(t->large, t->calls, 0.04, 0.15, name,
				"nsfs: a mount namespace request does not carry a larger struct three times in 32");
		expect_fraction(t->small, t->calls, 0.012, 0.06, name,
				"nsfs: a mount namespace request does not carry a smaller struct than the kernel knows once in 32");
		expect_fraction(t->valid, t->calls, 0.94, 0.99, name,
				"nsfs: the kernel does not know a mount namespace request as drawn 31 times in 32");
		return;
	}

	if (t->valid != t->calls) {
		fprintf(stderr, "%s: %u of %u calls name a cmd the kernel knows\n",
			name, t->valid, t->calls);
		BUG("nsfs: a cmd the kernel does not know is drawn");
	}
}

static void builds_args_the_kernel_takes(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = group();
	size_t c;

	for (c = 0; c < grp->ioctls_cnt; c++) {
		unsigned long request = grp->ioctls[c].request;
		struct tally t;
		unsigned int i;

		memset(&t, 0, sizeof(t));
		for (i = 0; i < ROUNDS; i++) {
			memset(&rec, 0, sizeof(rec));
			fake_ioctl_request = request;
			grp->sanitise(grp, &rec);
			tally_call(&t, request, &rec);
		}
		expect_request(grp->ioctls[c].name, request, &t);
	}
}

/*
 * NS_GET_USERNS and NS_GET_PARENT are _IO() requests that ignore their arg, so
 * the bogus one the EFAULT probe sends (ioctls/efault_cache.c) does not stop
 * them: on a namespace file they succeed, and the nsfd they return to the
 * probe is one nothing closes.  The group is opted out, and the probe is
 * not run for it; one that is not opted out is probed, which the control
 * shows.  A pipe stands in for the fd, so that nothing is made: it answers
 * every nsfs request -ENOTTY, which the probe takes for a scalar arg.
 */
static void is_kept_out_of_the_efault_probe(void)
{
	static const unsigned long getters[] = { NS_GET_USERNS, NS_GET_PARENT };
	const struct ioctl_group *grp = group();
	const struct ioctl_group *control = fake_ioctl_group("pidfd");
	unsigned int i;
	int pipefd[2];

	if (control == NULL || control->no_efault_probe)
		BUG("nsfs: no group to show the probe runs");
	if (pipe(pipefd) != 0)
		BUG("nsfs: no pipe");

	for (i = 0; i < ARRAY_SIZE(getters); i++) {
		if (ioctl_efault_classify(control, pipefd[0], getters[i]) !=
		    IOCTL_ARG_SCALAR)
			BUG("nsfs: the control group is not probed");
		if (ioctl_efault_classify(grp, pipefd[0], getters[i]) !=
		    IOCTL_ARG_UNKNOWN)
			BUG("nsfs: a cmd that returns an fd is probed with a bogus arg");
	}
	close(pipefd[0]);
	close(pipefd[1]);
}

void nsfs_self_check(void);
void nsfs_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	claims_only_namespace_files();
	builds_args_the_kernel_takes();
	is_kept_out_of_the_efault_probe();
}
