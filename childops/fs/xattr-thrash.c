/*
 * xattr_thrash - rapid getxattr/setxattr/removexattr/listxattr churn
 * against a small set of shared inodes.
 *
 * Trinity's random_syscall path exercises the xattr syscalls only
 * sporadically, with random (often -ENOTSUP) name/path combinations,
 * so the kernel's xattr slab (xattr_alloc / kmem_cache for struct
 * simple_xattr and the per-fs xattr handler dispatch) rarely sees
 * sustained allocation pressure on the same inodes.  No existing
 * childop pressures it.  xattr_thrash closes that gap: it opens
 * private fds onto the trinity-testfile? pool that the rest of the
 * fuzzer uses and in a tight bounded loop issues a curated mix of
 * set / get / remove / list against a fixed set of user.* names.
 *
 * Different children running xattr_thrash concurrently each open
 * independent fds onto the same underlying inodes, so the kernel
 * sees cross-process modification of the same per-inode xattr list
 * — exercising the simple_xattr_set / simple_xattr_get fast paths,
 * the per-inode i_xattrs rwsem, the xattr handler dispatch
 * (vfs_setxattr -> __vfs_setxattr -> handler->set), and the
 * underlying-fs xattr storage allocator.  The set operations vary
 * the value length across the small-object slab buckets (8 to 32
 * bytes) so the allocator sees a non-uniform size mix instead of a
 * single bucket repeatedly.
 *
 * Per-fd state isn't tracked.  The kernel returns -ENODATA on
 * get/remove of a name that isn't currently set; that reject path
 * is part of the test surface.  -ERANGE from listxattr against an
 * undersized buffer is also expected and counted as a benign fail.
 *
 * Self-bounding: the loop exits at the first of (a) MAX_ITERATIONS
 * inner ops, or (b) BUDGET_NS wall-clock elapsed.  Both bounds sit
 * well inside the 1-second SIGALRM the parent arms before dispatch,
 * so a wedged xattr handler still trips the stall detector.  All
 * xattrs left behind by the final iteration persist on the testfile
 * inodes — that's by design, so the next xattr_thrash invocation
 * (this child or another) starts against an inode that already has
 * xattrs to traverse.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Number of trinity-testfile? files we open private fds onto.  Matches
 * the MAX_TESTFILES bound in fds/testfiles.c so every testfile shows up
 * in our pool and cross-process contention concentrates on the same
 * inodes the rest of the fuzzer touches. */
#define NR_XATTR_FDS	4

/* Hard cap on inner iterations.  Sized like flock_thrash: small enough
 * that even worst-case xattr storage pressure on the test fs completes
 * well under the 1-second alarm. */
#define MAX_ITERATIONS	64

/* Wall-clock ceiling per invocation.  Sits in the 200ms band the other
 * recent thrash childops use so dump_stats still ticks regularly. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Curated xattr name list.  user.* is portable across every Linux fs
 * that supports xattrs and requires no privilege, so the same name set
 * works in every container/namespace trinity might run in.  16 names is
 * enough to keep the per-inode xattr list non-trivial (forces real list
 * walks in simple_xattr_get) without exhausting the per-inode xattr
 * value-size budget some filesystems impose. */
static const char * const xattr_names[] = {
	"user.test0",  "user.test1",  "user.test2",  "user.test3",
	"user.test4",  "user.test5",  "user.test6",  "user.test7",
	"user.test8",  "user.test9",  "user.test10", "user.test11",
	"user.test12", "user.test13", "user.test14", "user.test15",
};
#define NR_XATTR_NAMES	ARRAY_SIZE(xattr_names)

struct xattr_slot {
	int fd;
	unsigned int idx;	/* 1-based testfile index, for path-based syscalls */
	char path[PATH_MAX + 32];
};

static int open_one(unsigned int idx)
{
	char path[PATH_MAX + 32];

	snprintf(path, sizeof(path), "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), idx);
	return open(path, O_RDWR | O_CREAT, 0666);
}

/*
 * Phase: open private fds onto the trinity-testfile? pool.  Each slot
 * gets both an O_RDWR fd (for the f*xattr variants) and the absolute
 * path (for the path-based *xattr variants).  Returns the number of
 * slots successfully opened -- caller bails when zero.
 */
static unsigned int xattr_thrash_iter_setup_fds(struct xattr_slot *slots)
{
	unsigned int opened = 0;
	unsigned int i;

	for (i = 0; i < NR_XATTR_FDS; i++) {
		int fd = open_one(1 + i);

		if (fd < 0)
			continue;
		slots[opened].fd = fd;
		slots[opened].idx = 1 + i;
		snprintf(slots[opened].path, sizeof(slots[opened].path),
			 "%s/trinity-testfile%u", trinity_tmpdir_abs(), 1 + i);
		opened++;
	}

	return opened;
}

/*
 * Phase: SET dispatch.  use_path=false routes to fsetxattr with a
 * randomised flags arg (XATTR_CREATE / XATTR_REPLACE / 0) fuzzed via
 * RAND_NEGATIVE_OR -- the fd-based caller is the primary setxattr
 * exerciser.  use_path=true routes to setxattr with flags=0 and adds
 * the vfs_path lookup leg.  Both pick a value length in the 8-32 byte
 * range so the kmalloc-16 / kmalloc-32 buckets see a non-uniform size
 * mix instead of pounding a single class.
 */
static void xattr_thrash_iter_op_set(struct xattr_slot *s, const char *name,
				     bool use_path)
{
	unsigned char value[32];
	size_t vlen = 8 + rnd_modulo_u32(25);
	unsigned int j;
	int rc;

	for (j = 0; j < vlen; j++)
		value[j] = (unsigned char)rnd_u32();

	if (use_path) {
		rc = setxattr(s->path, name, value, vlen, 0);
	} else {
		int flags = (rnd_modulo_u32(8) == 0) ? XATTR_CREATE
			  : (rnd_modulo_u32(8) == 0) ? XATTR_REPLACE
			  : 0;
		rc = fsetxattr(s->fd, name, value, vlen,
			       (int)RAND_NEGATIVE_OR(flags));
	}

	if (rc == 0)
		__atomic_add_fetch(&shm->stats.xattr_thrash.set,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.xattr_thrash.failed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: GET dispatch.  use_path=false routes to fgetxattr; use_path=true
 * routes to getxattr and adds the vfs_path lookup leg.  Both variants
 * read into a small 64-byte stack buffer; -ENODATA on a name that isn't
 * currently set is part of the test surface and counted as a benign fail.
 */
static void xattr_thrash_iter_op_get(struct xattr_slot *s, const char *name,
				     bool use_path)
{
	unsigned char buf[64];
	int rc;

	if (use_path)
		rc = (int) getxattr(s->path, name, buf, sizeof(buf));
	else
		rc = (int) fgetxattr(s->fd, name, buf, sizeof(buf));

	if (rc >= 0)
		__atomic_add_fetch(&shm->stats.xattr_thrash.get,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.xattr_thrash.failed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: REMOVE dispatch.  use_path=false routes to fremovexattr;
 * use_path=true routes to removexattr and adds the vfs_path lookup leg.
 * -ENODATA on a name that isn't currently set is part of the test
 * surface and counted as a benign fail.
 */
static void xattr_thrash_iter_op_remove(struct xattr_slot *s, const char *name,
					bool use_path)
{
	int rc;

	if (use_path)
		rc = removexattr(s->path, name);
	else
		rc = fremovexattr(s->fd, name);

	if (rc == 0)
		__atomic_add_fetch(&shm->stats.xattr_thrash.remove,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.xattr_thrash.failed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: LIST dispatch.  use_path=false routes to flistxattr;
 * use_path=true routes to listxattr.  The deliberately small 256-byte
 * list buffer sometimes trips -ERANGE once enough names accumulate,
 * which exercises the size-probe path listxattr callers use to size
 * their second call.  No name argument -- list ops walk the whole
 * per-inode xattr list.
 */
static void xattr_thrash_iter_op_list(struct xattr_slot *s, bool use_path)
{
	char buf[256];
	int rc;

	if (use_path)
		rc = (int) listxattr(s->path, buf, sizeof(buf));
	else
		rc = (int) flistxattr(s->fd, buf, sizeof(buf));

	if (rc >= 0)
		__atomic_add_fetch(&shm->stats.xattr_thrash.list,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.xattr_thrash.failed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: 12-way per-iteration dispatch.  Routes the rolled op to one of
 * the four op-family helpers, splitting fd-based vs path-based variants
 * via use_path.  Set/get dominate (8/12) because those are the ops that
 * actually populate and walk the per-inode xattr list -- remove/list
 * are useful but consume what set produced.
 */
static void xattr_thrash_iter_dispatch(struct xattr_slot *s, const char *name,
				       unsigned int op)
{
	switch (op) {
	case 0:
	case 1:
	case 2:
		xattr_thrash_iter_op_set(s, name, false);
		break;
	case 3:
		xattr_thrash_iter_op_set(s, name, true);
		break;
	case 4:
	case 5:
	case 6:
		xattr_thrash_iter_op_get(s, name, false);
		break;
	case 7:
		xattr_thrash_iter_op_get(s, name, true);
		break;
	case 8:
		xattr_thrash_iter_op_remove(s, name, false);
		break;
	case 9:
		xattr_thrash_iter_op_remove(s, name, true);
		break;
	case 10:
		xattr_thrash_iter_op_list(s, false);
		break;
	case 11:
		xattr_thrash_iter_op_list(s, true);
		break;
	}
}

/*
 * Phase: close every fd opened by setup_fds.  All xattrs left behind by
 * the iteration loop persist on the testfile inodes by design, so the
 * next xattr_thrash invocation starts against an inode that already has
 * xattrs to traverse.
 */
static void xattr_thrash_iter_teardown_fds(struct xattr_slot *slots,
					   unsigned int opened)
{
	unsigned int i;

	for (i = 0; i < opened; i++)
		close(slots[i].fd);
}

bool xattr_thrash(struct childdata *child)
{
	struct xattr_slot slots[NR_XATTR_FDS];
	struct timespec start;
	unsigned int opened;
	unsigned int iter;
	unsigned int iters = BUDGETED(CHILD_OP_XATTR_THRASH,
				      JITTER_RANGE(MAX_ITERATIONS));

	__atomic_add_fetch(&shm->stats.xattr_thrash.runs, 1, __ATOMIC_RELAXED);

	opened = xattr_thrash_iter_setup_fds(slots);
	if (opened == 0)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (iter = 0; iter < iters; iter++) {
		struct xattr_slot *s = &slots[rnd_modulo_u32(opened)];
		const char *name = xattr_names[rnd_modulo_u32(NR_XATTR_NAMES)];

		xattr_thrash_iter_dispatch(s, name, rnd_modulo_u32(12));

		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}

	xattr_thrash_iter_teardown_fds(slots, opened);

	return true;
}
