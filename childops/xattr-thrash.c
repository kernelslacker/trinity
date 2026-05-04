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
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
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
};

static int open_one(unsigned int idx)
{
	char path[PATH_MAX + 32];

	snprintf(path, sizeof(path), "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), idx);
	return open(path, O_RDWR | O_CREAT, 0666);
}

static void slot_path(const struct xattr_slot *s, char *out, size_t outlen)
{
	snprintf(out, outlen, "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), s->idx);
}

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= BUDGET_NS;
}

bool xattr_thrash(struct childdata *child)
{
	struct xattr_slot slots[NR_XATTR_FDS];
	struct timespec start;
	unsigned int opened = 0;
	unsigned int iter;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.xattr_thrash_runs, 1, __ATOMIC_RELAXED);

	for (i = 0; i < NR_XATTR_FDS; i++) {
		int fd = open_one(1 + i);

		if (fd < 0)
			continue;
		slots[opened].fd = fd;
		slots[opened].idx = 1 + i;
		opened++;
	}

	if (opened == 0)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < MAX_ITERATIONS; iter++) {
		struct xattr_slot *s = &slots[(unsigned int)rand() % opened];
		const char *name = xattr_names[(unsigned int)rand() % NR_XATTR_NAMES];
		char path[PATH_MAX + 32];
		int rc;
		/* 12 distinct dispatches so the path-based and fd-based
		 * variants of every op all land regularly.  Set/get
		 * dominate (8/12) because those are the operations that
		 * actually populate and walk the per-inode xattr list —
		 * remove/list are useful but consume what set produced.*/
		unsigned int op = (unsigned int)rand() % 12;

		switch (op) {
		case 0:
		case 1:
		case 2: {
			/* fsetxattr with a randomised value length in the
			 * 8-32 byte range.  Spreading across slab buckets
			 * (kmalloc-16 / kmalloc-32) gives the allocator a
			 * realistic mixed workload instead of pounding a
			 * single size class. */
			unsigned char value[32];
			size_t vlen = 8 + ((unsigned int)rand() % 25);
			unsigned int j;
			int flags = (rand() % 8 == 0) ? XATTR_CREATE
				  : (rand() % 8 == 0) ? XATTR_REPLACE
				  : 0;

			for (j = 0; j < vlen; j++)
				value[j] = (unsigned char)rand();
			rc = fsetxattr(s->fd, name, value, vlen,
				       (int)RAND_NEGATIVE_OR(flags));
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_set,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		case 3: {
			/* setxattr (path-based variant) — exercises the
			 * vfs_path lookup leg in addition to the xattr
			 * write itself. */
			unsigned char value[32];
			size_t vlen = 8 + ((unsigned int)rand() % 25);
			unsigned int j;

			for (j = 0; j < vlen; j++)
				value[j] = (unsigned char)rand();
			slot_path(s, path, sizeof(path));
			rc = setxattr(path, name, value, vlen, 0);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_set,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		case 4:
		case 5:
		case 6: {
			unsigned char buf[64];

			rc = (int) fgetxattr(s->fd, name, buf, sizeof(buf));
			if (rc >= 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_get,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		case 7: {
			unsigned char buf[64];

			slot_path(s, path, sizeof(path));
			rc = (int) getxattr(path, name, buf, sizeof(buf));
			if (rc >= 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_get,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		case 8:
			rc = fremovexattr(s->fd, name);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_remove,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		case 9:
			slot_path(s, path, sizeof(path));
			rc = removexattr(path, name);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_remove,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		case 10: {
			/* Deliberately small list buffer so we sometimes
			 * trip -ERANGE once enough names accumulate, which
			 * exercises the size-probe path listxattr callers
			 * use to size their second call. */
			char buf[256];

			rc = (int) flistxattr(s->fd, buf, sizeof(buf));
			if (rc >= 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_list,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		case 11: {
			char buf[256];

			slot_path(s, path, sizeof(path));
			rc = (int) listxattr(path, buf, sizeof(buf));
			if (rc >= 0)
				__atomic_add_fetch(&shm->stats.xattr_thrash_list,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.xattr_thrash_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}
		}

		if (budget_elapsed(&start))
			break;
	}

	for (i = 0; i < opened; i++)
		close(slots[i].fd);

	return true;
}
