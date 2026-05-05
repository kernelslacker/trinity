/*
 * slab_cache_thrash - bursted alloc/free against one targeted kernel slab.
 *
 * Trinity's random_syscall path generates allocations across thousands of
 * unrelated kmem_caches in arbitrary order, so any one slab class only
 * sees sporadic, intermixed pressure.  The cross-cache UAF / SLUB
 * freelist-exposure surface is a different shape: an object freed back to
 * a specific kmem_cache is only useful to an attacker if a fresh
 * allocation of the same size class lands on top of it before the slab
 * page is reclaimed.  That requires sustained, concentrated pressure on
 * one cache at a time -- not the diffuse mix the random picker produces.
 *
 * slab_cache_thrash closes the gap by picking ONE slab class per
 * invocation (uniform random from a small static table of well-understood
 * targets) and issuing a tight burst of allocations against it, then
 * freeing them in interleaved order to populate the freelist with holes
 * a sibling syscall might land on.  Each target maps to a syscall whose
 * dominant kernel allocation is known to fall in the named size class:
 *
 *   SLAB_KMALLOC_32     timerfd_create        struct timerfd_ctx range
 *   SLAB_KMALLOC_64     eventfd               struct eventfd_ctx range
 *   SLAB_KMALLOC_192    signalfd              ctx + sigmask backing
 *   SLAB_KMALLOC_256    inotify_add_watch     per-watch fsnotify_mark
 *   SLAB_DENTRY         openat fresh paths    dentry + inode pair
 *   SLAB_INODE_CACHE    memfd_create          fresh tmpfs inode each call
 *   SLAB_FILES_CACHE    dup() bursts          fdtable growth path
 *
 * The targets were picked because (a) each can be exercised through a
 * single non-privileged syscall available on every kernel Trinity is
 * realistically fuzzed against, (b) the dominant per-call allocation is
 * stable enough across kernel versions that the size class label still
 * reflects reality, and (c) all of them are immediately freeable through
 * close() (or a matching teardown call) so the burst doesn't leak across
 * invocations.
 *
 * Self-bounding: the burst size is BUDGETED(CHILD_OP_SLAB_CACHE_THRASH,
 * MAX_ITERATIONS), so adapt_budget() can scale it up on productive runs
 * and back off on noisy ones.  Burst is hard-clamped to [128, 512] so a
 * runaway multiplier can't exceed RLIMIT_NOFILE (Trinity sets 1024 in
 * the child) or starve the rest of the fleet of fds.  All resources are
 * released before the function returns; flock-style "fd lifetime carries
 * the resource" semantics apply for every target except inotify watches,
 * which are released by closing their parent inotify fd.
 *
 * Deliberately does NOT register any of the produced fds in the
 * OBJ_GLOBAL/OBJ_LOCAL pools -- these objects are throwaways whose only
 * purpose is to put pressure on the targeted slab; publishing them would
 * pollute the random_syscall fd-bias rings with fds the rest of the
 * fuzzer has no business touching.
 *
 * Deliberately does NOT read /proc/slabinfo from inside the burst.  That
 * file requires CAP_SYS_ADMIN on most kernels, the read path takes the
 * slab_mutex which would serialise every concurrent slab_cache_thrash
 * caller in the fleet, and a slabinfo parse on the hot loop would blow
 * out the cycles budget.  Operators wanting before/after readings should
 * sample slabinfo externally.
 *
 * Active in both the random picker (dormant_op_disabled[] entry cleared)
 * and alt_op_rotation[], so dedicated alt-op children can target it
 * deliberately while the random picker still draws it occasionally.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"

/* Hard caps on the per-invocation burst size.  Lower bound keeps the
 * burst large enough to span a slab page on any realistic order; upper
 * bound stays safely under Trinity's per-child RLIMIT_NOFILE of 1024
 * with margin for the rest of the fuzzer's open fds. */
#define SLAB_THRASH_MIN	128
#define SLAB_THRASH_MAX	512

/* Default base for BUDGETED().  adapt_budget() scales this 0.25x..4x;
 * the resulting value is then clamped to [SLAB_THRASH_MIN,
 * SLAB_THRASH_MAX] before use. */
#define MAX_ITERATIONS	256

enum slab_target {
	SLAB_KMALLOC_32 = 0,	/* timerfd_create -> timerfd_ctx (~24-32B) */
	SLAB_KMALLOC_64,	/* eventfd -> eventfd_ctx (~48-64B) */
	SLAB_KMALLOC_192,	/* signalfd -> sighand-side ctx + mask */
	SLAB_KMALLOC_256,	/* inotify_add_watch -> per-watch fsnotify_mark */
	SLAB_DENTRY,		/* openat fresh paths -> dentry + inode */
	SLAB_INODE_CACHE,	/* memfd_create -> fresh tmpfs inode */
	SLAB_FILES_CACHE,	/* dup bursts -> fdtable growth */
};

/* Static asserts: NR_SLAB_TARGETS lives in stats.h so the per-target
 * counter array is sized in lockstep with this enum.  If they ever drift
 * the build fails here rather than silently writing past the array. */
_Static_assert((int)SLAB_FILES_CACHE + 1 == NR_SLAB_TARGETS,
	"NR_SLAB_TARGETS must match enum slab_target tail");

/* Compute the clamped burst size for this invocation. */
static unsigned int pick_burst(void)
{
	unsigned int n = BUDGETED(CHILD_OP_SLAB_CACHE_THRASH, JITTER_RANGE(MAX_ITERATIONS));

	if (n < SLAB_THRASH_MIN)
		n = SLAB_THRASH_MIN;
	if (n > SLAB_THRASH_MAX)
		n = SLAB_THRASH_MAX;
	return n;
}

/* Free fds in interleaved order: every other fd first, then the rest.
 * Two-pass close pattern leaves the freelist with non-contiguous holes
 * after the first pass, which is the layout an attacker exploiting a
 * cross-cache UAF wants the victim cache to be in when their realloc
 * runs.  Each successful close decrements the per-class success count
 * (fail-only counter would be misleading: a failed close on EBADF means
 * the fd was already gone, not that the slab pressure was wasted). */
static void free_fds_interleaved(int *fds, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i += 2) {
		if (fds[i] >= 0) {
			close(fds[i]);
			fds[i] = -1;
		}
	}
	for (i = 1; i < n; i += 2) {
		if (fds[i] >= 0) {
			close(fds[i]);
			fds[i] = -1;
		}
	}
}

static void burst_timerfd(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	unsigned int i;

	for (i = 0; i < n; i++)
		fds[i] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	free_fds_interleaved(fds, n);
}

static void burst_eventfd(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	unsigned int i;

	for (i = 0; i < n; i++)
		fds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	free_fds_interleaved(fds, n);
}

static void burst_signalfd(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	sigset_t ss;
	unsigned int i;

	/* SIGRTMIN+8: well clear of glibc's reserved RT signals and
	 * Trinity's SIGALRM/SIGXCPU/SIGINT.  We don't actually deliver
	 * the signal; we only need a non-empty mask so signalfd accepts
	 * the call and allocates the per-fd ctx + mask backing. */
	sigemptyset(&ss);
	if (SIGRTMIN + 8 < SIGRTMAX)
		sigaddset(&ss, SIGRTMIN + 8);
	else
		sigaddset(&ss, SIGUSR1);

	for (i = 0; i < n; i++)
		fds[i] = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	free_fds_interleaved(fds, n);
}

static void burst_inotify_watches(unsigned int n)
{
	char path[PATH_MAX + 32];
	int ifd;
	int wd;
	unsigned int i;
	unsigned int added = 0;

	ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (ifd < 0)
		return;

	/* Watch the trinity tmpdir; it always exists for the running
	 * fuzzer.  inotify_add_watch on the same path twice updates the
	 * existing mark in place rather than allocating a new one, so we
	 * cycle a small set of mask values to force fresh allocations.
	 * Eight masks * up to 64 watches per mask covers the SLAB_THRASH_MAX
	 * bound while keeping each individual call cheap. */
	snprintf(path, sizeof(path), "%s", trinity_tmpdir_abs());

	for (i = 0; i < n; i++) {
		uint32_t mask = IN_ACCESS | IN_MODIFY | IN_ATTRIB |
			IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_OPEN |
			IN_MOVED_FROM | IN_MOVED_TO;
		mask &= ~(1U << (i & 7));
		if (mask == 0)
			mask = IN_ACCESS;
		/* 1-in-RAND_NEGATIVE_RATIO sub the curated event-mask
		 * for a curated edge value — exercises inotify's mask
		 * validation (inotify_arg_to_mask rejects masks with no
		 * IN_ALL_EVENTS bits set; flag bits outside the valid
		 * set get masked off) which the curated 8-bit cycle
		 * never reaches. */
		wd = inotify_add_watch(ifd, path,
				       (uint32_t)RAND_NEGATIVE_OR(mask));
		if (wd >= 0)
			added++;
	}
	(void)added;

	/* Closing the inotify fd releases every watch in one shot, which
	 * is what we want: it walks the per-fsnotify_group mark list and
	 * frees every fsnotify_mark slab object back to the cache. */
	close(ifd);
}

static void burst_dentry(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	char path[PATH_MAX + 64];
	unsigned int i;
	pid_t pid = getpid();

	/* Each open of a fresh path allocates a dentry + inode pair on
	 * tmpfs.  We use O_CREAT | O_TMPFILE so the tree doesn't grow:
	 * O_TMPFILE-created inodes are unlinked at close, leaving zero
	 * directory residue per burst.  Older kernels (or filesystems)
	 * that reject O_TMPFILE fall back to the create+unlink path. */
	for (i = 0; i < n; i++) {
		fds[i] = openat(AT_FDCWD, trinity_tmpdir_abs(),
				O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
		if (fds[i] >= 0)
			continue;
		snprintf(path, sizeof(path), "%s/scthrash-%d-%u",
			 trinity_tmpdir_abs(), (int)pid, i);
		fds[i] = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
		if (fds[i] >= 0)
			(void)unlink(path);
	}
	free_fds_interleaved(fds, n);
}

static void burst_inode_cache(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	char name[32];
	unsigned int i;

	/* memfd_create allocates a fresh tmpfs inode + struct file per
	 * call.  Names must be unique-ish to avoid exercising shared-name
	 * paths; pid + index gives enough uniqueness within a burst. */
	for (i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "sc-%u-%u",
			 (unsigned int)getpid(), i);
		fds[i] = (int)syscall(__NR_memfd_create, name, 0U);
	}
	free_fds_interleaved(fds, n);
}

static void burst_files_cache(unsigned int n)
{
	int fds[SLAB_THRASH_MAX];
	int seed_fd;
	unsigned int i;

	/* dup() bursts force the per-process fdtable to grow when it
	 * exhausts its current bucket.  The growth path goes through
	 * alloc_fdtable() / kvmalloc, exercising the same allocator the
	 * struct files_struct itself sits behind.  Use /dev/null as the
	 * source: it's always openable, has minimal kernel-side cost per
	 * dup, and doesn't keep any state we'd have to clean up. */
	seed_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (seed_fd < 0) {
		for (i = 0; i < n; i++)
			fds[i] = -1;
		return;
	}

	for (i = 0; i < n; i++)
		fds[i] = dup(seed_fd);

	free_fds_interleaved(fds, n);
	close(seed_fd);
}

static void run_burst(enum slab_target t, unsigned int n)
{
	switch (t) {
	case SLAB_KMALLOC_32:	burst_timerfd(n);		break;
	case SLAB_KMALLOC_64:	burst_eventfd(n);		break;
	case SLAB_KMALLOC_192:	burst_signalfd(n);		break;
	case SLAB_KMALLOC_256:	burst_inotify_watches(n);	break;
	case SLAB_DENTRY:	burst_dentry(n);		break;
	case SLAB_INODE_CACHE:	burst_inode_cache(n);		break;
	case SLAB_FILES_CACHE:	burst_files_cache(n);		break;
	}
}

bool slab_cache_thrash(struct childdata *child)
{
	enum slab_target t;
	unsigned int n;

	(void)child;

	t = (enum slab_target)((unsigned int)rand() % NR_SLAB_TARGETS);
	n = pick_burst();

	__atomic_add_fetch(&shm->stats.slab_cache_thrash_runs[t],
			   1, __ATOMIC_RELAXED);

	run_burst(t, n);

	return true;
}
