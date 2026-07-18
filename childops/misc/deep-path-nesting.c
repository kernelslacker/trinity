/*
 * deep_path_nesting - stress kernel path-length / seq_file handling by
 * building a deeply-nested directory tree, then hammering readers that
 * assemble or render pathnames at extreme depth.
 *
 * Trinity's random_syscall path fires proc/seq_file readers, but with a
 * shallow cwd.  Kernel path assembly (__d_path / prepend_name /
 * seq_path) and the per-mount / per-vma renderers only exercise their
 * size_t-underflow / OOB / ENAMETOOLONG edges when the assembled
 * pathname genuinely approaches PATH_MAX.  Random blob mutation cannot
 * build a valid deep tree; only a producer that does mkdir + chdir in
 * a loop can.
 *
 * Per outer iteration:
 *   1. Under a private per-child scratch base (${TRINITY_TMP}/trinity-
 *      deep-path-<pid>) chdir into a fresh run-<seq> subdir, then
 *      mkdir + chdir a chain to a churned target depth in
 *      [DP_MIN_DEPTH, DP_MAX_DEPTH] with components of a churned length
 *      in [DP_MIN_COMPLEN, DP_MAX_COMPLEN].  Stop early on any mkdir /
 *      chdir failure (ENAMETOOLONG when the assembled path exceeds
 *      PATH_MAX, EMLINK on the per-dir subdir cap, ENOSPC, ...).
 *   2. At depth, take DP_READER_PASSES reader passes; each pass picks
 *      one of the path/seq_file readers in enum dp_reader:
 *        - open+read /proc/self/mountinfo (per-mount seq_path)
 *        - open+read /proc/self/maps       (per-vma  seq_path)
 *        - getcwd(buf, huge)               (d_path against extreme cwd)
 *        - readlink("/proc/self/cwd")      (proc_pid_readlink -> d_path)
 *        - statx(AT_FDCWD, ".", ...)       (statx path traversal)
 *        - unlink of a fresh leaf file     (leaf dcache ops at depth)
 *        - rename of a fresh leaf file     (two path lookups at depth)
 *   3. Walk back up: for level = depth-1 .. 0, chdir("..") then rmdir
 *      the same component name we used going down.  Regenerating the
 *      name from the counter (not getcwd) keeps teardown working even
 *      when the cwd exceeds getcwd's PATH_MAX cap.  Best-effort;
 *      partial cleanup is tolerated -- each iteration uses a fresh
 *      run-<seq> subdir so leaked partials do not compound.
 *
 * Latched-off gate: dp_unsupported flips true on first failure to
 * create or enter the scratch BASE dir (EACCES on a hardened tmpdir,
 * EROFS on read-only, ENOSPC on a full tmpfs).  Subsequent invocations
 * short-circuit and bump setup_failed.  Per-iter failures below the
 * base are silent noise (or reader_failed on a specific reader call).
 *
 * Bounds: outer BUDGETED base DP_OUTER_BASE / cap DP_OUTER_CAP,
 * JITTER +/- 50%.  target_depth in [DP_MIN_DEPTH, DP_MAX_DEPTH];
 * component length in [DP_MIN_COMPLEN, DP_MAX_COMPLEN].  Reader-pass
 * count fixed at DP_READER_PASSES per depth.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/stat.h>
#endif

#include "child.h"
#include "jitter.h"
#include "pids.h"
#include "rnd.h"
#include "shm.h"
#include "syscall-gate.h"
#include "trinity.h"

#include "kernel/fcntl.h"
/* Latched once per child if the scratch BASE cannot be created or
 * entered (hardened tmpdir, read-only mount, full tmpfs).  Subsequent
 * invocations short-circuit and bump setup_failed. */
static bool dp_unsupported;

/* Per-process monotonic run counter -- each outer iteration uses a
 * fresh run-<seq> subdir so a partial cleanup does not compound. */
static unsigned long dp_run_seq;

#define DP_OUTER_BASE		1U
#define DP_OUTER_CAP		3U

#define DP_MIN_DEPTH		64U
#define DP_MAX_DEPTH		2048U

/* 5 chars fits "d" + 4 decimal digits (0..9999), covering the full
 * DP_MAX_DEPTH ceiling without snprintf overrunning the padding. */
#define DP_MIN_COMPLEN		5U
#define DP_MAX_COMPLEN		32U

#define DP_READER_PASSES	8U

/* Large enough to hold an extreme cwd -- the kernel's d_path is capped
 * at PATH_MAX (4096) internally, but a generous userspace buffer lets
 * us catch the ENAMETOOLONG signal cleanly on the getcwd/readlink
 * paths and gives the seq_file readers a real target. */
#define DP_BUF_SZ		(16U * 1024U)

enum dp_reader {
	DP_RD_MOUNTINFO = 0,
	DP_RD_MAPS,
	DP_RD_GETCWD,
	DP_RD_READLINK_CWD,
	DP_RD_STATX_DOT,
	DP_RD_UNLINK_LEAF,
	DP_RD_RENAME_LEAF,
	NR_DP_READERS,
};

/* File-scope scratch buffer for the reader helpers.  Sized past
 * PATH_MAX so getcwd / readlink / seq_file read do not truncate
 * prematurely.  Single writer per child (no siblings in a child
 * process), no coherence needed. */
static char dp_buf[DP_BUF_SZ];

/*
 * Compose the component name for level `i`: "d" followed by a
 * zero-padded decimal of `i`, total width `complen` characters.
 * complen is clamped to [2, min(DP_MAX_COMPLEN, outsz - 1)].
 * The regeneration side of teardown uses the exact same routine so
 * the two walks stay in sync even without stashing names.
 */
static void dp_component(char *out, size_t outsz, unsigned int i,
			 unsigned int complen)
{
	unsigned int cl = complen;

	if (cl < 2U)
		cl = 2U;
	if (cl > DP_MAX_COMPLEN)
		cl = DP_MAX_COMPLEN;
	if ((size_t)cl >= outsz)
		cl = (unsigned int)(outsz - 1U);

	(void)snprintf(out, outsz, "d%0*u", (int)(cl - 1U), i);
}

/*
 * Ensure the scratch base and per-run subdir exist and chdir into the
 * per-run subdir.  Returns 0 on success, -1 on scratch-base failure
 * (which latches dp_unsupported), -2 on per-run subdir failure (no
 * latch -- may just be a stale leftover we can retry later).
 * base[] is populated with the absolute BASE path so the caller can
 * chdir back to it after tree teardown.
 */
static int dp_enter_scratch_run(char *base, size_t basesz,
				unsigned long seq)
{
	char run[64];

	(void)snprintf(base, basesz, "%s/trinity-deep-path-%d",
		       trinity_tmpdir_abs(), (int)mypid());
	if (mkdir(base, 0755) != 0 && errno != EEXIST) {
		dp_unsupported = true;
		return -1;
	}
	if (chdir(base) != 0) {
		dp_unsupported = true;
		return -1;
	}
	(void)snprintf(run, sizeof(run), "run-%lu", seq);
	if (mkdir(run, 0755) != 0 && errno != EEXIST)
		return -2;
	if (chdir(run) != 0)
		return -2;
	return 0;
}

/*
 * Build the deep tree from the current cwd.  Returns the depth
 * actually reached in [0, target_depth].  A shorter return means the
 * kernel hit its per-fs limit (ENAMETOOLONG once the assembled path
 * exceeds PATH_MAX, EMLINK on ext-family per-dir subdir caps, ENOSPC,
 * ...) -- treat that as the healthy stop signal.  EEXIST from a
 * residual tree of a prior invocation is tolerated: the chdir still
 * lands us at the same depth.
 */
static unsigned int dp_build_tree(unsigned int target_depth,
				  unsigned int complen)
{
	char comp[DP_MAX_COMPLEN + 1];
	unsigned int i;

	for (i = 0U; i < target_depth; i++) {
		dp_component(comp, sizeof(comp), i, complen);
		if (mkdir(comp, 0755) != 0 && errno != EEXIST)
			break;
		if (chdir(comp) != 0)
			break;
	}
	return i;
}

/*
 * seq_file / d_path readers rendered as one bucket: open() the proc
 * file, drain it, close.  Bumps reader_ok / reader_failed based on
 * open + read outcome.  read() returning 0 is EOF (success).
 */
static void dp_read_proc_file(const char *path)
{
	ssize_t sz = -1;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	do {
		sz = read(fd, dp_buf, sizeof(dp_buf));
	} while (sz > 0);
	(void)close(fd);
	if (sz < 0)
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Create a fresh leaf file at cwd, unlink it.  reader_seq keys the
 * name so successive passes do not collide.  Any error path bumps
 * reader_failed and returns cleanly.
 */
static void dp_reader_unlink_leaf(unsigned int reader_seq)
{
	char leaf[64];
	int fd;

	(void)snprintf(leaf, sizeof(leaf), "leaf-%u", reader_seq);
	fd = open(leaf, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	(void)close(fd);
	if (unlink(leaf) == 0)
		__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Create a fresh leaf, rename it to a sibling name (two path lookups
 * at extreme depth), then unlink the destination.  Any error path
 * bumps reader_failed and cleans up any residual leaf.
 */
static void dp_reader_rename_leaf(unsigned int reader_seq)
{
	char src[64], dst[64];
	int fd;

	(void)snprintf(src, sizeof(src), "leafA-%u", reader_seq);
	(void)snprintf(dst, sizeof(dst), "leafB-%u", reader_seq);
	fd = open(src, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	(void)close(fd);
	if (rename(src, dst) == 0) {
		(void)unlink(dst);
		__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		(void)unlink(src);
		__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * One reader pass at current cwd (the leaf of the deep tree).  Picks
 * one of the enum dp_reader kinds uniformly.  reader_seq is passed
 * through so unlink/rename can key their leaf names on the pass
 * counter.
 */
static void dp_reader_pass(unsigned int reader_seq)
{
	unsigned int kind = rnd_modulo_u32(NR_DP_READERS);
	ssize_t sz;

	switch (kind) {
	case DP_RD_MOUNTINFO:
		dp_read_proc_file("/proc/self/mountinfo");
		return;

	case DP_RD_MAPS:
		dp_read_proc_file("/proc/self/maps");
		return;

	case DP_RD_GETCWD:
		if (getcwd(dp_buf, sizeof(dp_buf)) == NULL)
			__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
					   1, __ATOMIC_RELAXED);
		return;

	case DP_RD_READLINK_CWD:
		sz = readlink("/proc/self/cwd", dp_buf, sizeof(dp_buf));
		if (sz < 0)
			__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
					   1, __ATOMIC_RELAXED);
		return;

	case DP_RD_STATX_DOT:
#if defined(__NR_statx) && defined(STATX_BASIC_STATS)
		{
			struct statx stx;
			long r = trinity_raw_syscall(__NR_statx,
					AT_FDCWD, ".", 0U,
					(unsigned int)STATX_BASIC_STATS, &stx);
			if (r < 0)
				__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
						   1, __ATOMIC_RELAXED);
		}
#else
		/* Kernel/glibc without statx: fall back to a stat on ".",
		 * which drives the same path-lookup machinery even if it
		 * bypasses the statx-specific renderers. */
		{
			struct stat st;
			if (stat(".", &st) < 0)
				__atomic_add_fetch(&shm->stats.deep_path.reader_failed,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.deep_path.reader_ok,
						   1, __ATOMIC_RELAXED);
		}
#endif
		return;

	case DP_RD_UNLINK_LEAF:
		dp_reader_unlink_leaf(reader_seq);
		return;

	case DP_RD_RENAME_LEAF:
		dp_reader_rename_leaf(reader_seq);
		return;
	}
}

/*
 * Walk back up from depth `depth` to the run-<seq> subdir.  For each
 * level, chdir("..") then rmdir the component we made on the way
 * down (regenerated from the counter, so a getcwd-uncookable extreme
 * cwd does not block the walk).  chdir("..") failure aborts the walk
 * -- anything left below is orphaned but bounded (this iteration's
 * fresh run-<seq> subdir).
 */
static void dp_teardown_tree(unsigned int depth, unsigned int complen)
{
	char comp[DP_MAX_COMPLEN + 1];
	unsigned int i;

	for (i = depth; i-- > 0U; ) {
		dp_component(comp, sizeof(comp), i, complen);
		if (chdir("..") != 0)
			return;
		(void)rmdir(comp);
	}
}

/*
 * One outer iteration: enter scratch, build tree, hammer readers,
 * tear down, drop the run-<seq> subdir.  All error paths clean up
 * what they can and return silently -- outer counters attribute the
 * work.
 */
static void dp_iter_one(void)
{
	char base[128];
	char runsub[64];
	unsigned long seq = ++dp_run_seq;
	unsigned int target_depth, complen, depth, i;

	if (dp_enter_scratch_run(base, sizeof(base), seq) != 0)
		return;

	target_depth = DP_MIN_DEPTH +
		rnd_modulo_u32(DP_MAX_DEPTH - DP_MIN_DEPTH + 1U);
	complen = DP_MIN_COMPLEN +
		rnd_modulo_u32(DP_MAX_COMPLEN - DP_MIN_COMPLEN + 1U);

	depth = dp_build_tree(target_depth, complen);
	if (depth == target_depth)
		__atomic_add_fetch(&shm->stats.deep_path.max_depth_reached,
				   1, __ATOMIC_RELAXED);

	/* Skip hammering when depth==0: the tree could not be built
	 * even to level 1, so hammering from the run subdir adds no
	 * relevant stress. */
	if (depth > 0U) {
		for (i = 0U; i < DP_READER_PASSES; i++)
			dp_reader_pass(i);
	}

	dp_teardown_tree(depth, complen);

	/* Return to BASE and drop the run subdir.  chdir(base) is
	 * reliable regardless of teardown residue because BASE is
	 * shallow.  rmdir on run-<seq> is best-effort -- a leaked leaf
	 * only wastes an inode for the life of the child.  If chdir
	 * back to BASE fails (should not happen), skip the rmdir --
	 * we would rmdir the wrong path from the leftover cwd. */
	if (chdir(base) != 0)
		return;
	(void)snprintf(runsub, sizeof(runsub), "run-%lu", seq);
	(void)rmdir(runsub);
}

bool deep_path_nesting(struct childdata *child)
{
	unsigned int iters, i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory
	 * and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its
	 * dispatch + alt-op accounting on the same valid_op snapshot.
	 * Skip the stats writes entirely when the snapshot is out of
	 * range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.deep_path.runs, 1, __ATOMIC_RELAXED);

	if (dp_unsupported) {
		__atomic_add_fetch(&shm->stats.deep_path.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	iters = BUDGETED(CHILD_OP_DEEP_PATH_NESTING,
			 JITTER_RANGE(DP_OUTER_BASE));
	if (iters > DP_OUTER_CAP)
		iters = DP_OUTER_CAP;
	if (iters == 0U)
		iters = 1U;

	for (i = 0U; i < iters; i++)
		dp_iter_one();

	return true;
}
