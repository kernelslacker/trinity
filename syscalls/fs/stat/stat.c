/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <limits.h>
#include <linux/stat.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include "arch.h"
#include "kernel/stat.h"
#include "output-poison.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, xattr-thrash, flock-thrash, ...) touch;
 * cross-process contention concentrates on the same per-inode i_rwsem /
 * getattr path.
 */
#define NR_TESTFILES 4

static void sanitise_statbuf_a2(struct syscallrecord *rec)
{
	char *path;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- stat
	 * returns ENOENT at the path walk before ever reaching the
	 * per-fs inode_operations->getattr path under i_rwsem.  Classic
	 * "high calls, low edges" cold-syscall shape the chmod / utime
	 * families were in before their testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent stat lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the
	 * permission check (trinity owns these inodes so the
	 * ownership/permission gates pass), the namei walk to a real
	 * dentry, and the per-fs getattr that the i_rwsem guards.  The
	 * other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT reject arm stays exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = get_testfile_path();
	if (path == NULL)
		return;

	rec->a1 = (unsigned long) path;
}

/*
 * Snapshot of the stat output-buffer pointer + poison seed the post
 * oracle needs, captured at sanitise time.  Lives in rec->post_state,
 * a slot the syscall ABI does not expose, so a sibling scribble of
 * rec->a2 between syscall return and post entry cannot retarget the
 * untouched-buffer check at a foreign user allocation or smear the
 * seed against a heap page that still carries a residual pattern from
 * an earlier call.
 */
#define STAT_POST_STATE_MAGIC	0x53544154UL	/* "STAT" */
struct stat_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
};

static void sanitise_stat(struct syscallrecord *rec)
{
	struct stat_post_state *snap;
	void *buf;

	rec->post_state = 0;

	sanitise_statbuf_a2(rec);

	/*
	 * ARG_NON_NULL_ADDRESS still hands out NULL when the writable pool
	 * cannot back the requested mapping size; keep the readability gate
	 * so poison_output_struct's byte-walk does not SIGSEGV the sanitiser
	 * on NULL or on a raw fuzz address outside the tracked writable
	 * regions.  On skip, rec->post_state stays 0 and the post handler
	 * no-ops via post_state_claim_owned() == NULL.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, sizeof(struct stat)))
		return;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = STAT_POST_STATE_MAGIC;
	snap->statbuf     = rec->a2;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct stat), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: stat(filename, statbuf) is the i386 compat entry point that
 * writes struct stat to userspace on success.  The x86-64 path lives in
 * syscall_newstat and is already poison-checked; this handler catches
 * the same "returned success but wrote zero bytes" bug shape on the
 * 32-bit ABI where cp_stat64() / __do_compat_stat() land instead.
 * check_output_struct() reports a match iff every byte of the returned
 * struct still equals the poison we stamped -- i.e. copy_to_user() was
 * skipped entirely.  See fstat64.c for the full rationale; the shape is
 * identical.
 */
static void post_stat(struct syscallrecord *rec)
{
	struct stat_post_state *snap;
	struct stat snapshot;

	snap = post_state_claim_owned(rec, STAT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(&snapshot,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(&snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_stat = {
	.name = "stat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_stat,
	.post = post_stat,
	.group = GROUP_VFS,
	.flags = REEXEC_SANITISE_OK,
};


/*
 * SYSCALL_DEFINE2(stat64, const char __user *, filename, struct stat64 __user *, statbuf)
 */

/*
 * Sibling of stat_post_state for the i386 __NR_stat64 entry.  Separate
 * magic + struct size so a snap installed by one entry cannot be
 * misclaimed by the other's post handler if a sibling scribble ever
 * flipped rec->a2 into the wrong post_state slot.
 */
#define STAT64_POST_STATE_MAGIC	0x53544136UL	/* "ST46" */
struct stat64_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
};

static void sanitise_stat64(struct syscallrecord *rec)
{
	struct stat64_post_state *snap;
	void *buf;

	rec->post_state = 0;

	sanitise_statbuf_a2(rec);

	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, sizeof(struct stat64)))
		return;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = STAT64_POST_STATE_MAGIC;
	snap->statbuf     = rec->a2;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct stat64), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: stat64(filename, statbuf) is the i386 LFS variant that fills a
 * struct stat64 (64-bit off_t, ino_t, blkcnt_t).  Same untouched-buffer
 * bug shape as stat above; the wider struct exercises cp_new_stat64()
 * rather than cp_stat64(), which is a separate copy path in the kernel.
 */
static void post_stat64(struct syscallrecord *rec)
{
	struct stat64_post_state *snap;
	struct stat64 snapshot;

	snap = post_state_claim_owned(rec, STAT64_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(&snapshot,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(&snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_stat64 = {
	.name = "stat64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_stat64,
	.post = post_stat64,
	.group = GROUP_VFS,
	.flags = REEXEC_SANITISE_OK,
};

/*
 * SYSCALL_DEFINE5(statx, int, dfd, const char __user *, filename, unsigned, flags, unsigned int, mask, struct statx __user *, buffer)
 */

#define AT_STATX_SYNC_TYPE      0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC     0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC      0x4000  /* - Don't sync attributes with the server */


static unsigned long statx_flags[] = {
	AT_STATX_SYNC_TYPE, AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC,
	AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
};

/*
 * Curated AT_* flag combinations for statx().  The sync-type subfield
 * is a three-state selector encoded inside the AT_STATX_SYNC_TYPE mask
 * (AS_STAT == 0, FORCE_SYNC, DONT_SYNC); FORCE | DONT is rejected as
 * EINVAL.  The other AT_* bits steer lookup behaviour and are freely
 * combinable.  Random-bit fills rarely line up with a legal sync-type
 * triplet; the curated table makes the legal sync paths well-trodden
 * while still allowing the random-bit bucket below to explore the rest.
 */
static const unsigned long statx_flag_combos[] = {
	0,
	AT_STATX_SYNC_AS_STAT,
	AT_STATX_FORCE_SYNC,
	AT_STATX_DONT_SYNC,
	AT_SYMLINK_NOFOLLOW,
	AT_NO_AUTOMOUNT,
	AT_EMPTY_PATH,
	AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
	AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
	AT_NO_AUTOMOUNT | AT_EMPTY_PATH,
	AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH,
	AT_STATX_FORCE_SYNC | AT_SYMLINK_NOFOLLOW,
	AT_STATX_DONT_SYNC | AT_NO_AUTOMOUNT,
	AT_STATX_FORCE_SYNC | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
	AT_STATX_DONT_SYNC | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
};

static unsigned long statx_mask[] = {
	STATX_TYPE, STATX_MODE, STATX_NLINK, STATX_UID, STATX_GID,
	STATX_ATIME, STATX_MTIME, STATX_CTIME, STATX_INO, STATX_SIZE,
	STATX_BLOCKS, STATX_BTIME, STATX_MNT_ID, STATX_DIOALIGN,
	STATX_MNT_ID_UNIQUE, STATX_SUBVOL, STATX_WRITE_ATOMIC,
	STATX_DIO_READ_ALIGN,
};

/*
 * Bit-select for the request mask passed to statx().
 *
 * The framework's default set_rand_bitmask over statx_mask gives every
 * bit equal weight, which means the newer fields (STATX_MNT_ID and
 * everything past it) ride alongside the basic-stats block on every
 * draw and rarely get isolated.  Bucket the draw so the kernel sees
 * meaningful spread:
 *
 *   30% bias toward STATX_MNT_ID | STATX_DIOALIGN | STATX_SUBVOL,
 *       optionally OR'd with STATX_WRITE_ATOMIC | STATX_DIO_READ_ALIGN
 *       and/or a random subset of the umbrella bits.  This drives
 *       coverage of the per-filesystem stx_mnt_id and stx_dio_* fill
 *       paths that the umbrella draw alone barely exercises.
 *   30% random subset over the full statx_mask[] (the historical
 *       behaviour, retained for breadth).
 *   20% STATX_ALL — the standard "give me everything" request.
 *   10% 0 — the documented "tell me what you can without asking"
 *       request that still has a defined kernel path.
 *   10% legal-mask | high garbage bits, to exercise the kernel's
 *       reserved-bit handling on the mask validator.
 */
static unsigned int generate_statx_mask(void)
{
	uint32_t pick = rnd_modulo_u32(100);
	unsigned int mask;

	if (pick < 30) {
		mask = STATX_MNT_ID | STATX_DIOALIGN | STATX_SUBVOL;
		if (RAND_BOOL())
			mask |= STATX_WRITE_ATOMIC | STATX_DIO_READ_ALIGN;
		if (RAND_BOOL())
			mask |= (unsigned int) set_rand_bitmask(
				ARRAY_SIZE(statx_mask), statx_mask);
	} else if (pick < 60) {
		mask = (unsigned int) set_rand_bitmask(
			ARRAY_SIZE(statx_mask), statx_mask);
	} else if (pick < 80) {
		mask = STATX_ALL;
	} else if (pick < 90) {
		mask = 0;
	} else {
		mask = (unsigned int) set_rand_bitmask(
			ARRAY_SIZE(statx_mask), statx_mask);
		mask |= rnd_u32() & 0xfff00000U;
	}
	return mask;
}

/*
 * Flag picker mirroring generate_statx_mask: 85% from the curated
 * combo table (legal sync-type triplets plus the AT_* lookup bits),
 * 15% combo | random high garbage bits to exercise the kernel's
 * flag validator on the rare unknown-bit path.
 */
static unsigned int generate_statx_flags(void)
{
	unsigned int flags = (unsigned int) RAND_ARRAY(statx_flag_combos);

	if (!ONE_IN(7))
		return flags;

	return flags | (rnd_u32() & 0xffff0000U);
}

/*
 * Snapshot of the five statx input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign pathname or statxbuf,
 * cannot flip the dfd, and cannot smear the lookup flags or the field-
 * select mask used to seed the re-issue.
 */
#define STATX_POST_STATE_MAGIC	0x53545458UL	/* "STTX" */
struct statx_post_state {
	unsigned long magic;
	unsigned long dfd;
	unsigned long pathname;
	unsigned long flags;
	unsigned long mask;
	unsigned long statxbuf;
	/*
	 * Seed for the poison pattern stamped into statxbuf at sanitise
	 * time.  Returned by poison_output_struct() and fed back into
	 * check_output_struct_user_or_skip() in the post handler so a
	 * stomp of rec->aN cannot redirect the check against an unrelated
	 * heap page that happens to still carry the original (or any)
	 * byte pattern.  Left at 0 on the arm where sanitise skipped the
	 * stamp (unreadable buffer, NULL statxbuf); the post handler
	 * no-ops the poison arm on a zero seed.
	 */
	uint64_t poison_seed;
};

static void sanitise_statx(struct syscallrecord *rec)
{
	struct statx_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a5, page_size);

	/*
	 * Overwrite the framework's ARG_LIST draws for flags (a3) and
	 * mask (a4) with the legality-aware pickers.  The framework
	 * populates these slots from statx_flags[] / statx_mask[] before
	 * .sanitise runs; replacing them here keeps the syscallentry
	 * arg metadata correct for printout / replay while steering the
	 * actual kernel call through the curated combo and bias paths.
	 * Order matters: the post_state snapshot below must capture the
	 * values the kernel actually sees, not the framework's draws.
	 */
	rec->a3 = generate_statx_flags();
	rec->a4 = generate_statx_mask();

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2, but the
	 * random path is most often not a real file at all -- statx
	 * returns ENOENT at the path walk before ever reaching
	 * vfs_getattr / the per-fs inode_operations->getattr path that
	 * the curated mask/flags above were chosen to exercise.
	 *
	 * Half the draws now repoint a2 at one of the trinity-testfile<N>
	 * absolute paths so the call lands on a real trinity-owned inode
	 * and penetrates the VFS path -- the namei walk to a real dentry,
	 * the per-fs getattr, and the mask intersection logic the post
	 * oracle relies on.  The other half preserves the slot exactly as
	 * the generic draw left it, so the ENOENT reject arm stays
	 * exercised.  AT_FDCWD-pin a1 on the same arm: the absolute path
	 * ignores dfd, but a sane dfd keeps the call tidy.  statx is
	 * read-only on the inode, so this cannot clobber the shared
	 * trinity-testfile pool.  Must run BEFORE the post_state snapshot
	 * below so the snapshot captures what the kernel actually sees.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL) {
			rec->a2 = (unsigned long) path;
			rec->a1 = (unsigned long) AT_FDCWD;
		}
	}

	/*
	 * Snapshot the five input args for the post oracle.  Without this
	 * the post handler reads rec->a1..a5 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * pathname or statxbuf pointers, so the strncpy / memcpy / re-issue
	 * would touch a foreign allocation, and a stomped flags or mask
	 * word would change the lookup semantics or the bits the kernel
	 * sets in stx_mask and break the intersection logic on the
	 * re-issue.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = STATX_POST_STATE_MAGIC;
	snap->dfd      = rec->a1;
	snap->pathname = rec->a2;
	snap->flags    = rec->a3;
	snap->mask     = rec->a4;
	snap->statxbuf = rec->a5;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks
	 * check_output_struct_user_or_skip() whether the pattern survived
	 * intact; a match after a rec->retval == 0 return means the
	 * kernel reported success without calling copy_to_user() on the
	 * statxbuf.  cp_statx() zero-fills then writes the whole struct
	 * on success, so a full-struct poison is safe (no legitimate
	 * partial-write path leaves poison in the tail).  Gate on
	 * range_readable_user() so an ARG_NON_NULL_ADDRESS draw the
	 * writable pool could not back does not SIGSEGV the sanitiser
	 * inside poison_output_struct's byte-walk; on skip poison_seed
	 * stays 0 and the post handler no-ops the poison arm while the
	 * equality re-issue arm keeps running.
	 */
	if (snap->statxbuf != 0) {
		void *buf = (void *)(unsigned long) snap->statxbuf;

		if (range_readable_user(buf, sizeof(struct statx)))
			snap->poison_seed =
				poison_output_struct(buf, sizeof(struct statx), 0);
	}

	post_state_install(rec, snap);
}

/*
 * Oracle: statx(dfd, pathname, flags, mask, statxbuf) is the modern
 * path-based stat — it resolves pathname relative to dfd, applies the
 * lookup flags (AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
 * AT_STATX_SYNC_*), and fills only those struct statx fields the caller
 * asked for in mask AND that the underlying filesystem actually supports.
 * The reply's stx_mask reports which fields are valid; everything else
 * in the buffer is undefined.  All five args steer either name resolution
 * or which fields the kernel writes, so all five must be snapshotted
 * before the re-issue.
 *
 * Mask intersection wrinkle: comparing a field that the original call
 * filled but the recheck did not (or vice versa) would false-positive
 * on transient mask differences — a filesystem that lazily computes
 * STATX_BLOCKS, a btrfs subvolume crossing, a recheck arriving before
 * STATX_BTIME has been read off disk.  Compare only fields whose bit
 * is set in BOTH stx_masks: valid_mask = first.stx_mask & recheck.stx_mask.
 *
 * Mask-gated fields (compare iff valid_mask has the bit):
 *   STATX_TYPE | STATX_MODE   stx_mode (one __u16, fed by either bit)
 *   STATX_NLINK              stx_nlink
 *   STATX_UID                stx_uid
 *   STATX_GID                stx_gid
 *   STATX_INO                stx_ino
 *   STATX_SIZE               stx_size
 *   STATX_BLOCKS             stx_blocks
 *
 * Always-on fields (kernel fills unconditionally per the UAPI):
 *   stx_blksize, stx_dev_major+stx_dev_minor, stx_rdev_major+stx_rdev_minor
 *
 * Excluded (would drift legitimately or carry no inode-stable signal):
 *   stx_atime / stx_mtime / stx_ctime / stx_btime — sibling read / write /
 *     chmod legitimately advances these.
 *   stx_attributes / stx_attributes_mask — file-attribute flags can
 *     legitimately flip (chattr +i, FS_DAX_FL toggle, FS_VERITY_FL set).
 *   stx_mnt_id — bind-mount churn / mount propagation across a private
 *     namespace can change this without the inode changing.
 *   stx_dio_mem_align / stx_dio_offset_align / stx_dio_read_offset_align /
 *     stx_subvol / stx_atomic_write_* — rare reconfiguration paths that
 *     legitimately change without the underlying inode rotating.
 *
 * A divergence in the compared fields is not benign drift; it points
 * at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct statx in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - struct-layout shift on a kernel/glibc skew that lands stx_ino in
 *     the stx_size slot, or stx_blocks in stx_blksize.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - sibling-thread rename / replace of the path component between the
 *     original lookup and the recheck (caught only because we resolved
 *     the snapshotted path and got a different inode).
 *
 * TOCTOU defeat (five buffers worth of it): pathname, flags, mask, and
 * statxbuf are all reachable from sibling-scribbleable user memory or
 * shared bookkeeping.  The five input args (dfd, pathname, flags, mask,
 * statxbuf) are snapshotted at sanitise time into a heap struct in
 * rec->post_state, so a sibling that scribbles rec->aN between syscall
 * return and post entry cannot retarget the dfd, redirect the strncpy
 * at a foreign pathname, smear the flags or mask used to seed the
 * re-issue, or steer the memcpy at a foreign statxbuf.  We still copy
 * the path into a PATH_MAX stack buffer and the original statx result
 * into a stack-local before re-issuing, so a sibling that scribbles the
 * user buffers themselves between the two reads cannot smear the
 * comparison.  Switching flags between calls would change lookup
 * semantics (NOFOLLOW vs follow, sync mode) and produce a benign
 * "different inode" or "different field" divergence that is purely an
 * artifact of our own race window — preserving the snapshotted flags
 * eliminates that source.  The mask preservation matters too:
 * requesting different fields the second time would shift which bits
 * the kernel sets in stx_mask and break the intersection logic.
 *
 * If the recheck syscall itself fails, a sibling has closed the dfd,
 * unlinked the path, or scribbled the statxbuf into an unmapped region;
 * all benign.  Treat any non-zero return from syscall(SYS_statx) as
 * "give up, sample skipped" so we never report on a torn-down path or
 * descriptor.  Sample one in a hundred to stay in line with the rest of
 * the oracle family; compare each field individually with no early-return
 * so multi-field corruption surfaces in a single sample, but bump the
 * anomaly counter only once per sample.
 */
static void post_statx(struct syscallrecord *rec)
{
	struct statx_post_state *snap;
	struct statx first, recheck;
	char local_path[PATH_MAX];
	unsigned int flags, mask, valid_mask;
	unsigned long retval;
	int dfd;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, STATX_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	/*
	 * Snapshot rec->retval once.  rec lives in the child's shm
	 * region; the original handler read rec->retval twice -- the
	 * STATX_TYPE cheap-oracle gate ((long) rec->retval == 0) and
	 * the field-divergence recheck gate ((long) rec->retval != 0)
	 * -- so a sibling-child stomp or a signal-handler reschedule
	 * rewriting the slot between the two reads can let the
	 * cheap-oracle path run on what it thinks is a success while
	 * the recheck path simultaneously sees a non-zero return, or
	 * vice versa.  The cheap oracle would then read the user
	 * buffer for an mxsk check on a call that actually failed,
	 * driving statx_oracle_anomalies on a memory-corruption shape
	 * rather than a real ABI break.  Same multi-read race the
	 * epoll post handlers had (commit 48279ed126bb).
	 */
	retval = rec->retval;

	/*
	 * Cheap stx_mask oracle: runs on every successful statx, not
	 * gated by the ONE_IN(100) sample of the field-divergence
	 * recheck below.  On success the kernel must report which
	 * fields it filled via returned->stx_mask; the kernel may
	 * legally clear newer bits it does not support (STATX_SUBVOL,
	 * STATX_DIOALIGN, STATX_WRITE_ATOMIC, ...) but STATX_TYPE has
	 * been mandatory since the syscall landed, so a cleared
	 * STATX_TYPE on a successful return where it was requested
	 * fingerprints a torn copy_to_user, a struct-layout drift on
	 * a kernel/glibc skew, or a sibling scribble of the receive
	 * buffer between the kernel's fill and our post-hook read.
	 */
	if ((long) retval == 0 && snap->statxbuf != 0) {
		void *buf = (void *)(unsigned long) snap->statxbuf;
		unsigned int req_mask = (unsigned int) snap->mask;
		unsigned int got_mask;

		if (post_snapshot_or_skip(&got_mask,
					  (char *)buf + offsetof(struct statx, stx_mask),
					  sizeof(got_mask))) {
			if ((req_mask & STATX_TYPE) && !(got_mask & STATX_TYPE)) {
				output(0,
				       "statx oracle: STATX_TYPE requested "
				       "(mask=0x%x) but kernel returned "
				       "stx_mask=0x%x on success "
				       "(dfd=%ld flags=0x%lx)\n",
				       req_mask, got_mask,
				       (long) snap->dfd, snap->flags);
				__atomic_add_fetch(&shm->stats.oracle.statx_oracle_anomalies,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	/*
	 * Untouched-buffer check: statx returned 0 (success) but the
	 * user buffer still byte-for-byte matches the poison pattern we
	 * stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Runs on every success (not gated by
	 * the ONE_IN(100) below) so the untouched-buffer signal is not
	 * diluted by the sampling that throttles the equality re-issue
	 * oracle; poison_seed == 0 means sanitise skipped the stamp and
	 * the arm no-ops.  A hit on this arm would also fire the cheap
	 * stx_mask oracle above (poison leaves stx_mask == 0, tripping
	 * the STATX_TYPE-requested-but-not-set check whenever the caller
	 * asked for STATX_TYPE) and the field-level recheck below on the
	 * ONE_IN(100) arm, but the dedicated counter is the cheapest
	 * no-re-issue signal.
	 */
	if ((long) retval == 0 && snap->statxbuf != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->statxbuf,
					     sizeof(struct statx),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if ((long) retval != 0)
		goto out_release;

	if (snap->pathname == 0 || snap->statxbuf == 0)
		goto out_release;

	dfd = (int) snap->dfd;

	if (!post_snapshot_str(local_path, sizeof(local_path),
			       (const char *)(unsigned long) snap->pathname))
		goto out_release;
	flags = (unsigned int) snap->flags;
	mask = (unsigned int) snap->mask;
	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->statxbuf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_statx, dfd, local_path, flags, mask, &recheck) != 0)
		goto out_release;

	valid_mask = first.stx_mask & recheck.stx_mask;

	if (valid_mask & (STATX_TYPE | STATX_MODE))
		if (first.stx_mode != recheck.stx_mode) diverged = 1;
	if (valid_mask & STATX_NLINK)
		if (first.stx_nlink != recheck.stx_nlink) diverged = 1;
	if (valid_mask & STATX_UID)
		if (first.stx_uid != recheck.stx_uid) diverged = 1;
	if (valid_mask & STATX_GID)
		if (first.stx_gid != recheck.stx_gid) diverged = 1;
	if (valid_mask & STATX_INO)
		if (first.stx_ino != recheck.stx_ino) diverged = 1;
	if (valid_mask & STATX_SIZE)
		if (first.stx_size != recheck.stx_size) diverged = 1;
	if (valid_mask & STATX_BLOCKS)
		if (first.stx_blocks != recheck.stx_blocks) diverged = 1;

	if (first.stx_blksize    != recheck.stx_blksize)    diverged = 1;
	if (first.stx_dev_major  != recheck.stx_dev_major)  diverged = 1;
	if (first.stx_dev_minor  != recheck.stx_dev_minor)  diverged = 1;
	if (first.stx_rdev_major != recheck.stx_rdev_major) diverged = 1;
	if (first.stx_rdev_minor != recheck.stx_rdev_minor) diverged = 1;

	if (!diverged)
		goto out_release;

	output(0,
	       "statx oracle anomaly: dfd=%d path=%s flags=%x mask=%x valid_mask=%x "
	       "first={mask=%x,mode=%o,nlink=%u,uid=%u,gid=%u,ino=%llu,size=%llu,"
	       "blocks=%llu,blksize=%u,dev=%u:%u,rdev=%u:%u} "
	       "recall={mask=%x,mode=%o,nlink=%u,uid=%u,gid=%u,ino=%llu,size=%llu,"
	       "blocks=%llu,blksize=%u,dev=%u:%u,rdev=%u:%u}\n",
	       dfd, local_path, flags, mask, valid_mask,
	       (unsigned int) first.stx_mask, (unsigned int) first.stx_mode,
	       (unsigned int) first.stx_nlink, (unsigned int) first.stx_uid,
	       (unsigned int) first.stx_gid,
	       (unsigned long long) first.stx_ino,
	       (unsigned long long) first.stx_size,
	       (unsigned long long) first.stx_blocks,
	       (unsigned int) first.stx_blksize,
	       (unsigned int) first.stx_dev_major, (unsigned int) first.stx_dev_minor,
	       (unsigned int) first.stx_rdev_major, (unsigned int) first.stx_rdev_minor,
	       (unsigned int) recheck.stx_mask, (unsigned int) recheck.stx_mode,
	       (unsigned int) recheck.stx_nlink, (unsigned int) recheck.stx_uid,
	       (unsigned int) recheck.stx_gid,
	       (unsigned long long) recheck.stx_ino,
	       (unsigned long long) recheck.stx_size,
	       (unsigned long long) recheck.stx_blocks,
	       (unsigned int) recheck.stx_blksize,
	       (unsigned int) recheck.stx_dev_major, (unsigned int) recheck.stx_dev_minor,
	       (unsigned int) recheck.stx_rdev_major, (unsigned int) recheck.stx_rdev_minor);

	__atomic_add_fetch(&shm->stats.oracle.statx_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_statx = {
	.name = "statx",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_LIST, [4] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "mask", [4] = "buffer" },
	.arg_params[2].list = ARGLIST(statx_flags),
	.arg_params[3].list = ARGLIST(statx_mask),
	.sanitise = sanitise_statx,
	.post = post_statx,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
