/*
 * The verdict the stat-family re-call oracles share: an attribute that moved
 * between the fuzzed call and the re-call counts only where nothing outside
 * the kernel can have moved it.
 */
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ctime-rule.h"
#include "kernel/stat.h"
#include "stat-recall.h"

/*
 * Siblings change the inode a path or fd names between the two calls: a
 * rename puts another inode at the path, and chmod, chown, link, truncate and
 * write stamp the ctime.  So a moved attribute counts only while dev, ino and
 * ctime held, and only where a held ctime means nothing changed
 * (ctime_marks_change()).  Left out, besides the timestamps a read or write
 * moves: st_blocks, which moves with no ctime stamped when xfs trims
 * speculative preallocation past EOF (xfs_free_eofblocks()) and when
 * writeback settles the delayed allocation btrfs_getattr() and ext4_getattr()
 * count, and st_blksize, which tmpfs reports from the huge page setting of
 * the moment (shmem_getattr()).
 */
bool stat_recall_diverged(const struct stat *first, const struct stat *recheck,
			  int dfd, const char *path, int flags,
			  const struct timespec *before)
{
	if (first->st_mode == recheck->st_mode &&
	    first->st_nlink == recheck->st_nlink &&
	    first->st_uid == recheck->st_uid &&
	    first->st_gid == recheck->st_gid &&
	    first->st_rdev == recheck->st_rdev &&
	    first->st_size == recheck->st_size)
		return false;

	if (first->st_dev != recheck->st_dev ||
	    first->st_ino != recheck->st_ino ||
	    first->st_ctim.tv_sec != recheck->st_ctim.tv_sec ||
	    first->st_ctim.tv_nsec != recheck->st_ctim.tv_nsec)
		return false;

	return ctime_marks_change(stat_mnt_id(dfd, path, flags,
					      first->st_dev, first->st_ino),
				  &first->st_ctim, before);
}

bool statx_recall_diverged(const struct statx *first,
			   const struct statx *recheck,
			   int dfd, const char *path, int flags,
			   const struct timespec *before)
{
	unsigned int valid = first->stx_mask & recheck->stx_mask;
	struct timespec ctime;

	if (!((valid & (STATX_TYPE | STATX_MODE)) &&
	      first->stx_mode != recheck->stx_mode) &&
	    !((valid & STATX_NLINK) && first->stx_nlink != recheck->stx_nlink) &&
	    !((valid & STATX_UID) && first->stx_uid != recheck->stx_uid) &&
	    !((valid & STATX_GID) && first->stx_gid != recheck->stx_gid) &&
	    !((valid & STATX_SIZE) && first->stx_size != recheck->stx_size) &&
	    first->stx_rdev_major == recheck->stx_rdev_major &&
	    first->stx_rdev_minor == recheck->stx_rdev_minor)
		return false;

	if (!(valid & STATX_INO) || !(valid & STATX_CTIME) ||
	    first->stx_dev_major != recheck->stx_dev_major ||
	    first->stx_dev_minor != recheck->stx_dev_minor ||
	    first->stx_ino != recheck->stx_ino ||
	    first->stx_ctime.tv_sec != recheck->stx_ctime.tv_sec ||
	    first->stx_ctime.tv_nsec != recheck->stx_ctime.tv_nsec)
		return false;

	ctime.tv_sec = first->stx_ctime.tv_sec;
	ctime.tv_nsec = first->stx_ctime.tv_nsec;
	return ctime_marks_change(stat_mnt_id(dfd, path, flags,
					      makedev(first->stx_dev_major,
						      first->stx_dev_minor),
					      first->stx_ino),
				  &ctime, before);
}
