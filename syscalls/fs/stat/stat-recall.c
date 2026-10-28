/*
 * The verdict the stat-family re-call oracles share: an attribute that moved
 * between the fuzzed call and the re-call counts only where nothing outside
 * the kernel can have moved it.
 */
#include "ctime-rule.h"
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
