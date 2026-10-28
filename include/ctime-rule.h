#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

/* A kernel release as ctime_rule_holds() compares them. */
#define KERNEL_RELEASE(major, minor)	(((major) << 8) | (minor))

/*
 * Whether any change made to an inode after a getattr that read its ctime as
 * @ctime is sure to leave it another ctime, so that a later getattr finding
 * the same ctime finds the inode unchanged.  @mnt_id is the unique id of a
 * mount of the inode's filesystem (0 when there is none to go by), @before a
 * CLOCK_REALTIME_COARSE reading taken before that getattr.
 */
bool ctime_marks_change(unsigned long long mnt_id, const struct timespec *ctime,
			const struct timespec *before);

/*
 * The rule ctime_marks_change() applies, over what it gathers: @fs_type is
 * the filesystem's type name (NULL when unknown) and @release the running
 * kernel's, as KERNEL_RELEASE() packs it.
 */
bool ctime_rule_holds(const char *fs_type, unsigned int release,
		      const struct timespec *ctime, const struct timespec *before);

/*
 * The unique id of the mount the lookup of @path from @dfd ends on, statx()'s
 * @flags steering it, when the inode it finds there is @dev, @ino: 0 when it
 * is another inode, or statx() gives no unique id (before v6.8).
 */
unsigned long long stat_mnt_id(int dfd, const char *path, int flags,
			       dev_t dev, ino_t ino);
