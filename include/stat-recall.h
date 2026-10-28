#pragma once

#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Whether a stat-family call's re-call found an attribute of the inode moved
 * while nothing could have moved it, which is the kernel's doing.  @first is
 * the fuzzed call's answer and @recheck the re-call's; the lookup of @path
 * from @dfd, statx()'s @flags steering it, finds the inode again for its
 * mount, and @before is the coarse clock read before the fuzzed call.
 */
bool stat_recall_diverged(const struct stat *first, const struct stat *recheck,
			  int dfd, const char *path, int flags,
			  const struct timespec *before);

struct statx;

/*
 * The same verdict for statx(), over the fields both answers' stx_mask
 * vouch for: an answer that filled no stx_ino or stx_ctime cannot say the
 * inode held, so it is not judged.
 */
bool statx_recall_diverged(const struct statx *first,
			   const struct statx *recheck,
			   int dfd, const char *path, int flags,
			   const struct timespec *before);
