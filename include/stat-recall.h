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
