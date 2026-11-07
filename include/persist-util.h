#pragma once

#include <stddef.h>

void persist_sweep_stale_tmp(const char *path);

/*
 * mkdir -p @dir, each component 0755 whatever the umask.  @dir is written
 * while the components are walked and restored before the return.
 * Returns 0 once the whole path exists, or -1 with errno set.
 */
int persist_mkdir_p(char *dir);

/*
 * The default path of a file holding one arch's and one kernel release's
 * state: <cache>/trinity/@subdir/<arch>-<release>, where <cache> is
 * $XDG_CACHE_HOME, or $HOME/.cache when that is unset or relative, and
 * <release> is uname()'s with any '/' made '_'.  Makes the directory.
 * Returns @buf, which gets the path, or NULL when neither variable names
 * an absolute directory, the path does not fit or the directory cannot be
 * made.
 */
const char *persist_default_path(const char *subdir, char *buf, size_t len);
