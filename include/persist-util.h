#pragma once

#include <stdbool.h>
#include <stddef.h>

void persist_sweep_stale_tmp(const char *path);

/*
 * mkdir -p @dir, each component 0755 whatever the umask.  @dir is written
 * while the components are walked and restored before the return.
 * Returns 0 once the whole path exists, or -1 with errno set.
 */
int persist_mkdir_p(char *dir);

/*
 * trinity's cache directory, <cache>/trinity, or <cache>/trinity/@subdir
 * when @subdir is not NULL, in @dir, made if missing: <cache> is
 * $XDG_CACHE_HOME, or $HOME/.cache when that is unset or relative.  False
 * when neither variable names an absolute directory, the path does not fit
 * or the directory cannot be made.
 */
bool persist_cache_dir(const char *subdir, char *dir, size_t len);

/*
 * The default path of a file holding one arch's and one kernel release's
 * state: <arch>-<release> in persist_cache_dir(@subdir), <release> being
 * uname()'s with any '/' made '_'.  Returns @buf, which gets the path, or
 * NULL when the directory or the path cannot be had.
 */
const char *persist_default_path(const char *subdir, char *buf, size_t len);
