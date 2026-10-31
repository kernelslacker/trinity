#pragma once

void persist_sweep_stale_tmp(const char *path);

/*
 * mkdir -p @dir, each component 0755 whatever the umask.  @dir is written
 * while the components are walked and restored before the return.
 * Returns 0 once the whole path exists, or -1 with errno set.
 */
int persist_mkdir_p(char *dir);
