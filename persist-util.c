/*
 * Stale staging-file sweeper for persisted-state loaders.
 *
 * Persisted-state writers (minicorpus, cmp_hints, kcov-bitmap) save
 * via the classic write-to-sibling-then-rename
 * pattern: create "<path>.tmp.<pid>", fsync, rename over <path>.
 * If the process dies between fsync and rename -- watchdog SIGKILL,
 * OOM kill, segfault -- the .tmp.<pid> sibling is orphaned and
 * never cleaned up.  Across many runs these accumulate beside the
 * canonical file.
 *
 * persist_sweep_stale_tmp() runs at the top of each load function.
 * It scans the directory holding <path> for siblings matching
 * "<basename>.tmp.<digits>" and unlinks any whose PID no longer
 * refers to a live process.  Live PIDs are left alone -- they
 * belong to a concurrent trinity instance mid-save, whose tmp
 * file is about to be renamed over the target.
 *
 * Best-effort: all errors are swallowed.  A failure to sweep does
 * not block the load -- the worst case is the existing leak, which
 * the next successful sweep cleans up.
 */

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "persist-util.h"

void persist_sweep_stale_tmp(const char *path)
{
	char *dir_dup, *base_dup;
	char *dir, *base;
	size_t base_len;
	DIR *d;
	struct dirent *de;

	if (path == NULL)
		return;

	/* dirname(3) / basename(3) may modify their arg, so dup twice. */
	dir_dup = strdup(path);
	if (dir_dup == NULL)
		return;
	base_dup = strdup(path);
	if (base_dup == NULL) {
		free(dir_dup);
		return;
	}

	dir = dirname(dir_dup);
	base = basename(base_dup);
	base_len = strlen(base);

	d = opendir(dir);
	if (d == NULL)
		goto out;

	while ((de = readdir(d)) != NULL) {
		const char *name = de->d_name;
		const char *suffix;
		char *end;
		long pid;
		char fullpath[PATH_MAX];
		int n;

		/* Match "<base>.tmp.<digits>" exactly. */
		if (strncmp(name, base, base_len) != 0)
			continue;
		if (strncmp(name + base_len, ".tmp.", 5) != 0)
			continue;

		suffix = name + base_len + 5;
		if (*suffix == '\0')
			continue;

		errno = 0;
		pid = strtol(suffix, &end, 10);
		if (errno != 0 || *end != '\0')
			continue;
		if (pid <= 0 || pid > INT_MAX)
			continue;

		if (kill((pid_t)pid, 0) == 0)
			continue;
		if (errno != ESRCH)
			continue;

		n = snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, name);
		if (n < 0 || (size_t)n >= sizeof(fullpath))
			continue;

		(void)unlink(fullpath);
	}

	(void)closedir(d);

out:
	free(dir_dup);
	free(base_dup);
}
