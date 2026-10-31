/*
 * Helpers for persisted-state files: the stale staging-file sweeper (writers
 * save via "<path>.tmp.<pid>" and rename over <path>, so one killed between
 * fsync and rename orphans its sibling; best-effort, never blocks a load),
 * and the mkdir -p the cache paths are made with.
 */

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

		/* A live PID is a concurrent instance mid-save: its tmp file
		 * is about to be renamed over the target. */
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

/*
 * The umask is 0 for the cascade so every component comes out 0755, as the
 * saved files are fchmod()ed to 0644 whatever it is.  EEXIST is fine at each
 * level: what counts is that the directory exists afterwards, not which
 * racing creator made it.
 */
int persist_mkdir_p(char *dir)
{
	mode_t saved_umask = umask(0);
	int ret = 0;
	char *p;

	for (p = dir + 1; *p != '\0' && ret == 0; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			ret = -1;
		*p = '/';
	}
	if (ret == 0 && mkdir(dir, 0755) != 0 && errno != EEXIST)
		ret = -1;
	(void) umask(saved_umask);
	return ret;
}
