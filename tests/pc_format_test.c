/*
 * Self-check for pc_to_source_line() (utils/pc_format.c): an addr2line that
 * stalls is killed at the timeout, and the resolver then stays off, so the
 * parent's periodic dump does not wait out the timeout again for every PC.
 * An addr2line that never answers sits first on PATH.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "pc_format.h"

void pc_format_self_check(void);

static double resolve_seconds(char *buf, size_t buflen)
{
	struct timespec t0, t1;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (pc_to_source_line((void *) pc_format_self_check, buf, buflen) != NULL)
		BUG("pc_format: a stalled addr2line resolved a PC");
	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (double) (t1.tv_sec - t0.tv_sec) +
	       (double) (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

void pc_format_self_check(void)
{
	char dir[] = "/tmp/trinity-pc-format-XXXXXX";
	char script[PATH_MAX], path[PATH_MAX * 2], buf[256];
	const char *old_path = getenv("PATH");
	char *saved_path = old_path != NULL ? strdup(old_path) : NULL;
	FILE *f;

	if (mkdtemp(dir) == NULL)
		BUG("pc_format: mkdtemp failed");
	snprintf(script, sizeof(script), "%s/addr2line", dir);
	f = fopen(script, "w");
	if (f == NULL)
		BUG("pc_format: cannot write the stand-in addr2line");
	fputs("#!/bin/sh\nexec sleep 60\n", f);
	fclose(f);
	if (chmod(script, 0755) != 0)
		BUG("pc_format: chmod failed");
	snprintf(path, sizeof(path), "%s:%s", dir,
		 saved_path != NULL ? saved_path : "/usr/bin:/bin");
	setenv("PATH", path, 1);

	resolve_seconds(buf, sizeof(buf));
	if (resolve_seconds(buf, sizeof(buf)) > 1.0)
		BUG("pc_format: the resolver ran addr2line again after it timed out");

	if (saved_path != NULL)
		setenv("PATH", saved_path, 1);
	else
		unsetenv("PATH");
	free(saved_path);
	unlink(script);
	rmdir(dir);
}
