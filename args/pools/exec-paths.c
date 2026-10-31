/*
 * Executable-file pool for the uprobe_multi path fill: absolute
 * paths of regular files with an execute bit, scanned lazily on
 * first use from the top level of the bin directories (no recursion
 * -- binaries live at the top, and a recursive walk is unbounded).
 * /bin is a symlink to /usr/bin on merged-usr systems, so a directory
 * that stat()s to one already scanned is skipped.  When the scan yields
 * nothing, /proc/self/exe -- the fuzzer's own binary, always an ELF --
 * is the fallback when it is executable.  An empty pool leaves the
 * path fill on random bytes, the pre-pool shape.
 */

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "exec-paths.h"
#include "rnd.h"
#include "utils-macros.h"

#define EXEC_PATHS_CAP		1024U

static const char *exec_dirs[] = {
	"/bin",
	"/usr/bin",
};

static const char *exec_paths[EXEC_PATHS_CAP];
static unsigned int num_exec_paths;
static bool exec_paths_built;

static void exec_paths_add(const char *path)
{
	char *copy;

	if (num_exec_paths >= EXEC_PATHS_CAP)
		return;
	copy = strdup(path);
	if (copy == NULL)
		return;
	exec_paths[num_exec_paths++] = copy;
}

static void exec_paths_scan_dir(const char *dir)
{
	DIR *d;
	struct dirent *entry;

	d = opendir(dir);
	if (d == NULL)
		return;
	while (num_exec_paths < EXEC_PATHS_CAP &&
	       (entry = readdir(d)) != NULL) {
		size_t len;
		char *full;
		struct stat st;

		if (entry->d_name[0] == '.')
			continue;
		len = strlen(dir) + 1 + strlen(entry->d_name) + 1;
		full = malloc(len);
		if (full == NULL)
			continue;
		snprintf(full, len, "%s/%s", dir, entry->d_name);
		if (stat(full, &st) == 0 && S_ISREG(st.st_mode) &&
		    (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)
			exec_paths_add(full);
		free(full);
	}
	closedir(d);
}

static void exec_paths_build(void)
{
	struct stat scanned[ARRAY_SIZE(exec_dirs)];
	unsigned int nr_scanned = 0;
	unsigned int i, j;

	if (exec_paths_built)
		return;
	exec_paths_built = true;

	for (i = 0; i < ARRAY_SIZE(exec_dirs); i++) {
		struct stat st;

		if (stat(exec_dirs[i], &st) != 0)
			continue;
		for (j = 0; j < nr_scanned; j++) {
			if (scanned[j].st_dev == st.st_dev &&
			    scanned[j].st_ino == st.st_ino)
				break;
		}
		if (j < nr_scanned)
			continue;
		scanned[nr_scanned++] = st;
		exec_paths_scan_dir(exec_dirs[i]);
	}

	if (num_exec_paths == 0 &&
	    access("/proc/self/exe", X_OK) == 0)
		exec_paths_add("/proc/self/exe");
}

const char *exec_path_pick(void)
{
	exec_paths_build();
	if (num_exec_paths == 0)
		return NULL;
	return exec_paths[rnd_modulo_u32(num_exec_paths)];
}

unsigned int exec_paths_count(void)
{
	exec_paths_build();
	return num_exec_paths;
}

const char *exec_path_at(unsigned int i)
{
	exec_paths_build();
	if (i >= num_exec_paths)
		return NULL;
	return exec_paths[i];
}
