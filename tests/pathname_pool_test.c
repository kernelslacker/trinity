/*
 * Self-check for the pathname pool (args/pools/pathnames.c): each -V
 * directory, up to the parser's MAX_VICTIM_PATHS, gets a pool of its own,
 * so get_filename(), which draws a pool first, reaches the last
 * directory's files as it does the first's.  The directories are made
 * under /tmp, one file in each.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "params.h"		/* MAX_VICTIM_PATHS */
#include "pathnames.h"		/* generate_filelist, get_filename, fileindex */
#include "utils.h"		/* waitpid_eintr */

/* Owned by main/params/state.c in production. */
char *victim_paths[MAX_VICTIM_PATHS];
unsigned int nr_victim_paths;

/* More directories than the pool table once held. */
#define NR_DIRS		6
/* Draws, all of which miss a pool one time in about 10^79. */
#define DRAWS		1000

#define DIR_TEMPLATE	"/tmp/trinity-pathname-test.XXXXXX"

/*
 * A shutdown that lands part way through the walk has generate_filelist()
 * return with files counted and pools set but no index built.  A child
 * builds a pool and drops its index, as that return leaves it: both
 * getters answer NULL rather than read it.  A child, since the pool is
 * built only once.
 */
static void getters_survive_an_unbuilt_index(char *dir)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		BUG("pathname pool: fork failed");
	if (pid == 0) {
		victim_paths[0] = dir;
		nr_victim_paths = 1;
		generate_filelist();
		fileindex = NULL;
		_exit(get_filename() == NULL && get_filename_for_pool(0) == NULL ?
		      0 : 1);
	}
	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		BUG("pathname pool: a getter read the index an aborted walk never built");
}

void pathname_pool_self_check(void);
void pathname_pool_self_check(void)
{
	char dirs[NR_DIRS][sizeof(DIR_TEMPLATE)];
	char files[NR_DIRS][sizeof(DIR_TEMPLATE) + 2];
	bool reached = false;
	unsigned int i;
	FILE *f;

	for (i = 0; i < NR_DIRS; i++) {
		strcpy(dirs[i], DIR_TEMPLATE);
		if (mkdtemp(dirs[i]) == NULL)
			BUG("pathname pool: cannot make a test directory");
		snprintf(files[i], sizeof(files[i]), "%s/f", dirs[i]);
		f = fopen(files[i], "w");
		if (f == NULL)
			BUG("pathname pool: cannot make a test file");
		fclose(f);
		victim_paths[i] = dirs[i];
	}
	nr_victim_paths = NR_DIRS;

	getters_survive_an_unbuilt_index(dirs[0]);
	generate_filelist();
	for (i = 0; i < DRAWS && !reached; i++) {
		const char *name = get_filename();

		reached = name != NULL &&
			  strncmp(name, dirs[NR_DIRS - 1], strlen(dirs[0])) == 0;
	}

	for (i = 0; i < NR_DIRS; i++) {
		(void) unlink(files[i]);
		(void) rmdir(dirs[i]);
		victim_paths[i] = NULL;
	}
	nr_victim_paths = 0;

	if (!reached)
		BUG("pathname pool: the last -V directory's files were never drawn");
}
