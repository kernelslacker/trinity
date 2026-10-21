/*
 * Self-check for stop_file_requested() (include/stop-file.h): a stop
 * file counts only when it exists and is owned by the run's uid or by
 * root, judged with lstat() so a symlink to a root-owned target does not
 * pass.  The negative ownership cases need a uid we are not, so they are
 * skipped when the test binary runs as root.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "stop-file.h"

void stop_file_self_check(void);
void stop_file_self_check(void)
{
	char dir[] = "/tmp/trinity-stop-test.XXXXXX";
	char path[sizeof(dir) + sizeof("/" STOP_FILE_NAME)];
	uid_t me = getuid();
	struct stat st;
	FILE *f;

	if (mkdtemp(dir) == NULL)
		BUG("stop file: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/" STOP_FILE_NAME, dir);

	if (stop_file_requested(path, me))
		BUG("stop file: a missing file counted as a request");

	f = fopen(path, "w");
	if (f == NULL)
		BUG("stop file: cannot create the test file");
	fclose(f);

	if (!stop_file_requested(path, me))
		BUG("stop file: the run's own file was not a request");

	/* Root's file is a request for any run; "/" stands in for one. */
	if (lstat("/", &st) == 0 && st.st_uid == 0 &&
	    !stop_file_requested("/", me + 1))
		BUG("stop file: a root-owned file was not a request");

	if (me != 0) {
		if (stop_file_requested(path, me + 1))
			BUG("stop file: another user's file counted as a request");

		/* "/" is root-owned: stat() would follow the link to it. */
		if (unlink(path) != 0 || symlink("/", path) != 0)
			BUG("stop file: cannot replace the file with a symlink");
		if (stop_file_requested(path, me + 1))
			BUG("stop file: judged a symlink by its target's owner");
	}

	if (unlink(path) != 0 || rmdir(dir) != 0)
		BUG("stop file: cleanup failed");
}
