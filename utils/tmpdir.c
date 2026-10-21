/*
 * trinity's tmp/ working directory: change_tmp_dir() moves the parent
 * into it at startup, and trinity_tmpdir_abs() hands its absolute path
 * to everything that has to find it again after a fuzzed chdir().
 */
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tmpdir.h"
#include "trinity.h"

/*
 * Absolute path of trinity's tmp/ directory, resolved once at startup
 * inside change_tmp_dir().  Used by the per-child crash log redirect in
 * signals.c so the path is stable even if a child fuzzes chdir() out
 * from under itself.  Empty string until change_tmp_dir() succeeds;
 * trinity_tmpdir_abs() returns "/tmp" as a safe fallback in that case
 * so a degraded run still puts the log somewhere writable.
 */
static char tmp_dir_abs[PATH_MAX];

const char *trinity_tmpdir_abs(void)
{
	return tmp_dir_abs[0] ? tmp_dir_abs : "/tmp";
}

/*
 * just in case we're not using the test.sh harness, we
 * change to the tmp dir if it exists.
 */
void change_tmp_dir(void)
{
	struct stat sb;
	const char tmpdir[]="tmp/";
	int ret;

	/* Check if it exists, bail early if it doesn't */
	ret = (lstat(tmpdir, &sb));
	if (ret == -1)
		return;

	/* Just in case a previous run screwed the perms. */
	ret = chmod(tmpdir, 0777);
	if (ret == -1)
		output(0, "Couldn't chmod %s to 0777.\n", tmpdir);

	ret = chdir(tmpdir);
	if (ret == -1) {
		output(0, "Couldn't change to %s\n", tmpdir);
		return;
	}

	/* Resolve tmp/ to an absolute path so the per-child crash log
	 * redirect in signals.c lands in the right place even after a
	 * fuzzed chdir() in the child.  Best-effort -- on failure we fall
	 * back to /tmp via trinity_tmpdir_abs(). */
	if (getcwd(tmp_dir_abs, sizeof(tmp_dir_abs)) == NULL)
		tmp_dir_abs[0] = '\0';
}
