/*
 * trinity's tmp/ working directory: change_tmp_dir() moves the parent
 * into it, trinity_tmpdir_abs() returns its absolute path for use after
 * a fuzzed chdir(), make_scratch_dir() creates per-pid scratch dirs in
 * it and sweep_dead_pid_dirs() removes those whose run has died.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tmpdir.h"
#include "trinity.h"

/*
 * Absolute path of trinity's tmp/ directory, resolved once at startup
 * inside change_tmp_dir().  Used by the per-child crash log redirect in
 * health/signals-precrash.c so the path is stable even if a child
 * fuzzes chdir() out from under itself.  Empty string until
 * change_tmp_dir() succeeds; trinity_tmpdir_abs() returns "/tmp" as a
 * safe fallback in that case so a degraded run still puts the log
 * somewhere writable.
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
	 * redirect in health/signals-precrash.c lands in the right
	 * place even after a fuzzed chdir() in the child.  Best-effort
	 * -- on failure we fall back to /tmp via trinity_tmpdir_abs(). */
	if (getcwd(tmp_dir_abs, sizeof(tmp_dir_abs)) == NULL)
		tmp_dir_abs[0] = '\0';
}

/*
 * mkdir a per-run scratch dir, or adopt one that a dead run with our
 * pid left behind.  Only a directory we own is adopted: scratch dirs
 * live in a world-writable directory (tmp/ is 0777, /tmp is shared), so
 * anything else under the name may have been planted.  Returns NULL, or
 * why @path cannot be used.
 */
const char *make_scratch_dir(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) == 0)
		return NULL;
	if (errno != EEXIST)
		return strerror(errno);
	if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
	    st.st_uid != geteuid())
		return "exists and is not a directory we own";
	return NULL;
}

/*
 * Unlink the sockets in dir @name under @parent.  O_NOFOLLOW, so a
 * symlink planted under the dir's name cannot aim the unlinks at
 * another directory.  Anything that is not a socket stays, and keeps
 * the dir.
 */
static void unlink_sockets(int parent, const char *name)
{
	struct dirent *de;
	DIR *dir;
	int fd;

	fd = openat(parent, name,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return;
	dir = fdopendir(fd);
	if (dir == NULL) {
		close(fd);
		return;
	}

	while ((de = readdir(dir)) != NULL) {
		struct stat st;

		if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
		    S_ISSOCK(st.st_mode))
			(void) unlinkat(fd, de->d_name, 0);
	}
	closedir(dir);
}

/*
 * Remove the scratch dirs that dead runs left under trinity_tmpdir_abs().
 * Each is named @prefix plus the pid of the parent that created it,
 * optionally followed by '-' and a slot number, and that parent's atexit
 * teardown never runs after a SIGKILL or an ASAN build's _exit().  A
 * live pid -- our own, another trinity's, or one a dead run's pid was
 * recycled to -- keeps its dirs.
 */
void sweep_dead_pid_dirs(const char *prefix)
{
	size_t len = strlen(prefix);
	struct dirent *de;
	DIR *dir;

	dir = opendir(trinity_tmpdir_abs());
	if (dir == NULL)
		return;

	while ((de = readdir(dir)) != NULL) {
		const char *digits = de->d_name + len;
		char *end;
		long pid;

		if (strncmp(de->d_name, prefix, len) != 0 ||
		    !isdigit((unsigned char) *digits))
			continue;
		errno = 0;
		pid = strtol(digits, &end, 10);
		if (errno != 0)
			continue;
		if (*end == '-' && isdigit((unsigned char) end[1]))
			end += 1 + strspn(end + 1, "0123456789");
		if (*end != '\0')
			continue;
		if (pid <= 0 || pid > INT_MAX)
			continue;
		if (kill((pid_t) pid, 0) == 0 || errno != ESRCH)
			continue;

		/*
		 * rmdir() refuses a mount point with EBUSY, so ENOTEMPTY
		 * means entries of the dir itself: drop the sockets a
		 * bind() left behind and try again.
		 */
		if (unlinkat(dirfd(dir), de->d_name, AT_REMOVEDIR) != 0 &&
		    errno == ENOTEMPTY) {
			unlink_sockets(dirfd(dir), de->d_name);
			(void) unlinkat(dirfd(dir), de->d_name, AT_REMOVEDIR);
		}
	}
	closedir(dir);
}
