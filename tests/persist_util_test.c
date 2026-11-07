/*
 * Self-check for persist_mkdir_p() (utils/persist-util.c): it makes every
 * missing component of a path 0755 whatever the umask, restores the umask
 * and the path, takes a path that exists already, and refuses one through
 * a file or ending at one.  Then persist_cache_dir() and
 * persist_default_path(), which build on it.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "persist-util.h"

void persist_util_self_check(void);

static void expect_dir_0755(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
		BUG("persist util: a component was not made");
	if ((st.st_mode & 07777) != 0755)
		BUG("persist util: a component's mode follows the umask");
}

/* persist_default_path() names <cache>/trinity/<subdir>/<arch>-<release>,
 * <cache> being $XDG_CACHE_HOME, or $HOME/.cache when that is unset or
 * relative, makes the directory, and gives up when neither is absolute.
 * The arch is checked for shape only: one name, no '/' or '-' in it. */
static void expect_default_path(const char *cache, const char *subdir,
				const char *release)
{
	char buf[PATH_MAX], dir[PATH_MAX];
	const char *arch, *dash;
	size_t dlen;

	if (persist_default_path(subdir, buf, sizeof(buf)) != buf)
		BUG("persist util: persist_default_path refused a usable cache dir");
	snprintf(dir, sizeof(dir), "%s/trinity/%s", cache, subdir);
	expect_dir_0755(dir);
	dlen = strlen(dir);
	if (strncmp(buf, dir, dlen) != 0 || buf[dlen] != '/')
		BUG("persist util: the default path is not in the cache dir");
	arch = buf + dlen + 1;
	dash = strchr(arch, '-');
	if (dash == NULL || dash == arch || strchr(arch, '/') != NULL ||
	    strcmp(dash + 1, release) != 0)
		BUG("persist util: the default path is not <arch>-<release>");
}

static void default_path_self_check(const char *base)
{
	const char *xdg = getenv("XDG_CACHE_HOME"), *home = getenv("HOME");
	char *saved_xdg = xdg != NULL ? strdup(xdg) : NULL;
	char *saved_home = home != NULL ? strdup(home) : NULL;
	char cache[PATH_MAX], buf[PATH_MAX];
	struct utsname u;
	char *r;

	if (uname(&u) != 0)
		BUG("persist util: uname failed");
	for (r = u.release; *r != '\0'; r++) {
		if (*r == '/')
			*r = '_';
	}

	setenv("XDG_CACHE_HOME", base, 1);
	setenv("HOME", "relative", 1);
	expect_default_path(base, "corpus", u.release);
	snprintf(cache, sizeof(cache), "%s/trinity", base);
	if (!persist_cache_dir(NULL, buf, sizeof(buf)) || strcmp(buf, cache) != 0)
		BUG("persist util: persist_cache_dir(NULL) is not <cache>/trinity");
	expect_dir_0755(cache);

	setenv("XDG_CACHE_HOME", "relative", 1);
	setenv("HOME", base, 1);
	snprintf(cache, sizeof(cache), "%s/.cache", base);
	expect_default_path(cache, "kcov-bitmap", u.release);

	unsetenv("XDG_CACHE_HOME");
	setenv("HOME", "relative", 1);
	if (persist_default_path("corpus", buf, sizeof(buf)) != NULL)
		BUG("persist util: persist_default_path made a path from relative dirs");

	if (saved_xdg != NULL)
		setenv("XDG_CACHE_HOME", saved_xdg, 1);
	else
		unsetenv("XDG_CACHE_HOME");
	if (saved_home != NULL)
		setenv("HOME", saved_home, 1);
	else
		unsetenv("HOME");
	free(saved_xdg);
	free(saved_home);

	snprintf(cache, sizeof(cache), "%s/trinity/corpus", base);
	rmdir(cache);
	snprintf(cache, sizeof(cache), "%s/trinity", base);
	rmdir(cache);
	snprintf(cache, sizeof(cache), "%s/.cache/trinity/kcov-bitmap", base);
	rmdir(cache);
	snprintf(cache, sizeof(cache), "%s/.cache/trinity", base);
	rmdir(cache);
	snprintf(cache, sizeof(cache), "%s/.cache", base);
	rmdir(cache);
}

void persist_util_self_check(void)
{
	char base[] = "/tmp/trinity-persist-util-test.XXXXXX";
	char path[PATH_MAX], copy[PATH_MAX], sub[PATH_MAX];
	mode_t old;
	FILE *f;

	if (mkdtemp(base) == NULL)
		BUG("persist util: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/a/b/c", base);
	strcpy(copy, path);

	old = umask(0777);
	if (persist_mkdir_p(path) != 0)
		BUG("persist util: persist_mkdir_p failed on a fresh path");
	if (umask(old) != 0777)
		BUG("persist util: persist_mkdir_p left the umask changed");
	if (strcmp(path, copy) != 0)
		BUG("persist util: persist_mkdir_p left the path changed");

	snprintf(sub, sizeof(sub), "%s/a", base);
	expect_dir_0755(sub);
	snprintf(sub, sizeof(sub), "%s/a/b", base);
	expect_dir_0755(sub);
	expect_dir_0755(path);

	if (persist_mkdir_p(path) != 0)
		BUG("persist util: persist_mkdir_p failed on a path that exists");

	snprintf(sub, sizeof(sub), "%s/file", base);
	f = fopen(sub, "w");
	if (f == NULL)
		BUG("persist util: cannot make the blocking file");
	fclose(f);
	snprintf(sub, sizeof(sub), "%s/file/d", base);
	if (persist_mkdir_p(sub) == 0)
		BUG("persist util: persist_mkdir_p made a path through a file");

	snprintf(sub, sizeof(sub), "%s/file", base);
	if (persist_mkdir_p(sub) == 0)
		BUG("persist util: persist_mkdir_p took a file for the directory");
	unlink(sub);
	rmdir(path);
	snprintf(sub, sizeof(sub), "%s/a/b", base);
	rmdir(sub);
	snprintf(sub, sizeof(sub), "%s/a", base);
	rmdir(sub);

	default_path_self_check(base);
	rmdir(base);
}
