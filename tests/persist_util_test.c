/*
 * Self-check for persist_mkdir_p() (utils/persist-util.c): it makes every
 * missing component of a path 0755 whatever the umask, restores the umask
 * and the path, takes a path that exists already, and refuses one through
 * a file or ending at one.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
	rmdir(base);
}
