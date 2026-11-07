/*
 * Self-check for the parent's reap of a child's inode spewer dir
 * (childops/fs/inode-spewer.c): inode_spewer_reap() empties and removes
 * trinity-inodes-<pid> under trinity_tmpdir_abs() when one of our children
 * made it, without following the links inside, and leaves alone a symlink
 * planted under the name and a dir a uid our children do not run as owns.
 */

#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "child-api.h"		/* inode_spewer_reap */
#include "debug.h"		/* BUG */
#include "tmpdir.h"
#include "uid.h"		/* orig_uid, nobody_uid */

#define PLANTED	100001		/* a symlink to ../victim */
#define OURS	100002		/* a dir one of our children made */
#define THEIRS	100003		/* a dir another uid owns */

static int tmpfd;

/* trinity-inodes-@pid in tmp/, holding what a killed spewer leaves: a
 * file, an empty dir and a symlink, this one to ../victim/file. */
static void make_spew_dir(pid_t pid)
{
	char name[32];
	int fd;

	snprintf(name, sizeof(name), "trinity-inodes-%d", (int) pid);
	if (mkdirat(tmpfd, name, 0700) != 0)
		BUG("inode spewer reap: cannot make a spew dir");
	fd = openat(tmpfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0 || mknodat(fd, "0", S_IFREG | 0600, 0) != 0 ||
	    mkdirat(fd, "d1", 0700) != 0 ||
	    symlinkat("../../victim/file", fd, "2") != 0)
		BUG("inode spewer reap: cannot fill a spew dir");
	close(fd);
}

static int remove_entry(const char *path, const struct stat *sb, int type,
			struct FTW *ftw)
{
	(void)sb;
	(void)type;
	(void)ftw;
	return remove(path);
}

void inode_spewer_self_check(void);
void inode_spewer_self_check(void)
{
	char base[] = "/tmp/trinity-spew-test.XXXXXX";
	uid_t saved_uid = orig_uid, saved_nobody_uid = nobody_uid;
	char name[32];
	int cwd;

	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0 ||
	    mkdir("tmp", 0700) != 0 || mkdir("victim", 0700) != 0 ||
	    mknod("victim/file", S_IFREG | 0600, 0) != 0)
		BUG("inode spewer reap: cannot set up the test tree");
	change_tmp_dir();
	tmpfd = open(trinity_tmpdir_abs(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (tmpfd < 0 || faccessat(tmpfd, "../victim", F_OK, 0) != 0)
		BUG("inode spewer reap: trinity_tmpdir_abs() is not the test tmp/");

	/* A root run's children are nobody, any other run's its own uid:
	 * here, either way, us. */
	orig_uid = geteuid();
	nobody_uid = geteuid();

	snprintf(name, sizeof(name), "trinity-inodes-%d", PLANTED);
	if (symlinkat("../victim", tmpfd, name) != 0)
		BUG("inode spewer reap: cannot plant a symlink");
	inode_spewer_reap(PLANTED);
	if (faccessat(tmpfd, "../victim/file", F_OK, 0) != 0)
		BUG("inode spewer reap: emptied the dir a planted symlink names");

	make_spew_dir(OURS);
	inode_spewer_reap(OURS);
	snprintf(name, sizeof(name), "trinity-inodes-%d", OURS);
	if (faccessat(tmpfd, name, F_OK, AT_SYMLINK_NOFOLLOW) == 0)
		BUG("inode spewer reap: left a child's spew dir behind");
	if (faccessat(tmpfd, "../victim/file", F_OK, 0) != 0)
		BUG("inode spewer reap: followed a symlink in a spew dir");

	make_spew_dir(THEIRS);
	orig_uid = geteuid() + 1;
	inode_spewer_reap(THEIRS);
	snprintf(name, sizeof(name), "trinity-inodes-%d/0", THEIRS);
	if (faccessat(tmpfd, name, F_OK, 0) != 0)
		BUG("inode spewer reap: emptied a dir our children do not own");

	orig_uid = saved_uid;
	nobody_uid = saved_nobody_uid;
	close(tmpfd);
	if (fchdir(cwd) != 0)
		BUG("inode spewer reap: cannot return to the starting directory");
	close(cwd);
	if (nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS) != 0)
		BUG("inode spewer reap: cannot remove the test tree");
}
