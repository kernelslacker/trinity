/*
 * Self-check for utils/tmpdir.c's scratch dirs: make_scratch_dir() adopts
 * only a dir we own, and sweep_dead_pid_dirs() removes dead pids' dirs,
 * bind's and mount's names alike (unlinking sockets), and nothing else.
 * change_tmp_dir() points trinity_tmpdir_abs() at a private tmp/ for the
 * rest of the test run.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "tmpdir.h"
#include "utils.h"		/* ARRAY_SIZE, waitpid_eintr */

static int tmpfd;

struct expect {
	const char *path;	/* under tmp/ */
	bool present;		/* after the sweep */
	const char *why;	/* BUG text when it is not */
};

/* A pid that existed a moment ago. */
static pid_t dead_pid(void)
{
	pid_t pid = fork();

	if (pid < 0)
		BUG("tmpdir sweep: fork failed");
	if (pid == 0)
		_exit(0);
	if (waitpid_eintr(pid, NULL, 0) != pid)
		BUG("tmpdir sweep: cannot reap the forked child");
	return pid;
}

/* mkdir @name in tmp/ with socket inodes s0 .. s<nr_socks - 1> inside. */
static void make_dir(const char *name, unsigned int nr_socks)
{
	unsigned int i;
	int fd;

	if (mkdirat(tmpfd, name, 0700) != 0)
		BUG("tmpdir sweep: mkdir failed");
	fd = openat(tmpfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		BUG("tmpdir sweep: cannot open a test dir");
	for (i = 0; i < nr_socks; i++) {
		char sock[16];

		snprintf(sock, sizeof(sock), "s%u", i);
		if (mknodat(fd, sock, S_IFSOCK | 0600, 0) != 0)
			BUG("tmpdir sweep: cannot create a socket inode");
	}
	close(fd);
}

static void check(const struct expect *e, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		struct stat st;
		bool present = fstatat(tmpfd, e[i].path, &st,
				       AT_SYMLINK_NOFOLLOW) == 0;

		if (present != e[i].present)
			BUG(e[i].why);
	}
}

/* rm -r @name under @parent, without following symlinks. */
static void remove_tree(int parent, const char *name)
{
	struct dirent *de;
	DIR *dir;
	int fd;

	if (unlinkat(parent, name, 0) == 0)
		return;
	fd = openat(parent, name,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	dir = fd < 0 ? NULL : fdopendir(fd);
	if (dir == NULL)
		BUG("tmpdir sweep: cannot open a test dir for cleanup");
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
			remove_tree(fd, de->d_name);
	}
	closedir(dir);
	if (unlinkat(parent, name, AT_REMOVEDIR) != 0)
		BUG("tmpdir sweep: cleanup failed");
}

void tmpdir_self_check(void);
void tmpdir_self_check(void)
{
	char base[] = "/tmp/trinity-tmpdir-test.XXXXXX";
	char gone[32], kept[32], self[32], link[32], file[32], junk[32];
	char other[32], kept_sock[40], kept_file[40], self_sock[40];
	char junk_sock[40], slot0[32], slot1[32], slotx[32], slot1x[32];
	pid_t pid;
	int cwd;

	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0 ||
	    mkdir("tmp", 0700) != 0 || mkdir("victim", 0700) != 0 ||
	    mknod("victim/s0", S_IFSOCK | 0600, 0) != 0)
		BUG("tmpdir sweep: cannot set up the test tree");
	change_tmp_dir();
	tmpfd = open(trinity_tmpdir_abs(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (tmpfd < 0 || faccessat(tmpfd, "../victim", F_OK, 0) != 0)
		BUG("tmpdir sweep: trinity_tmpdir_abs() is not the test tmp/");

	/* The cwd is tmp/ now, so these names land in it. */
	if (make_scratch_dir("fresh") != NULL ||
	    make_scratch_dir("fresh") != NULL)
		BUG("tmpdir scratch: did not make or adopt our own dir");
	if (mknodat(tmpfd, "plain", S_IFREG | 0600, 0) != 0 ||
	    symlinkat("fresh", tmpfd, "link-to-fresh") != 0)
		BUG("tmpdir scratch: cannot create the decoys");
	if (make_scratch_dir("plain") == NULL)
		BUG("tmpdir scratch: adopted a plain file");
	if (make_scratch_dir("link-to-fresh") == NULL)
		BUG("tmpdir scratch: adopted a symlink to our dir");
	if (make_scratch_dir("missing/dir") == NULL)
		BUG("tmpdir scratch: made a dir under a missing parent");
	/* root owns "/": for anyone else it stands in for a planted dir. */
	if (geteuid() != 0 && make_scratch_dir("/") == NULL)
		BUG("tmpdir scratch: adopted another user's dir");

	snprintf(gone, sizeof(gone), "trinity-bind-%d", (int) dead_pid());
	make_dir(gone, 2);

	snprintf(kept, sizeof(kept), "trinity-bind-%d", (int) dead_pid());
	make_dir(kept, 1);
	snprintf(kept_sock, sizeof(kept_sock), "%s/s0", kept);
	snprintf(kept_file, sizeof(kept_file), "%s/keep", kept);
	if (mknodat(tmpfd, kept_file, S_IFREG | 0600, 0) != 0)
		BUG("tmpdir sweep: cannot create a plain file");

	/* pid 1 always exists: EPERM, when we are not root, still means live. */
	make_dir("trinity-bind-1", 1);

	snprintf(self, sizeof(self), "trinity-bind-%d", (int) getpid());
	make_dir(self, 1);
	snprintf(self_sock, sizeof(self_sock), "%s/s0", self);

	snprintf(link, sizeof(link), "trinity-bind-%d", (int) dead_pid());
	if (symlinkat("../victim", tmpfd, link) != 0)
		BUG("tmpdir sweep: cannot create a symlink");

	snprintf(file, sizeof(file), "trinity-bind-%d", (int) dead_pid());
	if (mknodat(tmpfd, file, S_IFREG | 0600, 0) != 0)
		BUG("tmpdir sweep: cannot create a plain file");

	snprintf(junk, sizeof(junk), "trinity-bind-%dx", (int) dead_pid());
	make_dir(junk, 1);
	snprintf(junk_sock, sizeof(junk_sock), "%s/s0", junk);

	snprintf(other, sizeof(other), "trinity-mount-%d", (int) dead_pid());
	make_dir(other, 0);

	sweep_dead_pid_dirs("trinity-bind-");

	{
		const struct expect bind_checks[] = {
			{ gone, false,
			  "tmpdir sweep: kept a dead pid's dir" },
			{ kept_sock, false,
			  "tmpdir sweep: kept a socket" },
			{ kept_file, true,
			  "tmpdir sweep: removed a file that is not a socket" },
			{ "trinity-bind-1/s0", true,
			  "tmpdir sweep: touched a live pid's dir" },
			{ self_sock, true,
			  "tmpdir sweep: touched our own dir" },
			{ link, true,
			  "tmpdir sweep: removed a symlink" },
			{ "../victim/s0", true,
			  "tmpdir sweep: followed a symlink" },
			{ file, true,
			  "tmpdir sweep: removed an entry that is not a dir" },
			{ junk_sock, true,
			  "tmpdir sweep: matched junk after the pid" },
			{ other, true,
			  "tmpdir sweep: swept another prefix" },
		};

		check(bind_checks, ARRAY_SIZE(bind_checks));
	}

	/* mount's dirs carry a slot number after the pid. */
	pid = dead_pid();
	snprintf(slot0, sizeof(slot0), "trinity-mount-%d-0", (int) pid);
	snprintf(slot1, sizeof(slot1), "trinity-mount-%d-1", (int) pid);
	snprintf(slotx, sizeof(slotx), "trinity-mount-%d-x", (int) pid);
	snprintf(slot1x, sizeof(slot1x), "trinity-mount-%d-1x", (int) pid);
	make_dir(slot0, 0);
	make_dir(slot1, 0);
	make_dir(slotx, 0);
	make_dir(slot1x, 0);
	make_dir("trinity-mount-1-0", 0);

	sweep_dead_pid_dirs("trinity-mount-");

	{
		const struct expect mount_checks[] = {
			{ slot0, false,
			  "tmpdir sweep: kept a dead pid's slot dir" },
			{ slot1, false,
			  "tmpdir sweep: kept a dead pid's slot dir" },
			{ slotx, true,
			  "tmpdir sweep: took a slot that is not a number" },
			{ slot1x, true,
			  "tmpdir sweep: took a slot that is not a number" },
			{ "trinity-mount-1-0", true,
			  "tmpdir sweep: touched a live pid's slot dir" },
		};

		check(mount_checks, ARRAY_SIZE(mount_checks));
	}

	close(tmpfd);
	if (fchdir(cwd) != 0)
		BUG("tmpdir sweep: cannot return to the starting directory");
	close(cwd);
	remove_tree(AT_FDCWD, base);
}
