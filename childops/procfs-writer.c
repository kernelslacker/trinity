/*
 * procfs_writer - discover writable nodes under /proc, /sys and
 * /sys/kernel/debug, then write fuzzy payloads to them.
 *
 * These pseudo-filesystems contain hundreds of hand-written kernel parsers
 * (cgroup controllers, PMU event strings, ftrace, kprobe/uprobe, sysctls,
 * per-task knobs) reachable from user space and historically a rich source
 * of bugs.  The default random-write fuzzer aims at fds returned by
 * fd-creating syscalls; it almost never hits these targets because they
 * make up a tiny slice of the total fd space.
 *
 * Discovery happens once per child: walk a small set of well-known trees
 * with a bounded recursion depth, stat() every regular file, and keep
 * those accessible W_OK by the current user.  A blocklist refuses paths
 * that would corrupt trinity itself, change panic policy, spam dmesg into
 * uselessness, or trigger sysrq from random bytes.
 *
 * Each call: pick a random entry, generate a fuzzy payload with the
 * existing rand_bytes generator, open(O_WRONLY|O_NONBLOCK), write, close.
 * Errors are ignored — most writes will EINVAL/EACCES, which is fine; the
 * goal is to exercise the kernel's write handler, not to succeed.
 *
 * One write in four uses gen_text_payload() from rand/text-payloads.c with a
 * 4 KB buffer, exercising long-string, embedded-NUL, format-specifier, and
 * numeric-boundary paths that raw garbage bytes rarely reach.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "random.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "utils.h"

#define MAX_DISCOVERY_ENTRIES	1024
#define MAX_DISCOVERY_DEPTH	3
#define PROCFS_MAX_PATH		256

enum tree_kind {
	TREE_PROC = 0,
	TREE_SYS,
	TREE_DEBUGFS,
};

struct discovered_entry {
	char path[PROCFS_MAX_PATH];
	enum tree_kind tree;
};

static struct discovered_entry *entries;
static unsigned int nr_entries;
static bool discovery_done;

/*
 * Paths whose write handler would corrupt trinity itself, change panic
 * policy, drown dmesg, or fire sysrq from random bytes.  Covers
 * /proc/self/mem AND /proc/<self_pid>/mem via the trailing-component
 * suffix check.
 */
static bool path_blocklisted(const char *path)
{
	static const char * const exact[] = {
		"/proc/sysrq-trigger",
		"/proc/sys/kernel/sysrq",
		"/proc/sys/kernel/panic",
		"/proc/sys/kernel/panic_on_oops",
		"/sys/kernel/debug/dynamic_debug/control",
	};
	size_t len = strlen(path);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(exact); i++)
		if (strcmp(path, exact[i]) == 0)
			return true;

	if (strncmp(path, "/proc/", 6) == 0) {
		if (len >= 4 && strcmp(path + len - 4, "/mem") == 0)
			return true;
		if (len >= 16 &&
		    strcmp(path + len - 16, "/coredump_filter") == 0)
			return true;
	}

	return false;
}

static enum tree_kind tree_for_path(const char *path)
{
	if (strncmp(path, "/sys/kernel/debug", 17) == 0)
		return TREE_DEBUGFS;
	if (strncmp(path, "/sys/", 5) == 0)
		return TREE_SYS;
	return TREE_PROC;
}

static void add_entry(const char *path)
{
	if (nr_entries >= MAX_DISCOVERY_ENTRIES)
		return;
	if (strlen(path) >= PROCFS_MAX_PATH)
		return;
	if (path_blocklisted(path))
		return;
	if (access(path, W_OK) != 0)
		return;

	strcpy(entries[nr_entries].path, path);
	entries[nr_entries].tree = tree_for_path(path);
	nr_entries++;
}

/*
 * Recursive descent with bounded depth.  We use lstat() so we can refuse
 * to follow symlinks — /sys is full of them and they readily form loops
 * or escape into uninteresting territory.
 */
static void walk_dir(const char *root, unsigned int depth_left)
{
	DIR *dir;
	struct dirent *de;

	if (nr_entries >= MAX_DISCOVERY_ENTRIES)
		return;

	dir = opendir(root);
	if (dir == NULL)
		return;

	while ((de = readdir(dir)) != NULL) {
		char child[PROCFS_MAX_PATH];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;

		if ((size_t)snprintf(child, sizeof(child), "%s/%s",
				     root, de->d_name) >= sizeof(child))
			continue;

		if (lstat(child, &st) != 0)
			continue;
		if (S_ISLNK(st.st_mode))
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (depth_left > 0)
				walk_dir(child, depth_left - 1);
		} else if (S_ISREG(st.st_mode)) {
			add_entry(child);
		}

		if (nr_entries >= MAX_DISCOVERY_ENTRIES)
			break;
	}

	closedir(dir);
}

/*
 * Per-task interfaces are added by explicit allowlist rather than by
 * walking /proc/<pid>/, so we don't accidentally pick up dangerous nodes
 * such as /proc/<pid>/mem or /proc/<pid>/clear_refs side effects.
 */
static void add_per_task_files(const char *base)
{
	static const char * const names[] = {
		"oom_score_adj",
		"comm",
		"projid_map",
		"gid_map",
		"uid_map",
		"setgroups",
		"loginuid",
		"sessionid",
		"timerslack_ns",
		"autogroup",
	};
	char path[PROCFS_MAX_PATH];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if ((size_t)snprintf(path, sizeof(path), "%s/%s",
				     base, names[i]) >= sizeof(path))
			continue;
		add_entry(path);
	}
}

static void discover_targets(void)
{
	char per_pid[PROCFS_MAX_PATH];

	entries = zmalloc(MAX_DISCOVERY_ENTRIES * sizeof(*entries));

	walk_dir("/sys/kernel/debug", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/kernel", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/module", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/class", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/fs/cgroup", MAX_DISCOVERY_DEPTH);
	walk_dir("/proc/sys", MAX_DISCOVERY_DEPTH);

	add_per_task_files("/proc/self");
	snprintf(per_pid, sizeof(per_pid), "/proc/%d", getpid());
	add_per_task_files(per_pid);
}

static void bump_tree_counter(enum tree_kind tree)
{
	switch (tree) {
	case TREE_PROC:
		__atomic_add_fetch(&shm->stats.procfs_writes,
				   1, __ATOMIC_RELAXED);
		break;
	case TREE_SYS:
		__atomic_add_fetch(&shm->stats.sysfs_writes,
				   1, __ATOMIC_RELAXED);
		break;
	case TREE_DEBUGFS:
		__atomic_add_fetch(&shm->stats.debugfs_writes,
				   1, __ATOMIC_RELAXED);
		break;
	}
}

static void do_one_write(const struct discovered_entry *e)
{
	unsigned char buf[256];
	/*
	 * Larger buffer for text payloads: kernel sysfs/procfs parsers read up
	 * to PAGE_SIZE, so 4 KB gives long-string generators room to exercise
	 * the buffer-length checks that 256-byte writes never reach.
	 */
	char text_buf[4096];
	unsigned int len;
	ssize_t ret __unused__;
	int fd;

	fd = open(e->path, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		return;

	if (ONE_IN(4)) {
		len = gen_text_payload(text_buf, sizeof(text_buf));
		ret = write(fd, text_buf, len);
	} else {
		len = 1 + (rand() % sizeof(buf));
		generate_rand_bytes(buf, len);
		ret = write(fd, buf, len);
	}

	close(fd);

	bump_tree_counter(e->tree);
}

bool procfs_writer(struct childdata *child)
{
	(void)child;

	if (discovery_done == false) {
		discover_targets();
		discovery_done = true;
	}

	if (nr_entries == 0)
		return true;

	do_one_write(&entries[rand() % nr_entries]);
	return true;
}
