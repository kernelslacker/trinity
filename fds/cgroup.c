/* cgroup directory FDs (O_PATH on /sys/fs/cgroup subgroups) plus
 * O_RDWR control-file FDs under a trinity-created sacrificial sub-cgroup
 * so fd-arg syscalls (write / read / ftruncate / fallocate) exercise the
 * cgroup v2 control-file parse handlers (pid-list parsing in
 * cgroup.procs, token parsing in cgroup.subtree_control, value parsing
 * in memory.max / cgroup.events) instead of skipping past every non-
 * directory in /sys/fs/cgroup.
 */

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cgroup.h"
#include "fd.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define CGROUP_ROOT		"/sys/fs/cgroup"
#define CGROUP_INIT_POOL	8

/*
 * cgroup v2 control files opened O_RDWR under the sacrificial sub-cgroup.
 * Every entry is probed and a missing file (controller not enabled in this
 * subtree) skips silently.  Bounded to keep the per-provider pool depth
 * in the same order of magnitude as CGROUP_INIT_POOL above.
 */
static const char * const cgroup_ctl_files[] = {
	"cgroup.procs",
	"cgroup.subtree_control",
	"cgroup.events",
	"memory.max",
	"cpu.max",
	"io.max",
};

/*
 * Absolute path of the sacrificial sub-cgroup.  Empty when the feature
 * did not activate (dry-run gate, missing v2 line in /proc/self/cgroup,
 * mkdir failed with EACCES / EROFS / EPERM, path truncation).  Cleared
 * back to empty once atexit rmdir has run so a re-armed init is a no-op.
 */
static char sacrificial_cg_path[PATH_MAX];
static bool sacrificial_atexit_armed;

static int open_cgroup_dir(const char *path)
{
	return open(path, O_PATH | O_CLOEXEC | O_DIRECTORY);
}

static bool register_cgroup_fd(int fd)
{
	struct object *obj;

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->cgroupfdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_CGROUP);
	return true;
}

/*
 * Read the v2 line ("0::") of /proc/self/cgroup into @out.  Returns true
 * on a non-empty path that fit in the buffer, false on a missing v2 line
 * (pure v1 host), unreadable proc, or truncation.  The trailing newline
 * is stripped.
 */
static bool read_self_v2_cg(char *out, size_t len)
{
	FILE *f;
	char line[PATH_MAX + 32];
	bool ok = false;

	f = fopen("/proc/self/cgroup", "re");
	if (f == NULL)
		return false;
	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line + 3;
		size_t slen;

		if (strncmp(line, "0::", 3) != 0)
			continue;
		slen = strlen(p);
		while (slen > 0 && (p[slen - 1] == '\n' || p[slen - 1] == '\r'))
			p[--slen] = '\0';
		if (slen == 0)
			break;
		if (slen >= len)
			break;
		memcpy(out, p, slen + 1);
		ok = true;
		break;
	}
	fclose(f);
	return ok;
}

/*
 * rmdir the sacrificial sub-cgroup at process exit.  Best-effort: a
 * fuzzed write that migrated a live process into cgroup.procs leaves the
 * directory non-empty and rmdir returns EBUSY.  The kernel reaps the
 * empty cgroup once the migrated processes exit, so any leaked directory
 * only survives briefly beyond trinity's own exit.
 */
static void sacrificial_cg_cleanup(void)
{
	if (sacrificial_cg_path[0] == '\0')
		return;
	(void)rmdir(sacrificial_cg_path);
	sacrificial_cg_path[0] = '\0';
}

/*
 * Publish O_RDWR fds on cgroup v2 control files under a trinity-owned
 * sacrificial leaf sub-cgroup so fd-arg syscalls hit their write/parse
 * paths.  The sacrificial dir has no member processes and no children:
 * a fuzzed write to cgroup.procs / subtree_control cannot migrate a
 * process out of a foreign cgroup or toggle controllers at the cgroup
 * root -- the only visible effect is inside our own leaf.
 *
 * Every step probe/skips on failure so a host without cgroup v2 write
 * delegation (mkdir returns EACCES / EROFS / EPERM), a build with
 * dry_run set, a missing v2 line in /proc/self/cgroup (pure cgroup v1
 * host), or a current cgroup that is not one self_cgroup_setup carved
 * out for us all leave the on-disk cgroup hierarchy untouched.  The
 * existing O_PATH dir fd pool populated by the caller is not affected
 * in any of these cases.
 *
 * The self_cgroup gate is load-bearing: our current cgroup must be
 * inside utils/self_cgroup.c's "trinity-<pid>" container before we
 * mkdir a sibling under it.  A host where self_cgroup_setup fell back
 * to the outer scope leaves that marker absent and the whole feature
 * short-circuits before mkdir, so the smoke path (or any build that
 * lands trinity in a foreign scope) never creates a cgroup we did not
 * plan to own.
 */
static void init_cgroup_ctl_fds(void)
{
	char self_cg[PATH_MAX];
	char trinity_marker[64];
	unsigned int i;

	/* dry_run's contract is "run arg-gen + sanitise, skip the syscall";
	 * even when dry_run does end up true, stay inert here so a fuzzed
	 * dry-run repro path doesn't fault-inject cgroup mutation. */
	if (dry_run)
		return;

	if (!read_self_v2_cg(self_cg, sizeof(self_cg)))
		return;

	/* Only carve a sacrificial sub-cgroup out of a cgroup that
	 * self_cgroup_setup() carved out for trinity in the first place --
	 * the "trinity-<mypid>" segment names that container in both the
	 * split (.../trinity-<pid>/parent) and single-cgroup (.../
	 * trinity-<pid>) layouts.  A build host where self_cgroup fell back
	 * (delegation missing, cap wrapper already in place, --no-cgroup)
	 * leaves us in the outer scope where a mkdir would land next to
	 * unrelated services; require the marker to prove ownership before
	 * touching /sys/fs/cgroup.  Segment-name check (leading '/', no
	 * trailing '/') keeps a user cgroup coincidentally named
	 * "not-trinity-1" from tripping the gate. */
	if ((size_t)snprintf(trinity_marker, sizeof(trinity_marker),
			     "/trinity-%d", (int)mypid()) >= sizeof(trinity_marker))
		return;
	{
		const char *hit = strstr(self_cg, trinity_marker);
		size_t mlen = strlen(trinity_marker);

		if (hit == NULL)
			return;
		if (hit[mlen] != '\0' && hit[mlen] != '/')
			return;
	}

	/* Fold the v2 path into an absolute /sys/fs/cgroup<self_cg>/
	 * fuzzctl-<pid> path.  Truncation (deeply nested scope + long
	 * session id + the suffix) skips the whole feature rather than
	 * mkdir'ing a partial path. */
	if ((size_t)snprintf(sacrificial_cg_path, sizeof(sacrificial_cg_path),
			     "%s%s/fuzzctl-%d", CGROUP_ROOT, self_cg,
			     (int)mypid()) >= sizeof(sacrificial_cg_path)) {
		sacrificial_cg_path[0] = '\0';
		return;
	}

	if (mkdir(sacrificial_cg_path, 0755) != 0 && errno != EEXIST) {
		sacrificial_cg_path[0] = '\0';
		return;
	}

	/* Arm atexit only once we own a live sacrificial dir; a subsequent
	 * init call is a no-op because the path is captured up-front. */
	if (!sacrificial_atexit_armed) {
		sacrificial_atexit_armed = true;
		atexit(sacrificial_cg_cleanup);
	}

	for (i = 0; i < ARRAY_SIZE(cgroup_ctl_files); i++) {
		char path[PATH_MAX];
		int fd;

		if ((size_t)snprintf(path, sizeof(path), "%s/%s",
				     sacrificial_cg_path,
				     cgroup_ctl_files[i]) >= sizeof(path))
			continue;
		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd < 0)
			continue;
		if (!register_cgroup_fd(fd))
			return;
	}
}

static int init_cgroup_fds(void)
{
	struct objhead *head;
	struct dirent *entry;
	unsigned int added = 0;
	DIR *dir;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_CGROUP);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

	/* Always register the root itself first; it's the one cgroup dir
	 * we're certain exists if /sys/fs/cgroup is mounted at all. */
	fd = open_cgroup_dir(CGROUP_ROOT);
	if (fd >= 0) {
		if (register_cgroup_fd(fd) == false)
			return false;
		added++;
	}

	dir = opendir(CGROUP_ROOT);
	if (dir == NULL) {
		init_cgroup_ctl_fds();
		return added > 0;
	}

	while (added < CGROUP_INIT_POOL) {
		char path[PATH_MAX];
		struct stat st;

		entry = readdir(dir);
		if (entry == NULL)
			break;
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		if (snprintf(path, sizeof(path), "%s/%s",
			     CGROUP_ROOT, entry->d_name) >= (int)sizeof(path))
			continue;

		/* Skip non-directories (cgroup.procs, cpu.stat, ...). */
		if (lstat(path, &st) < 0)
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;

		fd = open_cgroup_dir(path);
		if (fd < 0)
			continue;

		if (register_cgroup_fd(fd) == false) {
			closedir(dir);
			return false;
		}
		added++;
	}

	closedir(dir);

	/* Additive: on a host with cgroup v2 write delegation, publish a
	 * bounded set of control files O_RDWR under a sacrificial sub-cgroup
	 * so fd-arg syscalls exercise the kernel's control-file parse
	 * handlers.  Failures degrade silently (see init_cgroup_ctl_fds). */
	init_cgroup_ctl_fds();

	return added > 0;
}

int get_rand_cgroup_fd(void)
{
	if (objects_empty(OBJ_FD_CGROUP) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->cgroupfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of the
	 * returned cgroup fd, the parent can destroy the obj; release_obj()
	 * zeroes the chunk and routes it through deferred-free, so the
	 * stale slot pointer can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_CGROUP, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_CGROUP))
			continue;

		fd = obj->cgroupfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider cgroup_fd_provider = {
	.name = "cgroup",
	.objtype = OBJ_FD_CGROUP,
	.enabled = true,
	.init = &init_cgroup_fds,
	.get = &get_rand_cgroup_fd,
};

REG_FD_PROV(cgroup_fd_provider);
