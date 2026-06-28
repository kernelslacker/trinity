/*
 * SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
 *	 char __user *, type, unsigned long, flags, void __user *, data)
 */

#include <dirent.h>
#include <errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <signal.h>
#include "csfu.h"
#include "deferred-free.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

/* Filesystem types read from /proc/filesystems at startup. */
const char **filesystem_types;
unsigned int nr_filesystem_types;

/*
 * Sacrificial mount targets created in the trinity tree at startup.
 * sanitise_mount / sanitise_move_mount steer the target argument at
 * one of these instead of the random pathnames generate_pathname()
 * would otherwise hand out (/etc, /dev, /proc, ...).  Mounts that
 * actually succeed land in the per-child mount namespace and are
 * cleaned up by the child-exit teardown -- they don't pollute the
 * host namespace.
 */
#define NR_SACRIFICIAL_MOUNT_PATHS 8
static char sacrificial_mount_paths[NR_SACRIFICIAL_MOUNT_PATHS][64];
static unsigned int nr_sacrificial_mount_paths;

/*
 * Parent-only atexit teardown.  Children fork after the constructor and
 * exit via _exit(), so they never run this -- only the parent rmdirs the
 * sacrificial dirs it mkdir'd.  Idempotent + fail-soft: a dir the kernel
 * already reaped (or a stray bind-mount in the host ns we cannot break)
 * is left alone rather than aborting teardown.  Without this, every
 * trinity invocation (including --dry-run smokes that gate childops off
 * but still run constructors) leaks NR_SACRIFICIAL_MOUNT_PATHS empty
 * /tmp/trinity-mount-<pid>-N dirs into /tmp.
 */
static void cleanup_sacrificial_mount_paths(void)
{
	unsigned int i;

	for (i = 0; i < nr_sacrificial_mount_paths; i++)
		(void) rmdir(sacrificial_mount_paths[i]);
}

/*
 * Sweep /tmp for stale trinity-mount-<pid>-* dirs whose owning pid is gone.
 * atexit only catches the clean-exit path -- SIGKILL, OOM and bare _exit()
 * all skip it, so each abnormal trinity death leaks up to
 * NR_SACRIFICIAL_MOUNT_PATHS dirs.  Self-heal on the next startup by
 * rmdir'ing only the dirs whose pid no longer exists (kill(pid, 0) == ESRCH).
 * Skip live pids (some other trinity is using them) and skip our own pid
 * (we are about to mkdir those).
 */
static void sweep_dead_sacrificial_mount_paths(void)
{
	DIR *dir;
	struct dirent *de;
	pid_t self = getpid();

	dir = opendir("/tmp");
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		int pid;
		unsigned int idx;
		char path[8 + 256];

		if (sscanf(de->d_name, "trinity-mount-%d-%u", &pid, &idx) != 2)
			continue;
		if (pid <= 0 || pid == (int) self)
			continue;
		if (kill(pid, 0) == 0)
			continue;
		if (errno != ESRCH)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		(void) rmdir(path);
	}

	closedir(dir);
}

static void __attribute__((constructor)) make_sacrificial_mount_paths(void)
{
	unsigned int i;

	sweep_dead_sacrificial_mount_paths();

	for (i = 0; i < NR_SACRIFICIAL_MOUNT_PATHS; i++) {
		snprintf(sacrificial_mount_paths[i],
			 sizeof(sacrificial_mount_paths[i]),
			 "/tmp/trinity-mount-%d-%u", (int) getpid(), i);
		if (mkdir(sacrificial_mount_paths[i], 0700) == 0 ||
		    errno == EEXIST)
			nr_sacrificial_mount_paths = i + 1;
		else
			break;
	}

	if (nr_sacrificial_mount_paths > 0)
		atexit(cleanup_sacrificial_mount_paths);
}

static char *pick_sacrificial_target(void)
{
	char *target;
	const char *src;

	if (nr_sacrificial_mount_paths == 0)
		return NULL;

	target = (char *) get_writable_struct(64);
	if (!target)
		return NULL;
	src = sacrificial_mount_paths[rnd_modulo_u32(nr_sacrificial_mount_paths)];
	strncpy(target, src, 63);
	target[63] = '\0';
	return target;
}

static const char *builtin_fs_types[] = {
	"ext4", "btrfs", "xfs", "tmpfs", "proc", "sysfs",
	"devtmpfs", "devpts", "cgroup2", "overlay", "nfs",
	"fuse", "hugetlbfs", "mqueue", "debugfs", "tracefs",
	"securityfs", "pstore", "efivarfs", "bpf", "ramfs",
};

static void __attribute__((constructor)) read_filesystem_types(void)
{
	FILE *fp;
	char line[256];
	unsigned int count = 0, alloc = 64;

	fp = fopen("/proc/filesystems", "r");
	if (!fp) {
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	filesystem_types = malloc(alloc * sizeof(char *));
	if (!filesystem_types) {
		fclose(fp);
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *name;
		size_t len;

		/* Format: optional "nodev\t" prefix, then filesystem name */
		name = line;
		if (strncmp(name, "nodev", 5) == 0)
			name += 5;
		while (*name == '\t' || *name == ' ')
			name++;

		len = strlen(name);
		if (len > 0 && name[len - 1] == '\n')
			name[--len] = '\0';
		if (len == 0)
			continue;

		if (count >= alloc) {
			char **tmp;

			alloc *= 2;
			tmp = realloc(filesystem_types, alloc * sizeof(char *));
			if (!tmp)
				break;
			filesystem_types = (const char **)tmp;
		}

		filesystem_types[count] = strdup(name);
		if (!filesystem_types[count])
			break;
		count++;
	}

	fclose(fp);

	if (count == 0) {
		free(filesystem_types);
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	nr_filesystem_types = count;
}

#ifndef MS_SUBMOUNT
#define MS_SUBMOUNT	(1<<26)
#endif

#ifndef MS_NOREMOTELOCK
#define MS_NOREMOTELOCK	(1<<27)
#endif

static unsigned long mount_flags[] = {
	MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC,
	MS_SYNCHRONOUS, MS_REMOUNT, MS_MANDLOCK, MS_DIRSYNC,
	MS_NOATIME, MS_NODIRATIME, MS_BIND, MS_MOVE,
	MS_REC, MS_VERBOSE, MS_SILENT, MS_POSIXACL,
	MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE, MS_SHARED,
	MS_RELATIME, MS_KERNMOUNT, MS_I_VERSION, MS_STRICTATIME,
	MS_NOSEC, MS_BORN, MS_ACTIVE,
	MS_NOUSER,
	MS_NOSYMFOLLOW,		/* v5.10 */
	MS_LAZYTIME,		/* v4.0 */
	MS_SUBMOUNT, MS_NOREMOTELOCK,
};

/*
 * Subset of mount_flags that pass do_new_mount()'s sanity gate on a
 * fresh sb -- bias toward these so the per-fstype get_tree() callback
 * actually runs.
 */
static unsigned long mount_legal_flags[] = {
	0,
	MS_RDONLY,
	MS_NOSUID,
	MS_NODEV,
	MS_NOEXEC,
	MS_NOATIME,
	MS_NODIRATIME,
	MS_RELATIME,
	MS_BIND,
	MS_REC | MS_BIND,
	MS_REMOUNT | MS_RDONLY,
	MS_REMOUNT,
	MS_MOVE,
	MS_RDONLY | MS_NOSUID | MS_NODEV,
};

static char *write_str(const char *s)
{
	size_t len = strlen(s);
	char *buf = (char *) get_writable_struct(len + 1);

	if (!buf)
		return NULL;
	memcpy(buf, s, len + 1);
	return buf;
}

static void build_tmpfs_data(struct syscallrecord *rec)
{
	static const char *tmpfs_data[] = {
		"size=1M", "size=4k", "mode=0700", "mode=0755",
		"uid=0", "gid=0", "nr_inodes=64",
		"size=1M,mode=0755", "size=4k,uid=0,gid=0",
	};
	const char *opts;
	char *data;

	if (RAND_BOOL()) {
		rec->a5 = 0;
		return;
	}
	opts = tmpfs_data[rnd_modulo_u32(ARRAY_SIZE(tmpfs_data))];
	data = write_str(opts);
	rec->a5 = (unsigned long) data;
	avoid_shared_buffer_inout(&rec->a5, strlen(opts) + 1);
}

static void sanitise_mount(struct syscallrecord *rec)
{
	const char *fstype;
	char *type, *target;
	unsigned int pick, flagpick;

	target = pick_sacrificial_target();
	if (target)
		rec->a2 = (unsigned long) target;

	/*
	 * Fstype + source distribution:
	 *   50% tmpfs (no source needed, easy to succeed)
	 *   20% ramfs (no source needed, no data)
	 *   10% bind (existing dir as source, sacrificial as target)
	 *   10% loaded type from /proc/filesystems
	 *   10% intentionally-invalid (random byte string)
	 */
	pick = rnd_modulo_u32(10);
	if (pick < 5) {
		type = write_str("tmpfs");
		if (type)
			rec->a3 = (unsigned long) type;
		rec->a1 = (unsigned long) write_str("trinity-tmpfs");
		build_tmpfs_data(rec);
	} else if (pick < 7) {
		type = write_str("ramfs");
		if (type)
			rec->a3 = (unsigned long) type;
		rec->a1 = (unsigned long) write_str("trinity-ramfs");
		rec->a5 = 0;
	} else if (pick < 8) {
		/* bind: source must be an existing dir, fstype is ignored. */
		type = write_str("none");
		if (type)
			rec->a3 = (unsigned long) type;
		rec->a1 = (unsigned long) write_str("/tmp");
		rec->a5 = 0;
		rec->a4 = MS_BIND;
		return;
	} else if (pick < 9 && nr_filesystem_types > 0) {
		fstype = filesystem_types[rnd_modulo_u32(nr_filesystem_types)];
		type = (char *) get_writable_struct(32);
		if (type) {
			strncpy(type, fstype, 31);
			type[31] = '\0';
			rec->a3 = (unsigned long) type;
		}
	} else {
		type = (char *) get_writable_struct(16);
		if (type) {
			generate_rand_bytes((unsigned char *) type, 15);
			type[15] = '\0';
			rec->a3 = (unsigned long) type;
		}
	}

	/*
	 * Flag distribution: 70% from the legal subset, 30% random
	 * OR-of-pool (the generic_sanitise default kept untouched).
	 */
	flagpick = rnd_modulo_u32(10);
	if (flagpick < 7)
		rec->a4 = mount_legal_flags[rnd_modulo_u32(ARRAY_SIZE(mount_legal_flags))];
}

/*
 * Cross-file by design: move_mount.c references this via its own
 * forward declaration so the syscall table picks it up without a new
 * header for a single symbol.
 */
void sanitise_move_mount(struct syscallrecord *rec);

void sanitise_move_mount(struct syscallrecord *rec)
{
	char *target;

	/*
	 * Steer the to_pathname at a sacrificial directory; from_pathname
	 * stays whatever ARG_PATHNAME picked and the typed fds at a1/a3
	 * already pull from open_tree / fsmount returns via ARG_FD_MOUNT.
	 */
	target = pick_sacrificial_target();
	if (target)
		rec->a4 = (unsigned long) target;
}

struct syscallentry syscall_mount = {
	.name = "mount",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "dev_name", [1] = "dir_name", [2] = "type", [3] = "flags", [4] = "data" },
	.arg_params[3].list = ARGLIST(mount_flags),
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_mount,
};

/*
 * Non-atime attr bits.  Kept separate from atime modes because the
 * kernel treats the MOUNT_ATTR__ATIME mask as a value-encoded enum,
 * not free bits.  MOUNT_ATTR_IDMAP intentionally excluded:
 * build_mount_idmapped() needs a paired userns_fd in attr->userns_fd,
 * which we have no source for yet, so the kernel EINVALs immediately
 * on any random-OR pick that includes the bit, wasting the iteration
 * before the idmap-build arm runs.  Re-enable once a userns_fd source
 * is wired in.
 */
static unsigned long mount_attrs_nonatime[] = {
	MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOSYMFOLLOW,
};

/*
 * Valid attr_set atime values per build_mount_kattr()'s switch:
 * RELATIME (==0), NOATIME, STRICTATIME.  Anything else (e.g. multiple
 * bits, or NODIRATIME which is *not* in MOUNT_ATTR__ATIME) hits the
 * switch's default and EINVALs.
 */
static __u64 mount_atime_set_modes[] = {
	MOUNT_ATTR_RELATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME,
};

/*
 * Propagation field.  build_mount_kattr() EINVALs on unknown bits and
 * also on hweight > 1, so pick at most one bit from the legal set.
 */
static __u64 mount_propagation_flags[] = {
	MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE, MS_SHARED,
};

/*
 * Paths most likely to BE a mount-point root on a typical Linux host,
 * so do_mount_setattr()'s path_mounted(path) check passes.  Random
 * ARG_PATHNAME picks (mostly /proc and /sys leaves) almost never are
 * mount roots and EINVAL out before any attr is applied.
 */
static const char * const mount_root_paths[] = {
	"/", "/proc", "/sys", "/dev", "/dev/shm", "/dev/pts",
	"/run", "/run/lock", "/tmp",
	"/sys/fs/cgroup", "/sys/kernel/debug", "/sys/kernel/tracing",
	"/sys/fs/bpf",
};

static void steer_mount_setattr_path(struct syscallrecord *rec)
{
	const char *src;
	char *dst = (char *) rec->a2;

	/*
	 * ARG_PATHNAME has already handed us a tracked MAX_PATH_LEN buffer
	 * in rec->a2 (gen_arg_pathname -> generate_pathname -> zmalloc_tracked).
	 * The argtype's cleanup hook will deferred_free_enqueue() that exact
	 * pointer after the call, so we must NOT swap in an alien allocation
	 * (the writable-struct pool isn't tracked; cleanup would reject the
	 * pointer and the tracked buffer would leak).  Overwrite in place.
	 */
	if (!dst)
		return;
	src = mount_root_paths[rnd_modulo_u32(ARRAY_SIZE(mount_root_paths))];
	strncpy(dst, src, MAX_PATH_LEN - 1);
	dst[MAX_PATH_LEN - 1] = '\0';
}

/*
 * Build a valid-baseline mount_attr body.  Kernel rules
 * (build_mount_kattr in fs/namespace.c):
 *   - attr_set/attr_clr bits must lie inside MOUNT_SETATTR_VALID_FLAGS.
 *   - attr_clr's atime portion must be either 0 or the FULL
 *     MOUNT_ATTR__ATIME mask (partial -> EINVAL).
 *   - If attr_set has any atime bit, attr_clr must contain the full
 *     MOUNT_ATTR__ATIME mask.
 *   - attr_set's atime portion, masked to MOUNT_ATTR__ATIME, must be
 *     exactly one of {RELATIME=0, NOATIME, STRICTATIME}.
 *   - propagation must be a single bit from MS_{UNBINDABLE,PRIVATE,SLAVE,SHARED}
 *     (or zero).
 */
static void build_valid_mount_attr(struct mount_attr *ma)
{
	__u64 set_bits = 0, clr_bits = 0;
	unsigned int i, nbits;

	nbits = 1 + rnd_modulo_u32(ARRAY_SIZE(mount_attrs_nonatime));
	for (i = 0; i < nbits; i++)
		set_bits |= mount_attrs_nonatime[rnd_modulo_u32(ARRAY_SIZE(mount_attrs_nonatime))];

	nbits = rnd_modulo_u32(ARRAY_SIZE(mount_attrs_nonatime) + 1);
	for (i = 0; i < nbits; i++)
		clr_bits |= mount_attrs_nonatime[rnd_modulo_u32(ARRAY_SIZE(mount_attrs_nonatime))];

	/*
	 * Atime: model the legal "clear all atime, then set one mode"
	 * transition.  Roughly half the time, request an atime change.
	 */
	if (RAND_BOOL()) {
		set_bits |= mount_atime_set_modes[rnd_modulo_u32(ARRAY_SIZE(mount_atime_set_modes))];
		clr_bits |= MOUNT_ATTR__ATIME;
	}

	ma->attr_set = set_bits;
	ma->attr_clr = clr_bits;

	if (RAND_BOOL())
		ma->propagation = mount_propagation_flags[rnd_modulo_u32(ARRAY_SIZE(mount_propagation_flags))];
}

#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0	32
#endif

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  Today
 * sizeof(struct mount_attr) == MOUNT_ATTR_SIZE_VER0, so the EXACT
 * bucket already covers VER0; the entry is kept in the pool so the
 * UNDERSIZE bucket still has a meaningful named ABI floor to draw
 * from once the kernel grows a VER1 and ksize moves past VER0.
 */
static const size_t mount_setattr_known_sizes[] = {
	MOUNT_ATTR_SIZE_VER0,
};

static const struct csfu_desc desc_mount_setattr = {
	.name = "mount_attr",
	.ksize = sizeof(struct mount_attr),
	.known_sizes = mount_setattr_known_sizes,
	.n_known_sizes = ARRAY_SIZE(mount_setattr_known_sizes),
};

static void sanitise_mount_setattr(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_mount_setattr);
	struct mount_attr *ma = buf.ptr;

	if (!ma)
		return;

	/*
	 * Steer the path argument at a known mount-point root so the
	 * kernel's path_mounted() check in do_mount_setattr() passes.
	 * The path is absolute, so dfd (a1) is ignored by filename_lookup.
	 */
	steer_mount_setattr_path(rec);

	/*
	 * mount_setattr has a separate usize syscall arg (a5); the
	 * csfu-picked usize is planted there.  Per-field attr_set /
	 * attr_clr / propagation population is gated on
	 * CSFU_BUCKET_EXACT -- the kernel rejects on usize before
	 * reading any body field for the non-exact buckets, and
	 * OVERSIZE_NONZERO / TAIL_MISMATCH need their tail garbage
	 * preserved.  zmalloc_tracked() already zeroed the buffer where
	 * the kernel cares to look.
	 */
	if (buf.bucket == CSFU_BUCKET_EXACT)
		build_valid_mount_attr(ma);

	rec->a4 = (unsigned long) ma;
	rec->a5 = buf.usize;

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it.  mount_setattr has no .post handler, so
	 * this was the only release point; post_state is private to the
	 * cleanup path and less stomp-prone than rec->a4.
	 */
	rec->post_state = (unsigned long) ma;
}

static unsigned long mount_setattr_flags[] = {
	AT_EMPTY_PATH, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT,
};

static void cleanup_mount_setattr(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_mount_setattr = {
	.name = "mount_setattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_STRUCT_PTR_IN, [4] = ARG_STRUCT_SIZE },
	.argname = { [0] = "dfd", [1] = "path", [2] = "flags", [3] = "uattr", [4] = "usize" },
	.arg_params[2].list = ARGLIST(mount_setattr_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.flags = KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_mount_setattr,
	.cleanup = cleanup_mount_setattr,
};
