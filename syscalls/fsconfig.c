/*
 *  SYSCALL_DEFINE5(fsconfig, int, fd, unsigned int, cmd, const char __user *, _key, const void __user *, _value, int, aux)
 */
#include <fcntl.h>
#include <string.h>
#include "fd.h"
#include "object-types.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

enum fsconfig_command {
    FSCONFIG_SET_FLAG       = 0,    /* Set parameter, supplying no value */
    FSCONFIG_SET_STRING     = 1,    /* Set parameter, supplying a string value */
    FSCONFIG_SET_BINARY     = 2,    /* Set parameter, supplying a binary blob value */
    FSCONFIG_SET_PATH       = 3,    /* Set parameter, supplying an object by path */
    FSCONFIG_SET_PATH_EMPTY = 4,    /* Set parameter, supplying an object by (empty) path */
    FSCONFIG_SET_FD         = 5,    /* Set parameter, supplying an object by fd */
    FSCONFIG_CMD_CREATE     = 6,    /* Invoke superblock creation */
    FSCONFIG_CMD_RECONFIGURE = 7,   /* Invoke superblock reconfiguration */
    FSCONFIG_CMD_CREATE_EXCL = 8,   /* Create new, fail if reusing existing */
};

static unsigned long fsconfig_ops[] = {
 FSCONFIG_SET_FLAG, FSCONFIG_SET_STRING, FSCONFIG_SET_BINARY, FSCONFIG_SET_PATH,
 FSCONFIG_SET_PATH_EMPTY, FSCONFIG_SET_FD, FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE,
 FSCONFIG_CMD_CREATE_EXCL,
};

/*
 * Keys recognised as flag-style options by most filesystems (no value
 * argument).  SET_FLAG with one of these has a chance of being accepted
 * by the fs_parser instead of bouncing at fs_lookup_key().
 */
static const char *flag_keys[] = {
	"ro", "rw", "sync", "async", "dirsync",
	"noatime", "atime", "relatime", "strictatime", "lazytime",
	"nosuid", "suid", "nodev", "dev", "noexec", "exec",
	"silent", "barrier", "nobarrier", "discard", "nodiscard",
};

/*
 * Keys that take a string value: a mix of universal (source, errors,
 * data) and per-fstype options (size= and mode= are tmpfs/ramfs,
 * uid=/gid= are tmpfs/fat/iso, commit= is ext*, max_inline_data= is
 * ext4).  fsconfig is per-mount so even unknown keys exercise the
 * fs_parser dispatch.
 */
static const char *string_keys[] = {
	"source", "errors", "data", "commit", "max_inline_data",
	"size", "nr_inodes", "mode", "uid", "gid",
	"fmask", "dmask", "iocharset", "huge", "mpol",
};

static const char *string_values[] = {
	"1", "0", "1M", "4096", "0755", "0700", "0", "65534",
	"continue", "remount-ro", "panic", "defaults",
	"/dev/sda1", "/dev/loop0", "tmpfs", "noinherit",
};

static void fill_flag_key(char *buf, size_t n)
{
	const char *key = flag_keys[rnd_modulo_u32(ARRAY_SIZE(flag_keys))];
	strncpy(buf, key, n - 1);
	buf[n - 1] = '\0';
}

static void fill_string_key(char *buf, size_t n)
{
	const char *key = string_keys[rnd_modulo_u32(ARRAY_SIZE(string_keys))];
	strncpy(buf, key, n - 1);
	buf[n - 1] = '\0';
}

static void fill_string_value(char *buf, size_t n)
{
	const char *val = string_values[rnd_modulo_u32(ARRAY_SIZE(string_values))];
	strncpy(buf, val, n - 1);
	buf[n - 1] = '\0';
}

static void build_valid_payload(struct syscallrecord *rec, unsigned long cmd)
{
	char *key, *val;

	switch (cmd) {
	case FSCONFIG_SET_FLAG:
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_flag_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_STRING:
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(64);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		fill_string_value(val, 64);
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_BINARY:
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(64);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		generate_rand_bytes((unsigned char *) val, 64);
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = 1 + (rnd_modulo_u32(64));	/* aux = length */
		break;

	case FSCONFIG_SET_PATH:
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(32);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		strncpy(val, RAND_BOOL() ? "/tmp" : "/", 31);
		val[31] = '\0';
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = AT_FDCWD;
		break;

	case FSCONFIG_SET_PATH_EMPTY:
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(8);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		val[0] = '\0';
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = get_random_fd();	/* aux = dirfd */
		break;

	case FSCONFIG_SET_FD:
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = get_random_fd();	/* aux = fd */
		break;

	case FSCONFIG_CMD_CREATE:
	case FSCONFIG_CMD_RECONFIGURE:
	case FSCONFIG_CMD_CREATE_EXCL:
		rec->a3 = 0;
		rec->a4 = 0;
		rec->a5 = 0;
		break;
	}
}

static void build_mismatched_payload(struct syscallrecord *rec, unsigned long cmd)
{
	char *key, *val;

	switch (cmd) {
	case FSCONFIG_SET_FLAG:
		/* SET_FLAG with a stray value attached -- fs_lookup_key warns. */
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(32);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		fill_string_value(val, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = rnd_u32();
		break;

	case FSCONFIG_SET_STRING:
		/* SET_STRING with NULL value -- vfs_parse_fs_string -EINVAL. */
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_BINARY:
		/* SET_BINARY with aux=0 -- vfs_parse_fs_param length check. */
		key = (char *) get_writable_address(32);
		val = (char *) get_writable_address(64);
		if (key == NULL || val == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_PATH:
	case FSCONFIG_SET_PATH_EMPTY:
		/* PATH with NULL path -- copy_user_string -EFAULT. */
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = AT_FDCWD;
		break;

	case FSCONFIG_SET_FD:
		/* SET_FD with a likely-invalid fd. */
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = (int) rnd_u32();
		break;

	case FSCONFIG_CMD_CREATE:
	case FSCONFIG_CMD_RECONFIGURE:
	case FSCONFIG_CMD_CREATE_EXCL:
		/* finalize commands with stray key/value still attached. */
		key = (char *) get_writable_address(32);
		if (key == NULL)
			break;
		fill_string_key(key, 32);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = 0;
		break;
	}
}

static void sanitise_fsconfig(struct syscallrecord *rec)
{
	unsigned long cmd;
	unsigned int pick;

	/*
	 * Cmd / payload distribution:
	 *   70%  real cmd + matching payload (drives the per-cmd handlers)
	 *   20%  real cmd + intentionally-mismatched payload
	 *   10%  random cmd + random payload (existing rec->a2 from ARG_OP
	 *        plus whatever fields were left from generic_sanitise)
	 */
	pick = rnd_modulo_u32(10);

	if (pick < 7) {
		cmd = fsconfig_ops[rnd_modulo_u32(ARRAY_SIZE(fsconfig_ops))];
		rec->a2 = cmd;
		build_valid_payload(rec, cmd);
	} else if (pick < 9) {
		cmd = fsconfig_ops[rnd_modulo_u32(ARRAY_SIZE(fsconfig_ops))];
		rec->a2 = cmd;
		build_mismatched_payload(rec, cmd);
	} else {
		/*
		 * Pure random fallthrough: keep rec->a2 from ARG_OP (or
		 * scribble it) and leave a3/a4/a5 to generic_sanitise.
		 */
		if (ONE_IN(2))
			rec->a2 = rnd_u32();
	}
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  fsconfig does not return a new object via
 * its retval -- the fs_context fd in rec->a1 was minted upstream by
 * fsopen / fspick (whose .ret_objtype = OBJ_FD_FS_CTX already
 * registered it).  What fsconfig changes is the fs_context's
 * lifecycle state: a successful FSCONFIG_CMD_CREATE /
 * FSCONFIG_CMD_CREATE_EXCL / FSCONFIG_CMD_RECONFIGURE transitions
 * the context to the mountable state ready for fsmount().
 *
 * The hook is a defensive backstop for the rare case where the
 * fs_context fd vanished from the local OBJ_FD_FS_CTX pool between
 * the original fsopen / fspick post path and this fsconfig dispatch
 * (parent destructor ran, fd recycling collided, scope migration).
 * Republishing keeps fsmount consumers finding it; the
 * find_local_object_by_fd() short-circuit avoids the duplicate-publish
 * shape post-double-publish.sh exists to flag.
 */
static void post_fsconfig_record_fsctx_ready(struct syscallrecord *rec)
{
	unsigned long cmd = get_arg_snapshot(rec, 2);
	int fd = (int) get_arg_snapshot(rec, 1);

	if ((long) rec->retval != 0)
		return;

	if (cmd != FSCONFIG_CMD_CREATE &&
	    cmd != FSCONFIG_CMD_CREATE_EXCL &&
	    cmd != FSCONFIG_CMD_RECONFIGURE)
		return;

	if (fd <= 2 || fd >= (1 << 20))
		return;

	if (find_local_object_by_fd(OBJ_FD_FS_CTX, fd) != NULL)
		return;

	(void) publish_resource(OBJ_FD_FS_CTX, (unsigned long) fd, NULL);
}

struct syscallentry syscall_fsconfig = {
	.name = "fsconfig",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_FS_CTX, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "_key", [3] = "_value", [4] = "aux" },
	.arg_params[1].list = ARGLIST(fsconfig_ops),
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_fsconfig,
	.ret_objtype_via_post = post_fsconfig_record_fsctx_ready,
	.rettype = RET_ZERO_SUCCESS,
	/*
	 * Snapshot a1 (fd) and a2 (cmd) so the post handler republishes the
	 * fd that THIS syscall actually dispatched with, not whatever a
	 * sibling child has since stomped into the shared rec.  Without this,
	 * a stomp landing between dispatch and the post handler causes
	 * publish_resource(OBJ_FD_FS_CTX, ...) to register an fd this
	 * syscall never produced -- and the gating cmd check could likewise
	 * flip from skip-to-publish (or vice versa) on a stomped a2.
	 */
	.arg_snapshot_mask = (1u << 0) | (1u << 1),
};
