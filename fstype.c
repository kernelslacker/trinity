/* Generate filesystem-type name strings for the fsopen/mount family. */
#include <stddef.h>
#include "fstype.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

/*
 * Loaded-into-kernel filesystem types.  Populated by the
 * read_filesystem_types() constructor in syscalls/mount.c from
 * /proc/filesystems at startup, with a hard-coded fallback inside
 * that constructor for the /proc-unreadable case -- so the pointer is
 * always non-NULL and nr_filesystem_types > 0 by the time any
 * argtype generator runs.  The defensive nr_filesystem_types > 0
 * check below still guards the indexing in case startup order ever
 * changes.
 */
extern const char **filesystem_types;
extern unsigned int nr_filesystem_types;

/*
 * Deterministic baseline pool: a tight subset present on virtually
 * every Linux installation.  Supplements the loaded-types bucket so
 * coverage of common-case names does not depend on /proc/filesystems
 * visibility or fleet-specific kernel build options.
 */
static const char *fstype_builtin_pool[] = {
	"ext4", "xfs", "btrfs", "tmpfs", "proc", "sysfs",
	"devtmpfs", "overlay", "cgroup2", "ramfs",
};

/*
 * Filesystem types frequently shipped as modules but rarely autoloaded
 * at boot.  Naming one of these drives get_fs_type() into
 * request_module("fs-<name>") and exercises the module-load + fresh
 * fs_context setup path -- distinct from the already-resident
 * file_systems-list walk a loaded type hits.  Folded from the
 * per-syscall pool in syscalls/fsopen.c so any ARG_FSTYPE_NAME slot
 * gets the autoload draw by declaration.
 */
static const char *fstype_unloaded_pool[] = {
	"9p", "ceph", "ocfs2", "gfs2", "reiserfs", "jfs", "ubifs",
	"ntfs3", "f2fs", "erofs", "squashfs", "exfat", "afs", "udf",
	"isofs", "ext2", "minix", "hfs", "hfsplus", "cifs", "smb3",
};

void gen_fstype_name_pooled(char *buf, size_t len)
{
	const char *src;
	unsigned int r;
	size_t n;

	if (buf == NULL || len == 0)
		return;

	r = rnd_modulo_u32(20);

	/* Loaded types -- runtime-varied draw, falls through to the
	 * builtin pool below if the constructor has not produced a
	 * usable list yet (defensive: it should always have, since
	 * mount.c falls back to its own builtin_fs_types). */
	if (r < 8 && nr_filesystem_types > 0) {
		src = filesystem_types[rnd_modulo_u32(nr_filesystem_types)];
		snprintf(buf, len, "%s", src);
		return;
	}

	if (r < 12) {
		src = RAND_ARRAY(fstype_builtin_pool);
		snprintf(buf, len, "%s", src);
		return;
	}

	if (r < 16) {
		src = RAND_ARRAY(fstype_unloaded_pool);
		snprintf(buf, len, "%s", src);
		return;
	}

	if (r < 18) {
		/* Short random bytes: ENODEV at the name-lookup gate.
		 * generate_rand_bytes may embed a NUL, shortening the
		 * string further; that is acceptable -- the gate is the
		 * code path under test, not the exact length. */
		n = 4 + rnd_modulo_u32(8);	/* 4..11 bytes */
		if (n >= len)
			n = len - 1;
		generate_rand_bytes((unsigned char *) buf, (unsigned int) n);
		buf[n] = '\0';
		return;
	}

	if (r < 19) {
		/* Buffer-cap-length filler: a deterministic non-NUL
		 * pattern so copy_mount_string()'s strndup_user reads
		 * the full (len-1) bytes before hitting our terminator.
		 * Random bytes would NUL-truncate early on ~25% of
		 * draws and silently degrade to the short-garbage
		 * bucket above. */
		if (len > 1) {
			memset(buf, 'a', len - 1);
			buf[len - 1] = '\0';
		} else {
			buf[0] = '\0';
		}
		return;
	}

	/* Empty string: a separate copyin shape from NULL, exercises
	 * the zero-length branch of the name validator. */
	buf[0] = '\0';
}
