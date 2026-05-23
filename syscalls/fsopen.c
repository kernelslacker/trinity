/*
 *  SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
 */
#include <string.h>
#include <unistd.h>
#include "object-types.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/* Populated by mount.c constructor from /proc/filesystems. */
extern const char **filesystem_types;
extern unsigned int nr_filesystem_types;

#define FSOPEN_CLOEXEC 0x00000001
static unsigned long fsopen_flags[] = {
	FSOPEN_CLOEXEC
};

/*
 * Filesystem types likely present as kernel modules but not yet loaded
 * into /proc/filesystems.  Naming one of these triggers a request_module()
 * autoload attempt, which exercises a different fs_context setup path
 * than the already-resident types served straight out of the
 * file_systems linked list.
 */
static const char *unloaded_fs_types[] = {
	"9p", "ceph", "ocfs2", "gfs2", "reiserfs", "jfs", "ubifs",
	"ntfs3", "f2fs", "erofs", "squashfs", "exfat", "afs", "udf",
	"isofs", "ext2", "minix", "hfs", "hfsplus", "cifs", "smb3",
};

static void sanitise_fsopen(struct syscallrecord *rec)
{
	const char *fstype;
	char *name;
	unsigned int pick;
	unsigned int flagpick;

	/*
	 * Fstype distribution:
	 *   60%  loaded type from /proc/filesystems
	 *   20%  likely-unloaded type (request_module autoload path)
	 *   10%  random bytes (ENODEV at the gate, exercises name copyin)
	 *   10%  empty / NULL
	 */
	pick = rnd_modulo_u32(10);
	if (pick < 6 && nr_filesystem_types > 0) {
		fstype = filesystem_types[rnd_modulo_u32(nr_filesystem_types)];
		name = (char *) get_writable_struct(32);
		if (!name)
			return;
		strncpy(name, fstype, 31);
		name[31] = '\0';
		rec->a1 = (unsigned long) name;
	} else if (pick < 8) {
		fstype = unloaded_fs_types[rnd_modulo_u32(ARRAY_SIZE(unloaded_fs_types))];
		name = (char *) get_writable_struct(32);
		if (!name)
			return;
		strncpy(name, fstype, 31);
		name[31] = '\0';
		rec->a1 = (unsigned long) name;
	} else if (pick < 9) {
		name = (char *) get_writable_struct(16);
		if (!name)
			return;
		generate_rand_bytes((unsigned char *) name, 15);
		name[15] = '\0';
		rec->a1 = (unsigned long) name;
	} else {
		if (RAND_BOOL()) {
			name = (char *) get_writable_struct(1);
			if (!name)
				return;
			name[0] = '\0';
			rec->a1 = (unsigned long) name;
		} else {
			rec->a1 = 0;
		}
	}

	/*
	 * Flags distribution:
	 *   70%  zero
	 *   25%  FSOPEN_CLOEXEC
	 *    5%  random bits (most reserved -- EINVAL gate)
	 */
	flagpick = rnd_modulo_u32(20);
	if (flagpick < 14)
		rec->a2 = 0;
	else if (flagpick < 19)
		rec->a2 = FSOPEN_CLOEXEC;
	else
		rec->a2 = rnd_u32();
}

struct syscallentry syscall_fsopen = {
	.name = "fsopen",
	.num_args = 2,
	.argtype = { [1] = ARG_OP },
	.argname = { [0] = "_fs_name", [1] = "flags" },
	.arg_params[1].list = ARGLIST(fsopen_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_FS_CTX,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_fsopen,
	.post = post_fs_ctx_fd,
};
