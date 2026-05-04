/*
 * SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
	__u64 mask, int dfd, const char  __user * pathname)
 */
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/fanotify.h>
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/* Event mask bits added in newer kernels; guard for older toolchains. */
#ifndef FAN_ATTRIB
#define FAN_ATTRIB		0x00000004
#endif
#ifndef FAN_DELETE_SELF
#define FAN_DELETE_SELF		0x00000400
#endif
#ifndef FAN_MOVE_SELF
#define FAN_MOVE_SELF		0x00000800
#endif
#ifndef FAN_OPEN_EXEC
#define FAN_OPEN_EXEC		0x00001000
#endif
#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM	0x00040000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME		0x10000000
#endif
#ifndef FAN_ONDIR
#define FAN_ONDIR		0x40000000
#endif
#ifndef FAN_FS_ERROR
#define FAN_FS_ERROR		0x00008000
#endif
#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS		0x00100000
#endif
#ifndef FAN_MNT_ATTACH
#define FAN_MNT_ATTACH		0x01000000
#endif
#ifndef FAN_MNT_DETACH
#define FAN_MNT_DETACH		0x02000000
#endif

/* Modifier flag bits added in newer kernels. */
#ifndef FAN_MARK_FILESYSTEM
#define FAN_MARK_FILESYSTEM	0x00000100
#endif
#ifndef FAN_MARK_EVICTABLE
#define FAN_MARK_EVICTABLE	0x00000200
#endif
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE		0x00000400
#endif
#ifndef FAN_MARK_INODE
#define FAN_MARK_INODE		0x00000000
#endif
#ifndef FAN_MARK_MNTNS
#define FAN_MARK_MNTNS		0x00000110
#endif

#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID		0x00000200
#endif
#ifndef FAN_CLASS_NOTIF
#define FAN_CLASS_NOTIF		0x00000000
#endif
#ifndef FAN_CLASS_CONTENT
#define FAN_CLASS_CONTENT	0x00000004
#endif
#ifndef FAN_CLASS_PRE_CONTENT
#define FAN_CLASS_PRE_CONTENT	0x00000008
#endif

/* Mask covering every object-type bit used by Group C choices. */
#define FAN_MARK_OBJTYPE_MASK	(FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)
/* Bits that encode the init-fd's class (NOTIF / CONTENT / PRE_CONTENT). */
#define FAN_CLASS_MASK		(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT)

static void sanitise_fanotify_mark(struct syscallrecord *rec)
{
	/* Group A: free-mix modifiers (any subset is legal together). */
	static const unsigned int free_mix[] = {
		FAN_MARK_DONT_FOLLOW, FAN_MARK_ONLYDIR,
		FAN_MARK_EVICTABLE, FAN_MARK_IGNORED_SURV_MODIFY,
	};
	/* Group B: ignore semantics — at most one (kernel EINVALs combos). */
	static const unsigned int ignore_choice[] = {
		FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORE,
	};
	/* Group C: object-type — pick one (low-nibble + bit 8 are exclusive). */
	static const unsigned int objtype_choice[] = {
		FAN_MARK_INODE, FAN_MARK_MOUNT,
		FAN_MARK_FILESYSTEM, FAN_MARK_MNTNS,
	};
	struct fd_hash_entry *entry;
	unsigned int chosen_objtype;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(free_mix); i++) {
		if (RAND_BOOL())
			rec->a2 |= free_mix[i];
	}

	if (RAND_BOOL())
		rec->a2 |= ignore_choice[rand() % ARRAY_SIZE(ignore_choice)];

	chosen_objtype = objtype_choice[rand() % ARRAY_SIZE(objtype_choice)];
	rec->a2 = (rec->a2 & ~(unsigned long)FAN_MARK_OBJTYPE_MASK) | chosen_objtype;

	/* FAN_MNT_ATTACH/DETACH are only legal when the mark is on a mntns. */
	if (chosen_objtype == FAN_MARK_MNTNS) {
		if (RAND_BOOL())
			rec->a3 |= FAN_MNT_ATTACH;
		if (RAND_BOOL())
			rec->a3 |= FAN_MNT_DETACH;
	}

	/*
	 * FAN_FS_ERROR / FAN_PRE_ACCESS are gated on the init-fd's class.
	 * Look up the fanotify fd in a1 and read back the flags it was
	 * opened with so we only OR in valid combinations.
	 */
	entry = fd_hash_lookup((int)rec->a1);
	if (entry != NULL && entry->type == OBJ_FD_FANOTIFY && entry->obj != NULL) {
		unsigned int init_flags = entry->obj->fanotifyobj.flags;
		unsigned int class_bits = init_flags & FAN_CLASS_MASK;

		if (class_bits == FAN_CLASS_NOTIF &&
		    (init_flags & FAN_REPORT_FID) && RAND_BOOL())
			rec->a3 |= FAN_FS_ERROR;

		if (class_bits == FAN_CLASS_PRE_CONTENT && RAND_BOOL())
			rec->a3 |= FAN_PRE_ACCESS;
	}
}

static unsigned long fanotify_mark_flags[] = {
	FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FLUSH,
};

static unsigned long fanotify_mark_mask[] = {
	FAN_ACCESS, FAN_MODIFY, FAN_ATTRIB,
	FAN_CLOSE, FAN_CLOSE_WRITE, FAN_CLOSE_NOWRITE,
	FAN_OPEN, FAN_OPEN_EXEC,
	FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM,
	FAN_EVENT_ON_CHILD, FAN_ONDIR,
	FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF,
	FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF,
	FAN_RENAME,
};

static void post_fanotify_mark(struct syscallrecord *rec)
{
#ifdef SYS_fanotify_mark
	unsigned long flags;

	if ((long) rec->retval != 0)
		return;
	if (!(rec->a2 & FAN_MARK_ADD))
		return;

	/*
	 * Mirror the ADD with a REMOVE carrying the same flags, mask, dfd
	 * and pathname so the kernel finds and clears the mark we just
	 * created.  REMOVE / FLUSH calls are no-ops to clean up — REMOVE
	 * is itself the cleanup, and FLUSH already wiped the type-bucket.
	 */
	flags = (rec->a2 & ~(unsigned long)FAN_MARK_ADD) | FAN_MARK_REMOVE;
	syscall(SYS_fanotify_mark, rec->a1, flags, rec->a3, rec->a4, rec->a5);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_fanotify_mark = {
	.name = "fanotify_mark",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_FANOTIFY, [1] = ARG_OP, [2] = ARG_LIST, [3] = ARG_FD, [4] = ARG_PATHNAME },
	.argname = { [0] = "fanotify_fd", [1] = "flags", [2] = "mask", [3] = "dfd", [4] = "pathname" },
	.arg_params[1].list = ARGLIST(fanotify_mark_flags),
	.arg_params[2].list = ARGLIST(fanotify_mark_mask),
	.sanitise = sanitise_fanotify_mark,
	.post = post_fanotify_mark,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
