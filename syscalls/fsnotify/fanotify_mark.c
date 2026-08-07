/*
 * SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
	__u64 mask, int dfd, const char  __user * pathname)
 */
#include <sys/syscall.h>
#include <unistd.h>
#include "kernel/fanotify.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

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
		rec->a2 |= ignore_choice[rnd_modulo_u32(ARRAY_SIZE(ignore_choice))];

	chosen_objtype = objtype_choice[rnd_modulo_u32(ARRAY_SIZE(objtype_choice))];
	rec->a2 = (rec->a2 & ~(unsigned long)FAN_MARK_OBJTYPE_MASK) | chosen_objtype;

	/*
	 * Look up the fanotify fd once; both the MNTNS arm and the
	 * FAN_FS_ERROR arm need the init-fd's flags.
	 */
	entry = fd_hash_lookup((int)rec->a1);

	/*
	 * FAN_MNT_ATTACH/DETACH are only legal on a FAN_REPORT_MNT group's
	 * mntns mark.  Gate on the init fd carrying FAN_REPORT_MNT, and
	 * replace rec->a3 (rather than OR into it) so no path/inode/error
	 * bits from ARG_LIST survive alongside the mount bits -- the kernel
	 * EINVALs that combination.
	 */
	if (chosen_objtype == FAN_MARK_MNTNS &&
	    entry != NULL && entry->type == OBJ_FD_FANOTIFY && entry->obj != NULL &&
	    (entry->obj->fanotifyobj.flags & FAN_REPORT_MNT)) {
		unsigned long mnt_mask = 0;
		if (RAND_BOOL())
			mnt_mask |= FAN_MNT_ATTACH;
		if (RAND_BOOL())
			mnt_mask |= FAN_MNT_DETACH;
		rec->a3 = mnt_mask;
	}

	/*
	 * FAN_FS_ERROR is gated on the init-fd's class and requires a
	 * filesystem mark -- force the mark type to FAN_MARK_FILESYSTEM
	 * when we decide to set the bit, so the kernel's cross-check passes.
	 */
	if (entry != NULL && entry->type == OBJ_FD_FANOTIFY && entry->obj != NULL) {
		unsigned int init_flags = entry->obj->fanotifyobj.flags;
		unsigned int class_bits = init_flags & FAN_CLASS_MASK;

		if (class_bits == FAN_CLASS_NOTIF &&
		    (init_flags & FAN_REPORT_FID) && RAND_BOOL()) {
			rec->a3 |= FAN_FS_ERROR;
			/* FAN_FS_ERROR requires a filesystem mark */
			rec->a2 = (rec->a2 & ~(unsigned long)FAN_MARK_OBJTYPE_MASK) |
				  FAN_MARK_FILESYSTEM;
		}

		/*
		 * FAN_PRE_ACCESS omitted for the same reason as the *_PERM mask
		 * bits: it is a pre-content permission event that blocks the access
		 * until a responder answers, and trinity has none.
		 */
	}
}

static unsigned long fanotify_mark_flags[] = {
	FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FLUSH,
};

static unsigned long fanotify_mark_mask[] = {
	FAN_ACCESS, FAN_MODIFY, FAN_ATTRIB,
	FAN_CLOSE, FAN_CLOSE_WRITE, FAN_CLOSE_NOWRITE,
	FAN_OPEN, FAN_OPEN_EXEC,
	/*
	 * Permission events (FAN_OPEN_PERM / FAN_ACCESS_PERM /
	 * FAN_OPEN_EXEC_PERM) are deliberately omitted: each blocks the
	 * marked open/access/exec until a userspace responder writes an
	 * ALLOW/DENY back on the fanotify fd, and trinity runs no responder
	 * loop -- so any op on the marked object wedges (killably) forever.
	 * Re-arm only alongside a thread that answers them.
	 */
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
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS_IO,
};
