/*
 * SYSCALL_DEFINE2(fanotify_init, unsigned int, flags, unsigned int, event_f_flags)
 */

#define FAN_CLOEXEC		0x00000001
#define FAN_NONBLOCK		0x00000002
#define FAN_CLASS_NOTIF		0x00000000
#define FAN_CLASS_CONTENT	0x00000004
#define FAN_CLASS_PRE_CONTENT	0x00000008
#define FAN_UNLIMITED_QUEUE	0x00000010
#define FAN_UNLIMITED_MARKS	0x00000020

/* FID-based reporting flags (5.1+); guard in case headers already define them. */
#ifndef FAN_REPORT_TID
#define FAN_REPORT_TID		0x00000100
#endif
#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID		0x00000200
#endif
#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID	0x00000400
#endif
#ifndef FAN_REPORT_NAME
#define FAN_REPORT_NAME		0x00000800
#endif
#ifndef FAN_REPORT_TARGET_FID
#define FAN_REPORT_TARGET_FID	0x00001000
#endif
#ifndef FAN_REPORT_PIDFD
#define FAN_REPORT_PIDFD	0x00000080
#endif
#ifndef FAN_REPORT_FD_ERROR
#define FAN_REPORT_FD_ERROR	0x00002000
#endif
#ifndef FAN_REPORT_MNT
#define FAN_REPORT_MNT		0x00004000
#endif
#ifndef FAN_ENABLE_AUDIT
#define FAN_ENABLE_AUDIT	0x00000040
#endif

#include <fcntl.h>
#include "fanotify.h"
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long fanotify_init_flags[] = {
	FAN_CLOEXEC, FAN_NONBLOCK, FAN_UNLIMITED_QUEUE, FAN_UNLIMITED_MARKS,
	FAN_CLASS_NOTIF, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT,
	FAN_REPORT_TID, FAN_REPORT_FID, FAN_REPORT_DIR_FID, FAN_REPORT_NAME,
	FAN_REPORT_TARGET_FID, FAN_REPORT_PIDFD, FAN_REPORT_FD_ERROR,
	FAN_REPORT_MNT, FAN_ENABLE_AUDIT,
};

unsigned long get_fanotify_init_flags(void)
{
	return RAND_ARRAY(fanotify_init_flags);
}


static unsigned long fanotify_event_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
};

static unsigned long fanotify_event_flags_extra[] = {
	O_LARGEFILE, O_CLOEXEC, O_APPEND, O_DSYNC,
	O_NOATIME, O_NONBLOCK, O_SYNC,
};

unsigned long get_fanotify_init_event_flags(void)
{
	unsigned long flags;

	flags = RAND_ARRAY(fanotify_event_flags_base);
	flags |= set_rand_bitmask(ARRAY_SIZE(fanotify_event_flags_extra), fanotify_event_flags_extra);

	return flags;
}

/*
 * ARG_LIST on a1 only picks a single bit from fanotify_init_flags[]
 * at a time, so most kernel cross-checks (FAN_REPORT_NAME requires
 * FAN_REPORT_DIR_FID; FAN_REPORT_TARGET_FID requires both;
 * FAN_REPORT_PIDFD requires FAN_CLASS_NOTIF; FAN_REPORT_FD_ERROR
 * requires FAN_REPORT_FID) are never satisfied and the syscall
 * rejects in the validation arm before reaching any reporting code.
 * Override a1 with 10 explicit shape buckets that respect those
 * cross-checks, keeping one random-OR bucket for invalid-combo
 * coverage.
 */
static unsigned long sanitise_fanotify_init_flags(void)
{
	unsigned int pick = rnd_modulo_u32(100);

	if (pick < 25)
		return FAN_CLOEXEC | FAN_NONBLOCK;
	if (pick < 40)
		return FAN_CLOEXEC | FAN_CLASS_CONTENT;
	if (pick < 50)
		return FAN_CLOEXEC | FAN_CLASS_PRE_CONTENT;
	if (pick < 65)
		return FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID;
	if (pick < 75)
		return FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID |
			FAN_REPORT_NAME;
	if (pick < 80)
		return FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID |
			FAN_REPORT_NAME | FAN_REPORT_TARGET_FID;
	if (pick < 85)
		return FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_PIDFD;
	if (pick < 90)
		return FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_FD_ERROR;
	if (pick < 95)
		return FAN_CLOEXEC | FAN_UNLIMITED_QUEUE |
			FAN_UNLIMITED_MARKS;
	/* Random-OR over fanotify_init_flags[] -- invalid-combo reject. */
	return set_rand_bitmask(ARRAY_SIZE(fanotify_init_flags),
				fanotify_init_flags);
}

/*
 * Snapshot of the (flags, event_f_flags) pair the post handler uses
 * to publish the new OBJ_FD_FANOTIFY.  The old post handler read
 * both fields directly off rec->a1 / rec->a2; a sibling child
 * scribbling those slots between the syscall returning and the post
 * handler running would mis-tag the published fanotify fd, so the
 * downstream fanotify_mark sanitiser (which reads back
 * fanotifyobj.flags to gate FAN_FS_ERROR / FAN_PRE_ACCESS on the
 * init-fd's class) would OR in invalid combinations the kernel
 * rejects or skip valid ones.  Stashing the snap in rec->post_state
 * — a slot the syscall ABI does not expose — keeps the post handler
 * immune to such scribbles.
 */
#define FANOTIFY_INIT_POST_STATE_MAGIC	0x46414e49UL	/* "FANI" */
struct fanotify_init_post_state {
	unsigned long magic;
	unsigned long flags;
	unsigned long event_f_flags;
};

static void sanitise_fanotify_init(struct syscallrecord *rec)
{
	struct fanotify_init_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	rec->a1 = sanitise_fanotify_init_flags();
	rec->a2 = get_fanotify_init_event_flags();

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic         = FANOTIFY_INIT_POST_STATE_MAGIC;
	snap->flags         = rec->a1;
	snap->event_f_flags = rec->a2;
	post_state_install(rec, snap);
}

static void post_fanotify_init(struct syscallrecord *rec)
{
	struct fanotify_init_post_state *snap;
	unsigned long retval;
	int fd;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, FANOTIFY_INIT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Snapshot rec->retval once.  rec lives in the child's shm
	 * region; reading it twice (the int fd cast for publish_resource()
	 * and the (long) < 0 success-vs-error guard) lets a sibling stomp
	 * between the two reads tag OBJ_FD_FANOTIFY with an fd the kernel
	 * never gave us, or silently drop a real fd.
	 */
	retval = rec->retval;
	fd = (int) retval;

	if ((long) retval < 0)
		goto out_free;

	{
		struct resource_meta meta = {
			.flags = snap->flags,
			.aux = snap->event_f_flags,
		};
		publish_resource(OBJ_FD_FANOTIFY, fd, &meta);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_fanotify_init = {
	.name = "fanotify_init",
	.num_args = 2,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags", [1] = "event_f_flags" },
	.arg_params[0].list = ARGLIST(fanotify_init_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_FANOTIFY,
	.sanitise = sanitise_fanotify_init,
	.post = post_fanotify_init,
	.group = GROUP_VFS,
};
