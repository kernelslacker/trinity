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

#include <fcntl.h>
#include "fanotify.h"
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/fanotify.h"

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
 * ARG_LIST on a1 ORs 1..N bits from fanotify_init_flags[]
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
	if (pick < 94)
		return FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_MNT;
	if (pick < 97)
		return FAN_CLOEXEC | FAN_UNLIMITED_QUEUE |
			FAN_UNLIMITED_MARKS;
	/* Random-OR over fanotify_init_flags[] -- invalid-combo reject. */
	return set_rand_bitmask(ARRAY_SIZE(fanotify_init_flags),
				fanotify_init_flags);
}

static void sanitise_fanotify_init(struct syscallrecord *rec)
{
	rec->a1 = sanitise_fanotify_init_flags();
	rec->a2 = get_fanotify_init_event_flags();
}

/*
 * Publish the new fd tagged with the flags and event flags the group was
 * made with: the fanotify_mark sanitiser reads fanotifyobj.flags back to
 * gate FAN_FS_ERROR and FAN_MNT_* on the init-fd's class, and a wrong tag
 * has it OR in combinations the kernel rejects or skip valid ones.  Both
 * come from the slots the kernel was handed, shadowed at dispatch: chain
 * substitution or a RedQueen pin can rewrite either after the sanitiser
 * drew its own.
 */
static void post_fanotify_init(struct syscallrecord *rec)
{
	unsigned long retval;
	int fd;

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
		return;

	{
		struct resource_meta meta = {
			.flags = get_arg_snapshot(rec, 1),
			.aux = get_arg_snapshot(rec, 2),
		};
		publish_resource(OBJ_FD_FANOTIFY, fd, &meta);
	}
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
	/* flags (a1) and event_f_flags (a2): the fd is tagged with the ones
	 * the kernel made the group with. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1),
	.group = GROUP_VFS_IO,
	.flags = REEXEC_SANITISE_OK,
};
