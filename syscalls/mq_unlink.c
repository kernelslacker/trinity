/*
 * SYSCALL_DEFINE1(mq_unlink, const char __user *, u_name)
 */
#include "objects.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_mq_unlink(struct syscallrecord *rec)
{
	char *name;

	/*
	 * Sized to struct mqobj.name so a stored "/trin<pid>_<idx>\0"
	 * fits exactly; the short "/trinX\0" random-string path uses the
	 * first 7 bytes of the same buffer.
	 */
	name = (char *) get_writable_address(sizeof(((struct mqobj *)0)->name));
	if (name == NULL)
		return;

	/*
	 * Biased draw, ~50/50.  The uniform "/trinX" string fuzz this
	 * sanitiser shipped with can never name trinity's own queues
	 * because every queue we open carries a per-instance "_<pid>"
	 * suffix (see make_mq_name() in fds/mq.c), so the kernel mqueue
	 * teardown path is never reached -- mq_unlink ENOENTs out at
	 * mqueue_lookup before touching any of the fs/posix-timers
	 * teardown→use code we care about.  Half the calls now draw a
	 * real name out of the OBJ_FD_MQ pool so unlink targets a live
	 * queue and forces the inode→mqueue_inode_info release path to
	 * run while the fd is potentially still in flight in a sibling
	 * mq_send/recv/notify.  The other half retains the random-string
	 * fuzz so namespace residue from other processes still gets hit.
	 */
	if (rnd_u32() & 1) {
		for (int i = 0; i < 16; i++) {
			struct object *obj;

			obj = get_random_object(OBJ_FD_MQ, OBJ_GLOBAL);
			if (!objpool_check(obj, OBJ_FD_MQ))
				continue;

			memcpy(name, obj->mqobj.name, sizeof(obj->mqobj.name));
			rec->a1 = (unsigned long) name;
			avoid_shared_buffer_inout(&rec->a1, sizeof(((struct mqobj *)0)->name));
			return;
		}
		/* Pool repeatedly came back empty/stale -- fall through. */
	}

	/* POSIX MQ names must start with '/' */
	name[0] = '/';
	name[1] = 't';
	name[2] = 'r';
	name[3] = 'i';
	name[4] = 'n';
	name[5] = '0' + (rnd_modulo_u32(10));
	name[6] = '\0';

	rec->a1 = (unsigned long) name;
	avoid_shared_buffer_inout(&rec->a1, sizeof(((struct mqobj *)0)->name));
}

struct syscallentry syscall_mq_unlink = {
	.name = "mq_unlink",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_IPC,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "u_name" },
	.sanitise = sanitise_mq_unlink,
};
