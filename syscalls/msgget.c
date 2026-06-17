/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "ipc-common.h"
#include "objects.h"
#include "prop_ring.h"
#include "publish_resource.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * OBJ_SYSV_MSG pool: producer-side cache of live SysV message queue
 * ids returned by msgget.  Consumed by msgctl/msgsnd/msgrcv argument
 * generation so subsequent fuzzed calls hit ids the kernel actually
 * has on hand instead of dead-on-arrival random integers.  Lives in
 * the per-child OBJ_LOCAL pool; the pool destructor calls real
 * msgctl(IPC_RMID) on shutdown so produced queues don't leak past
 * child lifetime.  Replaces a previous IPC_RMID-on-return shape that
 * prevented any pool-based tracking from being useful (sibling
 * consumers saw the id evaporate before they could touch it).
 */
static void sysv_msg_destructor(struct object *obj)
{
	msgctl(obj->sysvmsgobj.msqid, IPC_RMID, NULL);
}

static void init_sysv_msg_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_SYSV_MSG);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &sysv_msg_destructor;
}

REG_GLOBAL_OBJ(sysv_msg, init_sysv_msg_pool);

void register_sysv_msg(int msqid)
{
	if (msqid < 0)
		return;

	publish_resource(OBJ_SYSV_MSG, (unsigned long)msqid, NULL);
}

int get_random_sysv_msg(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_SYSV_MSG) == true)
		return 0;

	obj = get_random_object(OBJ_SYSV_MSG, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->sysvmsgobj.msqid;
}

static void post_msgget(struct syscallrecord *rec)
{
	long msqid;

	post_ipc_get(rec, register_sysv_msg, "msgget");

	/* Mirror the msqid into the per-child prop_ring so the typed
	 * consumer in gen_arg_msg_id can prefer recently-returned ids
	 * over raw randoms / stale pool draws.  Re-check the success
	 * window post_ipc_get accepted (>= 0, <= INT_MAX) as defence in
	 * depth -- mirrors the OBJ_KEY_SERIAL exemplar in syscall.c
	 * which also re-validates before prop_ring_push_scalar despite
	 * register_key_serial having just gated the same range.  The
	 * filters inside prop_ring_push_filtered still reject pointer-
	 * shaped and fd-aliased values. */
	msqid = (long) rec->retval;
	if (msqid < 0 || msqid > INT_MAX)
		return;
	prop_ring_push_scalar(rec->nr, msqid, SCALAR_SYSV_MSG);
}

static unsigned long ipc_flags[] = {
	IPC_CREAT,
	IPC_CREAT | 0600,
	IPC_CREAT | 0644,
	IPC_CREAT | 0666,
	IPC_CREAT | IPC_EXCL | 0600,
	IPC_CREAT | IPC_EXCL | 0644,
	IPC_CREAT | IPC_EXCL | 0666,
};

struct syscallentry syscall_msgget = {
	.name = "msgget",
	.group = GROUP_IPC,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LIST },
	.argname = { [0] = "key", [1] = "msgflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(ipc_flags),
	.post = post_msgget,
};
