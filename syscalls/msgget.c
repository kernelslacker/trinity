/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "objects.h"
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
	struct object *obj;

	if (msqid < 0)
		return;

	obj = alloc_object();
	obj->sysvmsgobj.msqid = msqid;
	add_object(obj, OBJ_LOCAL, OBJ_SYSV_MSG);
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
	long ret = (long) rec->retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	/*
	 * The kernel ABI guarantees msgget() returns either -1 or a
	 * non-negative int IPC id (i.e. 0..INT_MAX). A retval outside
	 * that range cannot have come from the kernel: either a
	 * sibling op has scribbled the syscallrecord retval slot with
	 * pointer-shaped junk, or the slot has been torn under us. In
	 * either case forwarding the bogus value into register_sysv_msg()
	 * would seed the pool with a fabricated id that msgctl(IPC_RMID)
	 * at child teardown would then issue against whatever real IPC
	 * id happens to collide with the low 31 bits of the garbage --
	 * typically destroying an unrelated object owned by another
	 * process on the host.
	 */
	if (ret > INT_MAX) {
		output(0, "msgget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	register_sysv_msg((int) ret);
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
