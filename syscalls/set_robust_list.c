/*
 * SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head, size_t, len)
 */
#include <linux/futex.h>
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_set_robust_list(struct syscallrecord *rec)
{
	struct robust_list_head *head;

	head = zmalloc_tracked(sizeof(struct robust_list_head));
	head->list.next = &head->list;
	head->futex_offset = 0;
	head->list_op_pending = NULL;

	rec->a1 = (unsigned long) head;
	rec->a2 = sizeof(struct robust_list_head);
}

struct syscallentry syscall_set_robust_list = {
	.name = "set_robust_list",
	.num_args = 2,
	.sanitise = sanitise_set_robust_list,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "head", [1] = "len" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
