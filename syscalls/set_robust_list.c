/*
 * SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head, size_t, len)
 */
#include <linux/futex.h>
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

static void sanitise_set_robust_list(struct syscallrecord *rec)
{
	rec->a2 = sizeof(struct robust_list_head);
}

struct syscallentry syscall_set_robust_list = {
	.name = "set_robust_list",
	.num_args = 2,
	.sanitise = sanitise_set_robust_list,
	.arg1name = "head",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
};
