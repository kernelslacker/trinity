/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_msgget = {
	.name = "msgget",
	.num_args = 2,
	.arg1name = "key",
	.arg2name = "msgflg",
};
