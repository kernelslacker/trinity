/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include "sanitise.h"

struct syscallentry syscall_semget = {
	.name = "semget",
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "nsems",
	.arg3name = "semflg",
};
