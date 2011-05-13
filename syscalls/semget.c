/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_semget = {
	.name = "semget",
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "nsems",
	.arg3name = "semflg",
};
