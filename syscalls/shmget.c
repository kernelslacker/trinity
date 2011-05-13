/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_shmget = {
	.name = "shmget",
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "shmflg",
};
