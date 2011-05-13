/*
 * SYSCALL_DEFINE0(inotify_init)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_inotify_init = {
	.name = "inotify_init",
	.num_args = 0,
};
