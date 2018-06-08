/*
 * SYSCALL_DEFINE1(timer_delete, timer_t, timer_id)
 */
#include "sanitise.h"

struct syscallentry syscall_timer_delete = {
	.name = "timer_delete",
	.num_args = 1,
	.arg1name = "timer_id",
};
