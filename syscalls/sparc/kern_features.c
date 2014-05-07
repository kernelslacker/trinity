/*
 * long sys_kern_features(void)
 */

#include "sanitise.h"

struct syscallentry syscall_kern_features = {
	.flags = BORING,
	.name = "kern_features",
	.num_args = 0,
};
