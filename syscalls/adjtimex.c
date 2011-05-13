/*
 * SYSCALL_DEFINE1(adjtimex, struct timex __user *, txc_p
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_adjtimex = {
	.name = "adjtimex",
	.num_args = 1,
	.arg1name = "txc_p",
	.arg1type = ARG_ADDRESS,
};
