/*
 * SYSCALL_DEFINE2(shutdown, int, fd, int, how)
 */
#include <sys/socket.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

static unsigned long shutdown_hows[] = {
	SHUT_RD, SHUT_WR, SHUT_RDWR,
};

/*
 * shutdown_hows[] via ARG_OP covers the three legal values but never
 * trips the kernel's `if (how > SHUT_RDWR) return -EINVAL` arm.  10%
 * of the time, override the ARG_OP pick with a value the kernel must
 * reject -- a negative how (sign-extends to a huge unsigned compare),
 * a just-out-of-range value (3), or a high-bit value.
 */
static const unsigned long shutdown_invalid_hows[] = {
	(unsigned long) -1,
	3,
	0x80000000UL,
};

static void sanitise_shutdown(struct syscallrecord *rec)
{
	if (ONE_IN(10))
		rec->a2 = RAND_ARRAY(shutdown_invalid_hows);
}

struct syscallentry syscall_shutdown = {
	.name = "shutdown",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_SOCKET, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "how" },
	.arg_params[1].list = ARGLIST(shutdown_hows),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_shutdown,
};
