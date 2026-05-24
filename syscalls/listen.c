/*
 * SYSCALL_DEFINE2(listen, int, fd, int, backlog)
 */
#include <limits.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Backlog edge cases.  The pre-bucket ARG_RANGE [0..128] missed:
 *
 *  - backlog == 0 (legal: kernel treats as "minimum" backlog),
 *  - backlog == 1 (smallest non-trivial queue depth),
 *  - backlog at SOMAXCONN (current default),
 *  - backlog above the net.core.somaxconn sysctl cap (kernel
 *    silently clamps; useful to keep that clamp warm),
 *  - signed-int negative values.  `int backlog` has historically
 *    been a regression source for sign-extension and ipv4_sysctl
 *    clamp ordering, so -1 and INT_MIN both belong in the rotation.
 *
 * The .sanitise win overrides the ARG_RANGE draw, so the existing
 * range params don't need to come out.
 */
static const long listen_backlog_buckets[] = {
	0,
	1,
	5,
	128,	/* SOMAXCONN default */
	4096,	/* well above the sysctl cap */
	-1,
	INT_MIN,
};

static void sanitise_listen(struct syscallrecord *rec)
{
	rec->a2 = (unsigned long) RAND_ARRAY(listen_backlog_buckets);
}

struct syscallentry syscall_listen = {
	.name = "listen",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_SOCKET, [1] = ARG_RANGE },
	.argname = { [0] = "fd", [1] = "backlog" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 128,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_listen,
};
