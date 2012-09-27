/*
 * SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen
 *
 * If the connection or binding succeeds, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_connect(int childno)
{
	generate_sockaddr(&shm->a2[childno], &shm->a3[childno]);
}

struct syscall syscall_connect = {
	.name = "connect",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "uservaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "addrlen",
	.arg3type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_connect,
};
