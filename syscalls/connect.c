/*
 * SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen
 *
 * If the connection or binding succeeds, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_connect(int childno)
{
	struct sockaddr_in *addr;

	addr = malloc(sizeof(struct sockaddr_in));
	if (addr == NULL)
		return;

	//TODO: Support more families
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(0x7f000001);
	addr->sin_port = rand() % 65535;
	shm->a2[childno] = (unsigned long) addr;
	shm->a3[childno] = sizeof(struct sockaddr_in);
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
