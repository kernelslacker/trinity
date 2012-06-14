/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <stdlib.h>
#include <linux/net.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static void sanitise_socketcall(int childno)
{
	unsigned long *args;

	args = malloc(6 * sizeof(unsigned long));

	shm->a1[childno] = rand() % 20;

	switch (shm->a1[childno]) {
	case SYS_SOCKET:
		sanitise_socket(childno);
		shm->syscallno[childno] = search_syscall_table(syscalls, max_nr_syscalls, "socket");
		break;
	case SYS_BIND:
		break;
	case SYS_CONNECT:
		break;
	case SYS_LISTEN:
		break;
	case SYS_ACCEPT:
		break;
	case SYS_GETSOCKNAME:
		break;
	case SYS_GETPEERNAME:
		break;
	case SYS_SOCKETPAIR:
		break;
	case SYS_SEND:
		break;
	case SYS_RECV:
		break;
	case SYS_SENDTO:
		break;
	case SYS_RECVFROM:
		break;
	case SYS_SHUTDOWN:
		break;
	case SYS_SETSOCKOPT:
		break;
	case SYS_GETSOCKOPT:
		break;
	case SYS_SENDMSG:
		break;
	case SYS_RECVMSG:
		break;
	case SYS_ACCEPT4:
		break;
	case SYS_RECVMMSG:
		break;
	case SYS_SENDMMSG:
		break;
	default:
		break;
	}

	shm->a2[childno] = (unsigned long) args;
}

struct syscall syscall_socketcall = {
	.name = "socketcall",
	.num_args = 2,
	.arg1name = "call",
	.arg2name = "args",
	.arg2type = ARG_ADDRESS,
	.sanitise = sanitise_socketcall,
};
