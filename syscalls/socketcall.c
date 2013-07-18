/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <stdlib.h>
#include <linux/net.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include "compat.h"
#include "net.h"
#include "sanitise.h"
#include "shm.h"

//FIXME: Change to table driven, instead of switch.

static void sanitise_socketcall(int childno)
{
	struct socket_triplet st;
	unsigned long *args;

	args = malloc(6 * sizeof(unsigned long));

	shm->a1[childno] = rand() % 20;

	switch (shm->a1[childno]) {

	case SYS_SOCKET:
		gen_socket_args(&st);
		args[0] = st.family;
		args[1] = st.type;
		args[2] = st.protocol;
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
