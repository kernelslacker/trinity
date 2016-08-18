/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <stdlib.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static void socketcall_socket(unsigned long *args)
{
	struct socket_triplet st = { .family = 0, .protocol = 0, .type = 0 };

	gen_socket_args(&st);

	args[0] = st.family;
	args[1] = st.type;
	args[2] = st.protocol;
}

struct socketcall_ptr {
        unsigned int call;
        void (*func)(unsigned long *args);
};

static const struct socketcall_ptr socketcallptrs[] = {
	{ .call = SYS_SOCKET, .func = socketcall_socket },
//	{ .call = SYS_BIND, .func = socketcall_bind },
//	{ .call = SYS_CONNECT, .func = socketcall_connect },
//	{ .call = SYS_LISTEN, .func = socketcall_listen },
//	{ .call = SYS_ACCEPT, .func = socketcall_accept },
//	{ .call = SYS_GETSOCKNAME, .func = socketcall_getsockname },
//	{ .call = SYS_GETPEERNAME, .func = socketcall_getpeername },
//	{ .call = SYS_SOCKETPAIR, .func = socketcall_socketpair },
//	{ .call = SYS_SEND, .func = socketcall_send },
//	{ .call = SYS_RECV, .func = socketcall_recv },
//	{ .call = SYS_SENDTO, .func = socketcall_sendto },
//	{ .call = SYS_RECVFROM, .func = socketcall_recvfrom },
//	{ .call = SYS_SHUTDOWN, .func = socketcall_shutdown },
//	{ .call = SYS_SETSOCKOPT, .func = socketcall_setsockopt },
//	{ .call = SYS_GETSOCKOPT, .func = socketcall_getsockopt },
//	{ .call = SYS_SENDMSG, .func = socketcall_sendmsg },
//	{ .call = SYS_RECVMSG, .func = socketcall_recvmsg },
//	{ .call = SYS_ACCEPT4, .func = socketcall_accept },
//	{ .call = SYS_RECVMMSG, .func = socketcall_recvmmsg },
//	{ .call = SYS_SENDMMSG, .func = socketcall_sendmmsg },
};


static void sanitise_socketcall(struct syscallrecord *rec)
{
	unsigned long *args;
	unsigned int i;

	args = zmalloc(6 * sizeof(unsigned long));

	//rec->a1 = rnd() % ARRAY_SIZE(socketcallptrs);
	rec->a1 = SYS_SOCKET;	//FIXME: Add other options and remove this hardcode.

	for (i = 0; i < ARRAY_SIZE(socketcallptrs); i++) {
		if (socketcallptrs[i].call == rec->a1)
			socketcallptrs[i].func(args);
	}

	rec->a2 = (unsigned long) args;
}

struct syscallentry syscall_socketcall = {
	.name = "socketcall",
	.num_args = 2,
	.arg1name = "call",
	.arg2name = "args",
	.arg2type = ARG_ADDRESS,
	.sanitise = sanitise_socketcall,
};
