/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <stdlib.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "deferred-free.h"
#include "utils.h"

static int get_random_socket_fd(void)
{
	struct socketinfo *si;

	si = get_rand_socketinfo();
	if (si == NULL)
		return -1;

	return fd_from_socketinfo(si);
}

static void socketcall_socket(unsigned long *args)
{
	struct socket_triplet st = { .family = 0, .protocol = 0, .type = 0 };

	gen_socket_args(&st);

	args[0] = st.family;
	args[1] = st.type;
	args[2] = st.protocol;
}

static void socketcall_bind(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_connect(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_listen(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[1] = rand32() % 128;
}

static void socketcall_accept(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_getsockname(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_getpeername(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_socketpair(unsigned long *args)
{
	struct socket_triplet st = { .family = 0, .protocol = 0, .type = 0 };

	gen_socket_args(&st);

	args[0] = st.family;
	args[1] = st.type;
	args[2] = st.protocol;
}

static void socketcall_send(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[2] = rand32() % page_size;
}

static void socketcall_recv(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[2] = rand32() % page_size;
}

static void socketcall_sendto(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[2] = rand32() % page_size;
}

static void socketcall_recvfrom(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[2] = rand32() % page_size;
}

static void socketcall_shutdown(unsigned long *args)
{
	args[0] = get_random_socket_fd();
	args[1] = rand32() % 3;	/* SHUT_RD, SHUT_WR, SHUT_RDWR */
}

static void socketcall_setsockopt(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_getsockopt(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_sendmsg(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_recvmsg(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_recvmmsg(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

static void socketcall_sendmmsg(unsigned long *args)
{
	args[0] = get_random_socket_fd();
}

struct socketcall_ptr {
        unsigned int call;
        void (*func)(unsigned long *args);
};

static const struct socketcall_ptr socketcallptrs[] = {
	{ .call = SYS_SOCKET, .func = socketcall_socket },
	{ .call = SYS_BIND, .func = socketcall_bind },
	{ .call = SYS_CONNECT, .func = socketcall_connect },
	{ .call = SYS_LISTEN, .func = socketcall_listen },
	{ .call = SYS_ACCEPT, .func = socketcall_accept },
	{ .call = SYS_GETSOCKNAME, .func = socketcall_getsockname },
	{ .call = SYS_GETPEERNAME, .func = socketcall_getpeername },
	{ .call = SYS_SOCKETPAIR, .func = socketcall_socketpair },
	{ .call = SYS_SEND, .func = socketcall_send },
	{ .call = SYS_RECV, .func = socketcall_recv },
	{ .call = SYS_SENDTO, .func = socketcall_sendto },
	{ .call = SYS_RECVFROM, .func = socketcall_recvfrom },
	{ .call = SYS_SHUTDOWN, .func = socketcall_shutdown },
	{ .call = SYS_SETSOCKOPT, .func = socketcall_setsockopt },
	{ .call = SYS_GETSOCKOPT, .func = socketcall_getsockopt },
	{ .call = SYS_SENDMSG, .func = socketcall_sendmsg },
	{ .call = SYS_RECVMSG, .func = socketcall_recvmsg },
	{ .call = SYS_ACCEPT4, .func = socketcall_accept },
	{ .call = SYS_RECVMMSG, .func = socketcall_recvmmsg },
	{ .call = SYS_SENDMMSG, .func = socketcall_sendmmsg },
};


static void sanitise_socketcall(struct syscallrecord *rec)
{
	unsigned long *args;
	unsigned int r;

	args = zmalloc(6 * sizeof(unsigned long));

	r = rand() % ARRAY_SIZE(socketcallptrs);
	rec->a1 = socketcallptrs[r].call;
	socketcallptrs[r].func(args);

	rec->a2 = (unsigned long) args;
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall before post_socketcall() runs. */
	rec->post_state = (unsigned long) args;
}

static void post_socketcall(struct syscallrecord *rec)
{
	void *args = (void *) rec->post_state;

	if (args == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, args)) {
		outputerr("post_socketcall: rejected suspicious args=%p (pid-scribbled?)\n", args);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_socketcall = {
	.name = "socketcall",
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "call", [1] = "args" },
	.group = GROUP_NET,
	.flags = NEED_ALARM,
	.sanitise = sanitise_socketcall,
	.post = post_socketcall,
};
