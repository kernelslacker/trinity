/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <stdlib.h>
#include <unistd.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
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
	/* SYS_SOCKETPAIR needs a writable int[2] for the kernel to deposit
	 * the pair of fds.  Without it the kernel returns -EFAULT and the
	 * post handler has nothing to register.  Freed in post_socketcall. */
	args[3] = (unsigned long) malloc(sizeof(int) * 2);
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

static void register_sock_fd(int fd, unsigned long family,
			     unsigned long type, unsigned long protocol)
{
	const struct netproto *proto;
	struct object *new;

	if (family >= TRINITY_PF_MAX) {
		close(fd);
		return;
	}

	proto = net_protocols[family].proto;
	if (proto != NULL)
		if (proto->socket_setup != NULL)
			proto->socket_setup(fd);

	new = alloc_object();
	new->sockinfo.fd = fd;
	new->sockinfo.triplet.family = family;
	new->sockinfo.triplet.type = type;
	new->sockinfo.triplet.protocol = protocol;
	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

static void register_accepted_fd(int fd, int listener_fd)
{
	struct fd_hash_entry *listen_entry;
	struct object *new;

	new = alloc_object();
	new->sockinfo.fd = fd;

	/* Inherit triplet from the listening socket. */
	listen_entry = fd_hash_lookup(listener_fd);
	if (listen_entry != NULL && listen_entry->type == OBJ_FD_SOCKET)
		new->sockinfo.triplet = listen_entry->obj->sockinfo.triplet;

	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

static void post_socketcall(struct syscallrecord *rec)
{
	unsigned long *args = (unsigned long *) rec->post_state;
	unsigned long call = rec->a1;
	long retval = (long) rec->retval;

	if (args == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, args)) {
		outputerr("post_socketcall: rejected suspicious args=%p (pid-scribbled?)\n", args);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * The args buffer is a multiplexer trampoline: each sub-call has its
	 * own per-syscall post handler in syscalls/socket.c, accept.c, etc.,
	 * but the multiplexer bypasses them.  Without this dispatch every fd
	 * created by socketcall(SYS_SOCKET/SOCKETPAIR/ACCEPT/ACCEPT4) leaks
	 * out of trinity's OBJ_FD_SOCKET pool, sits in the kernel fd table
	 * burning RLIMIT_NOFILE until child exit, and is invisible to sibling
	 * syscalls (no one can pick it).  Mirrors the IPC RMID handler added
	 * for the ipc() multiplexer.
	 */
	switch (call) {
	case SYS_SOCKET:
		if (retval >= 0)
			register_sock_fd(retval, args[0], args[1], args[2]);
		break;

	case SYS_ACCEPT:
	case SYS_ACCEPT4:
		if (retval >= 0)
			register_accepted_fd(retval, (int) args[0]);
		break;

	case SYS_SOCKETPAIR: {
		int *fds = (int *) args[3];

		if (fds != NULL) {
			if (retval >= 0) {
				register_sock_fd(fds[0], args[0], args[1], args[2]);
				register_sock_fd(fds[1], args[0], args[1], args[2]);
			}
			free(fds);
			args[3] = 0;
		}
		break;
	}

	default:
		break;
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
