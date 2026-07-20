/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include <unistd.h>
#include <linux/net.h>
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "deferred-free.h"
#include "utils.h"

#include "kernel/net.h"
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

static void socketcall_socketpair(unsigned long *args)
{
	struct socket_triplet st = { .family = 0, .protocol = 0, .type = 0 };

	gen_socket_args(&st);

	args[0] = st.family;
	args[1] = st.type;
	args[2] = st.protocol;
	/* SYS_SOCKETPAIR needs a writable int[2] for the kernel to deposit
	 * the pair of fds.  Without it the kernel returns -EFAULT and the
	 * post handler has nothing to register.  Route through
	 * avoid_shared_buffer_out() so the kernel can't scribble fds into the
	 * trinity-shared allocator pool or libc heap chunk metadata --
	 * blanket_address_scrub() only walks rec->a1..a6 and never reaches
	 * inner pointers inside multiplexer args. */
	args[3] = (unsigned long) get_writable_address(sizeof(int) * 2);
	avoid_shared_buffer_out(&args[3], sizeof(int) * 2);
}

/*
 * What to scribble into args[] for a given socketcall sub-call.  Most
 * sub-calls just want a random socket fd in args[0]; a handful also
 * want a length in args[2], a shutdown-how in args[1], or a listen
 * backlog in args[1].  SYS_SOCKET and SYS_SOCKETPAIR don't take an fd
 * at all and need their own argument generator (special != NULL); in
 * that case the dispatcher skips the args[0] = fd path entirely.
 */
enum socketcall_extra {
	EXTRA_NONE,
	EXTRA_LEN,	/* args[2] = rnd_modulo_u32(page_size)  (send/recv/sendto/recvfrom) */
	EXTRA_SHUT,	/* args[1] = rand32() % 3               (shutdown how) */
	EXTRA_BACKLOG,	/* args[1] = rnd_modulo_u32(128)        (listen) */
};

struct socketcall_desc {
	unsigned int call;
	enum socketcall_extra extra;
	void (*special)(unsigned long *args);
};

static const struct socketcall_desc socketcalls[] = {
	{ SYS_SOCKET,		EXTRA_NONE,	socketcall_socket },
	{ SYS_BIND,		EXTRA_NONE,	NULL },
	{ SYS_CONNECT,		EXTRA_NONE,	NULL },
	{ SYS_LISTEN,		EXTRA_BACKLOG,	NULL },
	{ SYS_ACCEPT,		EXTRA_NONE,	NULL },
	{ SYS_GETSOCKNAME,	EXTRA_NONE,	NULL },
	{ SYS_GETPEERNAME,	EXTRA_NONE,	NULL },
	{ SYS_SOCKETPAIR,	EXTRA_NONE,	socketcall_socketpair },
	{ SYS_SEND,		EXTRA_LEN,	NULL },
	{ SYS_RECV,		EXTRA_LEN,	NULL },
	{ SYS_SENDTO,		EXTRA_LEN,	NULL },
	{ SYS_RECVFROM,		EXTRA_LEN,	NULL },
	{ SYS_SHUTDOWN,		EXTRA_SHUT,	NULL },
	{ SYS_SETSOCKOPT,	EXTRA_NONE,	NULL },
	{ SYS_GETSOCKOPT,	EXTRA_NONE,	NULL },
	{ SYS_SENDMSG,		EXTRA_NONE,	NULL },
	{ SYS_RECVMSG,		EXTRA_NONE,	NULL },
	{ SYS_ACCEPT4,		EXTRA_NONE,	NULL },
	{ SYS_RECVMMSG,		EXTRA_NONE,	NULL },
	{ SYS_SENDMMSG,		EXTRA_NONE,	NULL },
};

static void sanitise_socketcall(struct syscallrecord *rec)
{
	const struct socketcall_desc *desc;
	unsigned long *args;
	unsigned int r;

	args = zmalloc_tracked(6 * sizeof(unsigned long));

	r = rnd_modulo_u32(ARRAY_SIZE(socketcalls));
	desc = &socketcalls[r];
	rec->a1 = desc->call;

	if (desc->special != NULL) {
		desc->special(args);
	} else {
		args[0] = get_random_socket_fd();
		switch (desc->extra) {
		case EXTRA_LEN:
			args[2] = rnd_modulo_u32(page_size);
			break;
		case EXTRA_SHUT:
			args[1] = rand32() % 3;	/* SHUT_RD, SHUT_WR, SHUT_RDWR */
			break;
		case EXTRA_BACKLOG:
			args[1] = rnd_modulo_u32(128);
			break;
		case EXTRA_NONE:
			break;
		}
	}

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
	unsigned long call = get_arg_snapshot(rec, 1);
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

		if (fds == NULL)
			break;

		if (looks_like_corrupted_ptr(rec, fds)) {
			outputerr("post_socketcall: rejected suspicious fds=%p (pid-scribbled?)\n", fds);
			rec->a2 = 0;
			rec->post_state = 0;
			return;
		}

		if (retval >= 0) {
			register_sock_fd(fds[0], args[0], args[1], args[2]);
			register_sock_fd(fds[1], args[0], args[1], args[2]);
		}
		/* fds points into the trinity writable pool (see
		 * socketcall_socketpair); the pool owns the memory,
		 * so no free here. */
		args[3] = 0;
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
	/* a1 (call) drives post_socketcall's multiplexer switch: it selects
	 * the SYS_SOCKET / ACCEPT / ACCEPT4 / SOCKETPAIR arm that registers
	 * the kernel-returned fd into trinity's OBJ_FD_SOCKET pool.  Shadow
	 * it so a sibling stomp between dispatch and post cannot redirect
	 * the switch into a different case and mis-register (or skip) the
	 * fd against the wrong sub-call -- mismatch bumps arg_shadow_stomp
	 * from inside get_arg_snapshot() and the handler still dispatches
	 * on the sub-call the kernel actually executed. */
	.arg_snapshot_mask = (1u << 0),
};
