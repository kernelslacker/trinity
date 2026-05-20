/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_accept(struct syscallrecord *rec)
{
	socklen_t *lenp;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sockaddr_storage));

	/*
	 * upeer_addrlen is a value-result socklen_t pointer.  ARG_SOCKADDRLEN
	 * published a scalar (the addr buffer's generated length) into the
	 * slot, but the kernel reads it as a __user pointer and EFAULTs the
	 * call every time -- accept never actually returned a connected fd.
	 * Replace with a real heap-resident socklen_t* initialised to the
	 * addr buffer's full sockaddr_storage capacity, then _inout (not
	 * _out) so the init value survives any heap-overlap relocation: the
	 * kernel reads *lenp as max_addrlen BEFORE writing the actual length
	 * back.  Mirrors getsockopt.c:73-101.
	 */
	lenp = zmalloc(sizeof(*lenp));
	*lenp = sizeof(struct sockaddr_storage);
	rec->a3 = (unsigned long) lenp;
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));
}

static void post_accept(struct syscallrecord *rec)
{
	struct fd_hash_entry *listen_entry;
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	new->sockinfo.fd = fd;

	/* Inherit triplet from the listening socket. */
	listen_entry = fd_hash_lookup(rec->a1);
	if (listen_entry != NULL && listen_entry->type == OBJ_FD_SOCKET) {
		new->sockinfo.triplet = listen_entry->obj->sockinfo.triplet;
	}

	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

struct syscallentry syscall_accept = {
	.name = "accept",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "upeer_sockaddr", [2] = "upeer_addrlen" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SOCKET,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_accept,
	.post = post_accept,
};

/*
 * SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
	 int __user *, upeer_addrlen, int, flags)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 *
 */

static unsigned long accept4_flags[] = {
	SOCK_NONBLOCK, SOCK_CLOEXEC,
};

static void sanitise_accept4(struct syscallrecord *rec)
{
	socklen_t *lenp;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sockaddr_storage));

	/* See sanitise_accept above for the value-result socklen_t* rationale. */
	lenp = zmalloc(sizeof(*lenp));
	*lenp = sizeof(struct sockaddr_storage);
	rec->a3 = (unsigned long) lenp;
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));
}

struct syscallentry syscall_accept4 = {
	.name = "accept4",
	.num_args = 4,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "upeer_sockaddr", [2] = "upeer_addrlen", [3] = "flags" },
	.arg_params[3].list = ARGLIST(accept4_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SOCKET,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_accept4,
	.post = post_accept,
};
