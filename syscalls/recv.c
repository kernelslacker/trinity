/*
   asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size,
                            unsigned flags)

 */
#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"
#include "sanitise.h"
#include "compat.h"

static void sanitise_recv(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

static unsigned long recv_flags[] = {
	MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
	MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
	MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
	MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
	MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT,
	MSG_BATCH, MSG_ZEROCOPY,
};

struct syscallentry syscall_recv = {
	.name = "recv",
	.num_args = 4,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "ubuf", [2] = "size", [3] = "flags" },
	.arg4list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recv,
};


/*
 * SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
	unsigned, flags, struct sockaddr __user *, addr,
	int __user *, addr_len)
 */
struct syscallentry syscall_recvfrom = {
	.name = "recvfrom",
	.num_args = 6,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST, [4] = ARG_SOCKADDR, [5] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "ubuf", [2] = "size", [3] = "flags", [4] = "addr", [5] = "addr_len" },
	.arg4list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recv,	// same as recv
};


/*
 * SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags)
 */
struct syscallentry syscall_recvmsg = {
	.name = "recvmsg",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "msg", [2] = "flags" },
	.arg3list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recv,	// same as recv
};

/*
 * SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
	 unsigned int, vlen, unsigned int, flags,
	 struct timespec __user *, timeout)
 */
struct syscallentry syscall_recvmmsg = {
	.name = "recvmmsg",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "mmsg", [2] = "vlen", [3] = "flags", [4] = "timeout" },
	.arg4list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recv,	// same as recv
};
