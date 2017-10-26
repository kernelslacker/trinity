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
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "ubuf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
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
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "ubuf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(recv_flags),
	.arg5name = "addr",
	.arg5type = ARG_SOCKADDR,
	.arg6name = "addr_len",
	.arg6type = ARG_SOCKADDRLEN,
	.flags = NEED_ALARM,
	.sanitise = sanitise_recv,	// same as recv
};


/*
 * SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags)
 */
struct syscallentry syscall_recvmsg = {
	.name = "recvmsg",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "msg",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
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
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "mmsg",
	.arg2type = ARG_ADDRESS,
	.arg3name = "vlen",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(recv_flags),
	.arg5name = "timeout",
	.arg5type = ARG_ADDRESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_recv,	// same as recv
};
