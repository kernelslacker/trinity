/*
 *  SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
                unsigned, flags)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

struct syscallentry syscall_send = {
	.name = "send",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
        .arg4type = ARG_LIST,
	.arg4list = {
		.num = 20,
		.values = { MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
			    MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
			    MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
			    MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
			    MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT,
		},
	},
};


/*
 * SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
	 unsigned, flags, struct sockaddr __user *, addr,
	 int, addr_len)
 */
struct syscallentry syscall_sendto = {
	.name = "sendto",
	.num_args = 6,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 20,
		.values = { MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
			    MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
			    MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
			    MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
			    MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT },
	},
	.arg5name = "addr",
	.arg5type = ARG_SOCKADDR,
	.arg6name = "addr_len",
	.arg6type = ARG_SOCKADDRLEN,
	.flags = NEED_ALARM,
};

static struct msghdr *msg;

/*
 * SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned, flags)
 */
static void sanitise_sendmsg(struct syscallrecord *rec)
{
	struct sockaddr *sa = NULL;
	socklen_t salen;

	msg = zmalloc(sizeof(struct msghdr));

	generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, rand() % TRINITY_PF_MAX);

	msg->msg_name = sa;
	msg->msg_namelen = salen;

	msg->msg_iov = get_address();
	msg->msg_iovlen = get_len();
	msg->msg_control = get_address();
	msg->msg_controllen = get_len();
	msg->msg_flags = rand32();

	rec->a2 = (unsigned long) msg;
}

static void post_sendmsg(__unused__ struct syscallrecord *rec)
{
	if (msg != NULL) {
		free(msg->msg_name);	// free sockaddr
		free(msg);
	}
}

struct syscallentry syscall_sendmsg = {
	.name = "sendmsg",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "msg",
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 20,
		.values = { MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
			    MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
			    MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
			    MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
			    MSG_WAITFORONE, MSG_CMSG_CLOEXEC, MSG_FASTOPEN, MSG_CMSG_COMPAT },
	},
	.sanitise = sanitise_sendmsg,
	.post = post_sendmsg,
	.flags = NEED_ALARM,
};
/*
 * SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
 *	unsigned int, vlen, unsigned int, flags)
 */
struct syscallentry syscall_sendmmsg = {
	.name = "sendmmsg",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "mmsg",
	.arg2type = ARG_ADDRESS,
	.arg3name = "vlen",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 20,
		.values = { MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
			    MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
			    MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
			    MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
			    MSG_WAITFORONE, MSG_CMSG_CLOEXEC, MSG_FASTOPEN, MSG_CMSG_COMPAT },
	},
	.flags = NEED_ALARM,
};
