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

static void sanitise_send(struct syscallrecord *rec)
{
	unsigned int size;
	void *ptr;

	rec->a1 = generic_fd_from_socketinfo((struct socketinfo *) rec->a1);

	if (RAND_BOOL())
		size = 1;
	else
		size = rand() % page_size;

	ptr = malloc(size);
	rec->a2 = (unsigned long) ptr;
	if (ptr == NULL)
		return;

	rec->a3 = size;

	// TODO: only use this as a fallback, and actually have
	// some per-proto generators here.
	generate_rand_bytes(ptr, size);
}

static void post_send(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
}

struct syscallentry syscall_send = {
	.name = "send",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "buff",
	.arg3name = "len",
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
	.sanitise = sanitise_send,
	.post = post_send,
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
	.sanitise = sanitise_send,	// same as send
	.post = post_send,
};

/*
 * SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned, flags)
 */
static void sanitise_sendmsg(struct syscallrecord *rec)
{
	struct msghdr *msg;
	struct sockaddr *sa = NULL;
	socklen_t salen;

	rec->a1 = generic_fd_from_socketinfo((struct socketinfo *) rec->a1);

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
	struct msghdr *msg = (struct msghdr *) rec->a2;

	if (msg != NULL) {
		free(msg->msg_name);	// free sockaddr
		freeptr(&rec->a2);
	}
}

struct syscallentry syscall_sendmsg = {
	.name = "sendmsg",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
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
static void sanitise_sendmmsg(struct syscallrecord *rec)
{
	rec->a1 = generic_fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_sendmmsg = {
	.name = "sendmmsg",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
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
	.sanitise = sanitise_sendmmsg,
};
