/*
 *  SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
                unsigned, flags)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "maps.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_send(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	size_t size;

	rec->a1 = fd_from_socketinfo(si);

	/* The rest of this function is only used as a fallback, if the per-proto
	 * send()'s aren't implemented.
	 */
	if (RAND_BOOL())
		size = 1;
	else
		size = rand() % page_size;

	rec->a3 = size;
}

static unsigned long sendflags[] = {
	MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
	MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
	MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
	MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
	MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT,
	MSG_BATCH, MSG_ZEROCOPY,
};

struct syscallentry syscall_send = {
	.name = "send",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg4name = "flags",
        .arg4type = ARG_LIST,
	.arg4list = ARGLIST(sendflags),
	.group = GROUP_NET,
	.sanitise = sanitise_send,
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
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(sendflags),
	.arg5name = "addr",
	.arg5type = ARG_SOCKADDR,
	.arg6name = "addr_len",
	.arg6type = ARG_SOCKADDRLEN,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_send,	// same as send
};

/*
 * SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned, flags)
 */
/* Set when sanitise_sendmsg uses gen_msg so post_sendmsg knows to free iov_base */
static int sendmsg_used_gen_msg;

static void sanitise_sendmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct msghdr *msg;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;

	sendmsg_used_gen_msg = 0;

	if (si == NULL)	// handle --disable-fds=sockets
		goto skip_si;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, si->triplet.family);

skip_si:
	msg = zmalloc(sizeof(struct msghdr));
	msg->msg_name = sa;
	msg->msg_namelen = salen;

	/*
	 * If the protocol has a gen_msg hook, use it to build a structured
	 * message instead of random garbage. Fall back to random iovecs
	 * with some probability to keep testing the unstructured path too.
	 */
	if (si != NULL && !ONE_IN(4)) {
		const struct netproto *proto;
		unsigned int family = si->triplet.family;

		if (family < TRINITY_PF_MAX) {
			proto = net_protocols[family].proto;
			if (proto != NULL && proto->gen_msg != NULL) {
				struct iovec *iov;
				void *buf = NULL;
				size_t len = 0;

				proto->gen_msg(&si->triplet, &buf, &len);
				iov = zmalloc(sizeof(struct iovec));
				iov->iov_base = buf;
				iov->iov_len = len;
				msg->msg_iov = iov;
				msg->msg_iovlen = 1;
				sendmsg_used_gen_msg = 1;
				goto set_control;
			}
		}
	}

	if (RAND_BOOL()) {
		unsigned int num_entries;

		num_entries = RAND_RANGE(1, 3);
		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;
	}

set_control:
	if (RAND_BOOL()) {
		msg->msg_controllen = rand32() % 20480;	// /proc/sys/net/core/optmem_max
		msg->msg_control = get_address();
	} else {
		msg->msg_controllen = 0;
	}

	if (ONE_IN(100))
		msg->msg_flags = rand32();
	else
		msg->msg_flags = 0;

	rec->a2 = (unsigned long) msg;
}

static void post_sendmsg(__unused__ struct syscallrecord *rec)
{
	struct msghdr *msg = (struct msghdr *) rec->a2;

	if (msg != NULL) {
		if (msg->msg_iov != NULL) {
			if (sendmsg_used_gen_msg)
				free(msg->msg_iov[0].iov_base);
			free(msg->msg_iov);
		}
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
	.arg3list = ARGLIST(sendflags),
	.sanitise = sanitise_sendmsg,
	.post = post_sendmsg,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
};
/*
 * SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
 *	unsigned int, vlen, unsigned int, flags)
 */
static void sanitise_sendmmsg(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
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
	.arg4list = ARGLIST(sendflags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_sendmmsg,
};
