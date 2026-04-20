/*
   asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size,
                            unsigned flags)

 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_recv(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	/* recv/recvfrom both pass a2 as the user output buffer with length
	 * a3 — the kernel writes the received bytes there.  ARG_MMAP hands
	 * us a struct map pointer rather than a real buffer, so the kernel
	 * scribbles into adjacent heap memory; defensively redirect away
	 * from any range that overlaps trinity's alloc_shared regions. */
	avoid_shared_buffer(&rec->a2, rec->a3);
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
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_MMAP, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "ubuf", [2] = "size", [3] = "flags" },
	.arg_params[3].list = ARGLIST(recv_flags),
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
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_MMAP, [2] = ARG_LEN, [3] = ARG_LIST, [4] = ARG_SOCKADDR, [5] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "ubuf", [2] = "size", [3] = "flags", [4] = "addr", [5] = "addr_len" },
	.arg_params[3].list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recv,	// same as recv
};


/*
 * SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags)
 */
static void sanitise_recvmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct msghdr *msg;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;

	if (si == NULL)		// handle --disable-fds=sockets
		goto skip_si;

	rec->a1 = fd_from_socketinfo(si);

	generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, si->triplet.family);

skip_si:
	msg = zmalloc(sizeof(struct msghdr));
	msg->msg_name = sa;
	msg->msg_namelen = salen;

	if (RAND_BOOL()) {
		unsigned int num_entries = RAND_RANGE(1, 3);

		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;
	}

	if (RAND_BOOL()) {
		msg->msg_controllen = rand32() % 4096;
		msg->msg_control = zmalloc(msg->msg_controllen);
	}

	if (ONE_IN(100))
		msg->msg_flags = rand32();
	else
		msg->msg_flags = 0;

	rec->a2 = (unsigned long) msg;
}

static void post_recvmsg(struct syscallrecord *rec)
{
	struct msghdr *msg = (struct msghdr *) rec->a2;

	if (msg != NULL) {
		free(msg->msg_control);
		free(msg->msg_iov);
		free(msg->msg_name);
		deferred_freeptr(&rec->a2);
	}
}

struct syscallentry syscall_recvmsg = {
	.name = "recvmsg",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "msg", [2] = "flags" },
	.arg_params[2].list = ARGLIST(recv_flags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recvmsg,
	.post = post_recvmsg,
};

/*
 * SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
	 unsigned int, vlen, unsigned int, flags,
	 struct timespec __user *, timeout)
 */
#define RECVMMSG_MAX_VLEN	4

static void sanitise_recvmmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct mmsghdr *msgs;
	unsigned int vlen;
	unsigned int i;

	rec->a1 = fd_from_socketinfo(si);

	vlen = RAND_RANGE(1, RECVMMSG_MAX_VLEN);
	msgs = zmalloc(vlen * sizeof(struct mmsghdr));

	for (i = 0; i < vlen; i++) {
		struct msghdr *msg = &msgs[i].msg_hdr;
		unsigned int num_entries = RAND_RANGE(1, 3);

		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;
	}

	rec->a2 = (unsigned long) msgs;
	rec->a3 = vlen;
}

static void post_recvmmsg(struct syscallrecord *rec)
{
	struct mmsghdr *msgs = (struct mmsghdr *) rec->a2;

	if (msgs != NULL) {
		unsigned int i;

		for (i = 0; i < (unsigned int) rec->a3; i++)
			free(msgs[i].msg_hdr.msg_iov);
		free(msgs);
	}
}

struct syscallentry syscall_recvmmsg = {
	.name = "recvmmsg",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "mmsg", [2] = "vlen", [3] = "flags", [4] = "timeout" },
	.arg_params[3].list = ARGLIST(recv_flags),
	.arg_params[2].range.low = 1, .arg_params[2].range.hi = 1024,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_recvmmsg,
	.post = post_recvmmsg,
};
