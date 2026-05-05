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
#include "shm.h"
#include "trinity.h"
#include "utils.h"
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

#ifndef MSG_SOCK_DEVMEM
#define MSG_SOCK_DEVMEM	0x2000000	/* 6.10+ */
#endif

static unsigned long recv_flags[] = {
	MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
	MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
	MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
	MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
	MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT,
	MSG_BATCH, MSG_ZEROCOPY, MSG_SOCK_DEVMEM,
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
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall (e.g. an objects.c add_object realloc) before post_recvmsg()
	 * runs, leaving a real-but-wrong heap pointer that the corruption
	 * guard cannot distinguish from the original. */
	rec->post_state = (unsigned long) msg;
}

static void post_recvmsg(struct syscallrecord *rec)
{
	struct msghdr *msg = (struct msghdr *) rec->post_state;

	if (msg == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped (e.g. by a child
	 * reusing the slot), so keep the corruption guard.
	 */
	if (looks_like_corrupted_ptr(rec, msg)) {
		outputerr("post_recvmsg: rejected suspicious msg=%p "
			  "(pid-scribbled?)\n", msg);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	if (inner_ptr_ok_to_free(rec, msg->msg_control, "post_recvmsg/msg_control"))
		free(msg->msg_control);
	deferred_free_enqueue(msg->msg_iov, NULL);
	if (inner_ptr_ok_to_free(rec, msg->msg_name, "post_recvmsg/msg_name"))
		free(msg->msg_name);
	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
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
		struct sockaddr *sa = NULL;
		socklen_t salen = 0;

		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;

		if (si != NULL)
			generate_sockaddr(&sa, &salen, si->triplet.family);
		msg->msg_name = sa;
		msg->msg_namelen = salen;

		if (RAND_BOOL()) {
			msg->msg_controllen = rand32() % 4096;
			msg->msg_control = zmalloc(msg->msg_controllen);
		}
	}

	rec->a2 = (unsigned long) msgs;
	rec->a3 = vlen;
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall (e.g. an objects.c add_object realloc) before
	 * post_recvmmsg() runs, leaving a real-but-wrong heap pointer that
	 * the corruption guard cannot distinguish from the original. */
	rec->post_state = (unsigned long) msgs;
}

static void post_recvmmsg(struct syscallrecord *rec)
{
	struct mmsghdr *msgs = (struct mmsghdr *) rec->post_state;
	unsigned int vlen = (unsigned int) rec->a3;
	unsigned int i;

	if (msgs == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so keep the
	 * corruption guard.
	 */
	if (looks_like_corrupted_ptr(rec, msgs)) {
		outputerr("post_recvmmsg: rejected suspicious msgs=%p "
			  "(pid-scribbled?)\n", msgs);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Snapshot rec->a3 (vlen) and bound against the sanitiser cap.
	 * Same shape as the post_sendmmsg vlen scribble: 914fbc6f1ff6 added
	 * the msgs pointer guard but rec->a3 is just as exposed to a
	 * sibling fuzzed value-result syscall scribbling it between the
	 * call and the post handler running.  The loop would walk past the
	 * vlen * sizeof(struct mmsghdr) allocation, heap-buffer-overflow.
	 */
	if (vlen > RECVMMSG_MAX_VLEN) {
		outputerr("post_recvmmsg: rejected suspicious vlen=%u "
			  "(pid-scribbled?)\n", vlen);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Kernel ABI: __sys_recvmmsg() returns the count of successfully
	 * received mmsghdr entries (1..vlen) on success or -1 on failure.
	 * Anything > vlen (excluding -1UL) is a structural ABI regression: a
	 * sign-extension tear, a torn write of the count by a parallel
	 * signal-restart path, or -errno leaking through the success slot.
	 * vlen is already validated by the cap guard above so it is safe to
	 * compare directly.  Mirrors epoll_wait 4c7a84058afd / epoll_pwait
	 * 1ae902d4b01d.
	 */
	if ((long) rec->retval != -1L && rec->retval > vlen) {
		outputerr("post_recvmmsg: rejecting retval %ld > vlen %u\n",
			  (long) rec->retval, vlen);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	for (i = 0; i < vlen; i++) {
		deferred_free_enqueue(msgs[i].msg_hdr.msg_iov, NULL);
		if (inner_ptr_ok_to_free(rec, msgs[i].msg_hdr.msg_control,
					 "post_recvmmsg/msg_control"))
			free(msgs[i].msg_hdr.msg_control);
		if (inner_ptr_ok_to_free(rec, msgs[i].msg_hdr.msg_name,
					 "post_recvmmsg/msg_name"))
			free(msgs[i].msg_hdr.msg_name);
	}
	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
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
