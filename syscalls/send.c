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
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
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
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_MMAP, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "buff", [2] = "len", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sendflags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_send,
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};


/*
 * SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
	 unsigned, flags, struct sockaddr __user *, addr,
	 int, addr_len)
 */
struct syscallentry syscall_sendto = {
	.name = "sendto",
	.num_args = 6,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_MMAP, [2] = ARG_LEN, [3] = ARG_LIST, [4] = ARG_SOCKADDR, [5] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "buff", [2] = "len", [3] = "flags", [4] = "addr", [5] = "addr_len" },
	.arg_params[3].list = ARGLIST(sendflags),
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_send,	// same as send
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned, flags)
 */
/*
 * Snapshot for the post handler.  rec->a2 (the msghdr pointer) may be
 * scribbled by a sibling syscall before post_sendmsg() runs, and the
 * msghdr's iov array is just as exposed to a sibling-thread torn write
 * of msg->msg_iovlen / msg->msg_iov[].iov_len that the count-bound
 * validator below relies on.  Captured at sanitise time into a
 * post_state-private heap struct that no syscall ABI slot points at.
 *
 * Leading magic cookie because the heap-shape check on rec->post_state
 * is value-based only -- a sibling scribbling rec->post_state with any
 * heap-shaped 8-byte aligned pointer (a different syscall's post_state,
 * a stale alloc_iovec(1) in the same free-list bucket, ...) sails past
 * looks_like_corrupted_ptr() and the post handler then loads snap->msg
 * from foreign bytes, treats the result as a struct msghdr *, and
 * dereferences into poisoned heap.  That is the dominant non-ASAN
 * crash cluster (__zmalloc -> malloc -> malloc_printerr -> abort).
 * Mirrors RECVMSG_POST_STATE_MAGIC at recv.c:103.  Sized 24 bytes to
 * stay clear of the 16-byte free-list bucket that holds alloc_iovec(1).
 */
#define SENDMSG_POST_STATE_MAGIC	0x53454E44505354UL	/* "SENDPST" */
struct sendmsg_post_state {
	unsigned long magic;
	struct msghdr *msg;
	unsigned long iov_len_sum;
};

static void sanitise_sendmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct msghdr *msg;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	struct sendmsg_post_state *snap;
	unsigned long iov_len_sum = 0;

	rec->a4 = 0;	/* sendmsg_used_gen_msg: set to 1 if gen_msg path taken */

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
				iov_len_sum = len;
				rec->a4 = 1;
				goto set_control;
			}
		}
	}

	if (RAND_BOOL()) {
		unsigned int num_entries;
		unsigned int i;

		num_entries = RAND_RANGE(1, 3);
		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;

		for (i = 0; i < num_entries; i++)
			iov_len_sum += msg->msg_iov[i].iov_len;
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

	/*
	 * Second-pass scrub of msg_iov before the kernel walks the array.
	 * Even though sendmsg is a kernel-read of the iov_base buffers,
	 * net/skbuff.c paths that copy the user data sometimes fault back
	 * in via copy_from_iter_full() and on the gen_msg / SCM_RIGHTS
	 * path the kernel writes the cmsg back into the iovec.  An
	 * iov_base scribbled into the libc brk arena by a sibling between
	 * this sanitiser returning and the kernel reading the array would
	 * then surface as a glibc heap-corruption assert via the next
	 * malloc anywhere in trinity (__zmalloc -> malloc ->
	 * malloc_printerr -> abort).  Mirrors recvmsg.
	 */
	scrub_msghdr_for_kernel_write(msg);

	rec->a2 = (unsigned long) msg;

	snap = zmalloc(sizeof(*snap));
	snap->magic = SENDMSG_POST_STATE_MAGIC;
	snap->msg = msg;
	snap->iov_len_sum = iov_len_sum;
	rec->post_state = (unsigned long) snap;
}

static void post_sendmsg(struct syscallrecord *rec)
{
	struct sendmsg_post_state *snap =
		(struct sendmsg_post_state *) rec->post_state;
	struct msghdr *msg;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_sendmsg: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * sendmsg_post_state.  A cookie mismatch means snap does not point
	 * at our struct -- abandon both the snap and the msghdr cleanup
	 * rather than feed wild bytes into the inner-field deref.  Cannot
	 * deferred_freeptr the snap because we cannot prove it is one of
	 * our allocations.  Mirrors recv.c:212.
	 */
	if (snap->magic != SENDMSG_POST_STATE_MAGIC) {
		outputerr("post_sendmsg: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	msg = snap->msg;

	if (msg == NULL || looks_like_corrupted_ptr(rec, msg)) {
		outputerr("post_sendmsg: rejected suspicious msg=%p "
			  "(post_state-scribbled?)\n", msg);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * STRONG-VAL count bound: __sys_sendmsg() returns the count of
	 * bytes sent (0..Σ msg->msg_iov[].iov_len) on success or -1 on
	 * failure.  Anything > Σ iov_len (excluding -1UL) is a structural
	 * ABI regression: a sign-extension tear, a torn write of the count
	 * by a parallel signal-restart path, or -errno leaking through the
	 * success slot.  iov_len_sum was snapshotted at sanitise time into
	 * the post_state-private slot rather than re-walked from the
	 * sibling-stomp-vulnerable msghdr.  Mirrors recvmsg 9f1fda362a96.
	 */
	if ((long) rec->retval == -1L)
		goto skip_bound;
	if (rec->retval > snap->iov_len_sum) {
		outputerr("post_sendmsg: rejecting retval %lu > iov_len_sum %lu\n",
			  rec->retval, snap->iov_len_sum);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a2 = 0;
		goto out_free;
	}
skip_bound:

	if (msg->msg_iov != NULL) {
		if (rec->a4 &&
		    inner_ptr_ok_to_free(rec, msg->msg_iov[0].iov_base,
					 "post_sendmsg/iov_base"))
			free(msg->msg_iov[0].iov_base);
		deferred_free_enqueue(msg->msg_iov, NULL);
	}
	if (inner_ptr_ok_to_free(rec, msg->msg_name, "post_sendmsg/msg_name"))
		free(msg->msg_name);	// free sockaddr
	rec->a2 = 0;
	deferred_free_enqueue(msg, NULL);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_sendmsg = {
	.name = "sendmsg",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "msg", [2] = "flags" },
	.arg_params[2].list = ARGLIST(sendflags),
	.sanitise = sanitise_sendmsg,
	.post = post_sendmsg,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.rettype = RET_NUM_BYTES,
};
/*
 * SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
 *	unsigned int, vlen, unsigned int, flags)
 */
#define SENDMMSG_MAX_VLEN	4

/*
 * Snapshot for the post handler.  rec->a2 (the msgs pointer) and rec->a3
 * (vlen) are both exposed to a sibling syscall scribbling an ABI slot
 * between sanitise returning and post_sendmmsg() running.  The pointer
 * scribble was caught by 914fbc6f1ff6 (msgs guard via post_state); vlen
 * was missed.  A sibling fuzzed value-result syscall scribbling rec->a3
 * to any value in [2, SENDMMSG_MAX_VLEN] above the original vlen makes
 * the cleanup loop walk past the vlen * sizeof(struct mmsghdr) zmalloc
 * — heap-buffer-overflow on the msgs[i].msg_hdr.msg_iov read.  ASAN
 * caught exactly that: original vlen=1 (64-byte allocation), rec->a3
 * scribbled to vlen>=2, post handler read msgs[1] = 16 bytes OOB.
 * Capture both into a post_state-private heap struct that no syscall
 * ABI slot points at.  Mirrors capset_post_state.
 */
struct sendmmsg_post_state {
	struct mmsghdr *msgs;
	unsigned int vlen;
};

static void sanitise_sendmmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct mmsghdr *msgs;
	struct sendmmsg_post_state *snap;
	unsigned int vlen;
	unsigned int i;

	rec->a1 = fd_from_socketinfo(si);

	vlen = RAND_RANGE(1, SENDMMSG_MAX_VLEN);
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
			msg->msg_controllen = rand32() % 20480;
			msg->msg_control = get_address();
		}

		/*
		 * Second-pass scrub of this entry's msg_iov before the
		 * kernel walks the array.  Mirrors sanitise_sendmsg --
		 * a sibling scribble of the iovec heap allocation can
		 * leave an iov_base in the libc brk arena, and a kernel
		 * write back via cmsg / copy_from_iter fault-in would
		 * scribble glibc chunk metadata.
		 */
		scrub_msghdr_for_kernel_write(msg);
	}

	rec->a2 = (unsigned long) msgs;
	rec->a3 = vlen;

	snap = zmalloc(sizeof(*snap));
	snap->msgs = msgs;
	snap->vlen = vlen;
	rec->post_state = (unsigned long) snap;
}

static void post_sendmmsg(struct syscallrecord *rec)
{
	struct sendmmsg_post_state *snap =
		(struct sendmmsg_post_state *) rec->post_state;
	struct mmsghdr *msgs;
	unsigned int vlen;
	unsigned int i;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_sendmmsg: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	msgs = snap->msgs;
	vlen = snap->vlen;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner fields.  Reject before
	 * the loop touches msgs[].
	 */
	if (msgs == NULL || looks_like_corrupted_ptr(rec, msgs)) {
		outputerr("post_sendmmsg: rejected suspicious msgs=%p "
			  "(post_state-scribbled?)\n", msgs);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * Paranoid bound on snap->vlen.  Set by sanitise into post_state-
	 * private storage no syscall ABI slot points at, so should never
	 * fire -- a hit means the snapshot itself was wholesale-scribbled.
	 */
	if (vlen > SENDMMSG_MAX_VLEN) {
		outputerr("post_sendmmsg: rejected suspicious vlen=%u "
			  "(post_state-scribbled?)\n", vlen);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * STRONG-VAL count bound: net/socket.c::__sys_sendmmsg() returns
	 * the count of successfully-sent mmsghdr entries (1..vlen) on
	 * success or -1UL on failure.  Compare against snap->vlen, the
	 * trusted sanitise-time value -- a sibling scribble of rec->a3
	 * between the call and the post handler running cannot launder an
	 * oversized retval past this bound.  Mirrors epoll_wait
	 * 4c7a84058afd / epoll_pwait 1ae902d4b01d.
	 */
	if ((long) rec->retval != -1L && rec->retval > vlen) {
		outputerr("post_sendmmsg: rejected retval=0x%lx > vlen=%u\n",
			  rec->retval, vlen);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	for (i = 0; i < vlen; i++) {
		deferred_free_enqueue(msgs[i].msg_hdr.msg_iov, NULL);
		if (inner_ptr_ok_to_free(rec, msgs[i].msg_hdr.msg_name,
					 "post_sendmmsg/msg_name"))
			free(msgs[i].msg_hdr.msg_name);
	}
	rec->a2 = 0;
	deferred_free_enqueue(msgs, NULL);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_sendmmsg = {
	.name = "sendmmsg",
	.num_args = 4,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "mmsg", [2] = "vlen", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sendflags),
	.arg_params[2].range.low = 1, .arg_params[2].range.hi = 1024,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_sendmmsg,
	.post = post_sendmmsg,
	.rettype = RET_BORING,
};
