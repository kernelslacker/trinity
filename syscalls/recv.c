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
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
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
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};


/*
 * SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags)
 */
/*
 * Snapshot for the post handler.  rec->a2 (the msghdr pointer) may be
 * scribbled by a sibling syscall before post_recvmsg() runs, and the
 * msghdr's iov array is just as exposed to a sibling-thread torn write
 * of msg->msg_iovlen / msg->msg_iov[].iov_len that the count-bound
 * validator below relies on.  Captured at sanitise time into a
 * post_state-private heap struct that no syscall ABI slot points at.
 *
 * The struct carries a leading magic cookie because the heap-shape check
 * on rec->post_state is value-based only -- a sibling that scribbles
 * rec->post_state with any heap-shaped 8-byte aligned pointer (e.g. a
 * stale alloc_iovec(1) from a different syscall, which is also a 16-byte
 * region) sails past looks_like_corrupted_ptr() and the post handler
 * then loads snap->msg from foreign bytes, treats the result as a
 * struct msghdr *, and dereferences into poisoned heap.  ASAN caught
 * exactly that: snap landed at a 16-byte region, snap->msg returned a
 * wild value, and post_recvmsg crashed on the subsequent inner-field
 * read 496 bytes past the foreign 16-byte allocation.  The cookie is
 * an arbitrary 64-bit constant: the chance a sibling scribble forges
 * the exact value is 2^-64 per stomp, so a mismatch is treated as a
 * stomp signature rather than as benign noise.
 *
 * The inner-pointer fields (control, name) are snapshotted alongside
 * the outer msghdr pointer because the kernel writes through the
 * msghdr in a recvmsg() call -- in particular msg_control gets the
 * cmsg buffer and msg_namelen gets the actual sockaddr length, and
 * the kernel can also write past msg_control if an iov_base alias
 * lands inside the msghdr struct itself.  After return the inner
 * pointer slots in the current msghdr cannot be trusted: a kernel
 * scribble of msg_control to a within-array offset (e.g. &msgs[5]
 * for a 4-elem array) is a heap-shaped value that passed the inner
 * shape-only check but is not the allocation we made, and free()ing
 * it aborts in libasan.  Stash the originals at sanitise time so the
 * post handler can free the allocations we made, not the values the
 * kernel left behind.  Mirrors the outer-pointer magic-cookie pattern
 * already in place for rec->post_state.
 *
 * Sized 40 bytes (lands in the 48-byte glibc malloc chunk bucket) so
 * the struct still does not collide with the 16-byte free-list bucket
 * that holds alloc_iovec(1).
 */
#define RECVMSG_POST_STATE_MAGIC	0x52435653504F5354UL	/* "RCVSPOST" */
struct recvmsg_post_state {
	unsigned long magic;
	struct msghdr *msg;
	unsigned long iov_len_sum;
	void *control;
	void *name;
};

static void sanitise_recvmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct msghdr *msg;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	struct recvmsg_post_state *snap;
	unsigned long iov_len_sum = 0;

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
		unsigned int i;

		msg->msg_iov = alloc_iovec(num_entries);
		msg->msg_iovlen = num_entries;

		for (i = 0; i < num_entries; i++)
			iov_len_sum += msg->msg_iov[i].iov_len;
	}

	if (RAND_BOOL()) {
		msg->msg_controllen = rand32() % 4096;
		msg->msg_control = zmalloc(msg->msg_controllen);
	}

	if (ONE_IN(100))
		msg->msg_flags = rand32();
	else
		msg->msg_flags = 0;

	/*
	 * Second-pass scrub of msg_iov before the kernel walks the array.
	 * alloc_iovec() above already runs avoid_shared_buffer() per
	 * iov_base at build time, but the iovec array lives in heap as a
	 * vlen * sizeof(struct iovec) zmalloc() and a sibling syscall can
	 * scribble bytes into that allocation between this sanitiser
	 * returning and the kernel reading the array, replacing iov_base
	 * with a fuzzed value.  An iov_base landing in the libc brk arena
	 * lets the kernel write the received data on top of glibc chunk
	 * metadata, surfacing later as a glibc heap-corruption assert via
	 * the next malloc anywhere in trinity (the dominant non-ASAN
	 * cluster: __zmalloc -> malloc -> malloc_printerr -> abort).
	 */
	scrub_msghdr_for_kernel_write(msg);

	rec->a2 = (unsigned long) msg;

	snap = zmalloc(sizeof(*snap));
	snap->magic = RECVMSG_POST_STATE_MAGIC;
	snap->msg = msg;
	snap->iov_len_sum = iov_len_sum;
	snap->control = msg->msg_control;
	snap->name = msg->msg_name;
	rec->post_state = (unsigned long) snap;
}

static void post_recvmsg(struct syscallrecord *rec)
{
	struct recvmsg_post_state *snap =
		(struct recvmsg_post_state *) rec->post_state;
	struct msghdr *msg;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped (e.g. by a child
	 * reusing the slot), so guard the snapshot pointer before
	 * dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_recvmsg: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation (a different syscall's post_state, an
	 * alloc_iovec(1) in the same 16/24-byte free-list bucket, ...)
	 * would let the wrong bytes pose as a recvmsg_post_state.  The
	 * cookie was set at sanitise time; a mismatch means snap does
	 * not point at our struct -- abandon both the snap and the msghdr
	 * cleanup rather than feed wild bytes into the inner-field deref.
	 * Cannot deferred_freeptr the snap because we cannot prove it is
	 * one of our allocations -- leak it and let the deferred-free
	 * tick reclaim the original snap on the next pass.
	 */
	if (snap->magic != RECVMSG_POST_STATE_MAGIC) {
		outputerr("post_recvmsg: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	msg = snap->msg;

	if (msg == NULL || looks_like_corrupted_ptr(rec, msg)) {
		outputerr("post_recvmsg: rejected suspicious msg=%p "
			  "(post_state-scribbled?)\n", msg);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * STRONG-VAL count bound: __sys_recvmsg() returns the count of
	 * bytes received (0..Σ msg->msg_iov[].iov_len) on success or -1
	 * on failure.  Anything > Σ iov_len (excluding -1UL) is a
	 * structural ABI regression: a sign-extension tear, a torn write
	 * of the count by a parallel signal-restart path, or -errno
	 * leaking through the success slot.  iov_len_sum was snapshotted
	 * at sanitise time into the post_state-private slot rather than
	 * re-walked from the sibling-stomp-vulnerable msghdr.  Mirrors
	 * lgetxattr d415648d2ee9 for the bound shape.
	 */
	if ((long) rec->retval == -1L)
		goto skip_bound;
	if (rec->retval > snap->iov_len_sum) {
		outputerr("post_recvmsg: rejecting retval %lu > iov_len_sum %lu\n",
			  rec->retval, snap->iov_len_sum);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a2 = 0;
		goto out_free;
	}
skip_bound:

	/*
	 * Free from the trusted snap, not from the current msghdr.  The
	 * kernel writes through msg_control on success, and a sibling
	 * iov_base aliased into the msghdr can scribble msg_control with
	 * a heap-shaped within-array offset that the inner shape-only
	 * check accepts but free() aborts on in libasan.  The snap fields
	 * are wrapped in the magic-cookie struct above, so they hold the
	 * sanitise-time allocations regardless of what the kernel (or a
	 * sibling) left in the live msghdr.
	 */
	free(snap->control);
	deferred_free_enqueue(msg->msg_iov, NULL);
	free(snap->name);
	rec->a2 = 0;
	deferred_free_enqueue(msg, NULL);

out_free:
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
	.rettype = RET_NUM_BYTES,
};

/*
 * SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
	 unsigned int, vlen, unsigned int, flags,
	 struct timespec __user *, timeout)
 */
#define RECVMMSG_MAX_VLEN	4

/*
 * Snapshot for the post handler.  Sister bug to sendmmsg: rec->a2 (msgs
 * pointer) and rec->a3 (vlen) are both exposed to a sibling syscall
 * scribbling an ABI slot between sanitise returning and post_recvmmsg()
 * running.  The pointer scribble was caught by 914fbc6f1ff6 (msgs guard
 * via post_state); vlen was missed.  A sibling scribble of rec->a3 to a
 * value above the original vlen makes the cleanup loop walk past the
 * vlen * sizeof(struct mmsghdr) zmalloc — heap-buffer-overflow.  Capture
 * both into a post_state-private heap struct that no syscall ABI slot
 * points at.  Mirrors capset_post_state.
 *
 * Leading magic cookie because the heap-shape check on rec->post_state
 * is value-based only -- a sibling scribbling rec->post_state with any
 * heap-shaped 8-byte aligned pointer to a foreign allocation sails past
 * looks_like_corrupted_ptr() and the post handler then loads snap->msgs
 * from foreign bytes; the subsequent cleanup loop walks wild memory and
 * surfaces as the dominant __zmalloc -> malloc -> malloc_printerr ->
 * abort crash cluster.  Mirrors RECVMSG_POST_STATE_MAGIC above.  Padded
 * to 32 bytes (48-byte glibc malloc chunk) so the snap lands in a
 * different free-list bucket than recvmsg_post_state (24B -> 32B chunk)
 * and the 16-byte alloc_iovec(1) bucket -- defense-in-depth on top of
 * the cookie.
 */
#define RECVMMSG_POST_STATE_MAGIC	0x5243564D54534154UL	/* "RCVMTSAT" */
struct recvmmsg_post_state {
	unsigned long magic;
	struct mmsghdr *msgs;
	unsigned int vlen;
	unsigned int _pad;
	unsigned long _bucket_pad;
};

static void sanitise_recvmmsg(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	struct mmsghdr *msgs;
	struct recvmmsg_post_state *snap;
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

		/*
		 * Second-pass scrub of this entry's msg_iov before the
		 * kernel walks the array.  Mirrors sanitise_recvmsg --
		 * a sibling scribble of the iovec heap allocation between
		 * this sanitiser returning and the kernel reading the
		 * array can replace iov_base with a fuzzed value, and a
		 * value landing in the libc brk arena lets the kernel
		 * write received data on top of glibc chunk metadata.
		 */
		scrub_msghdr_for_kernel_write(msg);
	}

	rec->a2 = (unsigned long) msgs;
	rec->a3 = vlen;

	snap = zmalloc(sizeof(*snap));
	snap->magic = RECVMMSG_POST_STATE_MAGIC;
	snap->msgs = msgs;
	snap->vlen = vlen;
	rec->post_state = (unsigned long) snap;
}

static void post_recvmmsg(struct syscallrecord *rec)
{
	struct recvmmsg_post_state *snap =
		(struct recvmmsg_post_state *) rec->post_state;
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
		outputerr("post_recvmmsg: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * recvmmsg_post_state.  A cookie mismatch means snap does not
	 * point at our struct -- abandon both the snap and the msgs
	 * cleanup rather than walk the cleanup loop over foreign memory.
	 * Mirrors recv.c:212 (post_recvmsg).
	 */
	if (snap->magic != RECVMMSG_POST_STATE_MAGIC) {
		outputerr("post_recvmmsg: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
		outputerr("post_recvmmsg: rejected suspicious msgs=%p "
			  "(post_state-scribbled?)\n", msgs);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * Paranoid bound on snap->vlen.  Set by sanitise into post_state-
	 * private storage no syscall ABI slot points at, so should never
	 * fire -- a hit means the snapshot itself was wholesale-scribbled.
	 */
	if (vlen > RECVMMSG_MAX_VLEN) {
		outputerr("post_recvmmsg: rejected suspicious vlen=%u "
			  "(post_state-scribbled?)\n", vlen);
		rec->a2 = 0;
		goto out_free;
	}

	/*
	 * Kernel ABI: __sys_recvmmsg() returns the count of successfully
	 * received mmsghdr entries (1..vlen) on success or -1 on failure.
	 * Compare against snap->vlen, the trusted sanitise-time value, so a
	 * sibling scribble of rec->a3 cannot launder an oversized retval
	 * past this bound.  Mirrors epoll_wait 4c7a84058afd / epoll_pwait
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
	deferred_free_enqueue(msgs, NULL);

out_free:
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
	.rettype = RET_BORING,
};
