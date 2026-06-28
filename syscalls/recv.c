/*
   asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size,
                            unsigned flags)

 */
#include <sys/socket.h>
#include <sys/uio.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "valresult.h"
#include "compat.h"

/*
 * UIO_MAXIOV is the kernel-side hard cap on iovec count.  Local
 * fallback to the canonical 1024 mirrors generate-args.c:262-267
 * so the file builds against any uapi header vintage.
 */
#ifndef UIO_MAXIOV
# define UIO_MAXIOV 1024
#endif

static void sanitise_recv(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	/* recv/recvfrom both pass a2 as the user output buffer with length
	 * a3 — the kernel writes the received bytes there.  ARG_MMAP hands
	 * us a struct map pointer rather than a real buffer, so the kernel
	 * scribbles into adjacent heap memory; defensively redirect away
	 * from any range that overlaps trinity's alloc_shared regions. */
	avoid_shared_buffer_out(&rec->a2, rec->a3);
}

/*
 * recvfrom shares the ubuf handling with recv but additionally writes
 * the peer's sockaddr into a5 and its length into a6.  ARG_SOCKADDRLEN
 * published a scalar into the a6 slot, which the kernel reads as a
 * __user pointer and EFAULTs the call every time -- recvfrom never
 * actually surfaced a peer address.  Allocate a fresh sockaddr_storage-
 * sized addr buffer at a5 so the kernel has room for any family it
 * surfaces, and route a6 (the value-result addrlen slot) through
 * valresult_alloc() so the shape catalogue (EXACT / UNDER /
 * EXACT_PLUS_ONE / HUGE / ZERO) mutates *lenp around the natural
 * sockaddr_storage capacity.  The kernel reads *lenp as max_addrlen
 * before writing back the actual count.
 *
 * The lenp slot was previously a leaky zmalloc(sizeof(*lenp)) with no
 * post handler -- valresult_free() in post_recvfrom now closes that
 * leak.  The valresult_alloc() also returns a buf the caller does not
 * use here (a5 has its own get_writable_address() backing); buf and
 * len_io are both released via the snap-owned vrb in the post handler.
 *
 * Mirrors getsockopt.c (38e1b000092d).
 */
#define RECVFROM_POST_STATE_MAGIC	0x5243564652533230UL	/* "RCVFRS20" */
struct recvfrom_post_state {
	unsigned long magic;
	struct valresult_buf vrb;
};

static void sanitise_recvfrom(struct syscallrecord *rec)
{
	struct sockaddr_storage *addr;
	struct recvfrom_post_state *snap;
	struct valresult_buf vrb;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	avoid_shared_buffer_out(&rec->a2, rec->a3);

	addr = (struct sockaddr_storage *) get_writable_address(sizeof(*addr));
	if (addr != NULL)
		rec->a5 = (unsigned long) addr;
	else
		/* On pool exhaustion / mincore failure, leaving the original
		 * undersized ARG_SOCKADDR buffer would preserve the very
		 * overflow shape this routine exists to prevent.  Force NULL
		 * so the kernel returns -EFAULT cleanly. */
		rec->a5 = 0;

	/*
	 * Allocate the value-result addrlen slot through the shared shape
	 * catalogue.  The natural capacity is sizeof(struct sockaddr_storage)
	 * -- the addr buffer above is sized to match -- and the helper
	 * mutates that into the picked shape (EXACT / UNDER / +1 / HUGE /
	 * ZERO).  The vrb.buf slot is not consumed here; valresult_free()
	 * in the post handler still releases it through the snap.
	 */
	vrb = valresult_alloc(sizeof(struct sockaddr_storage),
			      valresult_pick_shape());
	rec->a6 = (unsigned long) vrb.len_io;

	/*
	 * Snapshot the vrb BEFORE avoid_shared_buffer() runs.  a6 is
	 * about to be relocated off the libc heap; the post handler must
	 * free the zmalloc result, not the relocated pointer (which the
	 * deferred-free heap-bounds gate rejects).  Wired into the
	 * post_state ownership table via post_state_install() so
	 * post_recvfrom() can prove the snap belongs to this attempt
	 * before any field deref; a sibling stomp that redirects
	 * rec->post_state at a foreign heap chunk happening to carry
	 * RECVFROM_POST_STATE_MAGIC is rejected by the ownership lookup
	 * before the leading-word magic compare ever runs.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = RECVFROM_POST_STATE_MAGIC;
	snap->vrb = vrb;
	post_state_install(rec, snap);

	avoid_shared_buffer_inout(&rec->a6, sizeof(*vrb.len_io));
}

static void post_recvfrom(struct syscallrecord *rec)
{
	struct recvfrom_post_state *snap;

	/*
	 * a6 was the valresult len_io slot; the kernel has either written
	 * through it or EFAULTed by now.  Clear unconditionally before any
	 * early-return so a rejected-snap path does not leave a stale
	 * heap pointer in the ABI slot for replay.
	 */
	rec->a6 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- the caller just early-returns on NULL.
	 */
	snap = post_state_claim_owned(rec, RECVFROM_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	valresult_free(&snap->vrb);
	post_state_release(rec, snap);
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
	.sanitise = sanitise_recvfrom,
	.post = post_recvfrom,
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
 * Only msg_name is snapshotted as a free-from-trusted-snap slot.
 * msg_iov and msg_control both live in the writable-pool now
 * (get_writable_address) and are never freed by trinity, so there
 * is no scribble-mismatch concern for those fields.  msg_name is
 * still a heap allocation from generate_sockaddr(), and the kernel
 * writes msg_namelen back into the msghdr on success -- a sibling
 * iov_base aliased into the msghdr struct could scribble msg_name
 * with a heap-shaped within-array offset that the inner shape-only
 * check accepts but free() aborts on in libasan.  Stash the original
 * sa pointer at sanitise time so the post handler frees the
 * allocation we made.
 *
 * Sized 32 bytes (lands in the 32-byte glibc malloc chunk bucket) so
 * the struct still does not collide with the 16-byte free-list bucket
 * that holds alloc_iovec(1).
 */
#define RECVMSG_POST_STATE_MAGIC	0x52435653504F5354UL	/* "RCVSPOST" */
struct recvmsg_post_state {
	unsigned long magic;
	struct msghdr *msg;
	unsigned long iov_len_sum;
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

	/*
	 * msg_name is purely a kernel write-target on recvmsg; the kernel
	 * never reads it.  Allocate sizeof(struct sockaddr_storage) bytes
	 * unconditionally instead of generate_sockaddr's per-family alloc,
	 * which can be smaller than the kernel's max sockaddr write size
	 * (e.g., sockaddr_un at 110 bytes).  Without this, a sibling
	 * scribbling msg_namelen post-sanitise to a value >= sizeof(struct
	 * sockaddr_storage) under a non-UNIX socket lets the kernel overflow
	 * the undersized msg_name alloc with up to 128 bytes of peer
	 * address.  Free path unchanged: snap->name still tracks the live
	 * msg_name alloc through tracked_free_now().
	 */
	sa = (struct sockaddr *) zmalloc_tracked(sizeof(struct sockaddr_storage));
	salen = sizeof(struct sockaddr_storage);

skip_si:
	msg = zmalloc_tracked(sizeof(struct msghdr));
	rec_own(rec, msg);
	msg->msg_name = sa;
	msg->msg_namelen = salen;

	if (RAND_BOOL()) {
		unsigned int num_entries = RAND_RANGE(1, 3);
		struct iovec *iov;

		/*
		 * alloc_iovec() now returns a UIO_MAXIOV-sized writable-pool
		 * slot directly (see rand/random-address.c).  Pool slots are
		 * never freed by trinity, so a sibling scribble of
		 * msg_iovlen above num_entries walks zeroed pool bytes the
		 * kernel iov_iter advances over as no-ops, and the kernel's
		 * OOB iov walk's overflow target stays out of the libc
		 * arena.  Drop msg_iov / msg_iovlen to NULL / 0 on pool
		 * exhaustion -- mirrors the msg_control branch below.
		 */
		iov = alloc_iovec(num_entries, IOV_KERNEL_WRITE);
		if (iov != NULL) {
			msg->msg_iov = iov;
			msg->msg_iovlen = num_entries;
		} else {
			msg->msg_iov = NULL;
			msg->msg_iovlen = 0;
		}
	}

	if (RAND_BOOL()) {
		/*
		 * Back msg_control with a writable-pool slot rather than a
		 * libc-heap zmalloc().  scrub_msghdr_for_kernel_write() in
		 * rand/random-address.c intentionally does not redirect
		 * msg_controllen (only iov_base entries), so the size_t the
		 * kernel reads at syscall entry is sibling-writable.  Even
		 * with the preceding oversize-to-4096 commit a scribble
		 * above 4096 would resume the heap-buffer-overflow that
		 * surfaces as the __zmalloc -> malloc -> malloc_printerr ->
		 * abort cluster.  Migrating to get_writable_address() takes
		 * the cmsg writeback's overflow target out of the libc
		 * arena entirely: the pool's neighbours are other pool
		 * slots and trinity never free()s a pool address, so even
		 * an arbitrary-size kernel scribble cannot corrupt glibc
		 * chunk metadata.  Drop msg_control to NULL (and
		 * msg_controllen to 0) when the pool cannot surface a
		 * 4 KB slot -- mirrors the get_writable_address() failure
		 * mode for sanitise_recvfrom's sockaddr_storage slot.
		 */
		msg->msg_control = get_writable_address(4096);
		if (msg->msg_control != NULL)
			msg->msg_controllen = rand32() % 4096;
		else
			msg->msg_controllen = 0;
	}

	if (ONE_IN(100))
		msg->msg_flags = rand32();
	else
		msg->msg_flags = 0;

	/*
	 * Second-pass scrub of msg_iov before the kernel walks the array.
	 * alloc_iovec() above already runs avoid_shared_buffer_out() per
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

	/*
	 * Recompute iov_len_sum AFTER the scrub pass.  scrub_msghdr_for_
	 * kernel_write() zeros iov_len on any entry whose iov_base overlapped
	 * an alloc_shared region or the libc brk arena, so a sum captured
	 * before the scrub would over-count and let the post handler's
	 * retval bound reject legitimate kernel returns up to the actual
	 * post-scrub Σ iov_len.  Walks the same msg_iov the kernel sees.
	 */
	if (msg->msg_iov != NULL && msg->msg_iovlen != 0) {
		unsigned int i;

		for (i = 0; i < msg->msg_iovlen; i++)
			iov_len_sum += msg->msg_iov[i].iov_len;
	}

	rec->a2 = (unsigned long) msg;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = RECVMSG_POST_STATE_MAGIC;
	snap->msg = msg;
	snap->iov_len_sum = iov_len_sum;
	snap->name = msg->msg_name;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

static void post_recvmsg(struct syscallrecord *rec)
{
	struct recvmsg_post_state *snap =
		(struct recvmsg_post_state *) rec->post_state;
	struct msghdr *msg;
	unsigned long retval = rec->retval;

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
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (a stale
	 * same-type snap a sibling stomp resurrected by redirecting
	 * rec->post_state at it, an alloc_iovec(1) in the same 16/24-byte
	 * free-list bucket, ...), in which case reading snap->magic touches
	 * the wrong struct.  The ownership table proves "this is THIS
	 * attempt's snapshot"; everything below trusts that.  Reject before
	 * the inner-field deref hands tracked_free_now() an unowned
	 * snap->name, which a tracking-table miss would raw-free() --
	 * arbitrary free of an attacker-influenced pointer.  Mirrors
	 * prctl.c / pipe.c / execve.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_recvmsg: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: ownership table confirmed this is our snap,
	 * so reading snap->magic is now safe.  A mismatch here means the
	 * snapshot itself was wholesale-scribbled in place -- abandon the
	 * snap->name free rather than feed wild bytes into the inner-field
	 * deref.  Cannot deferred_freeptr the snap because its contents are
	 * no longer trustworthy -- leak it and let the deferred-free tick
	 * reclaim the original snap on the next pass.  The msghdr itself is
	 * owned by the rec carrier (rec_own at sanitise time) and gets
	 * reclaimed unconditionally by rec_owned_drain after .post runs,
	 * independent of this bail-out.
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
	if ((long) retval == -1L)
		goto skip_bound;
	if (retval > snap->iov_len_sum) {
		outputerr("post_recvmsg: rejecting retval %lu > iov_len_sum %lu\n",
			  retval, snap->iov_len_sum);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a2 = 0;
		goto out_free;
	}
skip_bound:

	/*
	 * Free msg_name from the trusted snap, not from the current
	 * msghdr.  The kernel writes through msg_namelen on success, and a
	 * sibling iov_base aliased into the msghdr can scribble msg_name
	 * with a heap-shaped within-array offset that the inner shape-only
	 * check accepts but free() aborts on in libasan.  snap->name holds
	 * the sanitise-time allocation regardless of what the kernel (or a
	 * sibling) left in the live msghdr.  The msghdr itself is owned by
	 * the rec carrier (rec_own at sanitise time) and gets reclaimed
	 * unconditionally by rec_owned_drain after .post runs -- that also
	 * closes the leak on paths where .post is skipped entirely
	 * (retfd-rejected, killed grandchild, ...).  msg_iov and
	 * msg_control are not freed -- both live in the writable-pool now
	 * (see sanitise_recvmsg) and pool allocations are never released
	 * by trinity.
	 */
	tracked_free_now(snap->name);
	rec->a2 = 0;

out_free:
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_recvmsg = {
	.name = "recvmsg",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "msg", [2] = "flags" },
	.arg_params[2].list = ARGLIST(recv_flags),
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
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
 * abort crash cluster.  Mirrors RECVMSG_POST_STATE_MAGIC above.
 *
 * Only the per-i msg_name pointers are snapshotted here.  msg_iov
 * and msg_control both live in the writable-pool now
 * (get_writable_address) and are never freed by trinity, so there is
 * no scribble-mismatch concern for those fields.  msg_name is still
 * a heap allocation from generate_sockaddr() and a sibling syscall
 * whose iov_base aliases bytes inside the
 * msgs[] allocation can let the kernel scribble msgs[i].msg_hdr.
 * msg_name with a heap-shaped within-array offset of msgs[] itself
 * (e.g. &msgs[5] for a 4-element array).  Such a value passes the
 * inner shape-only validator but free() of an interior offset aborts
 * in libasan's PoisonShadow alignment CHECK -- ASAN caught that exact
 * pattern.  Stash the originals at sanitise time so the post handler
 * frees the allocations we made, not the values the kernel left
 * behind.  Matches the post-state hardening already in place for the
 * outer msgs pointer.
 */
#define RECVMMSG_POST_STATE_MAGIC	0x5243564D54534154UL	/* "RCVMTSAT" */
struct recvmmsg_post_state {
	unsigned long magic;
	struct mmsghdr *msgs;
	unsigned int vlen;
	unsigned int _pad;
	void *name[RECVMMSG_MAX_VLEN];
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
	msgs = zmalloc_tracked(vlen * sizeof(struct mmsghdr));
	rec_own(rec, msgs);

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = RECVMMSG_POST_STATE_MAGIC;
	snap->msgs = msgs;
	snap->vlen = vlen;

	for (i = 0; i < vlen; i++) {
		struct msghdr *msg = &msgs[i].msg_hdr;
		unsigned int num_entries = RAND_RANGE(1, 3);
		struct sockaddr *sa = NULL;
		socklen_t salen = 0;
		struct iovec *iov;

		/*
		 * alloc_iovec() returns a writable-pool slot; see
		 * sanitise_recvmsg above for the structural rationale.
		 * Drop to NULL / 0 when the pool cannot surface a slot.
		 */
		iov = alloc_iovec(num_entries, IOV_KERNEL_WRITE);
		if (iov != NULL) {
			msg->msg_iov = iov;
			msg->msg_iovlen = num_entries;
		} else {
			msg->msg_iov = NULL;
			msg->msg_iovlen = 0;
		}

		/*
		 * Same rationale as sanitise_recvmsg: allocate sizeof(struct
		 * sockaddr_storage) unconditionally rather than the per-family
		 * shape generate_sockaddr would surface, so a sibling that
		 * scribbles msg_namelen post-sanitise cannot drive the kernel
		 * to overflow an undersized per-i msg_name alloc.  Free path
		 * unchanged: snap->name[i] still tracks the live alloc.
		 */
		if (si != NULL) {
			sa = (struct sockaddr *) zmalloc_tracked(sizeof(struct sockaddr_storage));
			salen = sizeof(struct sockaddr_storage);
		}
		msg->msg_name = sa;
		msg->msg_namelen = salen;
		snap->name[i] = sa;

		if (RAND_BOOL()) {
			/*
			 * Migrate msg_control to the writable-pool; see
			 * sanitise_recvmsg above for the structural
			 * rationale (sibling-scribbled msg_controllen
			 * cannot land a kernel overflow on glibc arena
			 * metadata when the backing buffer is not on
			 * the libc heap).  Drop to NULL/0 when the pool
			 * cannot surface a 4 KB slot.
			 */
			msg->msg_control = get_writable_address(4096);
			if (msg->msg_control != NULL)
				msg->msg_controllen = rand32() % 4096;
			else
				msg->msg_controllen = 0;
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
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

static void post_recvmmsg(struct syscallrecord *rec)
{
	struct recvmmsg_post_state *snap =
		(struct recvmmsg_post_state *) rec->post_state;
	struct mmsghdr *msgs;
	unsigned int vlen;
	unsigned int i;
	unsigned long retval = rec->retval;

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
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (a stale
	 * same-type snap a sibling stomp resurrected by redirecting
	 * rec->post_state at it), in which case reading snap->magic touches
	 * the wrong struct.  The ownership table proves "this is THIS
	 * attempt's snapshot"; everything below trusts that.  Reject before
	 * the per-i cleanup loop hands tracked_free_now() unowned
	 * snap->name[i] pointers, which a tracking-table miss would
	 * raw-free() -- arbitrary free of attacker-influenced pointers.
	 * Mirrors prctl.c / pipe.c / execve.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_recvmmsg: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: ownership table confirmed this is our snap,
	 * so reading snap->magic is now safe.  A mismatch here means the
	 * snapshot itself was wholesale-scribbled in place -- abandon both
	 * the snap and the msgs cleanup rather than walk the cleanup loop
	 * over foreign memory.  Mirrors recv.c:212 (post_recvmsg).
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
	if ((long) retval != -1L && retval > vlen) {
		outputerr("post_recvmmsg: rejecting retval %ld > vlen %u\n",
			  (long) retval, vlen);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	/*
	 * Free from the trusted per-i snap, not from the live msgs[]
	 * array.  The kernel writes msg_namelen on success, and a
	 * sibling iov_base aliased inside the msgs[] allocation can
	 * scribble msg_name with a heap-shaped within-array offset of
	 * msgs[] (e.g. &msgs[5] for a 4-elem array).  That value passes
	 * the inner shape-only check but free() of an interior offset
	 * aborts in libasan.  The snap fields are wrapped in the magic-
	 * cookie struct above, so they still hold the sanitise-time
	 * allocations.  msg_iov and msg_control are no longer freed --
	 * both live in the writable-pool now (see sanitise_recvmmsg) and
	 * pool allocations are never released by trinity.  The msgs[]
	 * array itself is owned by the rec carrier (rec_own at sanitise
	 * time) and gets reclaimed unconditionally by rec_owned_drain
	 * after .post runs -- no explicit free here.
	 */
	for (i = 0; i < vlen; i++)
		tracked_free_now(snap->name[i]);
	rec->a2 = 0;

out_free:
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_recvmmsg = {
	.name = "recvmmsg",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "mmsg", [2] = "vlen", [3] = "flags", [4] = "timeout" },
	.arg_params[3].list = ARGLIST(recv_flags),
	.arg_params[2].range.low = 1, .arg_params[2].range.hi = 1024,
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.group = GROUP_NET,
	.sanitise = sanitise_recvmmsg,
	.post = post_recvmmsg,
	.rettype = RET_BORING,
};
