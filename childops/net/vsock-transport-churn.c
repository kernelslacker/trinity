/*
 * vsock_transport_churn - drive AF_VSOCK loopback through transport
 * assignment, buffer-size rotation, connect-timeout rotation, and local-cid
 * ioctl mid-flow.  Targets net/vmw_vsock/af_vsock.c transport assignment,
 * vsock_loopback per-namespace teardown, and the buffer-size / timeout
 * setsockopt paths.
 *
 * Bug classes: vsock virtio refcount imbalance on transport release (per-sock
 * vsk->transport decremented twice when transport-switch races a buffer-size
 * update); vsock_loopback flush race leaving a dangling skb on the ringbuffer;
 * vsock UAF where the vsock_sock outlives a per-netns transport teardown;
 * vsock_bpf sockmap detach ordering.
 *
 * Per iteration (BUDGETED+JITTER, 200 ms wall cap, fresh sockets): listener
 * bound cid=VMADDR_CID_LOCAL port=VMADDR_PORT_ANY, connect from a client with
 * SO_RCV/SNDTIMEO=100ms, run a small send/recv burst, then race
 * SO_VM_SOCKETS_BUFFER_SIZE + SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW +
 * IOCTL_VM_SOCKETS_GET_LOCAL_CID against the still-queued skbs on the
 * loopback ringbuffer; shutdown/close last so the per-cpu loopback worker
 * drains as the final refs go.  Variant 1/4 wraps the whole iteration in a
 * userns_run_in_ns(CLONE_NEWNET) grandchild so vsock_loopback's per-netns
 * transport gets torn down under a live vsk->transport ref.
 *
 * Brick-safety: sockets bind to VMADDR_CID_LOCAL only, so traffic stays on
 * vsock_loopback -- VMADDR_CID_HOST is never touched even on hosts with
 * vhost-vsock loaded.  Inner burst BUDGETED base 4 / floor 8 / cap 16 with
 * JITTER, 200 ms wall cap.  Fresh-netns variant runs in a userns_run_in_ns
 * grandchild; the persistent child never changes creds or namespaces.
 *
 * Per-process cap-gate latch: ns_unsupported_vsock_transport_churn on
 * EAFNOSUPPORT / EPERM / ENOPROTOOPT / ENOENT from the first AF_VSOCK probe;
 * subsequent invocations bump runs+setup_failed and return.
 *
 * Header-gated by __has_include(<linux/vm_sockets.h>) with a setup_failed
 * stub fallback.  VMADDR_CID_LOCAL / PORT_ANY, SO_VM_SOCKETS_BUFFER_SIZE,
 * SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW, IOCTL_VM_SOCKETS_GET_LOCAL_CID get
 * #define fallbacks at their stable UAPI values; unrecognised values return
 * EINVAL/ENOPROTOOPT and the cap-gate latches.
 */

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#if __has_include(<linux/vm_sockets.h>)
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "kernel/vm_sockets.h"
#endif

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#if __has_include(<linux/vm_sockets.h>)

/* Latch lives in shm (shm->vsock_transport_churn_ns_unsupported).
 * Write sites include vsock_transport_iter_setup() (AF_VSOCK socket() /
 * bind() rejection) which is called from both the parent-side iter_one
 * path AND the userns_run_in_ns() grandchild's iter_one_in_fresh_netns
 * path, plus the outer wrapper -EPERM branch.  Grandchild-side writes
 * to a process-local static would die with the grandchild on _exit()
 * and every subsequent invocation would re-attempt the same
 * unsupported AF_VSOCK setup.  RELAXED atomic load/store is safe:
 * only false -> true, idempotent write. */
static bool ns_unsupported_vsock_transport_churn(void)
{
	return __atomic_load_n(&shm->vsock_transport_churn_ns_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_vsock_transport_churn(void)
{
	__atomic_store_n(&shm->vsock_transport_churn_ns_unsupported, true,
			 __ATOMIC_RELAXED);
}

#define VS_OUTER_BASE			4U
#define VS_OUTER_CAP			16U
#define VS_OUTER_FLOOR			8U
#define VS_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define VS_RCV_TIMEO_MS			100
#define VS_SND_TIMEO_MS			100
#define VS_INNER_SENDS			6U
#define VS_PAYLOAD_BYTES		128U
#define VS_BUFFER_SIZE_LO		(4U * 1024U)
#define VS_BUFFER_SIZE_HI		(64U * 1024U)
#define VS_CONNECT_TIMEO_US		(50ULL * 1000ULL)
#define VS_DRAIN_CAP			8U
#define VS_UNSHARE_VARIANT_PCT		25U
#define VS_SEQ_EOM_GATE			8U
#define VS_SEQ_EOM_BURST_MIN		4U
#define VS_SEQ_EOM_BURST_RANGE		5U	/* 4..8 inclusive */
#define VS_RECONNECT_TRIES		4U	/* inner re-connect iterations per arm invocation */
#define VS_RECONNECT_GATE		4U	/* ONE_IN gate: ~25 % of outer iterations */

static void apply_timeouts(int s, unsigned long *direct_calls)
{
	struct timeval rcv_to, snd_to;

	rcv_to.tv_sec = 0;
	rcv_to.tv_usec = VS_RCV_TIMEO_MS * 1000;
	(*direct_calls)++;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));
	snd_to.tv_sec = 0;
	snd_to.tv_usec = VS_SND_TIMEO_MS * 1000;
	(*direct_calls)++;
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));
}

/*
 * Per-iteration setup: open the loopback listener, bind to
 * VMADDR_CID_LOCAL with VMADDR_PORT_ANY, listen, open the client,
 * connect to the listener's resolved address, and drain one accept off
 * the queue so the loopback transport has a live server-side
 * vsock_sock backing the per-cpu work queue.  Out fds are initialised
 * to -1 up-front so the caller's teardown path handles every partial-
 * success state uniformly.  Returns 0 on success; nonzero means the
 * caller should goto out for cleanup.  EAFNOSUPPORT / EPERM /
 * ENOPROTOOPT / ENOENT on socket() and EADDRNOTAVAIL / EAFNOSUPPORT /
 * EPERM on bind() additionally latch
 * ns_unsupported_vsock_transport_churn so subsequent invocations
 * short-circuit to a runs+setup_failed bump.
 */
static int vsock_transport_iter_setup(struct childdata *child,
				      int *listener_out, int *cli_out,
				      int *srv_out,
				      unsigned long *direct_calls)
{
	struct sockaddr_vm addr;
	socklen_t slen = sizeof(addr);
	int listener, cli, srv;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	*listener_out = -1;
	*cli_out = -1;
	*srv_out = -1;

	(*direct_calls)++;
	listener = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listener < 0) {
		if (errno == EAFNOSUPPORT || errno == EPERM ||
		    errno == ENOPROTOOPT || errno == ENOENT) {
			mark_ns_unsupported_vsock_transport_churn();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	*listener_out = listener;

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = VMADDR_CID_LOCAL;
	addr.svm_port = VMADDR_PORT_ANY;

	(*direct_calls)++;
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* EADDRNOTAVAIL here typically means CONFIG_VSOCKETS_LOOPBACK
		 * isn't built; latch so we don't keep trying. */
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == EPERM) {
			mark_ns_unsupported_vsock_transport_churn();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	(*direct_calls)++;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	(*direct_calls)++;
	if (listen(listener, 8) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	__atomic_add_fetch(&shm->stats.vsock_transport_churn.bind_ok,
			   1, __ATOMIC_RELAXED);

	(*direct_calls)++;
	cli = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	*cli_out = cli;
	apply_timeouts(cli, direct_calls);

	(*direct_calls)++;
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.vsock_transport_churn.connect_ok,
			   1, __ATOMIC_RELAXED);

	/* Drain the listener accept queue so the loopback transport has a
	 * server-side vsock_sock with the same per-cpu work queue behind
	 * it; without the accept the buffer-size rotation only touches
	 * the client side and the loopback ringbuffer never queues a
	 * skb. */
	(*direct_calls)++;
	srv = accept(listener, NULL, NULL);
	if (srv >= 0)
		apply_timeouts(srv, direct_calls);
	*srv_out = srv;

	return 0;
}

/*
 * Step 3 inner burst: fire up to VS_INNER_SENDS small payloads at the
 * client and drain the server side with MSG_DONTWAIT after each send.
 * Respects the outer wall-clock cap on every iteration and bails on
 * any non-EAGAIN errno (the original code's "terminal errno (ENOTCONN
 * / EPIPE etc.)" bail-out).  All accounting is via shm stat bumps so
 * the burst returns nothing to the caller.
 */
static void vsock_transport_iter_send_burst(int cli, int srv,
					    const struct timespec *t_outer,
					    unsigned long *direct_calls)
{
	unsigned char payload[VS_PAYLOAD_BYTES];
	unsigned char drain[VS_PAYLOAD_BYTES * 2];
	unsigned int sent_count = 0;
	unsigned int i;

	memset(payload, 0xa5, sizeof(payload));

	for (i = 0; i < VS_INNER_SENDS; i++) {
		ssize_t r;

		if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
			break;

		(*direct_calls)++;
		r = send(cli, payload, sizeof(payload),
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (r >= 0) {
			sent_count++;
			__atomic_add_fetch(
				&shm->stats.vsock_transport_churn.send_ok,
				1, __ATOMIC_RELAXED);
		} else if (errno == EAGAIN) {
			break;
		} else {
			/* Terminal errno (ENOTCONN / EPIPE etc.) -- bail. */
			break;
		}

		if (srv >= 0) {
			unsigned int d;

			for (d = 0; d < VS_DRAIN_CAP; d++) {
				ssize_t n;

				(*direct_calls)++;
				n = recv(srv, drain, sizeof(drain),
					 MSG_DONTWAIT);
				if (n <= 0)
					break;
			}
		}
	}

	/* Suppress "set but never read" on sent_count without warning. */
	(void)sent_count;
}

/*
 * Steps 4/5/6 mid-flow races on the client socket.  Three back-to-back
 * setsockopt / ioctl rotations against the in-flight loopback
 * ringbuffer:
 *
 *   RACE A: SO_VM_SOCKETS_BUFFER_SIZE with a value picked uniformly in
 *           [VS_BUFFER_SIZE_LO, VS_BUFFER_SIZE_HI] so each iteration
 *           rotates the per-sock buffer size through both shrink and
 *           grow paths.
 *   RACE B: SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW (struct __kernel_timespec
 *           assembled inline to avoid a header dependency) -- exercises
 *           the timer-rearm path while the connection is established.
 *   RACE C: IOCTL_VM_SOCKETS_GET_LOCAL_CID -- read-only on the kernel
 *           side but takes the vsock transport rwlock, racing with the
 *           in-flight setsockopt paths above.
 *
 * Best-effort: each op is fire-and-forget with its own stats bump on
 * success; failures are silently dropped.
 */
static void vsock_transport_iter_race(int cli, unsigned long *direct_calls)
{
	uint64_t sz;
	struct {
		int64_t tv_sec;
		int64_t tv_nsec;
	} ts;
	unsigned int cid = 0;

	/* RACE A. */
	sz = VS_BUFFER_SIZE_LO +
	     rnd_modulo_u32(VS_BUFFER_SIZE_HI - VS_BUFFER_SIZE_LO + 1U);
	(*direct_calls)++;
	if (setsockopt(cli, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
		       &sz, sizeof(sz)) == 0)
		__atomic_add_fetch(
			&shm->stats.vsock_transport_churn.buffer_size_ok,
			1, __ATOMIC_RELAXED);

	/* RACE B. */
	ts.tv_sec = 0;
	ts.tv_nsec = (int64_t)(VS_CONNECT_TIMEO_US * 1000ULL);
	(*direct_calls)++;
	if (setsockopt(cli, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW,
		       &ts, sizeof(ts)) == 0)
		__atomic_add_fetch(
			&shm->stats.vsock_transport_churn.timeout_ok,
			1, __ATOMIC_RELAXED);

	/* RACE C. */
	(*direct_calls)++;
	if (ioctl(cli, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) == 0)
		__atomic_add_fetch(
			&shm->stats.vsock_transport_churn.get_cid_ok,
			1, __ATOMIC_RELAXED);
}

/*
 * Step 7 success-path teardown: shutdown(SHUT_RDWR) on cli (always
 * connected at this point) and on srv when the accept produced an fd.
 * Fires before the shared close-fds path at iter_one's out: label so
 * the per-cpu loopback worker has a chance to drain the in-flight skb
 * refs from the burst before the closes pull the sockets out from
 * under it.  Skipped on every goto-out failure path -- shutdown is
 * meaningless on a socket whose setup didn't reach connect.
 */
static void vsock_transport_iter_teardown(int cli, int srv,
					  unsigned long *direct_calls)
{
	(*direct_calls)++;
	(void)shutdown(cli, SHUT_RDWR);
	if (srv >= 0) {
		(*direct_calls)++;
		(void)shutdown(srv, SHUT_RDWR);
	}
}

/* One full sequence on a freshly-created loopback vsock pair. */
static void iter_one(struct childdata *child, const struct timespec *t_outer,
		     unsigned long *direct_calls)
{
	int listener = -1;
	int cli = -1;
	int srv = -1;

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
		return;

	if (vsock_transport_iter_setup(child, &listener, &cli, &srv,
				       direct_calls) != 0)
		goto out;

	vsock_transport_iter_send_burst(cli, srv, t_outer, direct_calls);

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
		goto out;

	vsock_transport_iter_race(cli, direct_calls);

	vsock_transport_iter_teardown(cli, srv, direct_calls);

out:
	if (cli >= 0) {
		(*direct_calls)++;
		close(cli);
	}
	if (srv >= 0) {
		(*direct_calls)++;
		close(srv);
	}
	if (listener >= 0) {
		(*direct_calls)++;
		close(listener);
	}
}

/* Per-invocation state handed to the in-ns callback so iter_one can
 * see the same childdata + wall-clock anchor the persistent child
 * tracks, without relying on globals visible across the grandchild
 * fork. */
struct vsock_netns_ctx {
	struct childdata *child;
	const struct timespec *t_outer;
};

/* Executed inside a transient grandchild forked by userns_run_in_ns();
 * the grandchild's userns + netns are torn down on _exit(), so every
 * vsock socket, loopback transport reference and per-cpu skb opened by
 * iter_one is reaped by the kernel along with the namespace stack.
 * Return value is ignored by the helper.
 *
 * The grandchild's direct-syscall tally lives on its stack and is
 * discarded on _exit() -- the parent's `childop_direct_syscalls_add()`
 * drain at vsock_transport_churn() exit therefore undercounts by the
 * fresh-netns iterations (VS_UNSHARE_VARIANT_PCT of outer_iters).
 * Keeping a single reporter call per invocation (mirroring pipe-thrash)
 * is worth the ~25% undercount vs. plumbing a fork-shared accumulator. */
static int iter_one_in_fresh_netns_fn(void *arg)
{
	struct vsock_netns_ctx *ctx = arg;
	unsigned long direct_calls = 0;

	iter_one(ctx->child, ctx->t_outer, &direct_calls);
	return 0;
}

/* Drive one iter_one inside a fresh private CLONE_NEWUSER+CLONE_NEWNET
 * stack so the unprivileged trinity child gains CAP_NET_ADMIN in the
 * owned netns and the vsock_loopback per-ns teardown actually runs. */
static void iter_one_in_fresh_netns(struct childdata *child,
				    const struct timespec *t_outer)
{
	struct vsock_netns_ctx ctx = { .child = child, .t_outer = t_outer };
	int rc;

	rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_fresh_netns_fn, &ctx);
	if (rc == -EPERM) {
		/* Hardened policy refused CLONE_NEWUSER
		 * (user.max_user_namespaces=0 or
		 * kernel.unprivileged_userns_clone=0).  Latch so the outer
		 * loop stops retrying for the rest of this child's life. */
		mark_ns_unsupported_vsock_transport_churn();
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, mirroring the child.c dispatch loop guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}
	/* rc < 0 (other): transient grandchild setup failure -- fork,
	 * id-map write, or secondary CLONE_NEWNET unshare refused.  Skip
	 * this iteration without latching; the failure is not policy and
	 * may not recur. */
}

/* Sub-mode: drive the VIRTIO_VSOCK_SEQ_EOM unbounded-queue path with a
 * burst of 0-length frames flagged MSG_EOR on a SEQPACKET socket (or a
 * STREAM fallback on kernels that reject SOCK_SEQPACKET on AF_VSOCK).
 * Pre-fix, the receive side enqueued every empty EOM packet on the rx
 * queue without bounds, since recv-side accounting only credited
 * payload bytes; a sender could pin arbitrary memory by spamming empty
 * EOM frames.  Upstream 059b7dbd20a6 ("vsock: drop 0-length
 * VIRTIO_VSOCK_SEQ_EOM frames") drops them at the transport layer.
 *
 * All I/O is MSG_DONTWAIT so the burst respects the SIGALRM(1s) cap.
 * EBADF / EINVAL / ENOTCONN bumps the skipped counter and returns
 * cleanly rather than aborting the whole sub-mode. */
static void iter_seq_eom_burst(const struct timespec *t_outer,
			       unsigned long *direct_calls)
{
	int listener = -1;
	int cli = -1;
	int srv = -1;
	struct sockaddr_vm addr;
	socklen_t slen = sizeof(addr);
	unsigned int burst, i;

	__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_runs, 1, __ATOMIC_RELAXED);

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_skipped, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	(*direct_calls)++;
	listener = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	if (listener < 0) {
		(*direct_calls)++;
		listener = socket(AF_VSOCK, SOCK_STREAM, 0);
	}
	if (listener < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_skipped, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = VMADDR_CID_LOCAL;
	addr.svm_port = VMADDR_PORT_ANY;

	(*direct_calls) += 3;
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    getsockname(listener, (struct sockaddr *)&addr, &slen) < 0 ||
	    listen(listener, 4) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_skipped, 1,
				   __ATOMIC_RELAXED);
		goto out;
	}

	(*direct_calls)++;
	cli = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	if (cli < 0) {
		(*direct_calls)++;
		cli = socket(AF_VSOCK, SOCK_STREAM, 0);
	}
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_skipped, 1,
				   __ATOMIC_RELAXED);
		goto out;
	}
	apply_timeouts(cli, direct_calls);

	(*direct_calls)++;
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_skipped, 1,
				   __ATOMIC_RELAXED);
		goto out;
	}

	(*direct_calls)++;
	srv = accept(listener, NULL, NULL);
	if (srv >= 0)
		apply_timeouts(srv, direct_calls);

	burst = VS_SEQ_EOM_BURST_MIN + rnd_modulo_u32(VS_SEQ_EOM_BURST_RANGE);
	for (i = 0; i < burst; i++) {
		struct iovec iov;
		struct msghdr mh;
		ssize_t r;

		if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
			break;

		iov.iov_base = NULL;
		iov.iov_len = 0;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;

		(*direct_calls)++;
		r = sendmsg(cli, &mh, MSG_EOR | MSG_NOSIGNAL | MSG_DONTWAIT);
		if (r >= 0) {
			__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_sends_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.vsock_transport_churn.seq_eom_sends_failed,
					   1, __ATOMIC_RELAXED);
			if (errno == EBADF || errno == EINVAL ||
			    errno == ENOTCONN || errno == EPIPE)
				break;
		}
	}

out:
	if (cli >= 0) {
		(*direct_calls)++;
		close(cli);
	}
	if (srv >= 0) {
		(*direct_calls)++;
		close(srv);
	}
	if (listener >= 0) {
		(*direct_calls)++;
		close(listener);
	}
}

/*
 * vsock_connect double-insert from reconnect-while-CLOSING race.
 *
 * vsock_connect() tests sk->sk_state == TCP_ESTABLISHED *after*
 * schedule_timeout() returns.  A peer RST arriving in that window moves
 * the socket to TCP_CLOSING without removing it from vsock_connected_table.
 * connect() then resets to TCP_CLOSE -- still on the table.  Reconnecting
 * to the same address calls __vsock_insert_connected() on a still-linked
 * hlist node, which is a hard BUG() under CONFIG_DEBUG_LIST=y.
 *
 * Arm: listener accepts and immediately RST-closes the child socket; client
 * reconnects the same fd to the same address while the RST may still be
 * in-flight (genuine timing race).  vsock_reconnect_attempted counts every
 * attempt; vsock_reconnect_while_closing counts the subset where SO_ERROR
 * returned ECONNRESET before the re-connect call (RST arrived in the race
 * window).  If DEBUG_LIST fires the BUG the kernel crashes -- that is the
 * oracle; no userspace catch is needed or attempted.
 *
 * Brick-safety: VMADDR_CID_LOCAL only, never VMADDR_CID_HOST.
 */
static void iter_reconnect_while_closing(const struct timespec *t_outer,
					 unsigned long *direct_calls)
{
	int listener = -1, cli = -1, child_srv = -1;
	struct sockaddr_vm addr;
	socklen_t slen = sizeof(addr);
	unsigned int i;

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
		return;

	/* Open listener bound to VMADDR_CID_LOCAL. */
	(*direct_calls)++;
	listener = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listener < 0)
		goto out;

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = VMADDR_CID_LOCAL;
	addr.svm_port = VMADDR_PORT_ANY;

	(*direct_calls)++;
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	(*direct_calls)++;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto out;

	(*direct_calls)++;
	if (listen(listener, 8) < 0)
		goto out;

	/* Open client socket with the standard 100 ms timeouts. */
	(*direct_calls)++;
	cli = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (cli < 0)
		goto out;
	apply_timeouts(cli, direct_calls);

	/* First blocking connect: cli reaches TCP_ESTABLISHED. */
	(*direct_calls)++;
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	/* Accept and immediately RST: the RST is injected into cli's receive
	 * path as close as possible behind the ESTABLISHED wakeup that
	 * connect() just returned from. */
	(*direct_calls)++;
	child_srv = accept(listener, NULL, NULL);
	if (child_srv >= 0) {
		(*direct_calls)++;
		(void)shutdown(child_srv, SHUT_RDWR);
		(*direct_calls)++;
		close(child_srv);
		child_srv = -1;
	}

	/* Reconnect loop.  Each iteration shuts down the client socket and
	 * reconnects on the SAME fd to the SAME address.  The bug path:
	 * vsock_connect() resets the socket to TCP_CLOSE without removing it
	 * from vsock_connected_table; the subsequent __vsock_insert_connected()
	 * call is a hlist double-add, a hard BUG() under CONFIG_DEBUG_LIST=y. */
	for (i = 0; i < VS_RECONNECT_TRIES; i++) {
		int so_err = 0;
		socklen_t elen = sizeof(so_err);

		if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
			break;

		/* Check whether the RST arrived while we were in the race window.
		 * SO_ERROR == ECONNRESET means sk_state moved through TCP_CLOSING;
		 * this is the observable half of the timing race. */
		(*direct_calls)++;
		if (getsockopt(cli, SOL_SOCKET, SO_ERROR,
			       &so_err, &elen) == 0 && so_err == ECONNRESET)
			__atomic_add_fetch(
				&shm->stats.vsock_transport_churn.vsock_reconnect_while_closing,
				1, __ATOMIC_RELAXED);

		/* shutdown(SHUT_RDWR) is required before reconnecting -- clears
		 * SOCK_DONE; mirrors what iter_one's teardown path does. */
		(*direct_calls)++;
		(void)shutdown(cli, SHUT_RDWR);

		__atomic_add_fetch(
			&shm->stats.vsock_transport_churn.vsock_reconnect_attempted,
			1, __ATOMIC_RELAXED);

		/* Reconnect to the SAME address on the SAME fd.  Under the bug,
		 * the socket is still in vsock_connected_table; this call fires
		 * __vsock_insert_connected() on an already-linked node. */
		(*direct_calls)++;
		(void)connect(cli, (struct sockaddr *)&addr, sizeof(addr));

		/* Accept and immediately RST the new child (if connect succeeded)
		 * to keep the race window open for the next iteration. */
		(*direct_calls)++;
		child_srv = accept(listener, NULL, NULL);
		if (child_srv >= 0) {
			(*direct_calls)++;
			(void)shutdown(child_srv, SHUT_RDWR);
			(*direct_calls)++;
			close(child_srv);
			child_srv = -1;
		}
	}

out:
	if (child_srv >= 0) {
		(*direct_calls)++;
		close(child_srv);
	}
	if (cli >= 0) {
		(*direct_calls)++;
		close(cli);
	}
	if (listener >= 0) {
		(*direct_calls)++;
		close(listener);
	}
}

bool vsock_transport_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	/* Local direct-syscall tally, drained once at op-exit via
	 * childop_direct_syscalls_add() so the hot path pays one atomic
	 * add per invocation instead of per-syscall.  Bumped in the
	 * non-fresh iter_one() and iter_seq_eom_burst() paths; the
	 * fresh-netns grandchild's tally is discarded on _exit() (see
	 * iter_one_in_fresh_netns_fn). */
	unsigned long direct_calls = 0;

	__atomic_add_fetch(&shm->stats.vsock_transport_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_vsock_transport_churn()) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_VSOCK_TRANSPORT_CHURN,
			       JITTER_RANGE(VS_OUTER_BASE));
	if (outer_iters < VS_OUTER_FLOOR)
		outer_iters = VS_OUTER_FLOOR;
	if (outer_iters > VS_OUTER_CAP)
		outer_iters = VS_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    VS_WALL_CAP_NS)
			break;

		if (rnd_modulo_u32(100U) < VS_UNSHARE_VARIANT_PCT)
			iter_one_in_fresh_netns(child, &t_outer);
		else
			iter_one(child, &t_outer, &direct_calls);

		if (ns_unsupported_vsock_transport_churn())
			break;

		if (ONE_IN(VS_SEQ_EOM_GATE))
			iter_seq_eom_burst(&t_outer, &direct_calls);

		if (ONE_IN(VS_RECONNECT_GATE))
			iter_reconnect_while_closing(&t_outer, &direct_calls);
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}

#else  /* !__has_include(<linux/vm_sockets.h>) */

bool vsock_transport_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.vsock_transport_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.vsock_transport_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/vm_sockets.h>) */
