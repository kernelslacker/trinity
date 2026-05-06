/*
 * vsock_transport_churn - drive AF_VSOCK loopback through transport
 * switch + buffer-size rotation + connect-timeout rotation + local-cid
 * ioctl mid-flow, exercising the net/vmw_vsock/af_vsock.c transport
 * assignment, the vsock_loopback transport's per-namespace teardown,
 * and the buffer-size / timeout setsockopt paths in
 * net/vmw_vsock/vmci_transport.c (and the loopback equivalent).
 *
 * The AF_VSOCK contract assigns a transport (g2h, h2g, dgram,
 * vsock_loopback) to each socket at bind/connect time based on the
 * destination cid.  The transport pointer lives on the vsock_sock and
 * is consulted on every send/recv; rotating buffer sizes, connect
 * timeouts, and the local-cid ioctl while the per-cpu skbs and the
 * per-sock virtio queues are still in flight has historically tripped
 * on:
 *
 *   - vsock virtio refcount imbalances on transport release where the
 *     per-sock vsk->transport pointer was decremented twice (once by
 *     the explicit release path and once by the destructor) when a
 *     transport-switch was racing with a buffer-size update;
 *   - vsock_loopback flush race where the per-cpu work queue was
 *     drained while a new send was being queued, leaving a dangling
 *     skb on the loopback ringbuffer;
 *   - vsock UAF on transport release where the vsock_sock kept a
 *     reference to a transport that had been torn down by the last
 *     namespace exit (vsock_loopback is per-netns);
 *   - vsock_bpf prog-detach during a sockmap update where the bpf
 *     prog ref on the vsock_sock was released without the matching
 *     sockmap entry being cleared first.
 *
 * Per outer-loop iteration (BUDGETED + JITTER, 200 ms wall-clock cap,
 * fresh sockets per iteration):
 *
 *   1.  socket(AF_VSOCK, SOCK_STREAM); bind cid=VMADDR_CID_LOCAL with
 *       port=VMADDR_PORT_ANY; listen(8).  Loopback transport only --
 *       VMADDR_CID_LOCAL routes through vsock_loopback and never
 *       reaches the virtio_transport host path.
 *   2.  socket(AF_VSOCK, SOCK_STREAM) for the client; SO_RCVTIMEO /
 *       SO_SNDTIMEO 100 ms; connect to the listener address obtained
 *       via getsockname.
 *   3.  Inner send/recv burst (BUDGETED 4 / floor 8 / cap 16, JITTER):
 *       send small payload, drain receiver with MSG_DONTWAIT.
 *   4.  RACE A: setsockopt SO_VM_SOCKETS_BUFFER_SIZE on the client
 *       mid-flow -- rotates the per-sock buffer size while the
 *       loopback ringbuffer may still hold queued skbs from step 3.
 *   5.  RACE B: setsockopt SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW on the
 *       client -- exercises the timer-rearm path while the connection
 *       is established.
 *   6.  RACE C: ioctl IOCTL_VM_SOCKETS_GET_LOCAL_CID -- mid-flight cid
 *       query.  Read-only on the kernel side but takes the vsock
 *       transport rwlock, racing with the in-flight setsockopt paths.
 *   7.  shutdown(SHUT_RDWR); close(client); close(listener).  Per-cpu
 *       loopback worker drains as the last skb refs go.
 *
 *   Variant 1/4: wrap the entire iteration in unshare(CLONE_NEWNET)
 *   with a setns-back anchor.  vsock_loopback maintains per-netns
 *   transport state, so the unshare exercises vsock_transport_assign
 *   on a fresh ns, and the setns-back closes it -- the historical UAF
 *   surface is the vsk->transport pointer outliving the per-ns
 *   teardown.  Anchor pattern mirrors netns_teardown_churn so the
 *   process never strands itself in the doomed ns.
 *
 * Per-process cap-gate latch: ns_unsupported_vsock_transport_churn
 * fires on EAFNOSUPPORT / EPERM / ENOPROTOOPT / ENOENT from the very
 * first socket(AF_VSOCK, SOCK_STREAM) probe.  Once latched, every
 * subsequent invocation just bumps runs+setup_failed and returns.
 * Mirrors msg_zerocopy_churn / iouring_send_zc_churn /
 * tcp_ulp_swap_churn / netns_teardown_churn.
 *
 * Brick-safety:
 *   - All sockets bind to VMADDR_CID_LOCAL (cid=1), routing through
 *     vsock_loopback exclusively.  The host's virtio-vsock transport
 *     (VMADDR_CID_HOST) is never touched, so even on a host with
 *     vhost-vsock loaded nothing escapes the loopback ringbuffer.
 *   - Inner send/recv loop is BUDGETED (base 4 / floor 8 / cap 16)
 *     with JITTER and a 200 ms wall-clock cap; SO_RCVTIMEO / SO_SNDTIMEO
 *     of 100 ms on every fd.
 *   - The unshare-variant uses the anchor-fd setns-back pattern from
 *     netns_teardown_churn so the calling process never persists a
 *     namespace switch across iterations.
 *   - BPF vsock_bpf hook (BPF_PROG_TYPE_SOCK_OPS attach to a vsock
 *     cgroup) is intentionally deferred; loading a runtime BPF prog
 *     adds a CAP_BPF requirement and a cgroup state machine that
 *     belongs in a follow-up childop.
 *
 * Header gate __has_include(<linux/vm_sockets.h>) replaces the entire
 * implementation with a stub that just bumps runs + setup_failed, so
 * the build still links on toolchains without the kernel uapi header.
 * Constants (VMADDR_CID_LOCAL, VMADDR_PORT_ANY, SO_VM_SOCKETS_BUFFER_SIZE,
 * SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW, IOCTL_VM_SOCKETS_GET_LOCAL_CID)
 * come from the header when present and from #define fallbacks set to
 * the stable UAPI integer values when absent; on kernels that do not
 * recognise them the syscall returns EINVAL or ENOPROTOOPT and the
 * cap-gate latches.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if __has_include(<linux/vm_sockets.h>)
#include <linux/vm_sockets.h>
#endif

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/vm_sockets.h>)

/* AF_VSOCK has been a fixed UAPI value since 3.9; some toolchains still
 * don't surface it via <sys/socket.h>.  Stable across every kernel that
 * ships AF_VSOCK. */
#ifndef AF_VSOCK
#define AF_VSOCK			40
#endif

/* VMADDR_CID_LOCAL was added in 5.6.  Older headers omit it; on a
 * kernel that doesn't recognise it the bind returns EADDRNOTAVAIL and
 * the cap-gate latches.  UAPI value (1) is stable. */
#ifndef VMADDR_CID_LOCAL
#define VMADDR_CID_LOCAL		1
#endif

#ifndef VMADDR_PORT_ANY
#define VMADDR_PORT_ANY			((unsigned int)-1)
#endif

#ifndef SO_VM_SOCKETS_BUFFER_SIZE
#define SO_VM_SOCKETS_BUFFER_SIZE	0
#endif

#ifndef SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW
#define SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW	9
#endif

#ifndef IOCTL_VM_SOCKETS_GET_LOCAL_CID
#define IOCTL_VM_SOCKETS_GET_LOCAL_CID	_IO(0x07, 0xb9)
#endif

/* Per-process latched gate.  Capability / config / kernel-version
 * support for AF_VSOCK + vsock_loopback is static across a child's
 * lifetime; once the install has paid the EAFNOSUPPORT we stop probing
 * and short-circuit to a runs+setup_failed bump.  Mirrors
 * msg_zerocopy_churn / iouring_send_zc_churn / tcp_ulp_swap_churn. */
static bool ns_unsupported_vsock_transport_churn;

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

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static void apply_timeouts(int s)
{
	struct timeval rcv_to, snd_to;

	rcv_to.tv_sec = 0;
	rcv_to.tv_usec = VS_RCV_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));
	snd_to.tv_sec = 0;
	snd_to.tv_usec = VS_SND_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));
}

/* One full sequence on a freshly-created loopback vsock pair. */
static void iter_one(const struct timespec *t_outer)
{
	int listener = -1;
	int cli = -1;
	int srv = -1;
	struct sockaddr_vm addr;
	socklen_t slen = sizeof(addr);
	unsigned int sent_count = 0;
	unsigned char payload[VS_PAYLOAD_BYTES];
	unsigned char drain[VS_PAYLOAD_BYTES * 2];

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
		return;

	listener = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listener < 0) {
		if (errno == EAFNOSUPPORT || errno == EPERM ||
		    errno == ENOPROTOOPT || errno == ENOENT)
			ns_unsupported_vsock_transport_churn = true;
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = VMADDR_CID_LOCAL;
	addr.svm_port = VMADDR_PORT_ANY;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* EADDRNOTAVAIL here typically means CONFIG_VSOCKETS_LOOPBACK
		 * isn't built; latch so we don't keep trying. */
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == EPERM)
			ns_unsupported_vsock_transport_churn = true;
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (listen(listener, 8) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	__atomic_add_fetch(&shm->stats.vsock_transport_churn_bind_ok,
			   1, __ATOMIC_RELAXED);

	cli = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	apply_timeouts(cli);

	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.vsock_transport_churn_connect_ok,
			   1, __ATOMIC_RELAXED);

	/* Drain the listener accept queue so the loopback transport has a
	 * server-side vsock_sock with the same per-cpu work queue behind
	 * it; without the accept the buffer-size rotation only touches
	 * the client side and the loopback ringbuffer never queues a
	 * skb. */
	srv = accept(listener, NULL, NULL);
	if (srv >= 0)
		apply_timeouts(srv);

	/* Step 3: inner send/recv burst. */
	memset(payload, 0xa5, sizeof(payload));
	{
		unsigned int i;

		for (i = 0; i < VS_INNER_SENDS; i++) {
			ssize_t r;

			if ((unsigned long long)ns_since(t_outer) >=
			    VS_WALL_CAP_NS)
				break;

			r = send(cli, payload, sizeof(payload),
				 MSG_DONTWAIT | MSG_NOSIGNAL);
			if (r >= 0) {
				sent_count++;
				__atomic_add_fetch(
					&shm->stats.vsock_transport_churn_send_ok,
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
					ssize_t n = recv(srv, drain,
							 sizeof(drain),
							 MSG_DONTWAIT);
					if (n <= 0)
						break;
				}
			}
		}
	}

	if ((unsigned long long)ns_since(t_outer) >= VS_WALL_CAP_NS)
		goto out;

	/* Step 4: RACE A.  Rotate buffer size mid-flow.  Pick a value in
	 * [VS_BUFFER_SIZE_LO, VS_BUFFER_SIZE_HI] so we exercise both
	 * shrink and grow paths across iterations. */
	{
		uint64_t sz = VS_BUFFER_SIZE_LO +
			      (rand() % (VS_BUFFER_SIZE_HI - VS_BUFFER_SIZE_LO + 1U));

		if (setsockopt(cli, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
			       &sz, sizeof(sz)) == 0)
			__atomic_add_fetch(
				&shm->stats.vsock_transport_churn_buffer_size_ok,
				1, __ATOMIC_RELAXED);
	}

	/* Step 5: RACE B.  Rotate connect timeout mid-flow.  The
	 * NEW variant takes a struct __kernel_timespec (8+8 bytes); we
	 * assemble it inline so we don't pull in a header dependency. */
	{
		struct {
			int64_t tv_sec;
			int64_t tv_nsec;
		} ts;

		ts.tv_sec = 0;
		ts.tv_nsec = (int64_t)(VS_CONNECT_TIMEO_US * 1000ULL);
		if (setsockopt(cli, AF_VSOCK,
			       SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW,
			       &ts, sizeof(ts)) == 0)
			__atomic_add_fetch(
				&shm->stats.vsock_transport_churn_timeout_ok,
				1, __ATOMIC_RELAXED);
	}

	/* Step 6: RACE C.  Mid-flight local-cid query.  Read-only on the
	 * kernel side but takes the vsock transport rwlock, racing with
	 * the in-flight setsockopt paths. */
	{
		unsigned int cid = 0;

		if (ioctl(cli, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) == 0)
			__atomic_add_fetch(
				&shm->stats.vsock_transport_churn_get_cid_ok,
				1, __ATOMIC_RELAXED);
	}

	/* Suppress "set but never read" on sent_count without warning. */
	(void)sent_count;

	(void)shutdown(cli, SHUT_RDWR);
	if (srv >= 0)
		(void)shutdown(srv, SHUT_RDWR);

out:
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	if (listener >= 0)
		close(listener);
}

/* Anchor-fd unshare wrapper.  Saves the current netns via /proc/self/ns/net,
 * runs iter_one in a fresh CLONE_NEWNET, then setns-es back.  Mirrors the
 * pattern in netns_teardown_churn so the calling process never strands
 * itself in the doomed ns. */
static void iter_one_in_fresh_netns(const struct timespec *t_outer)
{
	int anchor;

	anchor = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (anchor < 0) {
		iter_one(t_outer);
		return;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		close(anchor);
		iter_one(t_outer);
		return;
	}

	iter_one(t_outer);

	if (setns(anchor, CLONE_NEWNET) < 0) {
		/* Best-effort: if the setns-back fails we have no safe
		 * way to recover.  Bail the child rather than persisting
		 * the doomed ns across iterations. */
		close(anchor);
		ns_unsupported_vsock_transport_churn = true;
		return;
	}
	close(anchor);
}

bool vsock_transport_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.vsock_transport_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_vsock_transport_churn) {
		__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

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

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    VS_WALL_CAP_NS)
			break;

		if ((rand() % 100U) < VS_UNSHARE_VARIANT_PCT)
			iter_one_in_fresh_netns(&t_outer);
		else
			iter_one(&t_outer);

		if (ns_unsupported_vsock_transport_churn)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/vm_sockets.h>) */

bool vsock_transport_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.vsock_transport_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.vsock_transport_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif  /* __has_include(<linux/vm_sockets.h>) */
