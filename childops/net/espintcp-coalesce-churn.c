/*
 * espintcp_coalesce_churn - drive small back-to-back writes across a
 * loopback TCP pair with the espintcp ULP installed on both ends, so
 * the receive side reassembles the crafted length-prefixed frames
 * across skb boundaries via the espintcp TCP-coalesce path.
 *
 * Bug class: espintcp receive coalesce / page-cache replacement seam.
 * The espintcp ULP peels a 16-bit big-endian length prefix off each
 * frame and reassembles the ESP payload out of the tail-cloned TCP
 * receive skbs.  When a frame straddles skb boundaries the reader
 * walks a chain of coalesced fragments and replaces the head skb's
 * page-cache reference as it consumes bytes.  A local-priv escalation
 * fixed upstream on netdev (~2026-05) lived in that replacement path
 * -- a refcount / page-owner imbalance surfaced when a short frame
 * caused the reader to release a fragment whose page it still had a
 * pointer into.  KASAN-visible (page-cache use-after-free / refcount).
 * Flat TCP fuzzing does not assemble the shape: an ESTABLISHED TCP
 * socket, espintcp ULP armed on both ends, and a stream of tiny
 * back-to-back writes whose length prefixes cross the segment /
 * skb-coalesce boundary the way real espintcp sessions do.
 *
 * Approach: run entirely inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET) so nothing touches the host.
 * Bring lo up, fork a one-shot acceptor, connect from the parent,
 * install setsockopt(TCP_ULP, "espintcp") on both fds.  On EPERM /
 * ENOPROTOOPT / EAFNOSUPPORT / EOPNOTSUPP from the ULP install
 * (kernel built without CONFIG_INET_ESPINTCP or userns cap gate
 * refuses) latch the kind off in shm so subsequent grandchildren
 * short-circuit.  Then BUDGETED+JITTER burst of crafted frames:
 * rotate a 2-byte non-ESP marker keepalive, 1..8 byte tiny lengths,
 * medium 32..64 byte ESP-shape payloads, and a near-limit length
 * that spans multiple TCP segments; toggle TCP_CORK per write and
 * flip TCP_NODELAY between bursts to force the receive side to
 * either coalesce successive short segments into one skb or land
 * them as separate skbs across the reader's fragment walk.  Server
 * drains with MSG_DONTWAIT so the socket does not stall the burst.
 *
 * Brick-safety: loopback only inside the private netns; acceptor
 * child WNOHANG-reaped then SIGTERM if it overstays; BUDGETED base
 * 4 / cap 32 with JITTER; ~200 ms wall-clock cap; SO_RCVTIMEO and
 * SO_SNDTIMEO 100 ms on every fd; ULP install failure counted, not
 * fatal.  No xfrm SA install -- the receive-side coalesce path is
 * reached before the ESP demux discards the payload, and skipping
 * the SA keeps the op configuration-tolerant (CONFIG_INET_ESPINTCP
 * on, XFRM optional).  Any leftover socket dies with the grandchild
 * on _exit(); netns destruction reaps anything left behind.
 *
 * Latches: ns_unsupported_espintcp_coalesce master gate on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled).
 * shm->espintcp_coalesce_kind_unsupported on TCP_ULP "espintcp"
 * install failing with the CONFIG_INET_ESPINTCP absent errno set.
 * Kind latch lives in shm because the rejection is observed inside
 * the grandchild -- a process-local static would die on _exit() and
 * every subsequent grandchild would re-attempt the missing kind.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"	/* reap_acceptor, waitpid_eintr */
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

#ifndef TCP_ULP
#define TCP_ULP			31
#endif

#ifndef SOL_TCP
#define SOL_TCP			6
#endif

/* Per-invocation outer burst.  BUDGETED+JITTER scales this so a
 * productive run grows to ~iter*4 iterations and an unproductive
 * one shrinks toward the floor.  Small base keeps a single
 * invocation well under the 200 ms wall-clock cap. */
#define ESPINTCP_OUTER_BASE	4U
#define ESPINTCP_OUTER_FLOOR	4U
#define ESPINTCP_OUTER_CAP	32U

/* Inner burst per outer iteration.  Each inner write emits one
 * length-prefixed frame, so N inner writes at short lengths lands
 * as ~N frames the receive-side reassembler walks. */
#define ESPINTCP_INNER_BURST	16U

#define ESPINTCP_WALL_CAP_NS	(200ULL * 1000ULL * 1000ULL)
#define ESPINTCP_RCV_TIMEO_MS	100
#define ESPINTCP_SND_TIMEO_MS	100

/* Frame length upper bound: kernel espintcp caps a single frame at
 * ~16 KB; staying well under keeps the burst inside socket buffer
 * headroom while still crossing a couple of TCP segment sizes. */
#define ESPINTCP_FRAME_MAX	8192U
#define ESPINTCP_FRAME_MED_MIN	32U
#define ESPINTCP_FRAME_MED_MAX	64U
#define ESPINTCP_FRAME_TINY_MAX	8U

/* Per-process master latch.  Set by the wrapper on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled).
 * Without a private netns we would install ULPs and drive traffic
 * on host sockets; the op stays off for this child's lifetime. */
static bool ns_unsupported_espintcp_coalesce;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->espintcp_coalesce_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->espintcp_coalesce_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/* Set both timeouts on @fd so a wedged peer cannot pin the child
 * past the inherited SIGALRM(1s) or our own wall-clock cap.  100 ms
 * matches the sibling tcp_ulp_swap_churn value. */
static void set_sock_timeouts(int fd)
{
	struct timeval tv;

	tv.tv_sec  = 0;
	tv.tv_usec = ESPINTCP_RCV_TIMEO_MS * 1000;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	tv.tv_sec  = 0;
	tv.tv_usec = ESPINTCP_SND_TIMEO_MS * 1000;
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Draw the frame's length prefix.  Rotates:
 *   - non-ESP marker keepalive (0x0000): kernel espintcp treats a
 *     zero-length frame as a keepalive, dispatching through the
 *     zero-body branch of the reassembler,
 *   - tiny (1..8): parser reads a full length prefix before the
 *     body arrives, forcing the "partial frame" continuation on
 *     the next skb,
 *   - medium (32..64): typical ESP-header sized frame,
 *   - large (~ESPINTCP_FRAME_MAX): guaranteed to span multiple TCP
 *     segments so the reader walks the coalesced-fragment chain. */
static uint16_t pick_frame_len(void)
{
	switch (rnd_modulo_u32(8)) {
	case 0:
		return 0U;
	case 1:
	case 2:
	case 3:
		return (uint16_t)(1U + rnd_modulo_u32(ESPINTCP_FRAME_TINY_MAX));
	case 4:
	case 5:
	case 6:
		return (uint16_t)(ESPINTCP_FRAME_MED_MIN +
				  rnd_modulo_u32(ESPINTCP_FRAME_MED_MAX -
						 ESPINTCP_FRAME_MED_MIN + 1U));
	default:
		return (uint16_t)(ESPINTCP_FRAME_MAX -
				  rnd_modulo_u32(64U));
	}
}

/* Fork a one-shot loopback acceptor.  Parent gets the connected client
 * fd back; the child accept()s once, best-effort installs the espintcp
 * ULP on the accepted fd, then drains reads until the peer closes.
 * Returns the connected client fd on success, -1 on failure with
 * *out_pid set to -1.  Reaped via reap_acceptor() in the caller's
 * cleanup path so a half-built pair never leaves a zombie. */
static int open_loopback_pair(pid_t *out_pid)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener;
	int cli = -1;
	int one = 1;
	pid_t pid;

	*out_pid = -1;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = 0;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto fail;
	if (listen(listener, 1) < 0)
		goto fail;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto fail;

	pid = fork();
	if (pid < 0)
		goto fail;
	if (pid == 0) {
		int s = accept(listener, NULL, NULL);

		if (s >= 0) {
			unsigned char drain[2048];
			int loops = 64;

			set_sock_timeouts(s);
			(void)setsockopt(s, SOL_TCP, TCP_ULP,
					 "espintcp", 8);
			while (loops-- > 0) {
				ssize_t n = recv(s, drain, sizeof(drain),
						 MSG_DONTWAIT);
				if (n <= 0)
					break;
			}
			close(s);
		}
		close(listener);
		_exit(0);
	}

	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (cli < 0) {
		close(listener);
		goto reap;
	}
	set_sock_timeouts(cli);
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS) {
		close(cli);
		cli = -1;
		close(listener);
		goto reap;
	}
	close(listener);

	*out_pid = pid;
	return cli;

reap:
	{
		int status;
		(void)kill(pid, SIGTERM);
		(void)waitpid_eintr(pid, &status, 0);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

/* Install the espintcp ULP on the client fd.  Returns 0 on success,
 * -1 on rejection with the caller-visible errno preserved.  Latches
 * the kind off in shm on the CONFIG_INET_ESPINTCP absent errno set
 * (ENOPROTOOPT / EOPNOTSUPP / EAFNOSUPPORT / EPERM). */
static int install_espintcp_ulp(int fd, struct childdata *child)
{
	if (setsockopt(fd, SOL_TCP, TCP_ULP, "espintcp", 8) == 0)
		return 0;

	if (errno == ENOPROTOOPT || errno == EOPNOTSUPP ||
	    errno == EAFNOSUPPORT || errno == EPERM) {
		const enum child_op_type op = child->op_type;

		mark_kind_unsupported();
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
	return -1;
}

/* Inner send burst.  TCP_CORK is toggled per batch to bunch several
 * small frames into one segment then release; TCP_NODELAY is set
 * per-invocation so the receive-side skb-coalesce path sees both
 * shapes across runs: coalesced batches and per-write segments. */
static void send_burst(int fd, const struct timespec *t_outer)
{
	unsigned char buf[ESPINTCP_FRAME_MAX + 2];
	unsigned int i;
	int cork_on  = 1;
	int cork_off = 0;
	int nodelay  = RAND_BOOL() ? 1 : 0;

	(void)setsockopt(fd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
	(void)setsockopt(fd, SOL_TCP, TCP_CORK, &cork_on, sizeof(cork_on));

	for (i = 0; i < ESPINTCP_INNER_BURST; i++) {
		uint16_t len;
		size_t total;
		ssize_t n;

		if ((unsigned long long)ns_since(t_outer) >=
		    ESPINTCP_WALL_CAP_NS)
			break;

		len = pick_frame_len();
		total = 2U + (size_t)len;
		buf[0] = (unsigned char)(len >> 8);
		buf[1] = (unsigned char)(len & 0xffU);
		if (len > 0)
			generate_rand_bytes(buf + 2, len);

		n = send(fd, buf, total, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.espintcp_coalesce.send_ok,
					   1, __ATOMIC_RELAXED);
			if (len == 0)
				__atomic_add_fetch(&shm->stats.espintcp_coalesce.keepalive_ok,
						   1, __ATOMIC_RELAXED);
		} else if (n < 0 &&
			   (errno == EAGAIN || errno == EPIPE ||
			    errno == ECONNRESET)) {
			break;
		}

		/* Flip CORK mid-burst to release a coalesced batch, then
		 * re-arm.  The release is what drives the receive side
		 * to walk the coalesced-fragment chain. */
		if ((i & 3) == 3) {
			(void)setsockopt(fd, SOL_TCP, TCP_CORK,
					 &cork_off, sizeof(cork_off));
			(void)setsockopt(fd, SOL_TCP, TCP_CORK,
					 &cork_on, sizeof(cork_on));
		}
	}

	(void)setsockopt(fd, SOL_TCP, TCP_CORK, &cork_off, sizeof(cork_off));
}

struct espintcp_ns_ctx {
	struct childdata *child;
};

/* Per-invocation body that must run inside the private user + net
 * namespace.  Executed in a transient grandchild forked by
 * userns_run_in_ns(); the grandchild's namespaces are torn down on
 * _exit() so any socket or ULP state left behind is reaped along
 * with the namespace.  Return value ignored by the helper. */
static int espintcp_coalesce_in_ns(void *arg)
{
	struct espintcp_ns_ctx *cctx = (struct espintcp_ns_ctx *)arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	unsigned int outer_iters, i;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	{
		struct nl_ctx rtnl = { .fd = -1 };
		struct nl_open_opts rtnl_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = 1,
		};

		if (nl_open(&rtnl, &rtnl_opts) == 0) {
			rtnl_bring_lo_up(&rtnl);
			nl_close(&rtnl);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(op, JITTER_RANGE(ESPINTCP_OUTER_BASE));
	if (outer_iters < ESPINTCP_OUTER_FLOOR)
		outer_iters = ESPINTCP_OUTER_FLOOR;
	if (outer_iters > ESPINTCP_OUTER_CAP)
		outer_iters = ESPINTCP_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		pid_t acceptor = -1;
		int cli;

		if ((unsigned long long)ns_since(&t_outer) >=
		    ESPINTCP_WALL_CAP_NS)
			break;

		cli = open_loopback_pair(&acceptor);
		if (cli < 0) {
			__atomic_add_fetch(&shm->stats.espintcp_coalesce.setup_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		if (install_espintcp_ulp(cli, child) != 0) {
			__atomic_add_fetch(&shm->stats.espintcp_coalesce.ulp_install_failed,
					   1, __ATOMIC_RELAXED);
			close(cli);
			reap_acceptor(acceptor);
			if (kind_unsupported())
				break;
			continue;
		}
		__atomic_add_fetch(&shm->stats.espintcp_coalesce.ulp_install_ok,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		send_burst(cli, &t_outer);

		(void)shutdown(cli, SHUT_RDWR);
		close(cli);
		reap_acceptor(acceptor);
	}

	return 0;
}

bool espintcp_coalesce_churn(struct childdata *child)
{
	struct espintcp_ns_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.espintcp_coalesce.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_espintcp_coalesce)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.espintcp_coalesce.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, espintcp_coalesce_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_espintcp_coalesce = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.espintcp_coalesce.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.espintcp_coalesce.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
