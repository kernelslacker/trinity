/*
 * tcp_ulp_swap_churn - drive a TCP socket through a chain of TCP_ULP
 * install / illegal-swap / uninstall / re-install transitions on a
 * connected loopback fd.
 *
 * net/ipv4/tcp_ulp.c constrains setsockopt(TCP_ULP, ...) to a narrow
 * legal window that varies per ULP module:
 *
 *   - "tls" requires the socket to be in TCP_ESTABLISHED.
 *   - "espintcp" requires pre-connect / listener state.
 *   - "smc" likewise refuses on a connected socket.
 *   - "mptcp" upgrade is gated through a different inet_create() path.
 *
 * Once any ULP is installed, every subsequent TCP_ULP setsockopt against
 * the same socket has to walk through tcp_set_ulp -> ulp_ops->release
 * before another ulp_ops->init can fire.  The bug class is "user
 * attempted illegal transition and the cleanup path didn't fully undo
 * the prior ULP's per-sock state".  Historical examples:
 *
 *   CVE-2023-0461  inet ULP listener UAF (sk_psock leak after a failed
 *                  ULP install on a listener inherited the wrong proto
 *                  pointers; child socket survived the cleanup).
 *   CVE-2024-36010 tls_sw cleanup on ULP uninstall left ctx pointers
 *                  attached to the proto fallback ops, dangling on the
 *                  next sendmsg.
 *   CVE-2025-21683 espintcp + tcp ULP refcount imbalance: failed swap
 *                  decremented the encap module ref twice.
 *
 * Per outer-loop iteration (BUDGETED + JITTER, 200 ms wall-clock cap):
 *
 *   1.  socket(AF_INET, SOCK_STREAM)
 *   2.  loopback acceptor fork; client connect()s through the 3-way
 *       handshake so the socket lands in ESTABLISHED.
 *   3.  setsockopt(TCP_ULP, "tls") -- install kTLS (the legal window).
 *   4.  setsockopt(SOL_TLS, TLS_TX, &cinfo) and TLS_RX with a urandom-
 *       keyed AES_GCM_128 cinfo on each direction.
 *   5.  send() through the TX side; recv() on the RX side.  Drives
 *       tls_sw_sendmsg + tls_sw_recvmsg so the ULP has live per-sock
 *       state (ctx, strparser, sw_send/recv path) by the time the
 *       illegal-swap attempts hit it.
 *   6.  setsockopt(TCP_ULP, "espintcp") -- KERNEL REJECTS on a connected
 *       socket; EINVAL/EBUSY/EOPNOTSUPP are all the rejection-after-
 *       validate edge that flat fuzzing skips.  Counter bump.
 *   7.  setsockopt(TCP_ULP, "smc") -- likewise rejected post-connect.
 *   8.  ioctl SIOCGIFNAME(ifindex=1), then SIOCSIFNAME with the SAME
 *       name that came back -- the kernel returns 0 / EEXIST and never
 *       disturbs lo.  EPERM latches off the ifname probe forever; this
 *       is gravy, the swap-rejection edge above is the main signal.
 *   9.  setsockopt(TCP_ULP, "") -- uninstall.  net/tls historically
 *       refused this on a TLS-armed socket (CVE-2024-36010 cleanup
 *       window) but the rejection itself is the path.  When accepted,
 *       it races whatever in-flight rx / strparser work is queued.
 *  10.  setsockopt(TCP_ULP, "tls") AGAIN -- re-install on the same
 *       sock.  net/tls's tls_init() takes a fresh trip through the
 *       proto-pointer dance; if the prior cleanup didn't fully unwind
 *       the dangling ctx (the bug class), the second init is the
 *       trigger.
 *  11.  close().
 *
 * Per-process cap-gate latch: ns_unsupported_tcp_ulp_swap fires on
 * EAFNOSUPPORT / ENOPROTOOPT / EPERM from the very first TCP_ULP "tls"
 * install attempt.  Once latched, every subsequent invocation just
 * bumps runs+setup_failed and returns.  Mirrors tls_ulp_churn,
 * netns_teardown_churn, etc.
 *
 * Brick-safety:
 *   - Every mutation runs on a fresh loopback TCP socket connected to
 *     a one-shot accept-and-exit fork.  Nothing host-visible.
 *   - SIOCSIFNAME passes back the name the kernel just handed us, so
 *     the device is never actually renamed.
 *   - Inner sequence is BUDGETED (base 4 / cap 32) with JITTER and
 *     a 200 ms wall-clock cap; SO_RCVTIMEO of 100 ms on every fd.
 *   - Acceptor child is reaped via WNOHANG-poll then SIGTERM if it
 *     overstays.
 *
 * Header gate: the kTLS install structs come from include/tls.h
 * (trinity's private cipher-info shim that shadows <linux/tls.h>); the
 * TCP_ULP optname comes from <netinet/tcp.h>.  SOL_TLS is not always
 * exposed by libc headers -- fall back to the upstream UAPI value if
 * the toolchain hasn't seen it.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

#include <net/if.h>
#include <linux/sockios.h>

/* SOL_TLS lives in <linux/tls.h> on the kernel side; some libc trees
 * don't surface it via the standard socket headers.  282 is the UAPI
 * value (matches include/uapi/linux/tls.h) and is stable across every
 * kernel that ships kTLS.  Same fallback shape used in other childops
 * that talk to net/tls/. */
#ifndef SOL_TLS
#define SOL_TLS			282
#endif

/* Per-process latched gates.  Module / config / capability state is
 * static for a child's lifetime, so once we've paid the EFAIL we stop
 * probing.  Mirrors tls_ulp_churn / handshake_req_abort. */
static bool ns_unsupported_tcp_ulp_swap;
static bool ns_unsupported_ifname_probe;

#define ULP_SWAP_OUTER_BASE		4U
#define ULP_SWAP_OUTER_CAP		32U
#define ULP_SWAP_FLOOR			8U
#define ULP_SWAP_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)
#define ULP_SWAP_RCV_TIMEO_MS		100
#define ULP_SWAP_PAYLOAD_BYTES		32U
#define ULP_SWAP_LO_IFINDEX		1

/* Fill an aes_gcm_128 cinfo with urandom-derived material; falls back
 * to generate_rand_bytes when /dev/urandom is unavailable.  Same shape
 * as tls_ulp_churn's helper but inlined here per the spec (the brief
 * explicitly allows local inlining over a cross-childop factor-out).
 */
static void fill_cinfo_aes_gcm_128(struct tls12_crypto_info_aes_gcm_128 *ci,
				   unsigned short version)
{
	int fd;
	bool filled = false;

	memset(ci, 0, sizeof(*ci));

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		size_t want = sizeof(ci->iv) + sizeof(ci->key) +
			      sizeof(ci->salt) + sizeof(ci->rec_seq);
		unsigned char buf[sizeof(ci->iv) + sizeof(ci->key) +
				  sizeof(ci->salt) + sizeof(ci->rec_seq)];
		size_t off = 0;

		while (off < want) {
			ssize_t n = read(fd, buf + off, want - off);
			if (n <= 0)
				break;
			off += (size_t)n;
		}
		close(fd);
		if (off == want) {
			memcpy(ci->iv,      buf, sizeof(ci->iv));
			memcpy(ci->key,     buf + sizeof(ci->iv),
			       sizeof(ci->key));
			memcpy(ci->salt,    buf + sizeof(ci->iv) +
			       sizeof(ci->key), sizeof(ci->salt));
			memcpy(ci->rec_seq, buf + sizeof(ci->iv) +
			       sizeof(ci->key) + sizeof(ci->salt),
			       sizeof(ci->rec_seq));
			filled = true;
		}
	}
	if (!filled) {
		generate_rand_bytes((unsigned char *)ci->iv, sizeof(ci->iv));
		generate_rand_bytes((unsigned char *)ci->key, sizeof(ci->key));
		generate_rand_bytes((unsigned char *)ci->salt, sizeof(ci->salt));
		generate_rand_bytes((unsigned char *)ci->rec_seq,
				    sizeof(ci->rec_seq));
	}

	ci->info.version     = version;
	ci->info.cipher_type = TLS_CIPHER_AES_GCM_128;
}

/* Install kTLS on a connected fd.  Returns 0 on success, -1 with the
 * caller-visible errno preserved on failure.  Self-contained per the
 * spec; the global tls_ulp_churn helper is intentionally NOT shared
 * (different latch shape, different cinfo lifecycle). */
static int install_tls_ulp(int sock)
{
	if (setsockopt(sock, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0)
		return -1;
	return 0;
}

/* Fork a one-shot loopback acceptor.  Parent gets the connected client
 * fd back; the child accept()s once, drains a few packets so the parent
 * doesn't fill its receive window, and exits.  Returns the connected
 * client fd on success, -1 on failure (with *out_pid set to -1).
 * Acceptor pid is reaped via reap_acceptor() in the cleanup path so a
 * half-built pair never leaves a zombie.
 */
static int open_loopback_pair(pid_t *out_pid)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener;
	int cli = -1;
	int one = 1;
	struct timeval rcv_to;
	pid_t pid;

	*out_pid = -1;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

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
		/* Acceptor child.  accept() one connection, drain so the
		 * parent's sends don't stall on receive-window watermarks,
		 * exit.  Self-bound by alarm(2) so a parent that crashes
		 * before connect() can't strand us. */
		int s;
		unsigned char drain[1024];

		alarm(2);
		s = accept(listener, NULL, NULL);
		if (s >= 0) {
			ssize_t n;
			int loops = 16;

			while (loops-- > 0) {
				n = recv(s, drain, sizeof(drain), MSG_DONTWAIT);
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

	rcv_to.tv_sec = 0;
	rcv_to.tv_usec = ULP_SWAP_RCV_TIMEO_MS * 1000;
	(void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

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
		(void)waitpid(pid, &status, 0);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

static void reap_acceptor(pid_t pid)
{
	int status;
	int waited = 0;

	if (pid <= 0)
		return;

	while (waited++ < 8) {
		pid_t r = waitpid(pid, &status, WNOHANG);
		if (r == pid || r < 0)
			return;
		{
			struct timespec ts = { 0, 1000000L };  /* 1 ms */
			(void)nanosleep(&ts, NULL);
		}
	}
	(void)kill(pid, SIGTERM);
	(void)waitpid(pid, &status, 0);
}

/* SIOCGIFNAME(ifindex=1) -> SIOCSIFNAME with the same name back.  The
 * "rename to current name" round-trip exercises the dev_change_name()
 * path without actually mutating lo.  EPERM (no CAP_NET_ADMIN) latches
 * the probe off; EEXIST / 0 is the success edge.  Per spec, this is
 * gravy on top of the ULP swap rejection (the main signal).
 */
static void ifname_probe(int sock)
{
	struct ifreq req;
	char saved_name[IFNAMSIZ];

	if (ns_unsupported_ifname_probe)
		return;

	memset(&req, 0, sizeof(req));
	req.ifr_ifindex = ULP_SWAP_LO_IFINDEX;
	if (ioctl(sock, SIOCGIFNAME, &req) < 0) {
		if (errno == EPERM || errno == ENOTTY || errno == EINVAL)
			ns_unsupported_ifname_probe = true;
		return;
	}

	/* Defensive: ensure NUL-termination before round-tripping. */
	req.ifr_name[IFNAMSIZ - 1] = '\0';
	memcpy(saved_name, req.ifr_name, IFNAMSIZ);

	/* Same name back.  Kernel dev_change_name() short-circuits when
	 * the new name equals the current one (EEXIST) or accepts the
	 * no-op (0) -- never disturbs the device.  EPERM means we lack
	 * CAP_NET_ADMIN; latch and stop probing. */
	memcpy(req.ifr_name, saved_name, IFNAMSIZ);
	if (ioctl(sock, SIOCSIFNAME, &req) < 0) {
		if (errno == EPERM)
			ns_unsupported_ifname_probe = true;
	}

	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_ifname_probe_ok,
			   1, __ATOMIC_RELAXED);
}

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

/* One full sequence on a freshly-created loopback TCP socket. */
static void iter_one(const struct timespec *t_outer)
{
	unsigned char payload[ULP_SWAP_PAYLOAD_BYTES];
	unsigned char rxbuf[ULP_SWAP_PAYLOAD_BYTES];
	pid_t acceptor = -1;
	int s;
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		return;

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Step 3: install kTLS.  This is the one TCP_ULP call that
	 * SHOULD succeed on a connected v4 TCP socket.  EAFNOSUPPORT /
	 * ENOPROTOOPT / EPERM here mean the platform can't reach any
	 * of the codepaths this childop targets -- latch off. */
	if (install_tls_ulp(s) < 0) {
		if (errno == EAFNOSUPPORT || errno == ENOPROTOOPT ||
		    errno == EPERM)
			ns_unsupported_tcp_ulp_swap = true;
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_install_failed,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_install_tls_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 4: install TLS_TX / TLS_RX with urandom-derived cinfo.
	 * Best-effort: TX install bumps the tx counter on success; RX
	 * is fire-and-forget (some kernels reject RX install on a
	 * client-side fd when no peer ChangeCipherSpec has fired yet,
	 * which is a coverage edge in itself). */
	{
		struct tls12_crypto_info_aes_gcm_128 cinfo;
		unsigned short version;

		version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
		fill_cinfo_aes_gcm_128(&cinfo, version);
		rc = setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_tx_install_ok,
					   1, __ATOMIC_RELAXED);

		fill_cinfo_aes_gcm_128(&cinfo, version);
		(void)setsockopt(s, SOL_TLS, TLS_RX, &cinfo, sizeof(cinfo));
	}

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		goto out;

	/* Step 5: drive tls_sw_sendmsg + tls_sw_recvmsg so the ULP
	 * carries live per-sock state (ctx, strparser, sw paths armed)
	 * by the time the illegal-swap attempts hit it. */
	generate_rand_bytes(payload, sizeof(payload));
	if (send(s, payload, sizeof(payload),
		 MSG_DONTWAIT | MSG_NOSIGNAL) > 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_send_ok,
				   1, __ATOMIC_RELAXED);
	(void)recv(s, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);

	/* Step 6: setsockopt(TCP_ULP, "espintcp") -- post-connect, the
	 * kernel tcp_set_ulp() validate-then-reject path bumps EBUSY/
	 * EINVAL/EOPNOTSUPP.  THIS IS THE TEST.  The rejection IS the
	 * bug surface (CVE-2025-21683 espintcp refcount imbalance lived
	 * exactly here -- the encap module ref leaked when the swap was
	 * rejected after partial setup).  Counter bump on any non-zero
	 * return from setsockopt; only ENOPROTOOPT (espintcp not built)
	 * is treated as benign coverage. */
	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "espintcp", 8);
	if (rc < 0 && errno != ENOPROTOOPT)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_swap_rejected_ok,
				   1, __ATOMIC_RELAXED);

	/* Step 7: same swap attempt against "smc" -- net/smc/smc_inet.c
	 * registers an ULP that refuses install on an already-ULP'd or
	 * post-connect socket.  Same rejection edge as espintcp. */
	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "smc", 3);
	if (rc < 0 && errno != ENOPROTOOPT)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_swap_rejected_ok,
				   1, __ATOMIC_RELAXED);

	/* Step 8: ifname round-trip.  No-op on the device. */
	ifname_probe(s);

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		goto out;

	/* Step 9: setsockopt(TCP_ULP, "") -- uninstall.  net/tls's
	 * tls_update path is the canonical CVE-2024-36010 cleanup
	 * window: the prior ctx is meant to be torn down before the
	 * next install dances the proto pointers back to plain TCP,
	 * but historically the unwind missed strparser teardown when
	 * an in-flight rx skb was queued.  Setting "" here races
	 * exactly that.  Bump on success; on rejection the rejection
	 * itself is the unreachable-from-flat-fuzzing edge. */
	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "", 0);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_uninstall_ok,
				   1, __ATOMIC_RELAXED);

	/* Step 10: re-install kTLS on the same sock.  net/tls's
	 * tls_init() retreads the proto-pointer dance; if the prior
	 * cleanup left ctx state dangling (the bug class) the second
	 * init is the trigger.  EEXIST when the kernel still sees a
	 * live ULP attached -- itself a reject-after-validate edge. */
	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", 3);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_reinstall_ok,
				   1, __ATOMIC_RELAXED);

	(void)shutdown(s, SHUT_RDWR);

out:
	if (s >= 0)
		close(s);
	reap_acceptor(acceptor);
}

bool tcp_ulp_swap_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_tcp_ulp_swap) {
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_TCP_ULP_SWAP_CHURN,
			       JITTER_RANGE(ULP_SWAP_OUTER_BASE));
	if (outer_iters < ULP_SWAP_FLOOR)
		outer_iters = ULP_SWAP_FLOOR;
	if (outer_iters > ULP_SWAP_OUTER_CAP)
		outer_iters = ULP_SWAP_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    ULP_SWAP_WALL_CAP_NS)
			break;
		iter_one(&t_outer);
		if (ns_unsupported_tcp_ulp_swap)
			break;
	}

	return true;
}
