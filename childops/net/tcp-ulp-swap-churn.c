/*
 * tcp_ulp_swap_churn - drive a TCP socket through a chain of TCP_ULP install,
 * illegal-swap, uninstall, and re-install transitions on a connected loopback
 * fd.  Targets net/ipv4/tcp_ulp.c and its tcp_set_ulp -> ulp_ops->release ->
 * ulp_ops->init dance.
 *
 * Bug class: illegal ULP transitions where the cleanup path fails to fully
 * unwind the prior ULP's per-sock state -- CVE-2023-0461 (inet ULP listener
 * UAF), CVE-2024-36010 (tls_sw cleanup leaves dangling ctx on proto fallback),
 * CVE-2025-21683 (espintcp/tcp ULP refcount imbalance on failed swap).  Flat
 * fuzzing never assembles the full sequence: an ESTABLISHED socket, kTLS
 * armed with live TX/RX SW ctx, then post-connect swap attempts to "espintcp"
 * / "smc" (rejected: rejection-after-validate edge), TCP_ULP "" uninstall,
 * and a second "tls" re-install that trips the missed-unwind.
 *
 * Brick-safety: every mutation runs on a fresh loopback TCP socket connected
 * to a one-shot accept-and-exit fork; nothing host-visible.  The SIOCSIFNAME
 * probe reuses the name SIOCGIFNAME just returned, so no device is renamed.
 * BUDGETED (base 4 / cap 32) with JITTER, 200 ms wall-clock cap, SO_RCVTIMEO
 * 100 ms on every fd; acceptor child WNOHANG-reaped then SIGTERM if it
 * overstays.
 *
 * Per-process latch: ns_unsupported_tcp_ulp_swap fires on EAFNOSUPPORT /
 * ENOPROTOOPT / EPERM from the first "tls" install; subsequent invocations
 * bump runs+setup_failed and return.  Same shape as tls_ulp_churn.
 *
 * Header gate: kTLS install structs come from trinity's private include/tls.h
 * shim; TCP_ULP from <netinet/tcp.h>.  SOL_TLS falls back to the upstream
 * UAPI value if libc headers don't expose it.
 */

#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

#include <net/if.h>
#include <linux/sockios.h>

#include "kernel/fcntl.h"
#include "kernel/socket.h"
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
				   unsigned short version,
				   int urandom_fd)
{
	bool filled = false;

	memset(ci, 0, sizeof(*ci));

	if (urandom_fd >= 0) {
		size_t want = sizeof(ci->iv) + sizeof(ci->key) +
			      sizeof(ci->salt) + sizeof(ci->rec_seq);
		unsigned char buf[sizeof(ci->iv) + sizeof(ci->key) +
				  sizeof(ci->salt) + sizeof(ci->rec_seq)];
		size_t off = 0;

		while (off < want) {
			ssize_t n = read(urandom_fd, buf + off, want - off);
			if (n <= 0)
				break;
			off += (size_t)n;
		}
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
		 * then exit. */
		int s;
		unsigned char drain[1024];

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
		(void)waitpid_eintr(pid, &status, 0);
	}
	return -1;

fail:
	close(listener);
	return -1;
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

	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.ifname_probe_ok,
			   1, __ATOMIC_RELAXED);
}

/* Install kTLS on @s, then push TLS_TX / TLS_RX cinfo with urandom-
 * derived key material.  The TCP_ULP "tls" install is the one swap that
 * SHOULD succeed on a connected v4 TCP socket; EAFNOSUPPORT /
 * ENOPROTOOPT / EPERM here mean the platform can't reach any of the
 * codepaths this childop targets, so the cap-gate latches.  TX install
 * bumps tx_install_ok on success; RX is fire-and-forget (some kernels
 * reject RX install on a client-side fd when no peer ChangeCipherSpec
 * has fired yet, itself a coverage edge).  Returns 0 on success, -1
 * when iter_one should bail to its out: cleanup. */
static int tcp_ulp_swap_iter_install_tls(int s, struct childdata *child,
					 int urandom_fd)
{
	struct tls12_crypto_info_aes_gcm_128 cinfo;
	unsigned short version;

	if (install_tls_ulp(s) < 0) {
		if (errno == EAFNOSUPPORT || errno == ENOPROTOOPT ||
		    errno == EPERM) {
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * snapshot once and bounds-check before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern
			 * the child.c dispatch loop uses. */
			const enum child_op_type op = child->op_type;

			ns_unsupported_tcp_ulp_swap = true;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.install_failed,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.install_tls_ok,
			   1, __ATOMIC_RELAXED);

	version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
	fill_cinfo_aes_gcm_128(&cinfo, version, urandom_fd);
	if (setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo)) == 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.tx_install_ok,
				   1, __ATOMIC_RELAXED);

	fill_cinfo_aes_gcm_128(&cinfo, version, urandom_fd);
	(void)setsockopt(s, SOL_TLS, TLS_RX, &cinfo, sizeof(cinfo));

	return 0;
}

/* Drive tls_sw_sendmsg + tls_sw_recvmsg so the ULP carries live per-
 * sock state (ctx, strparser, sw paths armed) by the time the illegal-
 * swap attempts hit it.  send_ok bumps on a successful send; the recv
 * is fire-and-forget (the loopback acceptor drains best-effort and the
 * SO_RCVTIMEO of 100 ms bounds the wait). */
static void tcp_ulp_swap_iter_traffic_burst(int s)
{
	unsigned char payload[ULP_SWAP_PAYLOAD_BYTES];
	unsigned char rxbuf[ULP_SWAP_PAYLOAD_BYTES];

	generate_rand_bytes(payload, sizeof(payload));
	if (send(s, payload, sizeof(payload),
		 MSG_DONTWAIT | MSG_NOSIGNAL) > 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.send_ok,
				   1, __ATOMIC_RELAXED);
	(void)recv(s, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
}

/* Illegal-swap attempts on the now-armed kTLS socket.  Both "espintcp"
 * and "smc" must be rejected by the kernel tcp_set_ulp() validate-then-
 * reject path on a connected, already-ULP'd socket -- the rejection IS
 * the test (CVE-2025-21683 lived in exactly the espintcp-after-partial-
 * setup edge).  Counter bumps on any non-zero return except ENOPROTOOPT
 * (the module isn't built; benign coverage).  Closes with the ifname
 * SIOCGIFNAME / SIOCSIFNAME round-trip gravy probe. */
static void tcp_ulp_swap_iter_swap_attempts(int s)
{
	int rc;

	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "espintcp", 8);
	if (rc < 0 && errno != ENOPROTOOPT)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.swap_rejected_ok,
				   1, __ATOMIC_RELAXED);

	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "smc", 3);
	if (rc < 0 && errno != ENOPROTOOPT)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.swap_rejected_ok,
				   1, __ATOMIC_RELAXED);

	ifname_probe(s);
}

/* Uninstall the live ULP via setsockopt(TCP_ULP, ""), then re-install
 * "tls" on the same socket.  Setting "" is the CVE-2024-36010 cleanup
 * window: tls_update's prior-ctx teardown historically missed strparser
 * state when an in-flight rx skb was queued, and the re-install retreads
 * the proto-pointer dance so any leftover ctx is the trigger.  Closes
 * with shutdown(SHUT_RDWR) to flush whatever the cycle left armed. */
static void tcp_ulp_swap_iter_cycle_uninstall_reinstall(int s)
{
	int rc;

	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "", 0);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.uninstall_ok,
				   1, __ATOMIC_RELAXED);

	rc = setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", 3);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.reinstall_ok,
				   1, __ATOMIC_RELAXED);

	(void)shutdown(s, SHUT_RDWR);
}

/* One full sequence on a freshly-created loopback TCP socket. */
static void iter_one(const struct timespec *t_outer, struct childdata *child,
		     int urandom_fd)
{
	pid_t acceptor = -1;
	int s;

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		return;

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	/* Steps 3+4: install kTLS, then TLS_TX / TLS_RX cinfo. */
	if (tcp_ulp_swap_iter_install_tls(s, child, urandom_fd) != 0)
		goto out;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		goto out;

	/* Step 5: drive live tls_sw send + recv on the ULP. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	tcp_ulp_swap_iter_traffic_burst(s);

	/* Steps 6-8: illegal swap attempts + ifname round-trip. */
	tcp_ulp_swap_iter_swap_attempts(s);

	if ((unsigned long long)ns_since(t_outer) >= ULP_SWAP_WALL_CAP_NS)
		goto out;

	/* Steps 9-10: uninstall + reinstall ULP, then shutdown. */
	tcp_ulp_swap_iter_cycle_uninstall_reinstall(s);

out:
	if (s >= 0)
		close(s);
	reap_acceptor(acceptor);
}

bool tcp_ulp_swap_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;
	int urandom_fd;

	__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_tcp_ulp_swap) {
		__atomic_add_fetch(&shm->stats.tcp_ulp_swap_churn.setup_failed,
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

	urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    ULP_SWAP_WALL_CAP_NS)
			break;
		iter_one(&t_outer, child, urandom_fd);
		if (ns_unsupported_tcp_ulp_swap)
			break;
	}

	if (urandom_fd >= 0)
		close(urandom_fd);

	return true;
}
