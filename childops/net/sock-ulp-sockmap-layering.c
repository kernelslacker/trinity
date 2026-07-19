/*
 * sock_ulp_sockmap_layering — layer TCP_ULP "tls" and a BPF_SK_SKB
 * STREAM_VERDICT sockmap on the SAME loopback TCP socket, in BOTH
 * orderings, then drive concurrent non-blocking send()/recv() to push
 * traffic through the skmsg-verdict <-> ktls-rx interaction.
 *
 * Flat per-syscall fuzzing essentially never assembles this stack: it
 * needs BPF_MAP_CREATE(SOCKMAP) + BPF_PROG_LOAD(SK_SKB) +
 * BPF_PROG_ATTACH(SK_SKB_STREAM_VERDICT) + BPF_MAP_UPDATE_ELEM (with the
 * sock fd as value) + setsockopt(TCP_ULP,"tls") + setsockopt(SOL_TLS,
 * TLS_RX) — six grammar-distant operations against the same fd before
 * net/tls/ <-> net/core/skmsg.c interplay is reachable at all.  The
 * order matters: ulp-then-sockmap exercises the tls_strp install
 * detecting an already-rewired sk_data_ready (the path that gave us
 * CVE-2023-0461 family fixes), and sockmap-then-ulp exercises the
 * sockmap psock_strp checking whether the protocol has been replaced
 * underneath it.  We drive both orderings within a single run so a
 * full alt-op rotation covers both halves of the bifurcation.
 *
 * Sequence per invocation:
 *   1. Two loopback TCP pairs (cli_a/srv_a, cli_b/srv_b), non-blocking.
 *   2. Create SOCKMAP, load+attach minimal SK_SKB STREAM_VERDICT prog
 *      (r0=0;exit — returns SK_PASS implicitly).
 *   3. Pair A: setsockopt(TCP_ULP,"tls") + setsockopt(SOL_TLS,TLS_RX)
 *      BEFORE adding cli_a to the sockmap.  (ulp-then-sockmap)
 *   4. Pair B: add cli_b to the sockmap FIRST, then setsockopt(TCP_ULP,
 *      "tls") + setsockopt(SOL_TLS,TLS_RX).  (sockmap-then-ulp)
 *   5. Burst send() + recv() with MSG_DONTWAIT on both pairs, ordering
 *      interleaved so tls_strp_read and sk_psock_strp_read can race
 *      against each other on the loopback enqueue path.
 *   6. Close everything: sockets, sockmap fd, prog fd.  No host state.
 *
 * Self-bounding: a single run per invocation, all sockets non-blocking,
 * SIGALRM(1s) from child.c bounds any stray blocking call.  Every step
 * failure is COVERAGE, never a childop failure — without CONFIG_BPF or
 * CONFIG_TLS the early steps short-circuit and we still return true.
 * Counter-latching on the first hard fail (map create, prog load) keeps
 * a hostile kernel from inflating the run counter forever.
 *
 * Non-destructive: loopback-only TCP, no host-visible kernel state
 * mutated, every fd closed on exit (sockmap + prog + sockets).
 */

#include <errno.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <linux/bpf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

#include "kernel/socket.h"
#ifndef BPF_PROG_TYPE_SK_SKB
# define BPF_PROG_TYPE_SK_SKB	17
#endif

#ifndef BPF_SK_SKB_STREAM_VERDICT
# define BPF_SK_SKB_STREAM_VERDICT 9
#endif

static const char sock_ulp_layering_license[] = "GPL";

/* Latches: once the kernel proves these features are absent, stop
 * pretending future invocations are different — the counter would
 * otherwise inflate every alt-op rotation pass for nothing. */
static int sock_ulp_layering_bpf_off;	/* BPF_PROG_LOAD ENOSYS / EPERM */
static int sock_ulp_layering_tls_off;	/* TCP_ULP "tls" ENOENT */

static int make_loopback_pair(int *cli, int *srv)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener = -1;
	int c = -1, s = -1;
	int one = 1;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
		goto fail;

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

	c = socket(AF_INET, SOCK_STREAM, 0);
	if (c < 0)
		goto fail;

	/* Non-blocking connect — loopback completes synchronously in
	 * practice, but EINPROGRESS is also fine; we accept() regardless. */
	(void)fcntl(c, F_SETFL, O_NONBLOCK);
	if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS)
		goto fail;

	s = accept(listener, NULL, NULL);
	if (s < 0)
		goto fail;
	(void)fcntl(s, F_SETFL, O_NONBLOCK);

	close(listener);
	*cli = c;
	*srv = s;
	return 0;

fail:
	if (listener >= 0)
		close(listener);
	if (c >= 0)
		close(c);
	if (s >= 0)
		close(s);
	return -1;
}

static int create_sockmap(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_SOCKMAP;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(int);
	attr.max_entries = 4;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int load_sk_skb_verdict_prog(void)
{
	/* Minimal SK_SKB program: r0 = 0 (SK_PASS); exit.  The verifier
	 * accepts a constant-return program for SK_SKB without needing
	 * BPF helpers or context loads. */
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 0),
		EBPF_EXIT(),
	};
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SK_SKB;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (__u64)(uintptr_t)insns;
	attr.license = (__u64)(uintptr_t)sock_ulp_layering_license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int attach_verdict(int map_fd, int prog_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd = map_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = BPF_SK_SKB_STREAM_VERDICT;

	return sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

static int sockmap_add(int map_fd, __u32 key, int sock_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (__u64)(uintptr_t)&key;
	attr.value = (__u64)(uintptr_t)&sock_fd;
	attr.flags = 0;	/* BPF_ANY */

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int sockmap_del(int map_fd, __u32 key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (__u64)(uintptr_t)&key;

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/* Install TCP_ULP "tls" plus a SOL_TLS TLS_RX cipher_info on a fd.
 * Returns 0 if BOTH installed, -1 otherwise (still treated as coverage
 * by the caller — the rejection path is itself a code-path edge). */
static int install_tls_rx(int fd, struct childdata *child)
{
	struct tls12_crypto_info_aes_gcm_128 ci;

	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0) {
		if (errno == ENOENT) {
			__atomic_store_n(&sock_ulp_layering_tls_off, 1,
					 __ATOMIC_RELAXED);
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}

	generate_rand_bytes((unsigned char *)&ci, sizeof(ci));
	ci.info.version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
	ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	if (setsockopt(fd, SOL_TLS, TLS_RX, &ci, sizeof(ci)) < 0)
		return -1;
	return 0;
}

bool sock_ulp_sockmap_layering(struct childdata *child)
{
	unsigned char payload[64];
	unsigned char drain[256];
	int cli_a = -1, srv_a = -1;
	int cli_b = -1, srv_b = -1;
	int map_fd = -1, prog_fd = -1;
	int i;
	bool layered_a = false, layered_b = false;

	__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.runs, 1,
			   __ATOMIC_RELAXED);

	if (__atomic_load_n(&sock_ulp_layering_bpf_off, __ATOMIC_RELAXED))
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (make_loopback_pair(&cli_a, &srv_a) < 0 ||
	    make_loopback_pair(&cli_b, &srv_b) < 0) {
		__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	map_fd = create_sockmap();
	if (map_fd < 0) {
		if (errno == ENOSYS || errno == EPERM || errno == EINVAL) {
			__atomic_store_n(&sock_ulp_layering_bpf_off, 1,
					 __ATOMIC_RELAXED);
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.map_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	prog_fd = load_sk_skb_verdict_prog();
	if (prog_fd < 0) {
		if (errno == ENOSYS || errno == EPERM) {
			__atomic_store_n(&sock_ulp_layering_bpf_off, 1,
					 __ATOMIC_RELAXED);
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.prog_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (attach_verdict(map_fd, prog_fd) < 0) {
		__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.attach_failed,
				   1, __ATOMIC_RELAXED);
		/* Keep going — verdict-attach can fail per-build (e.g.
		 * BPF_STREAM_PARSER off) without invalidating the BOTH-
		 * orderings probe of the install-side state machines. */
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Pair A: ulp-then-sockmap.  Install TLS RX FIRST on the cli
	 * side; THEN add to the sockmap, so the sockmap psock attach
	 * lands on a socket whose sk_prot has already been swapped to
	 * tls_prots.  This is the path where sk_psock_init must detect
	 * the ULP and bail / re-route. */
	if (install_tls_rx(cli_a, child) == 0)
		layered_a = true;
	(void)sockmap_add(map_fd, 0, cli_a);
	(void)sockmap_add(map_fd, 1, srv_a);

	/* Pair B: sockmap-then-ulp.  Add to the sockmap FIRST so a
	 * psock + sk_data_ready rewire is already in place; THEN
	 * setsockopt(TCP_ULP,"tls") drives the tls_init path against
	 * a socket whose sk_data_ready isn't the vanilla one. */
	(void)sockmap_add(map_fd, 2, cli_b);
	(void)sockmap_add(map_fd, 3, srv_b);
	if (install_tls_rx(cli_b, child) == 0)
		layered_b = true;

	if (layered_a || layered_b)
		__atomic_add_fetch(&shm->stats.sock_ulp_sockmap_layering.layered_ok,
				   1, __ATOMIC_RELAXED);

	/* Drive traffic — short, non-blocking, interleaved across both
	 * pairs so tls_strp_read and sk_psock_strp_read race on the
	 * loopback enqueue path.  Every send/recv may return -1 with
	 * EAGAIN/EPIPE/EINVAL; all are coverage, none are failure. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	generate_rand_bytes(payload, sizeof(payload));
	for (i = 0; i < 4; i++) {
		size_t n = 1 + rnd_modulo_u32(sizeof(payload));

		(void)send(cli_a, payload, n, MSG_DONTWAIT | MSG_NOSIGNAL);
		(void)send(cli_b, payload, n, MSG_DONTWAIT | MSG_NOSIGNAL);
		(void)recv(srv_a, drain, sizeof(drain), MSG_DONTWAIT);
		(void)recv(srv_b, drain, sizeof(drain), MSG_DONTWAIT);
		/* Reverse direction too — exercises the RX-armed cli side
		 * receiving the verdict-rewritten stream. */
		(void)send(srv_a, payload, n, MSG_DONTWAIT | MSG_NOSIGNAL);
		(void)send(srv_b, payload, n, MSG_DONTWAIT | MSG_NOSIGNAL);
		(void)recv(cli_a, drain, sizeof(drain), MSG_DONTWAIT);
		(void)recv(cli_b, drain, sizeof(drain), MSG_DONTWAIT);
	}

	/* Best-effort detach of the map entries before fd close —
	 * exercises the sockmap unlink path against ULP-armed sockets. */
	(void)sockmap_del(map_fd, 0);
	(void)sockmap_del(map_fd, 1);
	(void)sockmap_del(map_fd, 2);
	(void)sockmap_del(map_fd, 3);

out:
	/* Close ALL fds — sockmap + prog + sockets — every path. */
	if (cli_a >= 0) {
		(void)shutdown(cli_a, SHUT_RDWR);
		close(cli_a);
	}
	if (srv_a >= 0) {
		(void)shutdown(srv_a, SHUT_RDWR);
		close(srv_a);
	}
	if (cli_b >= 0) {
		(void)shutdown(cli_b, SHUT_RDWR);
		close(cli_b);
	}
	if (srv_b >= 0) {
		(void)shutdown(srv_b, SHUT_RDWR);
		close(srv_b);
	}
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	return true;
}
