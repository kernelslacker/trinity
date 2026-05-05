/*
 * tcp_ao_rotate - TCP-AO key add / rotate / delete race over a live
 * loopback connection.
 *
 * TCP-AO landed in Linux 6.7 (RFC 5925 Authentication Option for TCP).
 * The keying API (setsockopt TCP_AO_ADD_KEY / TCP_AO_DEL_KEY /
 * TCP_AO_INFO) is essentially unexercised by flat fuzzing.  Trinity's
 * per-syscall fuzzer can issue an isolated setsockopt with garbage,
 * but it never assembles the five-step sequence the kernel requires
 * before any of net/ipv4/tcp_ao.c becomes reachable:
 *
 *   socket -> ADD_KEY (with peer address) -> connect -> ESTABLISHED
 *   -> rotate-while-flowing
 *
 * A brand-new keying API in a recently-merged subsystem is the
 * textbook shape for an in-flight race window between key install /
 * rotate / delete and the verify path on incoming segments — the same
 * bug class TLS_TX rekey rejection paths cover for kTLS, but reached
 * by a different protocol.  net/ipv4/tcp_ao.c uses RCU for the per-
 * socket key list; rotate/delete vs verify races land inside
 * tcp_ao_lookup_key and tcp_ao_calc_key on the receive path, and
 * mid-flow rotate stresses the tcp_ao_set_info rcu_replace_pointer
 * paths when the connection is still actively retransmitting under
 * the old sndid.
 *
 * Sequence (per CV.46 spec):
 *   1. listener TCP socket on 127.0.0.1; bind+listen.
 *   2. setsockopt(TCP_AO_ADD_KEY) on the listener: sndid=1 / rcvid=1,
 *      peer=127.0.0.1/32, alg_name chosen from a small set the kernel
 *      crypto layer accepts ("hmac(sha1)" / "hmac(md5)" /
 *      "cmac(aes128)"), set_current=1.
 *   3. client TCP socket; setsockopt(TCP_AO_ADD_KEY) with the same
 *      matching key (peer = listener addr).
 *   4. client connect(); server accept().  Both ends now on key 1.
 *   5. send() a short payload to drive tcp_ao_hash / tcp_ao_calc_key.
 *   6. BUDGETED loop alternating, rolling sndid forward each turn:
 *        a) TCP_AO_ADD_KEY sndid=N+1 on accepted+client fds.
 *        b) TCP_AO_INFO rotate current_key N -> N+1 mid-flow.
 *        c) send() during the rotation window — drives the verify
 *           path against the just-rotated key on the peer side.
 *        d) TCP_AO_DEL_KEY sndid=N — the targeted race window: the
 *           peer may still be retransmitting with sndid=N when we
 *           yank it.
 *   7. shutdown / close.
 *
 * Self-bounding: one cycle per invocation, rotation iterations capped
 * via BUDGETED + JITTER_RANGE around a small base (4 ±50%).  Sockets
 * are O_NONBLOCK so a wedged peer can't pin us past child.c's
 * SIGALRM(1s) safety net.  Loopback only — no external traffic, no
 * external interfaces touched.
 *
 * Failure modes are all expected coverage and never propagated as
 * childop failure:
 *   - ENOPROTOOPT on the first TCP_AO_ADD_KEY: no CONFIG_TCP_AO
 *     (pre-6.7 kernel or a build without it).  Latched per-process
 *     via ns_unsupported so siblings stop probing.
 *   - EPERM on TCP_AO_ADD_KEY: no CAP_NET_ADMIN (typical for trinity
 *     children).  Also latched.
 *   - EINVAL / EEXIST / EKEYREJECTED on rotation steps: kernel
 *     rejecting an illegal key-state transition — those are the
 *     reject-after-validate edges flat fuzzing skips entirely.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* TCP_AO_* constant fallbacks already live in include/compat.h.  The
 * structs (tcp_ao_add / tcp_ao_del / tcp_ao_info_opt) live in
 * <linux/tcp.h>.  TCP_AO_MAXKEYLEN was introduced in the same header
 * patch as the structs, so use it as the gate for our private fallback
 * definitions on hosts whose toolchain headers predate 6.7.  When the
 * fallback fires we use the kernel struct names so the rest of this
 * file is identical between code paths. */
#ifndef TCP_AO_MAXKEYLEN
#define TCP_AO_MAXKEYLEN	80

#define TCP_AO_KEYF_IFINDEX	(1 << 0)
#define TCP_AO_KEYF_EXCLUDE_OPT	(1 << 1)

struct tcp_ao_add {
	struct sockaddr_storage	addr;
	char	alg_name[64];
	__s32	ifindex;
	__u32   set_current	:1,
		set_rnext	:1,
		reserved	:30;
	__u16	reserved2;
	__u8	prefix;
	__u8	sndid;
	__u8	rcvid;
	__u8	maclen;
	__u8	keyflags;
	__u8	keylen;
	__u8	key[TCP_AO_MAXKEYLEN];
} __attribute__((aligned(8)));

struct tcp_ao_del {
	struct sockaddr_storage	addr;
	__s32	ifindex;
	__u32   set_current	:1,
		set_rnext	:1,
		del_async	:1,
		reserved	:29;
	__u16	reserved2;
	__u8	prefix;
	__u8	sndid;
	__u8	rcvid;
	__u8	current_key;
	__u8	rnext;
	__u8	keyflags;
} __attribute__((aligned(8)));

struct tcp_ao_info_opt {
	__u32   set_current	:1,
		set_rnext	:1,
		ao_required	:1,
		set_counters	:1,
		accept_icmps	:1,
		reserved	:27;
	__u16	reserved2;
	__u8	current_key;
	__u8	rnext;
	__u64	pkt_good;
	__u64	pkt_bad;
	__u64	pkt_key_not_found;
	__u64	pkt_ao_required;
	__u64	pkt_dropped_icmp;
} __attribute__((aligned(8)));
#endif	/* TCP_AO_MAXKEYLEN */

/* Latched per-child: TCP_AO_ADD_KEY returned ENOPROTOOPT or EPERM
 * once.  Neither flips during this process's lifetime (config/cap is
 * fixed), so further attempts just burn CPU on identical setup that
 * has zero coverage value. */
static bool ns_unsupported;

/* Algorithm names the kernel crypto layer registers for TCP-AO.  All
 * three are accepted by net/ipv4/tcp_ao.c's crypto_alloc_ahash; the
 * kernel rejects unknown names early in tcp_ao_parse_crypto. */
static const char * const ao_algs[] = {
	"hmac(sha1)",
	"hmac(md5)",
	"cmac(aes128)",
};
#define NR_AO_ALGS	(sizeof(ao_algs) / sizeof(ao_algs[0]))

/* Base inner-loop iteration count for the rotation dance.  Real value
 * gets ±50% jitter via JITTER_RANGE() and per-op multiplier scaling
 * via BUDGETED() so adapt_budget can grow it on productive runs. */
#define ROTATE_ITERS_BASE	4U

/*
 * Build a TCP-AO key descriptor pointing at `peer`.  Caller controls
 * sndid/rcvid (the matching key ID pair on each end).  set_current=1
 * tells the kernel to make this the active outbound key immediately
 * once installed, which is what we want for the very first ADD_KEY on
 * each side; subsequent ADD_KEY calls during the rotation loop pass
 * set_current=0 and rely on a follow-up TCP_AO_INFO rotate.
 *
 * Key material is random per call — TCP-AO doesn't validate the key
 * shape (it's just bytes fed to the HMAC/CMAC), so randomising it
 * just keeps the per-iteration HMAC output unique.
 */
static void fill_ao_add(struct tcp_ao_add *opt,
			const struct sockaddr_in *peer,
			uint8_t sndid, uint8_t rcvid,
			bool set_current, const char *alg)
{
	memset(opt, 0, sizeof(*opt));
	memcpy(&opt->addr, peer, sizeof(*peer));
	(void)snprintf(opt->alg_name, sizeof(opt->alg_name), "%s", alg);
	opt->prefix      = 32;
	opt->sndid       = sndid;
	opt->rcvid       = rcvid;
	opt->maclen      = 12;
	opt->keylen      = 16;
	opt->set_current = set_current ? 1 : 0;
	generate_rand_bytes(opt->key, opt->keylen);
}

static void fill_ao_del(struct tcp_ao_del *opt,
			const struct sockaddr_in *peer,
			uint8_t sndid, uint8_t rcvid)
{
	memset(opt, 0, sizeof(*opt));
	memcpy(&opt->addr, peer, sizeof(*peer));
	opt->prefix = 32;
	opt->sndid  = sndid;
	opt->rcvid  = rcvid;
}

/*
 * Set up a loopback TCP server: bind to 127.0.0.1:0, listen, return
 * the listener fd via *listener and the bound address (port filled
 * in) via *addr.  Returns -1 on any failure.  Listener is O_CLOEXEC.
 */
static int open_loopback_listener(int *listener, struct sockaddr_in *addr)
{
	socklen_t slen = sizeof(*addr);
	int one = 1;
	int s;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr->sin_port = 0;

	if (bind(s, (struct sockaddr *)addr, sizeof(*addr)) < 0)
		goto fail;
	if (listen(s, 1) < 0)
		goto fail;
	if (getsockname(s, (struct sockaddr *)addr, &slen) < 0)
		goto fail;

	*listener = s;
	return 0;

fail:
	close(s);
	return -1;
}

/*
 * Drive one short non-blocking send to push bytes through the TCP-AO
 * sign / verify path.  No retry, no error handling — we don't care
 * whether the bytes land, just that the send path is exercised.  A
 * succeeded packets_sent stat tick distinguishes "key worked" from
 * "key was rejected before egress" without needing a return value.
 */
static void rotate_send(int fd)
{
	unsigned char buf[64];
	ssize_t n;

	generate_rand_bytes(buf, sizeof(buf));
	n = send(fd, buf, 1 + ((unsigned int)rand() % sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_packets_sent,
				   1, __ATOMIC_RELAXED);
}

bool tcp_ao_rotate(struct childdata *child)
{
	struct sockaddr_in srv_addr;
	struct sockaddr_in cli_addr;
	struct tcp_ao_add  ao_add;
	struct tcp_ao_del  ao_del;
	struct tcp_ao_info_opt ao_info;
	socklen_t slen;
	const char *alg;
	int listener = -1;
	int cli = -1;
	int srv_acc = -1;
	int rc;
	unsigned int iters;
	unsigned int i;
	uint8_t cur_id;

	(void)child;

	__atomic_add_fetch(&shm->stats.tcp_ao_rotate_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (open_loopback_listener(&listener, &srv_addr) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Bind the client to a known address/port BEFORE installing the
	 * listener-side key: the listener's TCP_AO_ADD_KEY needs the
	 * client's exact peer address (prefix=32) for the key to match
	 * the incoming SYN.  Bind to port 0 and getsockname() to recover
	 * the assigned ephemeral port. */
	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	cli_addr.sin_port = 0;
	if (bind(cli, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	slen = sizeof(cli_addr);
	if (getsockname(cli, (struct sockaddr *)&cli_addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	alg = ao_algs[(unsigned int)rand() % NR_AO_ALGS];

	/* Install the listener-side key first, peer = client's bound
	 * address.  This is the call that hits the support gate: if
	 * TCP-AO isn't compiled in, we get ENOPROTOOPT here and latch
	 * for the rest of the process.  EPERM means no CAP_NET_ADMIN —
	 * also latched, since trinity children don't gain caps mid-life. */
	fill_ao_add(&ao_add, &cli_addr, 1, 1, true, alg);
	rc = setsockopt(listener, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		if (errno == ENOPROTOOPT || errno == EPERM)
			ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_addkey_rejected,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate_keys_added,
			   1, __ATOMIC_RELAXED);

	/* Install the matching key on the client, peer = listener.
	 * Same alg, same id pair, fresh random key bytes (no need for
	 * the keys to actually match here — the kernel doesn't verify
	 * cross-host key equality at install time, only at handshake
	 * time when the HMAC mismatches.  That mismatch is itself an
	 * exercised verify-reject edge). */
	fill_ao_add(&ao_add, &srv_addr, 1, 1, true, alg);
	rc = setsockopt(cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_addkey_rejected,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate_keys_added,
			   1, __ATOMIC_RELAXED);

	/* Non-blocking connect so a wedged loopback can't pin us past
	 * SIGALRM(1s).  Loopback usually completes synchronously even
	 * with the AO sign/verify overhead, but EINPROGRESS is fine —
	 * accept() succeeds regardless and we proceed to the rotate
	 * loop. */
	(void)fcntl(cli, F_SETFL, O_NONBLOCK);
	if (connect(cli, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0 &&
	    errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_connect_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	srv_acc = accept(listener, NULL, NULL);
	if (srv_acc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate_connect_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	(void)fcntl(srv_acc, F_SETFL, O_NONBLOCK);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate_connected,
			   1, __ATOMIC_RELAXED);

	/* Drive the AO sign/verify path with an initial send before any
	 * rotation, so the first ADD_KEY/INFO race actually has live
	 * ESTABLISHED traffic to interact with. */
	rotate_send(cli);
	rotate_send(srv_acc);

	/* Rotation loop.  cur_id starts at 1 (the just-installed key)
	 * and rolls forward each iteration: we add cur_id+1, rotate
	 * current to cur_id+1 via TCP_AO_INFO, send during the window,
	 * then DEL the old cur_id while the peer may still be in the
	 * middle of retransmit/ack with it.  The DEL after rotate is
	 * the targeted race — RCU walkers in tcp_ao_lookup_key on the
	 * verify path may still hold a pointer to the freed key node. */
	iters = BUDGETED(CHILD_OP_TCP_AO_ROTATE,
			 JITTER_RANGE(ROTATE_ITERS_BASE));
	cur_id = 1;
	for (i = 0; i < iters; i++) {
		uint8_t next_id = cur_id + 1;

		/* sndid wraps inside a single byte; if we run long enough
		 * to wrap to 0 the kernel rejects (sndid 0 is reserved as
		 * "no key") which is itself another reject-edge.  Cap
		 * before wrap so a long inner loop doesn't quietly spend
		 * all its budget on EINVAL. */
		if (next_id == 0)
			break;

		/* a) ADD_KEY sndid=next_id on both ends.  set_current=0:
		 *    we want INFO to be the call that flips current_key,
		 *    so the rotate path is exercised separately from the
		 *    install path. */
		fill_ao_add(&ao_add, &cli_addr, next_id, next_id, false, alg);
		rc = setsockopt(srv_acc, IPPROTO_TCP, TCP_AO_ADD_KEY,
				&ao_add, sizeof(ao_add));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_keys_added,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_addkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_add(&ao_add, &srv_addr, next_id, next_id, false, alg);
		rc = setsockopt(cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
				&ao_add, sizeof(ao_add));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_keys_added,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_addkey_rejected,
					   1, __ATOMIC_RELAXED);

		/* b) INFO rotate current_key cur_id -> next_id mid-flow. */
		memset(&ao_info, 0, sizeof(ao_info));
		ao_info.set_current = 1;
		ao_info.current_key = next_id;
		rc = setsockopt(cli, IPPROTO_TCP, TCP_AO_INFO,
				&ao_info, sizeof(ao_info));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_key_rotations,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_info_rejected,
					   1, __ATOMIC_RELAXED);
		(void)setsockopt(srv_acc, IPPROTO_TCP, TCP_AO_INFO,
				 &ao_info, sizeof(ao_info));

		/* c) Send through the rotated key.  This is the "verify
		 *    against the new key on the peer" edge.  Drive both
		 *    directions so retransmit / dup-ack races land on
		 *    both endpoints' AO state machines. */
		rotate_send(cli);
		rotate_send(srv_acc);

		/* d) DEL_KEY old cur_id — race against in-flight retx
		 *    that's still using sndid=cur_id on the wire.  This
		 *    is the rcu-walk-vs-free race window. */
		fill_ao_del(&ao_del, &srv_addr, cur_id, cur_id);
		rc = setsockopt(cli, IPPROTO_TCP, TCP_AO_DEL_KEY,
				&ao_del, sizeof(ao_del));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_key_dels,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_delkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_del(&ao_del, &cli_addr, cur_id, cur_id);
		rc = setsockopt(srv_acc, IPPROTO_TCP, TCP_AO_DEL_KEY,
				&ao_del, sizeof(ao_del));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_key_dels,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate_delkey_rejected,
					   1, __ATOMIC_RELAXED);

		cur_id = next_id;
	}

	(void)shutdown(cli, SHUT_RDWR);
	(void)shutdown(srv_acc, SHUT_RDWR);

out:
	if (srv_acc >= 0)
		close(srv_acc);
	if (cli >= 0)
		close(cli);
	if (listener >= 0)
		close(listener);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate_cycles, 1, __ATOMIC_RELAXED);
	return true;
}
