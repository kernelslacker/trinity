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
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <time.h>
#include <net/if.h>
#include <sched.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
#include "utils.h"
/* TCP_AO_* constant fallbacks already live in include/kernel/socket.h.  The
 * structs (tcp_ao_add / tcp_ao_del / tcp_ao_info_opt) live in
 * <linux/tcp.h>.  TCP_AO_MAXKEYLEN was introduced in the same header
 * patch as the structs, so use it as the gate for our private fallback
 * definitions on hosts whose toolchain headers predate 6.7.  When the
 * fallback fires we use the kernel struct names so the rest of this
 * file is identical between code paths. */
#ifndef IFLA_VRF_TABLE
#define IFLA_VRF_TABLE	1
#endif

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER	1
#endif

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

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 so the teardown helper can close them
 * unconditionally regardless of which earlier phase bailed.  srv_addr
 * is populated by open_loopback_listener; cli_addr by the client
 * getsockname; alg by install_keys (used again by rotate_loop).  child
 * is the caller's struct childdata so phase helpers can attribute
 * per-childop yield counters to child->op_type. */
struct tcp_ao_rotate_iter_ctx {
	int listener;
	int cli;
	int srv_acc;
	struct sockaddr_in srv_addr;
	struct sockaddr_in cli_addr;
	const char *alg;
	/* Second listener for the reconnect-to-different-peer arm. */
	int srv2_listener;
	int srv2_acc;
	struct sockaddr_in srv2_addr;
	struct childdata *child;
	/* Running tally of direct kernel syscalls this invocation issued
	 * (socket / bind / listen / getsockname / fcntl / connect / accept /
	 * setsockopt / send / shutdown / close).  Bumped on every attempt,
	 * including those that return an error, so the count reflects the
	 * saturation cost we imposed on the kernel regardless of outcome.
	 * Published once from tcp_ao_rotate() via
	 * childop_direct_syscalls_add() gated on valid_op. */
	unsigned long direct_calls;
};

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
static int open_loopback_listener(int *listener, struct sockaddr_in *addr,
				  unsigned long *direct_calls)
{
	socklen_t slen = sizeof(*addr);
	int one = 1;
	int s;

	(*direct_calls)++;
	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	(*direct_calls)++;
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr->sin_port = 0;

	(*direct_calls)++;
	if (bind(s, (struct sockaddr *)addr, sizeof(*addr)) < 0)
		goto fail;
	(*direct_calls)++;
	if (listen(s, 1) < 0)
		goto fail;
	(*direct_calls)++;
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
static void rotate_send(int fd, unsigned long *direct_calls)
{
	unsigned char buf[64];
	ssize_t n;

	generate_rand_bytes(buf, sizeof(buf));
	(*direct_calls)++;
	n = send(fd, buf, 1 + rnd_modulo_u32(sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.packets_sent,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase 1: open the loopback listener (via open_loopback_listener),
 * then open the client socket, bind it to 127.0.0.1:0, and recover the
 * assigned ephemeral port via getsockname.  The client side has to be
 * bound BEFORE the listener-side TCP_AO_ADD_KEY because the listener's
 * key carries the client's exact peer address (prefix=32) and the
 * kernel pins the match at install time.  Returns 0 on success or -1
 * if the iteration should bail to the out: cleanup path; on failure
 * tcp_ao_rotate_setup_failed is bumped and the caller's teardown
 * helper handles whichever fds we did manage to open.
 */
static int tcp_ao_rotate_iter_setup_sockets(struct tcp_ao_rotate_iter_ctx *ctx)
{
	socklen_t slen;

	if (open_loopback_listener(&ctx->listener, &ctx->srv_addr,
				   &ctx->direct_calls) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	ctx->direct_calls++;
	ctx->cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (ctx->cli < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	memset(&ctx->cli_addr, 0, sizeof(ctx->cli_addr));
	ctx->cli_addr.sin_family = AF_INET;
	ctx->cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ctx->cli_addr.sin_port = 0;
	ctx->direct_calls++;
	if (bind(ctx->cli, (struct sockaddr *)&ctx->cli_addr,
		 sizeof(ctx->cli_addr)) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	slen = sizeof(ctx->cli_addr);
	ctx->direct_calls++;
	if (getsockname(ctx->cli, (struct sockaddr *)&ctx->cli_addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 2: pick the AO algorithm for this invocation and install the
 * initial sndid/rcvid=1 key on each side.  The listener-side call is
 * the support gate: ENOPROTOOPT (no CONFIG_TCP_AO) or EPERM (no
 * CAP_NET_ADMIN) latch ns_unsupported so siblings stop probing.  The
 * client-side install reuses the same id pair with fresh random key
 * bytes (the kernel verifies HMACs at handshake, not key equality at
 * install).  Returns 0 on success or -1 if the iteration should bail
 * to the out: cleanup path.
 */
static int tcp_ao_rotate_iter_install_keys(struct tcp_ao_rotate_iter_ctx *ctx)
{
	struct tcp_ao_add ao_add;
	int rc;

	ctx->alg = ao_algs[rnd_modulo_u32(NR_AO_ALGS)];

	fill_ao_add(&ao_add, &ctx->cli_addr, 1, 1, true, ctx->alg);
	ctx->direct_calls++;
	rc = setsockopt(ctx->listener, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		if (errno == ENOPROTOOPT || errno == EPERM) {
			ns_unsupported = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
			   1, __ATOMIC_RELAXED);

	fill_ao_add(&ao_add, &ctx->srv_addr, 1, 1, true, ctx->alg);
	ctx->direct_calls++;
	rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 3: bring the connection to ESTABLISHED and prime the
 * AO sign/verify path.  cli goes O_NONBLOCK so a wedged loopback can't
 * pin us past child.c's SIGALRM(1s) cap (EINPROGRESS is fine — accept()
 * still completes).  srv_acc also goes O_NONBLOCK so the in-loop
 * rotate_send bursts don't block on a slow receiver.  The two initial
 * rotate_send calls drive bytes through the just-installed key so the
 * very first ADD_KEY/INFO race has live ESTABLISHED traffic to
 * interact with.  Returns 0 on success or -1 if the iteration should
 * bail to the out: cleanup path.
 */
static int tcp_ao_rotate_iter_connect(struct tcp_ao_rotate_iter_ctx *ctx)
{
	ctx->direct_calls++;
	(void)fcntl(ctx->cli, F_SETFL, O_NONBLOCK);
	ctx->direct_calls++;
	if (connect(ctx->cli, (struct sockaddr *)&ctx->srv_addr,
		    sizeof(ctx->srv_addr)) < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connect_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	ctx->direct_calls++;
	ctx->srv_acc = accept(ctx->listener, NULL, NULL);
	if (ctx->srv_acc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connect_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->direct_calls++;
	(void)fcntl(ctx->srv_acc, F_SETFL, O_NONBLOCK);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connected,
			   1, __ATOMIC_RELAXED);

	rotate_send(ctx->cli, &ctx->direct_calls);
	rotate_send(ctx->srv_acc, &ctx->direct_calls);
	return 0;
}

/*
 * Phase 4: BUDGETED rotation dance.  cur_id starts at 1 (the
 * just-installed key) and rolls forward each iteration: ADD_KEY
 * next_id (set_current=0) on both ends, INFO rotate current_key
 * cur_id -> next_id mid-flow, send through the rotated key, then
 * DEL_KEY old cur_id while the peer may still be retransmitting with
 * it.  The DEL after rotate is the targeted race — RCU walkers in
 * tcp_ao_lookup_key on the verify path may still hold a pointer to
 * the freed key node.  Returns the final active sndid so the
 * reconnect arm knows which key id is current_key on exit.
 */
static uint8_t tcp_ao_rotate_iter_rotate_loop(struct tcp_ao_rotate_iter_ctx *ctx)
{
	struct tcp_ao_add ao_add;
	struct tcp_ao_del ao_del;
	struct tcp_ao_info_opt ao_info;
	unsigned int iters, i;
	uint8_t cur_id;
	int rc;

	iters = BUDGETED(CHILD_OP_TCP_AO_ROTATE,
			 JITTER_RANGE(ROTATE_ITERS_BASE));
	cur_id = 1;
	for (i = 0; i < iters; i++) {
		uint8_t next_id = (uint8_t)(cur_id + 1);

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
		fill_ao_add(&ao_add, &ctx->cli_addr, next_id, next_id, false, ctx->alg);
		ctx->direct_calls++;
		rc = setsockopt(ctx->srv_acc, IPPROTO_TCP, TCP_AO_ADD_KEY,
				&ao_add, sizeof(ao_add));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_add(&ao_add, &ctx->srv_addr, next_id, next_id, false, ctx->alg);
		ctx->direct_calls++;
		rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
				&ao_add, sizeof(ao_add));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
					   1, __ATOMIC_RELAXED);

		/* b) INFO rotate current_key cur_id -> next_id mid-flow. */
		memset(&ao_info, 0, sizeof(ao_info));
		ao_info.set_current = 1;
		ao_info.current_key = next_id;
		ctx->direct_calls++;
		rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_INFO,
				&ao_info, sizeof(ao_info));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_rotations,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.info_rejected,
					   1, __ATOMIC_RELAXED);
		ctx->direct_calls++;
		(void)setsockopt(ctx->srv_acc, IPPROTO_TCP, TCP_AO_INFO,
				 &ao_info, sizeof(ao_info));

		/* c) Send through the rotated key.  This is the "verify
		 *    against the new key on the peer" edge.  Drive both
		 *    directions so retransmit / dup-ack races land on
		 *    both endpoints' AO state machines. */
		rotate_send(ctx->cli, &ctx->direct_calls);
		rotate_send(ctx->srv_acc, &ctx->direct_calls);

		/* d) DEL_KEY old cur_id — race against in-flight retx
		 *    that's still using sndid=cur_id on the wire.  This
		 *    is the rcu-walk-vs-free race window. */
		fill_ao_del(&ao_del, &ctx->srv_addr, cur_id, cur_id);
		ctx->direct_calls++;
		rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_DEL_KEY,
				&ao_del, sizeof(ao_del));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_dels,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.delkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_del(&ao_del, &ctx->cli_addr, cur_id, cur_id);
		ctx->direct_calls++;
		rc = setsockopt(ctx->srv_acc, IPPROTO_TCP, TCP_AO_DEL_KEY,
				&ao_del, sizeof(ao_del));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_dels,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.delkey_rejected,
					   1, __ATOMIC_RELAXED);

		cur_id = next_id;
	}

	return cur_id;
}

/*
 * Phase 5 (reconnect arm): trigger the peer-change current_key
 * use-after-free window.
 *
 * After the rotate loop the client socket still holds stale_id as its
 * current_key, matched against peer-1's address.  We open a second
 * loopback listener on a fresh ephemeral port and install a new AO key
 * pair using sndid/rcvid RECONNECT_SNDID on each side.  We then
 * disconnect the client with connect(AF_UNSPEC), which causes the
 * kernel to free peer-1's AO key list while leaving current_key
 * pointing into the freed allocation.  Reconnecting to the second
 * listener completes the peer-change; any subsequent TCP_AO_INFO or
 * TCP_AO_DEL_KEY call that touches current_key dereferences the freed
 * node — the UAF window the Hyunwoo Kim net/ipv4/tcp_ao.c fix closes.
 */
#define RECONNECT_SNDID	200u

static void tcp_ao_rotate_iter_reconnect_peer(struct tcp_ao_rotate_iter_ctx *ctx,
					  uint8_t stale_id)
{
	struct sockaddr discon;
	struct tcp_ao_add ao_add;
	struct tcp_ao_del ao_del;
	struct tcp_ao_info_opt ao_info;
	int rc;

	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_attempted,
			   1, __ATOMIC_RELAXED);

	/* Stand up a second loopback listener for the new peer address. */
	if (open_loopback_listener(&ctx->srv2_listener, &ctx->srv2_addr,
				   &ctx->direct_calls) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* AO key on the second listener: peer = client, sndid=RECONNECT_SNDID. */
	fill_ao_add(&ao_add, &ctx->cli_addr,
		    RECONNECT_SNDID, RECONNECT_SNDID, true, ctx->alg);
	ctx->direct_calls++;
	rc = setsockopt(ctx->srv2_listener, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
			   1, __ATOMIC_RELAXED);

	/* AO key on the client: peer = second listener, sndid=RECONNECT_SNDID.
	 * set_current=0: the peer-1 current_key stays dangling until we
	 * explicitly probe it after the reconnect. */
	fill_ao_add(&ao_add, &ctx->srv2_addr,
		    RECONNECT_SNDID, RECONNECT_SNDID, false, ctx->alg);
	ctx->direct_calls++;
	rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
			&ao_add, sizeof(ao_add));
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
			   1, __ATOMIC_RELAXED);

	/* Disconnect from peer 1: the kernel frees peer-1's AO key list but
	 * current_key still points into it — the dangling-reference window
	 * opens here. */
	memset(&discon, 0, sizeof(discon));
	discon.sa_family = AF_UNSPEC;
	ctx->direct_calls++;
	(void)connect(ctx->cli, &discon, sizeof(discon));

	/* Reconnect to peer 2: this is the peer-change path in
	 * tcp_ao_connect_init that the kernel fix targets. */
	ctx->direct_calls++;
	rc = connect(ctx->cli, (struct sockaddr *)&ctx->srv2_addr,
		     sizeof(ctx->srv2_addr));
	if (rc < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	/* Client connect() returned 0 or EINPROGRESS — peer-change sequence
	 * is underway from the client's perspective regardless of whether
	 * the server-side accept() completes.  Key reconnect_ok on this
	 * client-side outcome so the accounting partition holds:
	 *   reconnect_attempted == reconnect_ok + reconnect_failed
	 *                          + reconnect_setup_failed */
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_ok,
			   1, __ATOMIC_RELAXED);

	/*
	 * Both probes operate on ctx->cli and are independent of whether
	 * the server-side accept has completed.  The UAF window is opened
	 * by the connect(AF_UNSPEC) -> connect(srv2_addr) pair above, so
	 * fire the probes now before accept() can gate them.
	 */
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_probed,
			   1, __ATOMIC_RELAXED);

	/* Probe the stale current_key via TCP_AO_INFO — primary UAF vector.
	 * stale_id is the peer-1 sndid that current_key may still reference
	 * after the peer-change freed it. */
	memset(&ao_info, 0, sizeof(ao_info));
	ao_info.set_current = 1;
	ao_info.current_key = stale_id;
	ctx->direct_calls++;
	rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_INFO,
			&ao_info, sizeof(ao_info));
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.stale_key_probed,
			   1, __ATOMIC_RELAXED);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_rotations,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.info_rejected,
				   1, __ATOMIC_RELAXED);

	/* TCP_AO_DEL_KEY against the stale peer-1 sndid — second UAF probe. */
	fill_ao_del(&ao_del, &ctx->srv_addr, stale_id, stale_id);
	ctx->direct_calls++;
	rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_DEL_KEY,
			&ao_del, sizeof(ao_del));
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_dels,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.delkey_rejected,
				   1, __ATOMIC_RELAXED);

	ctx->direct_calls++;
	ctx->srv2_acc = accept(ctx->srv2_listener, NULL, NULL);
	if (ctx->srv2_acc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.reconnect_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	ctx->direct_calls++;
	(void)fcntl(ctx->srv2_acc, F_SETFL, O_NONBLOCK);

	rotate_send(ctx->cli, &ctx->direct_calls);
	rotate_send(ctx->srv2_acc, &ctx->direct_calls);

	ctx->direct_calls++;
	(void)shutdown(ctx->srv2_acc, SHUT_RDWR);
}

/*
 * Phase 6: close whichever fds we managed to open.  Runs on every
 * exit path — both the success path falling through to out: after
 * the reconnect arm returns, and the early-bail goto out from any
 * earlier phase failure.  Shutdown is attempted before each close so
 * the peer sees an orderly FIN rather than a silent close.  Fields
 * default to -1 via the orchestrator's designated initialiser so the
 * guards skip fds that were never opened.
 */
static void tcp_ao_rotate_iter_teardown(struct tcp_ao_rotate_iter_ctx *ctx)
{
	if (ctx->srv2_acc >= 0) {
		ctx->direct_calls++;
		close(ctx->srv2_acc);
	}
	if (ctx->srv2_listener >= 0) {
		ctx->direct_calls++;
		close(ctx->srv2_listener);
	}
	if (ctx->srv_acc >= 0) {
		ctx->direct_calls++;
		(void)shutdown(ctx->srv_acc, SHUT_RDWR);
		ctx->direct_calls++;
		close(ctx->srv_acc);
	}
	if (ctx->cli >= 0) {
		ctx->direct_calls++;
		(void)shutdown(ctx->cli, SHUT_RDWR);
		ctx->direct_calls++;
		close(ctx->cli);
	}
	if (ctx->listener >= 0) {
		ctx->direct_calls++;
		close(ctx->listener);
	}
}

/*
 * VRF-enslave / detach arm
 * ========================
 * Exercises the L3-master membership path in tcp_ao_connect_init().
 *
 * The loopback sequence above always takes the default-domain path in
 * tcp_ao_connect_init() because no bound device is set.  This arm
 * creates a private VRF master and a veth pair inside the netns, enslaves
 * one veth end to the VRF, installs TCP-AO keys against the peer address,
 * then races connect() against a concurrent RTM_SETLINK IFLA_MASTER=0
 * on the enslaved device.  The race opens the window described in
 * tcp_ao_connect_init(): the L3 master is resolved twice without the
 * socket lock stabilising VRF membership, so the AO key list can be
 * freed while the receive path holds a pointer under RCU.
 *
 * Primitives lifted from childops/net/vrf-fib-churn.c (VRF NEWLINK
 * builder + IFLA_VRF_TABLE attribute) and childops/net/bridge-fdb-stp-
 * setup.c (veth-pair NEWLINK builder and IFLA_MASTER set/clear helpers).
 * Kept local so the .c file remains self-contained.
 *
 * Self-bounding: userns_run_in_ns() forks a transient grandchild that
 * _exit()s after one iteration; the netns and every interface/socket it
 * contains are reaped by the kernel on grandchild exit.  The racing
 * detach child is an additional fork inside the grandchild; both
 * descend from the grandchild, not the persistent trinity child.
 */

/* VRF arm address constants.  Both are in the 10.57.0.0/30 subnet;
 * the choice is arbitrary — a fresh private netns has no host routes,
 * so any non-overlapping pair works.  /30 gives exactly two host
 * addresses (no broadcast collision with .0 and .3). */
#define VRF_ARM_ADDR_A	0x0a390001u	/* 10.57.0.1 — enslaved veth end */
#define VRF_ARM_ADDR_B	0x0a390002u	/* 10.57.0.2 — free veth end / listener */
#define VRF_ARM_PREFIXLEN	30
#define VRF_ARM_TABLE		77u	/* arbitrary; private netns */

#define VRF_ARM_BUF		2048

/*
 * RTM_NEWLINK kind="vrf" with IFLA_VRF_TABLE.  Lifted from
 * childops/net/vrf-fib-churn.c:build_vrf_link().
 */
static int vrf_arm_build_vrf_link(struct nl_ctx *ctx, const char *name,
				  __u32 table)
{
	unsigned char buf[VRF_ARM_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "vrf");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_VRF_TABLE, table);
	if (!off)
		return -EIO;
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK kind="veth" with VETH_INFO_PEER.  Lifted from
 * childops/net/bridge-fdb-stp-setup.c:bfs_build_veth_create().
 */
static int vrf_arm_build_veth_pair(struct nl_ctx *ctx, const char *name,
				   const char *peer_name)
{
	unsigned char buf[VRF_ARM_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer_name);
	if (!off)
		return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK IFLA_MASTER=master_ifindex — enslave ifindex to master.
 * Lifted from childops/net/bridge-fdb-stp-setup.c:bfs_build_setlink_master().
 */
static int vrf_arm_build_enslave(struct nl_ctx *ctx, int ifindex,
				 int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR adding an IPv4 /30 address to ifindex.
 * Lifted from childops/net/vrf-fib-churn.c:build_addaddr() and
 * narrowed to a fixed-prefix /30 for the veth address pair.
 */
static int vrf_arm_build_addaddr(struct nl_ctx *ctx, int ifindex, __u32 addr_hbo)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr = htonl(addr_hbo);
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = VRF_ARM_PREFIXLEN;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK setlink IFF_UP — bring ifindex up.
 * Lifted from childops/net/vrf-fib-churn.c:build_setlink_up().
 */
static int vrf_arm_build_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}


struct vrf_arm_ctx {
	struct childdata *child;
};

/*
 * In-ns body: runs inside a private user+net namespace forked by
 * userns_run_in_ns().  The grandchild's netns is torn down on _exit()
 * so every interface, address and socket is reaped by the kernel.
 *
 * Race shape:
 *   parent (grandchild): connect(cli, srv_addr) — fires tcp_ao_connect_init()
 *                        with an SO_BINDTODEVICE socket on a VRF-enslaved veth.
 *   child  (gg-child)  : RTM_SETLINK IFLA_MASTER=0 on the enslaved veth —
 *                        changes the answer l3mdev_master_ifindex_by_index()
 *                        returns between tcp_ao_connect_init()'s two lookups.
 *
 * A detach that completes before connect() enters the kernel is still
 * exercised coverage: it drives the "no l3mdev master" branch of
 * tcp_ao_connect_init(), which previously required hand-crafted
 * reproducer setups to reach.
 */
static int tcp_ao_vrf_arm_in_ns(void *arg)
{
	struct vrf_arm_ctx *actx = (struct vrf_arm_ctx *)arg;
	struct childdata *child = actx->child;
	char vrf_name[IFNAMSIZ], veth_a[IFNAMSIZ], veth_b[IFNAMSIZ];
	struct nl_ctx nlctx = NL_CTX_INIT;
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = NR_CHILD_OP_TYPES, /* netlink calls not tallied separately */
	};
	int listener = -1, cli = -1, srv_acc = -1;
	int vrf_idx = 0, va_idx = 0, vb_idx = 0;
	struct sockaddr_in srv_addr, cli_addr;
	struct tcp_ao_add ao_add;
	socklen_t slen;
	pid_t pid;
	int rc;
	int race_pfd[2];
	int rendezvous_pfd[2];
	int ready_pfd[2];
	unsigned long direct_calls = 0;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	unsigned int rng = rand32() & 0xffffu;
	snprintf(vrf_name, sizeof(vrf_name), "trvf%04x", rng);
	snprintf(veth_a,  sizeof(veth_a),   "trva%04x", rng);
	snprintf(veth_b,  sizeof(veth_b),   "trvb%04x", rng);

	if (nl_open(&nlctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_enslave_setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	/* Step 1: VRF master device. */
	if (vrf_arm_build_vrf_link(&nlctx, vrf_name, VRF_ARM_TABLE) != 0)
		goto setup_fail;
	vrf_idx = (int)if_nametoindex(vrf_name);
	if (vrf_idx == 0)
		goto setup_fail;

	/* Step 2: veth pair. */
	if (vrf_arm_build_veth_pair(&nlctx, veth_a, veth_b) != 0)
		goto setup_fail;
	va_idx = (int)if_nametoindex(veth_a);
	vb_idx = (int)if_nametoindex(veth_b);
	if (va_idx == 0 || vb_idx == 0)
		goto setup_fail;

	/* Step 3: enslave veth_a to the VRF. */
	if (vrf_arm_build_enslave(&nlctx, va_idx, vrf_idx) != 0)
		goto setup_fail;

	/* Step 4: assign addresses and bring interfaces up. */
	(void)vrf_arm_build_addaddr(&nlctx, va_idx, VRF_ARM_ADDR_A);
	(void)vrf_arm_build_addaddr(&nlctx, vb_idx, VRF_ARM_ADDR_B);
	(void)vrf_arm_build_setlink_up(&nlctx, vrf_idx);
	(void)vrf_arm_build_setlink_up(&nlctx, va_idx);
	(void)vrf_arm_build_setlink_up(&nlctx, vb_idx);

	/* Step 5: listener on veth_b's address. */
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family      = AF_INET;
	srv_addr.sin_addr.s_addr = htonl(VRF_ARM_ADDR_B);
	srv_addr.sin_port        = 0;

	direct_calls++;
	/*
	 * SOCK_NONBLOCK is mandatory here: this function runs inside a
	 * grandchild forked by userns_run_in_ns(CLONE_NEWNET, ...).  POSIX
	 * resets pending alarms across fork(), so the parent's alarm(1)
	 * cap (set by child.c) does not protect this context.  The socket
	 * itself must provide the safety bound.  The poll() before accept()
	 * below enforces the 1-second limit matching the loopback arm's
	 * documented invariant.  TODO: add SIGALRM inside userns_run_in_ns
	 * so all callers are covered at the fork boundary.
	 */
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (listener < 0)
		goto setup_fail;
	{
		int one = 1;
		direct_calls++;
		(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
				 &one, sizeof(one));
	}
	direct_calls++;
	if (bind(listener, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		goto setup_fail;
	direct_calls++;
	if (listen(listener, 1) < 0)
		goto setup_fail;
	slen = sizeof(srv_addr);
	direct_calls++;
	if (getsockname(listener, (struct sockaddr *)&srv_addr, &slen) < 0)
		goto setup_fail;

	/* Step 6: client socket bound to veth_a (the VRF-enslaved side). */
	direct_calls++;
	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (cli < 0)
		goto setup_fail;

	/*
	 * SO_BINDTODEVICE makes the kernel resolve the L3 master from
	 * veth_a's ifindex on every connect() — that is the index path
	 * inside tcp_ao_connect_init() that the race targets.
	 */
	direct_calls++;
	(void)setsockopt(cli, SOL_SOCKET, SO_BINDTODEVICE,
			 veth_a, (socklen_t)strlen(veth_a));

	/* Explicit bind so the source address is deterministic and the
	 * listener's AO key prefix=32 match resolves cleanly. */
	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family      = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(VRF_ARM_ADDR_A);
	cli_addr.sin_port        = 0;
	direct_calls++;
	if (bind(cli, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0)
		goto setup_fail;
	slen = sizeof(cli_addr);
	direct_calls++;
	if (getsockname(cli, (struct sockaddr *)&cli_addr, &slen) < 0)
		goto setup_fail;

	/* Step 7: TCP-AO key on the listener (peer = veth_a's address). */
	fill_ao_add(&ao_add, &cli_addr, 1, 1, true, "hmac(sha1)");
	direct_calls++;
	if (setsockopt(listener, IPPROTO_TCP, TCP_AO_ADD_KEY,
		       &ao_add, sizeof(ao_add)) < 0) {
		/* TCP-AO not available on this host; separate from setup errors. */
		goto ao_unavailable;
	}

	/* TCP-AO key on the client (peer = veth_b's address). */
	fill_ao_add(&ao_add, &srv_addr, 1, 1, true, "hmac(sha1)");
	direct_calls++;
	if (setsockopt(cli, IPPROTO_TCP, TCP_AO_ADD_KEY,
		       &ao_add, sizeof(ao_add)) < 0)
		goto setup_fail;

	/* Step 8: O_NONBLOCK so connect() returns EINPROGRESS and the
	 * racing detach has a wider window to race against. */
	direct_calls++;
	(void)fcntl(cli, F_SETFL, O_NONBLOCK);

	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_enslave_attempted,
			   1, __ATOMIC_RELAXED);

	/*
	 * Step 9: fork the racing detacher.  The child sends
	 * RTM_SETLINK IFLA_MASTER=0 on va_idx — the same operation that
	 * the reporter's reproducer uses to open the UAF window in
	 * tcp_ao_connect_init().
	 *
	 * Rendezvous protocol (two-way, introduced after
	 * c3593fa388fa ("child: tcp-ao: add rendezvous pipe to VRF race
	 * childop")):
	 *   ready_pfd  (child→parent): child writes one byte after its
	 *              netlink message is pre-built; parent blocks on this
	 *              read before coin-flipping.  Guarantees the child is
	 *              truly poised when the token fires — not a scheduler
	 *              lottery.
	 *   rendezvous_pfd (parent→child): parent writes one byte either
	 *              before or after connect() (coin-flip), controlling
	 *              which side of the SYN the detach fires on.
	 *
	 * vrf_detach_raced bumps after a successful message build (child
	 * is poised at the rendezvous gate).  vrf_detach_landed gates on
	 * nl_send_recv() == 0 (kernel accepted MASTER=0).  The child passes
	 * its RTM_SETLINK timestamp back to the parent via race_pfd so the
	 * parent can record per-iteration ordering without shm aliasing.
	 */
	race_pfd[0] = race_pfd[1] = -1;
	rendezvous_pfd[0] = rendezvous_pfd[1] = -1;
	ready_pfd[0] = ready_pfd[1] = -1;
	if (pipe(race_pfd) != 0 || pipe(rendezvous_pfd) != 0 ||
	    pipe(ready_pfd) != 0) {
		__atomic_add_fetch(
			&shm->stats.tcp_ao_rotate.vrf_pipe_unavailable,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	direct_calls++; /* fork */
	pid = fork();
	if (pid == 0) {
		/*
		 * Detach child: open a fresh netlink socket, pre-build the
		 * RTM_SETLINK MASTER=0 message, then block on the rendezvous
		 * pipe until the parent sends a 1-byte token.  The parent
		 * controls the connect/detach interleaving: it writes the
		 * token either before or after connect() depending on a
		 * coin-flip, so both before_connect and after_connect
		 * orderings get sampled across iterations.
		 */
		struct nl_ctx race_nl = NL_CTX_INIT;
		struct nl_open_opts race_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = 1,
			.caller_op    = NR_CHILD_OP_TYPES,
		};
		close(race_pfd[0]);
		close(rendezvous_pfd[1]);
		close(ready_pfd[0]); /* child only writes to ready_pfd */
		if (nl_open(&race_nl, &race_opts) == 0) {
			unsigned char _dbuf[128];
			struct nlmsghdr *_dnlh;
			struct ifinfomsg *_difi;
			size_t _doff;
			struct timespec _dts;
			int _det_rc;

			/* Pre-build the RTM_SETLINK MASTER=0 message so the
			 * child holds everything it needs and only the send
			 * itself races against the parent's connect(). */
			memset(_dbuf, 0, sizeof(_dbuf));
			_dnlh = (struct nlmsghdr *)_dbuf;
			_dnlh->nlmsg_type  = RTM_SETLINK;
			_dnlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
			_dnlh->nlmsg_seq   = nl_seq_next(&race_nl);
			_difi = (struct ifinfomsg *)NLMSG_DATA(_dnlh);
			_difi->ifi_family  = AF_UNSPEC;
			_difi->ifi_index   = va_idx;
			_doff = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*_difi));
			_doff = nla_put_u32(_dbuf, _doff, sizeof(_dbuf),
					    IFLA_MASTER, 0);
			if (_doff != 0) {
				_dnlh->nlmsg_len = (__u32)_doff;

				/* Signal parent: message is built and child
				 * is poised at the rendezvous gate.  Parent
				 * blocks on ready_pfd[0] before coin-flipping
				 * so connect() vs detach ordering is truly
				 * controlled, not a scheduler lottery. */
				{ char _rdy = 1;
				  ssize_t _w = write(ready_pfd[1], &_rdy, 1);
				  (void)_w; }

				/* vrf_detach_raced: setup complete; poised
				 * to send RTM_SETLINK once token arrives. */
				__atomic_add_fetch(
					&shm->stats.tcp_ao_rotate.vrf_detach_raced,
					1, __ATOMIC_RELAXED);

				/* Block until parent sends the rendezvous
				 * token; this guarantees the parent controls
				 * which side of connect() the detach fires
				 * on rather than leaving it to scheduler
				 * whim. */
				{ char _tok;
				  ssize_t _r = read(rendezvous_pfd[0],
						    &_tok, 1);
				  (void)_r; }

				clock_gettime(CLOCK_MONOTONIC, &_dts);
				_det_rc = nl_send_recv(&race_nl, _dbuf, _doff);
				/* vrf_detach_landed: kernel accepted MASTER=0. */
				if (_det_rc == 0)
					__atomic_add_fetch(
						&shm->stats.tcp_ao_rotate.vrf_detach_landed,
						1, __ATOMIC_RELAXED);
				{ ssize_t _n = write(race_pfd[1], &_dts,
						     sizeof(_dts));
				  (void)_n; }
			}
			nl_close(&race_nl);
		}
		close(rendezvous_pfd[0]);
		close(race_pfd[1]);
		close(ready_pfd[1]);
		_exit(0);
	}
	close(race_pfd[1]);
	close(rendezvous_pfd[0]);
	close(ready_pfd[1]); /* parent only reads from ready_pfd */

	/* Wait for child to signal readiness: it has pre-built its netlink
	 * message and is blocked at the rendezvous gate.  Only after this
	 * read do we coin-flip, so the connect/detach interleaving is
	 * deterministic rather than scheduler-dependent. */
	{ char _rdy;
	  ssize_t _r = read(ready_pfd[0], &_rdy, 1);
	  (void)_r; }
	close(ready_pfd[0]);

	/*
	 * Parent: coin-flip the rendezvous token write around connect().
	 *
	 * coin==0: write token BEFORE connect() — child unblocks and races
	 *          to fire RTM_SETLINK ahead of the SYN; samples the
	 *          before_connect interleaving.
	 * coin==1: call connect() FIRST, then write token — child fires
	 *          RTM_SETLINK after the SYN is already in flight; samples
	 *          the after_connect interleaving.
	 *
	 * Capture a monotonic timestamp immediately before connect() in
	 * both branches and compare against the child's post-gate timestamp
	 * (received via race_pfd) to confirm the ordering and catch any
	 * timing inversions.
	 */
	{
		struct timespec cts;
		int coin = (int)(rand32() & 1);

		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_connect_issued,
				   1, __ATOMIC_RELAXED);

		if (coin == 0) {
			/* Token first: unblock child before issuing SYN. */
			{ char _tok = 1;
			  ssize_t _w = write(rendezvous_pfd[1], &_tok, 1);
			  (void)_w; }
			close(rendezvous_pfd[1]);
			clock_gettime(CLOCK_MONOTONIC, &cts);
			direct_calls++;
			rc = connect(cli, (struct sockaddr *)&srv_addr,
				     sizeof(srv_addr));
		} else {
			/* Connect first: issue SYN before unblocking child. */
			clock_gettime(CLOCK_MONOTONIC, &cts);
			direct_calls++;
			rc = connect(cli, (struct sockaddr *)&srv_addr,
				     sizeof(srv_addr));
			{ char _tok = 1;
			  ssize_t _w = write(rendezvous_pfd[1], &_tok, 1);
			  (void)_w; }
			close(rendezvous_pfd[1]);
		}

		if (rc == 0 || errno == EINPROGRESS) {
			struct pollfd pfd = { .fd = listener, .events = POLLIN };
			int pr;
			direct_calls++;
			/* Bounded wait: listener is SOCK_NONBLOCK so we must poll
			 * before accept(); 1000 ms matches the loopback arm's 1-second
			 * invariant and caps the grandchild even without an alarm(). */
			pr = poll(&pfd, 1, 1000);
			if (pr > 0 && (pfd.revents & POLLIN)) {
				direct_calls++;
				srv_acc = accept(listener, NULL, NULL);
			} else {
				__atomic_add_fetch(
					&shm->stats.tcp_ao_rotate.vrf_accept_timeout,
					1, __ATOMIC_RELAXED);
			}
		}

		/* Reap the detach child before closing the netns. */
		if (pid > 0) {
			int wstatus;
			direct_calls++; /* waitpid */
			(void)waitpid_eintr(pid, &wstatus, 0);
		}

		/*
		 * Read the child's RTM_SETLINK timestamp from race_pfd and
		 * record per-iteration ordering.  Three buckets:
		 *   d > 0: cts > dts — detach fired before connect()  → before_connect
		 *   d < 0: cts < dts — detach fired after connect()   → after_connect
		 *   d == 0: timestamps equal                          → tied
		 * dts=={0,0} means the child's netlink open or message build
		 * failed and no timestamp was written; count as an additional
		 * setup failure since the race window did not fire.
		 */
		{
			struct timespec dts = {0, 0};
			{ ssize_t _n = read(race_pfd[0], &dts, sizeof(dts));
			  (void)_n; }
			close(race_pfd[0]);
			if (dts.tv_sec || dts.tv_nsec) {
				long long d =
					((long long)cts.tv_sec  - (long long)dts.tv_sec)  * 1000000000LL
					+ ((long long)cts.tv_nsec - (long long)dts.tv_nsec);
				if (d > 0)
					__atomic_add_fetch(
						&shm->stats.tcp_ao_rotate.vrf_detach_before_connect,
						1, __ATOMIC_RELAXED);
				else if (d < 0)
					__atomic_add_fetch(
						&shm->stats.tcp_ao_rotate.vrf_detach_after_connect,
						1, __ATOMIC_RELAXED);
				else
					__atomic_add_fetch(
						&shm->stats.tcp_ao_rotate.vrf_detach_tied,
						1, __ATOMIC_RELAXED);
			} else {
				/* No timestamp: child's netlink setup failed
				 * before the gate; the race window never
				 * opened.  Count as an additional setup
				 * failure so the zero in before/after/tied
				 * is explainable from the stats output. */
				__atomic_add_fetch(
					&shm->stats.tcp_ao_rotate.vrf_enslave_setup_failed,
					1, __ATOMIC_RELAXED);
			}
		}
	}

	/* vrf_connect_ok: accept() succeeded — server saw the SYN through VRF. */
	if (srv_acc >= 0)
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_connect_ok,
				   1, __ATOMIC_RELAXED);
	goto out;

ao_unavailable:
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_ao_unavailable,
			   1, __ATOMIC_RELAXED);
	goto out;
setup_fail:
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_enslave_setup_failed,
			   1, __ATOMIC_RELAXED);
out:
	if (srv_acc >= 0) {
		direct_calls++;
		(void)shutdown(srv_acc, SHUT_RDWR);
		direct_calls++;
		close(srv_acc);
	}
	if (cli >= 0) {
		direct_calls++;
		(void)shutdown(cli, SHUT_RDWR);
		direct_calls++;
		close(cli);
	}
	if (listener >= 0) {
		direct_calls++;
		close(listener);
	}
	nl_close(&nlctx);
	if (valid_op && direct_calls > 0)
		childop_direct_syscalls_add(op, direct_calls);
	return 0;
}

/*
 * Outer entrypoint for the VRF-enslave/detach arm.  Runs the in-ns body
 * inside a transient grandchild with a fresh user+net namespace so link
 * creation does not touch the host routing table and the kernel reaps
 * every interface with the grandchild's netns on exit.
 *
 * ns_unsupported is shared with the loopback arm: if ENOPROTOOPT or
 * EPERM latched the flag on TCP_AO_ADD_KEY, skip immediately — the VRF
 * arm's same setsockopt will fail identically.
 */
static void tcp_ao_rotate_vrf_arm(struct childdata *child)
{
	struct vrf_arm_ctx actx = { .child = child };
	int rc;

	rc = userns_run_in_ns(CLONE_NEWNET, tcp_ao_vrf_arm_in_ns, &actx);
	if (rc == -EPERM) {
		/* Policy refuses CLONE_NEWUSER; the loopback arm would
		 * already have latched ns_unsupported for a different
		 * reason, but match the shape: bump setup_failed so the
		 * stats surface explains the zero vrf_enslave_attempted. */
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.vrf_enslave_setup_failed,
				   1, __ATOMIC_RELAXED);
	}
	/* rc == -EAGAIN: transient fork / id-map failure; skip silently. */
}

bool tcp_ao_rotate(struct childdata *child)
{
	struct tcp_ao_rotate_iter_ctx ctx = {
		.listener      = -1,
		.cli           = -1,
		.srv_acc       = -1,
		.srv2_listener = -1,
		.srv2_acc      = -1,
		.child         = child,
		.direct_calls  = 0,
	};

	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (tcp_ao_rotate_iter_setup_sockets(&ctx) != 0)
		goto out;

	if (tcp_ao_rotate_iter_install_keys(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (tcp_ao_rotate_iter_connect(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	{
		uint8_t stale_id = tcp_ao_rotate_iter_rotate_loop(&ctx);
		tcp_ao_rotate_iter_reconnect_peer(&ctx, stale_id);
	}
	/* VRF-enslave/detach arm: runs in its own netns via
	 * userns_run_in_ns() so it does not interfere with the
	 * loopback iteration above.  Skipped if TCP-AO is absent. */
	if (!ns_unsupported)
		tcp_ao_rotate_vrf_arm(child);

out:
	tcp_ao_rotate_iter_teardown(&ctx);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.cycles, 1, __ATOMIC_RELAXED);
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_calls);
	return true;
}
