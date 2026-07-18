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
#include <unistd.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
/* TCP_AO_* constant fallbacks already live in include/kernel/socket.h.  The
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
	struct childdata *child;
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

	if (open_loopback_listener(&ctx->listener, &ctx->srv_addr) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

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
	if (bind(ctx->cli, (struct sockaddr *)&ctx->cli_addr,
		 sizeof(ctx->cli_addr)) < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	slen = sizeof(ctx->cli_addr);
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
	(void)fcntl(ctx->cli, F_SETFL, O_NONBLOCK);
	if (connect(ctx->cli, (struct sockaddr *)&ctx->srv_addr,
		    sizeof(ctx->srv_addr)) < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connect_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	ctx->srv_acc = accept(ctx->listener, NULL, NULL);
	if (ctx->srv_acc < 0) {
		__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connect_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	(void)fcntl(ctx->srv_acc, F_SETFL, O_NONBLOCK);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.connected,
			   1, __ATOMIC_RELAXED);

	rotate_send(ctx->cli);
	rotate_send(ctx->srv_acc);
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
 * the freed key node.  The trailing shutdown(SHUT_RDWR) on both fds
 * lives here so the orchestrator just owns control flow; on any
 * earlier-phase bail the teardown helper still closes the fds.
 */
static void tcp_ao_rotate_iter_rotate_loop(struct tcp_ao_rotate_iter_ctx *ctx)
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
		fill_ao_add(&ao_add, &ctx->cli_addr, next_id, next_id, false, ctx->alg);
		rc = setsockopt(ctx->srv_acc, IPPROTO_TCP, TCP_AO_ADD_KEY,
				&ao_add, sizeof(ao_add));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.keys_added,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.addkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_add(&ao_add, &ctx->srv_addr, next_id, next_id, false, ctx->alg);
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
		rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_INFO,
				&ao_info, sizeof(ao_info));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_rotations,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.info_rejected,
					   1, __ATOMIC_RELAXED);
		(void)setsockopt(ctx->srv_acc, IPPROTO_TCP, TCP_AO_INFO,
				 &ao_info, sizeof(ao_info));

		/* c) Send through the rotated key.  This is the "verify
		 *    against the new key on the peer" edge.  Drive both
		 *    directions so retransmit / dup-ack races land on
		 *    both endpoints' AO state machines. */
		rotate_send(ctx->cli);
		rotate_send(ctx->srv_acc);

		/* d) DEL_KEY old cur_id — race against in-flight retx
		 *    that's still using sndid=cur_id on the wire.  This
		 *    is the rcu-walk-vs-free race window. */
		fill_ao_del(&ao_del, &ctx->srv_addr, cur_id, cur_id);
		rc = setsockopt(ctx->cli, IPPROTO_TCP, TCP_AO_DEL_KEY,
				&ao_del, sizeof(ao_del));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.key_dels,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_ao_rotate.delkey_rejected,
					   1, __ATOMIC_RELAXED);

		fill_ao_del(&ao_del, &ctx->cli_addr, cur_id, cur_id);
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

	(void)shutdown(ctx->cli, SHUT_RDWR);
	(void)shutdown(ctx->srv_acc, SHUT_RDWR);
}

/*
 * Phase 5: close whichever fds we managed to open.  Runs on every
 * exit path — both the success path falling through to out: after
 * rotate_loop returns, and the early-bail goto out from any earlier
 * phase failure.  Order matches the original out: cleanup: accepted
 * server fd first, then client, then listener.  Fields default to -1
 * via the orchestrator's designated initialiser so the guards skip
 * fds that were never opened.
 */
static void tcp_ao_rotate_iter_teardown(struct tcp_ao_rotate_iter_ctx *ctx)
{
	if (ctx->srv_acc >= 0)
		close(ctx->srv_acc);
	if (ctx->cli >= 0)
		close(ctx->cli);
	if (ctx->listener >= 0)
		close(ctx->listener);
}

bool tcp_ao_rotate(struct childdata *child)
{
	struct tcp_ao_rotate_iter_ctx ctx = {
		.listener = -1,
		.cli      = -1,
		.srv_acc  = -1,
		.child    = child,
	};

	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (tcp_ao_rotate_iter_setup_sockets(&ctx) != 0)
		goto out;

	if (tcp_ao_rotate_iter_install_keys(&ctx) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (tcp_ao_rotate_iter_connect(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	tcp_ao_rotate_iter_rotate_loop(&ctx);

out:
	tcp_ao_rotate_iter_teardown(&ctx);
	__atomic_add_fetch(&shm->stats.tcp_ao_rotate.cycles, 1, __ATOMIC_RELAXED);
	return true;
}
