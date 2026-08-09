/*
 * esp_crafted_rx - inject crafted IPv4(ESP) / IPv6(ESP) packets with
 * truncated inner payloads onto the loopback RX path inside a private
 * netns.  Targets the post-decapsulation inner-header parse path: the
 * decapsulated inner header is walked on the RX done path without a
 * fresh length check, so a truncated inner payload can drive an over-
 * read.  Fills the coverage gap left by xfrm-churn (which exercises
 * SA/SP lifecycle + encrypt) and ip_gre / sctp-chunk-rx (which cover
 * their own decap paths).
 *
 * Bug class of interest: post-ESP-decrypt inner-header pull.  The
 * kernel strips the outer IP + ESP header, decrypts the payload, then
 * walks the inner header (TCP/UDP/ICMP/...) trusting the decrypted
 * length past its own bounds when the ciphertext was shorter than the
 * declared inner header claims.  KASAN-visible when the inner payload
 * lands adjacent to the end of the linear alloc.  This op does not try
 * to repro a fixed bug -- HMAC / decrypt will reject most forged
 * frames long before the inner-parse seam trips -- but the SPI lookup
 * plus the small set of null-cipher/null-auth SAs that DO accept
 * arbitrary content still land steadily on the parser, and any
 * KASAN-visible bug of that class surfaces here.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child
 * runs a one-shot best-effort modprobe of esp4 / esp6 before the
 * userns hop (finit_module needs CAP_SYS_MODULE in init_user_ns).  In
 * the grandchild:
 *   1. Bring lo up (127.0.0.1 and ::1 are valid outer endpoints).
 *   2. Open NETLINK_XFRM and install one inbound ESP SA -- cipher_null
 *      + digest_null so any ciphertext survives verify + decrypt and
 *      reaches the inner-parse seam.  SPI + reqid + family are rolled
 *      per invocation.  Family v4 / v6 flipped roughly 50/50.
 *      Failing NEWSA with EOPNOTSUPP / EPROTONOSUPPORT /
 *      EAFNOSUPPORT / ENOPROTOOPT / ENOENT latches the whole op off
 *      via shm (transient grandchild would otherwise re-attempt every
 *      invocation).
 *   3. Open SOCK_RAW with IPPROTO_RAW (v4) or SOCK_RAW /
 *      IPPROTO_RAW with IPV6_HDRINCL (v6) so we can hand-roll the
 *      outer IP + ESP header + inner payload ourselves.
 *   4. BUDGETED+JITTER burst (base 5) of hand-rolled frames.  Roughly
 *      one-in-three iterations instead emits a two-fragment large-inner
 *      ESP datagram so IP defrag reassembles into a non-linear skb --
 *      ESP decrypt then walks it via skb_cow_data() into a
 *      scatter-gather crypto request, and the SG teardown runs
 *      esp_ssg_unref() over managed frag pages.  Same SA / SPI mix, so
 *      the fragmented path shares SPI-lookup and replay-window
 *      coverage with the linear path.  On v6 invocations, roughly
 *      one-in-six iterations instead emits a max-depth stacked-ESP
 *      IPv6 frame -- six nested cipher_null/digest_null transport-mode
 *      SAs whose sequential decap drives sp->len up to XFRM_MAX_DEPTH,
 *      with an inner destination-options HAO or type-2 routing header
 *      as the innermost payload so mip6's handlers call xfrm6_input_addr()
 *      at the depth boundary.  Non-fragmented, non-stacked frames still
 *      dominate the burst and each such frame picks:
 *        - SPI: matches the installed SA most of the time, occasional
 *          random miss to exercise the SPI-lookup miss path,
 *        - sequence number: rotates {0, 1, rand16, rand32} to walk the
 *          replay-window edges,
 *        - inner protocol: TCP / UDP / ICMP / random -- picks the
 *          post-decap parser entry,
 *        - inner truncation: {0, 1, 4, 8, 16} bytes emitted, so most
 *          frames declare an inner header that runs past the actual
 *          payload end,
 *        - ESP trailer (pad_len + next_header) is stamped after the
 *          inner so the length arithmetic on the RX done path has
 *          something plausible to walk.
 *   5. sendto MSG_DONTWAIT so a queue-backed loopback cannot pin us
 *      past the inherited SIGALRM(1s) safety net.
 *
 * Brick-safety: loopback only inside the private netns (outer daddr
 * is 127.0.0.1 or ::1 inside the grandchild's own netns), one SA
 * install / DELSA per invocation, all sends MSG_DONTWAIT, no
 * persistent state.  Netns destruction on grandchild exit catches any
 * SA / socket left behind by a mid-iteration bail.
 *
 * Latches: ns_unsupported_esp_crafted_rx master gate on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled).
 * shm->esp_crafted_rx_kind_unsupported on NETLINK_XFRM open or NEWSA
 * failing with the CONFIG_INET_ESP / CONFIG_INET6_ESP absent errno
 * set.  Per-kind latch lives in shm because the rejection is observed
 * inside the grandchild -- a process-local static would die on _exit
 * and re-attempt the missing kind forever.
 *
 * Not attempted here: reproducing a specific fixed inner-pull bug.
 * cipher_null + digest_null is enough to reach the inner-parse seam
 * generically; a targeted repro on top of this op would fix the
 * inner-proto and truncation distribution rather than churn them.
 */

#include <errno.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's SAD, so the op stays disabled for the
 * remainder of this child's lifetime.
 */
static bool ns_unsupported_esp_crafted_rx;

/* Per-grandchild lo-up latch lives in shm
 * (shm->esp_crafted_rx_lo_brought_up).  The write site sits inside
 * the userns_run_in_ns() grandchild's esp_crafted_rx_in_ns() path,
 * so a process-local static would die with the grandchild on _exit()
 * and every subsequent invocation would re-open a NETLINK_ROUTE
 * socket and re-pay the rtnetlink "lo up" round-trip forever -- the
 * parent never observes the latch.  Living in shm lets one
 * successful lo-up persist fleet-wide.  RELAXED atomic load/store is
 * safe: only false -> true, idempotent write. */
static bool lo_brought_up(void)
{
	return __atomic_load_n(&shm->esp_crafted_rx_lo_brought_up,
			       __ATOMIC_RELAXED);
}

static void mark_lo_brought_up(void)
{
	__atomic_store_n(&shm->esp_crafted_rx_lo_brought_up, true,
			 __ATOMIC_RELAXED);
}

/* Set once per persistent child after the modprobe attempts run.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->esp_crafted_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->esp_crafted_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * Bring lo up (per-grandchild one-time) and open NETLINK_XFRM.
 * Returns 0 on success, -1 on failure.  On NETLINK_XFRM open failure
 * with the CONFIG_XFRM absent errno set, latches the kind off so
 * subsequent invocations short-circuit.
 */
static int esp_crafted_rx_iter_open_ctx(struct esp_crafted_rx_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_XFRM,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_ESP_CRAFTED_RX,
	};
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (!lo_brought_up()) {
		struct nl_ctx rtnl = { .fd = -1 };
		struct nl_open_opts rtnl_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = 1,
			.caller_op    = CHILD_OP_ESP_CRAFTED_RX,
		};

		if (nl_open(&rtnl, &rtnl_opts) == 0) {
			rtnl_bring_lo_up(&rtnl);
			nl_close(&rtnl);
		}
		mark_lo_brought_up();
	}

	if (nl_open(&ctx->nl, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			mark_kind_unsupported();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	return 0;
}

/*
 * Install the inbound ESP SA for this invocation.  Rolls spi + reqid
 * + v6 fresh each call so the SPI-lookup + hash-insert path is
 * exercised across a range of keys.  Latches the kind off on
 * CONFIG_INET_ESP / CONFIG_INET6_ESP absent (EOPNOTSUPP /
 * EPROTONOSUPPORT / EAFNOSUPPORT / ENOPROTOOPT / ENOENT).
 */
static int esp_crafted_rx_iter_install_sa(struct esp_crafted_rx_iter_ctx *ctx)
{
	int rc;
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->spi   = htonl((rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN);
	ctx->reqid = (rand32() & 0xfU) + 1U;
	ctx->v6    = ONE_IN(2);

	rc = install_null_esp_sa(&ctx->nl, ctx->spi, ctx->reqid, ctx->v6);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.sa_install_failed,
				   1, __ATOMIC_RELAXED);
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT || rc == -ENOPROTOOPT ||
		    rc == -ENOENT) {
			mark_kind_unsupported();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->sa_added = true;
	__atomic_add_fetch(&shm->stats.esp_crafted_rx.sa_install_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Open the raw socket for the SA's family.  IPPROTO_RAW implies
 * IP_HDRINCL for v4; for v6 we set IPV6_HDRINCL explicitly.  Failure
 * to open leaves ctx->raw_* at -1 and the burst phase becomes a no-op
 * for that family; the SA install already ran so the SPI-lookup +
 * insert path was still exercised for the invocation.
 */
static void esp_crafted_rx_iter_open_raw(struct esp_crafted_rx_iter_ctx *ctx)
{
	int one = 1;

	if (ctx->v6) {
		ctx->raw_v6 = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC,
				     IPPROTO_RAW);
		ctx->direct_calls++;
		if (ctx->raw_v6 >= 0) {
			(void)setsockopt(ctx->raw_v6, IPPROTO_IPV6,
					 IPV6_HDRINCL, &one, sizeof(one));
			ctx->direct_calls++;
		}
	} else {
		ctx->raw_v4 = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC,
				     IPPROTO_RAW);
		ctx->direct_calls++;
	}
}

/*
 * BUDGETED+JITTER burst of hand-rolled ESP frames at 127.0.0.2 (v4)
 * or ::1 (v6).  Each iteration rerolls seq, inner proto, and inner
 * truncation; SPI is the installed SA's SPI ~7/8 of the time and a
 * random miss the remainder so the SPI-lookup miss path is exercised
 * too.  Roughly 1-in-3 iterations emit a two-fragment large-inner
 * datagram instead, driving IP defrag reassembly into a non-linear skb
 * so ESP decrypt exercises the scatter-gather teardown (esp_ssg_unref)
 * over managed frag pages.  On v6 with stacked SAs successfully
 * installed, roughly 1-in-6 iterations instead emits a max-depth
 * stacked-ESP frame driving xfrm6_input_addr() at the XFRM_MAX_DEPTH
 * secpath boundary.  MSG_DONTWAIT so a backed-up loopback queue
 * cannot stall the iteration past the SIGALRM(1s) cap.
 */
static void esp_crafted_rx_iter_send_burst(struct esp_crafted_rx_iter_ctx *ctx)
{
	unsigned int iters;
	unsigned int i;
	int fd = ctx->v6 ? ctx->raw_v6 : ctx->raw_v4;

	if (fd < 0)
		return;

	iters = BUDGETED(CHILD_OP_ESP_CRAFTED_RX,
			 JITTER_RANGE(ESPRX_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[ESPRX_PKT_MAX];
		size_t len;
		ssize_t n;
		__be32 spi;
		__u32 seq;
		uint8_t inner_proto;
		uint8_t trunc_len;

		if (ctx->v6 && ctx->stack_depth > 0 && ONE_IN(6)) {
			esp_crafted_rx_send_stacked_v6(ctx, fd);
			continue;
		}

		if (ONE_IN(3)) {
			esp_crafted_rx_send_frag_pair(ctx, fd);
			continue;
		}

		spi = ONE_IN(8)
			? htonl((rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN)
			: ctx->spi;
		seq         = esprx_pick_esp_seq();
		inner_proto = esprx_pick_inner_proto();
		trunc_len   = esprx_pick_inner_trunc_len();

		if (ctx->v6) {
			struct sockaddr_in6 dst;

			memset(&dst, 0, sizeof(dst));
			dst.sin6_family = AF_INET6;
			dst.sin6_addr.s6_addr[15] = 1;	/* ::1 */
			len = esprx_build_v6_frame(pkt, spi, seq, inner_proto,
					     trunc_len);
			n = sendto(fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			ctx->direct_calls++;
		} else {
			struct sockaddr_in dst;

			memset(&dst, 0, sizeof(dst));
			dst.sin_family      = AF_INET;
			dst.sin_addr.s_addr = ESPRX_V4_DADDR_BE;
			len = esprx_build_v4_frame(pkt, spi, seq, inner_proto,
					     trunc_len);
			n = sendto(fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			ctx->direct_calls++;
		}
		if (n > 0)
			__atomic_add_fetch(&shm->stats.esp_crafted_rx.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown: DELSA the installed SA (best-effort; netns teardown
 * covers a mid-flow bail) and close the raw fds and netlink socket.
 * Guards ensure the helper is safe to call from any bail point,
 * including one where the SA was never installed.
 */
static void esp_crafted_rx_iter_teardown(struct esp_crafted_rx_iter_ctx *ctx)
{
	unsigned int i;

	if (ctx->raw_v4 >= 0)
		close(ctx->raw_v4);
	if (ctx->raw_v6 >= 0)
		close(ctx->raw_v6);
	if (ctx->sa_added) {
		if (delete_esp_sa(&ctx->nl, ctx->spi, ctx->v6) == 0)
			__atomic_add_fetch(&shm->stats.esp_crafted_rx.sa_delete_ok,
					   1, __ATOMIC_RELAXED);
	}
	for (i = 0; i < ctx->stack_depth; i++) {
		if (delete_esp_sa(&ctx->nl, ctx->stack_spi[i], true) == 0)
			__atomic_add_fetch(&shm->stats.esp_crafted_rx.sa_delete_ok,
					   1, __ATOMIC_RELAXED);
	}
	nl_close(&ctx->nl);
}

struct esp_crafted_rx_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any SA,
 * raw socket and packet buffers left behind are reaped along with
 * the namespace.  Return value is ignored by the helper.
 */
static int esp_crafted_rx_in_ns(void *arg)
{
	struct esp_crafted_rx_ctx *cctx = (struct esp_crafted_rx_ctx *)arg;
	struct childdata *child = cctx->child;
	struct esp_crafted_rx_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw_v4 = -1,
		.raw_v6 = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (esp_crafted_rx_iter_open_ctx(&ctx) != 0)
		return 0;

	if (esp_crafted_rx_iter_install_sa(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	install_stacked_null_esp_sas(&ctx);

	esp_crafted_rx_iter_open_raw(&ctx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	esp_crafted_rx_iter_send_burst(&ctx);

out:
	esp_crafted_rx_iter_teardown(&ctx);
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_calls);
	return 0;
}

bool esp_crafted_rx(struct childdata *child)
{
	struct esp_crafted_rx_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.esp_crafted_rx.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_esp_crafted_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("esp4");
		try_modprobe("esp6");
		/* mip6 registers the destopt/rthdr handlers whose
		 * xfrm6_input_addr() call is the depth-boundary target. */
		try_modprobe("mip6");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, esp_crafted_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_esp_crafted_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
