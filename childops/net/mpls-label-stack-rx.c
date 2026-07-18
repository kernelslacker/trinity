/*
 * mpls_label_stack_rx - v4 MPLS L2.5 crafted-RX fuzz.  Fills the
 * coverage gap left by mpls_route_churn (RTM_NEWROUTE / lwtunnel install
 * on net/mpls/af_mpls.c) and the netlink kinds table: those reach the
 * MPLS FIB install path but nothing exercises net/mpls/af_mpls.c:
 * mpls_forward -- the packet_type-registered RX walker that pops the
 * label stack, walks the S=bottom-of-stack chain, and hands the inner
 * L3 frame off to the AF_INET / AF_INET6 input path -- with a crafted
 * outer Ethernet(0x8847) / label-stack / inner-L3 frame.  Random arg
 * fuzzing cannot chance-assemble that L2 + label-stack + inner-L3 shape
 * aimed at a live MPLS-enabled input interface.
 *
 * MPLS is L2.5: Ethernet ethertype 0x8847 (MPLS_UC) directly frames a
 * 32-bit label stack, no UDP encap.  Delivery is via AF_PACKET SOCK_RAW
 * bound to a loopback ifindex with net.mpls.conf.lo.input=1 so the
 * kernel's mpls_forward is invoked on the local RX path.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs
 * a one-shot best-effort modprobe of mpls_router + mpls_iptunnel before
 * the userns hop (finit_module needs CAP_SYS_MODULE in init_user_ns).
 * The grandchild brings lo up, writes net.mpls.platform_labels + net.
 * mpls.conf.lo.input to enable MPLS input on lo, opens an AF_PACKET
 * SOCK_RAW bound to lo with sll_protocol=ETH_P_MPLS_UC, then blasts a
 * BUDGETED+JITTER (base 5) burst of hand-rolled Ethernet(0x8847) /
 * label-stack / inner-L3 frames.  Each iteration rerolls stack depth,
 * S-bit placement, label values, TTL, and truncation past the parsed
 * stack length so the walker sees the full range of legal and abusive
 * frame shapes.
 *
 * Bug class of interest: the MPLS label-stack walker.  Each 32-bit
 * label-stack entry carries a 1-bit S "bottom of stack" marker; the
 * walker loops until it sees S=1 or the packet ends.  A stack that
 * declares no S=1 bit and runs off the end of the frame drives the
 * walker past skb_tail (parse-past-end shape).  A stack declared much
 * longer than the frame (truncation past the last emitted entry) hits
 * the same shape.  Deep-nested stacks (>16 entries) exercise the
 * post-pop TTL propagation and the inner-L3 ip_hdr peek that decides
 * whether to hand the inner frame to ip_local_deliver / ipv6_rcv.
 *
 * Brick-safety: loopback only inside the private netns (frames target
 * lo inside the grandchild's own netns), sysctl writes are per-netns
 * (net.mpls.* is registered per-net so the host tree is untouched),
 * all sends MSG_DONTWAIT, netlink ack SO_RCVTIMEO=1s so an unresponsive
 * rtnl can't wedge past child.c's SIGALRM.
 *
 * Latches: ns_unsupported_mpls_label_stack_rx master gate on userns_
 * run_in_ns() -EPERM (unprivileged userns disabled).
 * shm->mpls_label_stack_rx_kind_unsupported on
 * /proc/sys/net/mpls/platform_labels open ENOENT (CONFIG_MPLS_ROUTING
 * absent).  Per-kind latch lives in shm because the rejection is
 * observed inside a transient grandchild -- a process-local static
 * would die on _exit and re-attempt the missing kind forever.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC			0x8847
#endif
#ifndef ETH_P_IP
#define ETH_P_IP			0x0800
#endif

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define MLR_PACKET_BASE			5U

/* Outer packet buffer size.  Eth (14) + label stack (up to 32*4 = 128)
 * + inner IPv4 (20) + slack fits well under 256; leaves headroom for
 * length randomisation. */
#define MLR_PKT_MAX			256

/* Label-stack depth ceiling.  MPLS has no formal max but linux caps at
 * MAX_NEW_LABELS=30 on FIB entries; a receive-side stack can be deeper
 * in principle.  32 is a safe upper bound that still fits comfortably
 * inside MLR_PKT_MAX after the Ethernet + inner headers. */
#define MLR_STACK_MAX			32U

/* platform_labels sysctl payload.  Zero disables MPLS input entirely
 * (mpls_platform_labels = 0 -> mpls_route_input drops).  1024 gives
 * the FIB a small but nonzero label space so mpls_forward walks the
 * lookup path even if the frame's label doesn't match any installed
 * route -- the pop + inner-header peek still runs before the miss. */
#define MLR_PLATFORM_LABELS		"1024"

/* Ethernet + MPLS constants for hand-rolled frames. */
#define MLR_ETH_HLEN			14U

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's routing tables, so the op stays disabled
 * for the remainder of this child's lifetime.
 */
static bool ns_unsupported_mpls_label_stack_rx;

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

/* Set once per persistent child after the modprobe attempt runs.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->mpls_label_stack_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->mpls_label_stack_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/*
 * Encode one MPLS label-stack entry into a 32-bit big-endian word.
 * label is masked to 20 bits, tc to 3 bits, s to 1 bit, ttl to 8 bits.
 * Matches the mpls_label_encode() shape in mpls-route-churn.c but
 * exposes tc + ttl as parameters so the burst can rotate them.
 */
static uint32_t mlr_encode_entry(uint32_t label, uint8_t tc, bool s,
				 uint8_t ttl)
{
	uint32_t entry;

	entry = (label & 0xfffffU) << 12;
	entry |= (uint32_t)(tc & 0x7U) << 9;
	if (s)
		entry |= (uint32_t)0x100U;
	entry |= (uint32_t)ttl;
	return entry;
}

/*
 * Draw a label-stack depth.  {1, 2, 4, 8, 16, 32} covers single-entry
 * (typical), shallow (typical LSP), and deep-nested (stress the walker's
 * per-pop loop and the TTL propagation across many pops).  A run of
 * BUDGETED iters hits each depth multiple times so the walker's inner
 * loop sees both fast-path and deep-recursion shapes.
 */
static unsigned int pick_stack_depth(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0:  return 1U;
	case 1:  return 2U;
	case 2:  return 4U;
	case 3:  return 8U;
	case 4:  return 16U;
	default: return MLR_STACK_MAX;
	}
}

/*
 * Draw a label value.  Reserved labels (0..15) drive the special-case
 * branches: 0 = IPv4 Explicit NULL, 1 = Router Alert, 2 = IPv6 Explicit
 * NULL, 3 = Implicit NULL, 7 = Entropy Label Indicator, 13 = GAL,
 * 14 = OAM Alert.  Values >=16 are user-installable and drive the
 * general FIB lookup.  Rotate through reserved + general so both
 * branches get exercised.
 */
static uint32_t pick_label(void)
{
	switch (rnd_modulo_u32(8)) {
	case 0:  return 0U;			/* IPv4 Explicit NULL */
	case 1:  return 1U;			/* Router Alert */
	case 2:  return 2U;			/* IPv6 Explicit NULL */
	case 3:  return 3U;			/* Implicit NULL */
	case 4:  return 13U;			/* GAL */
	default: return 16U + rnd_modulo_u32(0xffffU);
	}
}

/*
 * Draw a TTL value.  0 drives the TTL-expired branch (icmp_send +
 * frame drop); 1 tests the "expire after this hop" path; 255 is the
 * spec maximum; a random value in-between covers the general path.
 */
static uint8_t pick_ttl(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 255U;
	default: return (uint8_t)(rand32() & 0xffU);
	}
}

/*
 * Draw a truncation length in bytes shaved off the emitted stack.
 * {0, 1, 4, 8} covers no-truncation (full stack), mid-entry truncation
 * (walker sees a partial 32-bit word), one-entry truncation (walker
 * over-reads by exactly one entry), two-entry truncation (walker
 * over-reads deeper).  The recurring tunnel-RX bug shape is truncation
 * past a parsed length -- here the parsed length is implicit (the
 * walker keeps going until S=1 or end-of-frame) so a stack with no
 * S=1 bit and a physical truncation forces the walk-past-end path.
 */
static uint8_t pick_stack_trunc(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 4U;
	default: return 8U;
	}
}

/*
 * Draw where the bottom-of-stack S=1 bit lands.  "last" is the RFC
 * shape (walker stops after the last entry); "never" omits S=1
 * entirely so the walker runs off the end (or into the inner L3
 * payload's first byte, whose top bit is often 0 -- forces the
 * over-walk).  "first" places S=1 on entry 0 so a multi-entry stack
 * gets its walker short-circuited after one pop, leaving unclaimed
 * label bytes at the head of the inner frame.
 */
enum mlr_bos_placement {
	MLR_BOS_LAST = 0,
	MLR_BOS_FIRST,
	MLR_BOS_NEVER,
};

static enum mlr_bos_placement pick_bos_placement(void)
{
	switch (rnd_modulo_u32(6)) {
	case 0: case 1: case 2: case 3:	return MLR_BOS_LAST;
	case 4:				return MLR_BOS_FIRST;
	default:			return MLR_BOS_NEVER;
	}
}

/*
 * Compose one Ethernet / MPLS-stack / inner-IPv4 frame at buf.  Layout:
 *   [ether hdr (14): dst=broadcast, src=locally-admin, type=0x8847]
 *   [MPLS label stack (depth*4 bytes; truncated per trunc)]
 *   [inner IPv4 (20 bytes) -- gives the walker a valid ip_hdr peek
 *    when it hits the bottom-of-stack]
 * Returns total wire length.
 */
static size_t build_mpls_frame(uint8_t *buf, unsigned int depth,
			       enum mlr_bos_placement bos, uint8_t stack_trunc)
{
	unsigned int stack_bytes = depth * 4U;
	unsigned int stack_emit;
	unsigned int i;
	size_t off = 0;
	struct iphdr *inner;

	memset(buf, 0, MLR_PKT_MAX);

	/* Ethernet header. */
	memset(buf + off, 0xff, 6);		/* dst broadcast */
	off += 6;
	buf[off + 0] = 0x02;			/* locally-administered src */
	buf[off + 1] = 0x00;
	buf[off + 2] = 0x00;
	buf[off + 3] = 0x00;
	buf[off + 4] = 0x00;
	buf[off + 5] = 0x01;
	off += 6;
	buf[off + 0] = 0x88;			/* ethertype MPLS_UC = 0x8847 */
	buf[off + 1] = 0x47;
	off += 2;

	/* MPLS label stack.  Emit `depth` entries but shave `stack_trunc`
	 * bytes off the tail so the walker sees a partial or missing final
	 * entry when combined with MLR_BOS_NEVER. */
	stack_emit = stack_bytes;
	if (stack_trunc >= stack_emit)
		stack_emit = 0U;
	else
		stack_emit -= stack_trunc;
	if (off + stack_emit > MLR_PKT_MAX)
		stack_emit = (unsigned int)(MLR_PKT_MAX - off);

	for (i = 0; i + 4U <= stack_emit; i += 4U) {
		unsigned int entry_idx = i / 4U;
		uint32_t label = pick_label();
		uint8_t  tc    = (uint8_t)(rand32() & 0x7U);
		uint8_t  ttl   = pick_ttl();
		bool     s;
		uint32_t entry;

		switch (bos) {
		case MLR_BOS_LAST:
			s = (entry_idx == depth - 1U);
			break;
		case MLR_BOS_FIRST:
			s = (entry_idx == 0U);
			break;
		case MLR_BOS_NEVER:
		default:
			s = false;
			break;
		}

		entry = mlr_encode_entry(label, tc, s, ttl);
		buf[off + i + 0] = (uint8_t)((entry >> 24) & 0xffU);
		buf[off + i + 1] = (uint8_t)((entry >> 16) & 0xffU);
		buf[off + i + 2] = (uint8_t)((entry >> 8)  & 0xffU);
		buf[off + i + 3] = (uint8_t)(entry & 0xffU);
	}

	/* If truncation left a partial-entry tail, stamp random bytes so
	 * the walker sees a plausibly-shaped fragment rather than zeros. */
	if (i < stack_emit)
		generate_rand_bytes(buf + off + i, stack_emit - i);

	off += stack_emit;

	/* Inner IPv4 header so mpls_forward's post-pop ip_hdr peek sees a
	 * legal version=4 nibble and hands the frame to the AF_INET input
	 * path when the walker actually reaches S=1. */
	if (off + sizeof(*inner) <= MLR_PKT_MAX) {
		inner = (struct iphdr *)(buf + off);
		inner->version  = 4;
		inner->ihl      = 5;
		inner->ttl      = 64;
		inner->protocol = IPPROTO_UDP;
		inner->saddr    = (__be32)__builtin_bswap32(0x7f000001U);
		inner->daddr    = (__be32)__builtin_bswap32(0x7f000001U);
		inner->tot_len  = htons((uint16_t)sizeof(*inner));
		off += sizeof(*inner);
	}

	return off;
}

/*
 * Enable MPLS input on lo inside the current netns by writing the two
 * per-net sysctls.  Returns 0 on success, -1 on failure.  ENOENT on
 * /proc/sys/net/mpls/platform_labels is the CONFIG_MPLS_ROUTING-absent
 * signal and latches the kind off for the remainder of the run.
 */
static int mlr_enable_mpls_on_lo(void)
{
	int fd;
	ssize_t n;

	fd = open("/proc/sys/net/mpls/platform_labels",
		  O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			mark_kind_unsupported();
		return -1;
	}
	n = write(fd, MLR_PLATFORM_LABELS, sizeof(MLR_PLATFORM_LABELS) - 1);
	close(fd);
	if (n <= 0)
		return -1;

	fd = open("/proc/sys/net/mpls/conf/lo/input",
		  O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = write(fd, "1", 1);
	close(fd);
	if (n <= 0)
		return -1;

	return 0;
}

/*
 * Per-invocation state shared across the mpls_label_stack_rx_iter_*
 * helpers.  Lives on the orchestrator's stack.  Only fields read/written
 * across helper boundaries are lifted here; packet-burst scratch stays
 * on that helper's stack.  Gates encode the partial-state teardown
 * contract.
 */
struct mpls_label_stack_rx_iter_ctx {
	struct nl_ctx	nl;
	int		lo_ifindex;
	int		raw;		/* AF_PACKET fd, -1 until opened */
	bool		nl_opened;
	bool		mpls_enabled;
	struct childdata *child;
};

/*
 * Open the rtnl socket and bring lo up inside the private netns.
 * Returns 0 on success, -1 on failure.  Teardown is safe on failure
 * because it gates on ctx->nl_opened.
 */
static int mpls_label_stack_rx_iter_open_ctx(struct mpls_label_stack_rx_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->nl_opened = true;

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ctx->nl);
		lo_brought_up = true;
	}
	return 0;
}

/*
 * Build phase: resolve lo's ifindex, enable MPLS input on lo via the
 * per-net sysctls.  Returns 0 if the burst phase should run, -1
 * otherwise.  On the sysctl-open ENOENT path the kind is latched off
 * (missing CONFIG_MPLS_ROUTING); other failures leave the latch alone.
 */
static int mpls_label_stack_rx_iter_build_link(struct mpls_label_stack_rx_iter_ctx *ctx)
{
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->lo_ifindex = (int)if_nametoindex("lo");
	if (ctx->lo_ifindex <= 0) {
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (mlr_enable_mpls_on_lo() < 0) {
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_config_failed,
				   1, __ATOMIC_RELAXED);
		if (kind_unsupported() && valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return -1;
	}
	ctx->mpls_enabled = true;
	__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_config_ok,
			   1, __ATOMIC_RELAXED);

	if (rtnl_setlink_up(&ctx->nl, ctx->lo_ifindex) == 0)
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_link_up_ok,
				   1, __ATOMIC_RELAXED);

	return 0;
}

/*
 * Burst phase: open AF_PACKET / SOCK_RAW bound to lo with sll_protocol=
 * ETH_P_MPLS_UC, then push BUDGETED+JITTER hand-rolled Ethernet(0x8847)
 * / label-stack / inner-IPv4 frames at lo.  The kernel's mpls_forward
 * packet_type handler runs on delivery, walks the label stack, and
 * hands the inner IPv4 frame to the ip_local_deliver path when it
 * reaches S=1.  Each iteration rerolls stack depth, S-bit placement,
 * label values, TTL, and truncation length so the decap path sees the
 * full set of label-stack shapes -- including the parse-past-end shape
 * that MLR_BOS_NEVER + truncation combined produces.  MSG_DONTWAIT so
 * a backed-up loopback queue can't stall the iteration past the
 * inherited SIGALRM(1s) cap.
 */
static void mpls_label_stack_rx_iter_send_burst(struct mpls_label_stack_rx_iter_ctx *ctx)
{
	struct sockaddr_ll sll;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_MPLS_UC));
	if (ctx->raw < 0)
		return;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_MPLS_UC);
	sll.sll_ifindex  = ctx->lo_ifindex;
	if (bind(ctx->raw, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return;

	iters = BUDGETED(CHILD_OP_MPLS_LABEL_STACK_RX,
			 JITTER_RANGE(MLR_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[MLR_PKT_MAX];
		size_t len;
		ssize_t n;
		unsigned int depth = pick_stack_depth();
		enum mlr_bos_placement bos = pick_bos_placement();
		uint8_t stack_trunc = pick_stack_trunc();
		struct sockaddr_ll dst;

		len = build_mpls_frame(pkt, depth, bos, stack_trunc);

		memset(&dst, 0, sizeof(dst));
		dst.sll_family   = AF_PACKET;
		dst.sll_protocol = htons(ETH_P_MPLS_UC);
		dst.sll_ifindex  = ctx->lo_ifindex;
		dst.sll_halen    = 6;
		memset(dst.sll_addr, 0xff, 6);

		n = sendto(ctx->raw, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown phase: close the raw fd and the rtnl socket.  Each cleanup
 * is gated independently so it is safe to call from any bail-out point
 * in the orchestrator -- including the early returns where ctx is
 * fully zero-initialised -- without leaking the raw fd or the netlink
 * socket.  Netns destruction on grandchild exit catches the sysctl
 * writes and any per-net MPLS FIB state.
 */
static void mpls_label_stack_rx_iter_teardown(struct mpls_label_stack_rx_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (ctx->nl_opened)
		nl_close(&ctx->nl);
}

struct mpls_label_stack_rx_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the raw
 * socket, per-net MPLS sysctls, and any FIB state left behind are
 * reaped along with the namespace.  Return value is ignored by the
 * helper.
 */
static int mpls_label_stack_rx_in_ns(void *arg)
{
	struct mpls_label_stack_rx_ctx *cctx = (struct mpls_label_stack_rx_ctx *)arg;
	struct childdata *child = cctx->child;
	struct mpls_label_stack_rx_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (kind_unsupported())
		return 0;

	if (mpls_label_stack_rx_iter_open_ctx(&ctx) == 0 &&
	    mpls_label_stack_rx_iter_build_link(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		mpls_label_stack_rx_iter_send_burst(&ctx);
	}

	mpls_label_stack_rx_iter_teardown(&ctx);
	return 0;
}

bool mpls_label_stack_rx(struct childdata *child)
{
	struct mpls_label_stack_rx_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_mpls_label_stack_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("mpls_router");
		try_modprobe("mpls_iptunnel");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, mpls_label_stack_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_mpls_label_stack_rx = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.mpls_label_stack_rx_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
