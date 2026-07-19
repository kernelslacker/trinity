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

#include <linux/netlink.h>

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

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

/*
 * UAPI fallbacks.  linux/xfrm.h may be absent on a stripped sysroot;
 * the IDs and structure layouts have been stable in the kernel UAPI
 * since 2.6.x so a compile-time shim is safe.  Guarded by
 * __has_include above so the real header wins when present.
 */
#ifndef XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSA		0x10
#define XFRM_MSG_DELSA		0x11
#endif

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH		1
#define XFRMA_ALG_CRYPT		2
#endif

#ifndef XFRMA_SA_DIR
#define XFRMA_SA_DIR		33
#endif

#ifndef XFRM_SA_DIR_IN
#define XFRM_SA_DIR_IN		1
#endif

#ifndef XFRM_MODE_TRANSPORT
#define XFRM_MODE_TRANSPORT	0
#endif

#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50
#endif

#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING		43
#endif

#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS		60
#endif

#if !__has_include(<linux/xfrm.h>)
typedef union {
	__be32			a4;
	__be32			a6[4];
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t		daddr;
	__be32			spi;
	__u8			proto;
};

struct xfrm_selector {
	xfrm_address_t		daddr;
	xfrm_address_t		saddr;
	__be16			dport;
	__be16			dport_mask;
	__be16			sport;
	__be16			sport_mask;
	__u16			family;
	__u8			prefixlen_d;
	__u8			prefixlen_s;
	__u8			proto;
	int			ifindex;
	__u32			user;
};

struct xfrm_lifetime_cfg {
	__u64			soft_byte_limit;
	__u64			hard_byte_limit;
	__u64			soft_packet_limit;
	__u64			hard_packet_limit;
	__u64			soft_add_expires_seconds;
	__u64			hard_add_expires_seconds;
	__u64			soft_use_expires_seconds;
	__u64			hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64			bytes;
	__u64			packets;
	__u64			add_time;
	__u64			use_time;
};

struct xfrm_stats {
	__u32			replay_window;
	__u32			replay;
	__u32			integrity_failed;
};

struct xfrm_algo {
	char			alg_name[64];
	unsigned int		alg_key_len;
	char			alg_key[];
};

struct xfrm_algo_auth {
	char			alg_name[64];
	unsigned int		alg_key_len;
	unsigned int		alg_trunc_len;
	char			alg_key[];
};

struct xfrm_usersa_info {
	struct xfrm_selector		sel;
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	struct xfrm_stats		stats;
	__u32				seq;
	__u32				reqid;
	__u16				family;
	__u8				mode;
	__u8				replay_window;
	__u8				flags;
};

struct xfrm_usersa_id {
	xfrm_address_t			daddr;
	__be32				spi;
	__u16				family;
	__u8				proto;
};
#endif /* !__has_include(<linux/xfrm.h>) */

/* Loopback endpoints.  v4 pairs 127.0.0.1 -> 127.0.0.2 like xfrm-churn
 * does; v6 stays on ::1 both sides (single-address loopback is enough
 * for a private-netns RX-only op).  Kernel's automatic loopback route
 * covers both without an explicit route install. */
#define ESPRX_V4_SADDR_BE	(__be32)__builtin_bswap32(0x7f000001U)
#define ESPRX_V4_DADDR_BE	(__be32)__builtin_bswap32(0x7f000002U)

/* SPI range mirrors xfrm-churn: kernel reserves SPI < 256 for ISAKMP,
 * so we rotate within [0x100, 0xffffff]. */
#define ESPRX_SPI_MIN		0x100U
#define ESPRX_SPI_RANGE		0xfff000U

/* Per-invocation packet burst base.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define ESPRX_PACKET_BASE	5U

/* Outer packet buffer size.  Outer IPv6 (40) + ESP header (8) + inner
 * (up to 32 with truncation applied) + ESP trailer (2 + pad up to 4)
 * fits well under 192; leaves headroom for header stamping variance. */
#define ESPRX_PKT_MAX		192

/*
 * Fragmented-inner path knobs.  A large ESP-encapsulated payload
 * (SPI+seq + 1 KiB inner + trailer) split across two IP fragments
 * forces IP defrag reassembly to build a non-linear skb.  ESP decrypt
 * then walks that skb via skb_cow_data() into a scatter-gather layout,
 * driving the crypto request through the SG allocation and, on
 * completion, the esp_ssg_unref() cleanup path with managed frag pages
 * in play.  First-fragment slice is 8-byte aligned per IPv4 / IPv6
 * fragmentation rules; tail carries the remainder including the ESP
 * trailer (pad_len + next_header). */
#define ESPRX_FRAG_INNER	1024U
#define ESPRX_FRAG_ESP_LEN	(8U + ESPRX_FRAG_INNER + 2U)
#define ESPRX_FRAG_SLICE1	520U
#define ESPRX_FRAG_FRAME_MAX	(40U + 8U + ESPRX_FRAG_SLICE1)

/*
 * Stacked-ESP-inner path knobs.  Kernel's XFRM_MAX_DEPTH is 6 (see
 * include/net/xfrm.h in linux-linus).  A max-depth stacked-ESP IPv6
 * frame nests six cipher_null/digest_null transport-mode ESP layers
 * ahead of a mip6-shaped inner extension header (destination-options
 * HAO or type-2 routing).  Each successful decap adds a secpath entry,
 * so after the innermost layer strips, sp->len == XFRM_MAX_DEPTH and
 * mip6_destopt_input() / mip6_rthdr_input() call xfrm6_input_addr()
 * against a full secpath -- covers the depth-boundary reinject slot
 * that single-frame and fragmented-inner emitters never reach.
 * Buffer size: 40 (IPv6) + 6*8 (ESP hdrs) + 24 (dstopts/rthdr)
 * + 8 (fake inner UDP) + 6*2 (ESP trailers) = 132; 256 leaves
 * headroom for header-stamping variance. */
#define ESPRX_STACK_DEPTH	6U
#define ESPRX_STACK_PKT_MAX	256U

/* Nominal inner header sizes.  Kernel's post-decap parse reads at
 * least this many bytes for each proto; truncating the emitted payload
 * below the nominal size is what drives the over-read seam. */
#define ESPRX_INNER_TCP_MIN	20	/* struct tcphdr fixed */
#define ESPRX_INNER_UDP_MIN	8	/* struct udphdr */
#define ESPRX_INNER_ICMP_MIN	8	/* struct icmphdr */
#define ESPRX_INNER_NOMINAL	32	/* upper bound of what we may write */

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's SAD, so the op stays disabled for the
 * remainder of this child's lifetime.
 */
static bool ns_unsupported_esp_crafted_rx;

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

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
 * IPv4 header checksum, standard one's-complement over the 20-byte
 * header.  Kept local so this file has no dependency on utils/csum
 * plumbing.  Mirrors ip_gre-churn.c / sctp-chunk-rx.c.
 */
static __u16 ip_csum16(const void *data, size_t len)
{
	const __u16 *p = data;
	__u32 s = 0;

	while (len > 1) {
		s += *p++;
		len -= 2;
	}
	if (len)
		s += *(const __u8 *)p;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/*
 * Install an inbound ESP SA with cipher_null + digest_null so any
 * ciphertext survives ICV verify and decrypt.  reqid, spi and v6
 * are captured by the caller so the packet-emit loop can stamp
 * matching SPIs on the outer frames and later DELSA can look the
 * SA up.  Returns 0 on netlink-ack success, negated errno on
 * kernel rejection, -EIO on local encode failure.
 */
static int install_null_esp_sa(struct nl_ctx *ctx, __be32 spi, __u32 reqid,
			       bool v6)
{
	unsigned char buf[1024];
	unsigned char ebuf[sizeof(struct xfrm_algo)];
	unsigned char abuf[sizeof(struct xfrm_algo_auth)];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_algo *enc;
	struct xfrm_algo_auth *au;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);

	if (v6) {
		sa->sel.saddr.a6[3] = (__be32)__builtin_bswap32(1U);
		sa->sel.daddr.a6[3] = (__be32)__builtin_bswap32(1U);
		sa->sel.family      = AF_INET6;
		sa->sel.prefixlen_s = 128;
		sa->sel.prefixlen_d = 128;
		sa->id.daddr.a6[3]  = (__be32)__builtin_bswap32(1U);
		sa->saddr.a6[3]     = (__be32)__builtin_bswap32(1U);
		sa->family          = AF_INET6;
	} else {
		sa->sel.saddr.a4    = ESPRX_V4_SADDR_BE;
		sa->sel.daddr.a4    = ESPRX_V4_DADDR_BE;
		sa->sel.family      = AF_INET;
		sa->sel.prefixlen_s = 32;
		sa->sel.prefixlen_d = 32;
		sa->id.daddr.a4     = ESPRX_V4_DADDR_BE;
		sa->saddr.a4        = ESPRX_V4_SADDR_BE;
		sa->family          = AF_INET;
	}

	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_ESP;

	sa->lft.soft_byte_limit   = (__u64)~0ULL;
	sa->lft.hard_byte_limit   = (__u64)~0ULL;
	sa->lft.soft_packet_limit = (__u64)~0ULL;
	sa->lft.hard_packet_limit = (__u64)~0ULL;

	sa->reqid         = reqid;
	sa->mode          = XFRM_MODE_TRANSPORT;
	sa->replay_window = 32;
	sa->flags         = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	/* XFRMA_ALG_CRYPT: ecb(cipher_null), zero-length key.  Kernel
	 * accepts a bare header with no key bytes for the null cipher. */
	memset(ebuf, 0, sizeof(ebuf));
	enc = (struct xfrm_algo *)ebuf;
	strncpy(enc->alg_name, "ecb(cipher_null)", sizeof(enc->alg_name) - 1);
	enc->alg_key_len = 0;
	off = nla_put(buf, off, sizeof(buf), XFRMA_ALG_CRYPT, ebuf, sizeof(*enc));
	if (!off)
		return -EIO;

	/* XFRMA_ALG_AUTH: digest_null, zero-length key + zero trunc.  Any
	 * ciphertext will verify.  Paired with cipher_null the SA accepts
	 * arbitrary ESP payload and the inner-parse seam is reachable. */
	memset(abuf, 0, sizeof(abuf));
	au = (struct xfrm_algo_auth *)abuf;
	strncpy(au->alg_name, "digest_null", sizeof(au->alg_name) - 1);
	au->alg_key_len   = 0;
	au->alg_trunc_len = 0;
	off = nla_put(buf, off, sizeof(buf), XFRMA_ALG_AUTH, abuf, sizeof(*au));
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, XFRM_SA_DIR_IN);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Tear the SA down on the way out so the SAD does not accumulate
 * across iterations.  Netns destruction on grandchild exit would reap
 * anything left behind, but an explicit DELSA moves the DELSA counter
 * and exercises xfrm_state_delete on the success path.  Failure is
 * benign -- the netns teardown will take care of it.
 */
static int delete_esp_sa(struct nl_ctx *ctx, __be32 spi, bool v6)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	if (v6) {
		uid->daddr.a6[3] = (__be32)__builtin_bswap32(1U);
		uid->family      = AF_INET6;
	} else {
		uid->daddr.a4    = ESPRX_V4_DADDR_BE;
		uid->family      = AF_INET;
	}
	uid->spi   = spi;
	uid->proto = IPPROTO_ESP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Draw the inner protocol byte for a crafted frame.  Weighting keeps
 * TCP/UDP/ICMP in the mix (each maps to its own kernel parser entry
 * on the post-decap path) plus an escape hatch of random bytes for
 * the unknown-protocol branch.
 */
static uint8_t pick_inner_proto(void)
{
	uint32_t roll = rnd_modulo_u32(8);

	switch (roll) {
	case 0: case 1: case 2: return IPPROTO_TCP;
	case 3: case 4:         return IPPROTO_UDP;
	case 5:                 return IPPROTO_ICMP;
	default:                return (uint8_t)rnd_modulo_u32(256);
	}
}

/*
 * Draw an inner-payload length shorter than the nominal parser read
 * for that proto, so the post-decap header walk over-reads.  Values
 * span {0, 1, 4, 8, 16} -- 0 leaves the parser reading the ESP
 * trailer bytes as if they were an inner header; 4/8/16 are common
 * short-header sizes that slice a real fixed header off mid-field.
 */
static uint8_t pick_inner_trunc_len(void)
{
	uint32_t roll = rnd_modulo_u32(5);

	switch (roll) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 4U;
	case 3:  return 8U;
	default: return 16U;
	}
}

/*
 * Draw an ESP sequence number.  Rotates {0, 1, small random, large
 * random} to walk the replay-window edges the kernel checks before
 * the ICV verify.  Zero is included even though the kernel typically
 * treats seq=0 as invalid -- the reject path itself is worth
 * exercising.
 */
static __u32 pick_esp_seq(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return rand32() & 0xffffU;
	default: return rand32();
	}
}

/*
 * Build an IPv4(ESP) frame with a truncated inner payload of the
 * given proto.  Returns the total wire length ready for sendto().
 * Layout:
 *   [outer IPv4 (20)]
 *   [ESP header (8): SPI + seq]
 *   [inner payload of trunc_len bytes -- shorter than the parser's
 *    nominal minimum for the picked inner_proto]
 *   [ESP trailer (2): pad_len=0, next_header=inner_proto]
 */
static size_t build_v4_frame(uint8_t *buf, __be32 spi, __u32 seq,
			     uint8_t inner_proto, uint8_t trunc_len)
{
	struct iphdr *iph;
	size_t off;
	size_t esp_hdr_start;
	size_t inner_start;

	if (trunc_len > ESPRX_INNER_NOMINAL)
		trunc_len = ESPRX_INNER_NOMINAL;

	memset(buf, 0, ESPRX_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_ESP;
	iph->saddr    = ESPRX_V4_SADDR_BE;
	iph->daddr    = ESPRX_V4_DADDR_BE;
	off = sizeof(*iph);

	esp_hdr_start = off;
	*(__be32 *)(buf + off + 0) = spi;
	*(__be32 *)(buf + off + 4) = htonl(seq);
	off += 8;
	(void)esp_hdr_start;

	inner_start = off;
	if (trunc_len > 0) {
		uint8_t stub[ESPRX_INNER_NOMINAL];

		generate_rand_bytes(stub, trunc_len);
		memcpy(buf + inner_start, stub, trunc_len);
		off += trunc_len;
	}

	/* ESP trailer: pad_len=0, next_header=inner_proto.  Kernel reads
	 * these two bytes from the tail of the decrypted plaintext to
	 * determine what proto to walk next; without them the RX done
	 * path has nothing plausible to hand to the inner parser. */
	buf[off + 0] = 0;
	buf[off + 1] = inner_proto;
	off += 2;

	iph->tot_len = htons((uint16_t)off);
	iph->check   = 0;
	iph->check   = ip_csum16(iph, sizeof(*iph));

	return off;
}

/*
 * Build an IPv6(ESP) frame.  Same shape as the v4 builder but with an
 * outer IPv6 header (40 bytes, next_header=IPPROTO_ESP, payload_length
 * covers ESP header + inner + trailer).  IPv6 has no header checksum.
 */
static size_t build_v6_frame(uint8_t *buf, __be32 spi, __u32 seq,
			     uint8_t inner_proto, uint8_t trunc_len)
{
	size_t off;
	uint16_t payload_len;

	if (trunc_len > ESPRX_INNER_NOMINAL)
		trunc_len = ESPRX_INNER_NOMINAL;

	memset(buf, 0, ESPRX_PKT_MAX);

	/* IPv6 fixed header: version=6, next_header=ESP, hop_limit=64.
	 * saddr and daddr both ::1 -- single-address loopback is enough
	 * for a private-netns RX-only op. */
	buf[0]  = 0x60;
	buf[6]  = IPPROTO_ESP;
	buf[7]  = 64;
	buf[8 + 15]  = 1;	/* saddr = ::1 */
	buf[24 + 15] = 1;	/* daddr = ::1 */
	off = 40;

	*(__be32 *)(buf + off + 0) = spi;
	*(__be32 *)(buf + off + 4) = htonl(seq);
	off += 8;

	if (trunc_len > 0) {
		uint8_t stub[ESPRX_INNER_NOMINAL];

		generate_rand_bytes(stub, trunc_len);
		memcpy(buf + off, stub, trunc_len);
		off += trunc_len;
	}

	buf[off + 0] = 0;
	buf[off + 1] = inner_proto;
	off += 2;

	payload_len = (uint16_t)(off - 40);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)payload_len;

	return off;
}

/*
 * Compose an ESP-encapsulated blob (SPI + seq + inner payload + ESP
 * trailer) for the fragmented emitter to slice across IP fragments.
 * Total length is fixed at ESPRX_FRAG_ESP_LEN so the caller can pick
 * the fragment offsets without re-inspecting the blob.  Inner bytes are
 * random; trailer pads to 0 with next_header carrying the picked inner
 * proto so the reassembled ESP payload has a plausible trailer on the
 * decrypt done path.
 */
static void build_esp_blob(uint8_t *esp, __be32 spi, __u32 seq,
			   uint8_t inner_proto)
{
	*(__be32 *)(esp + 0) = spi;
	*(__be32 *)(esp + 4) = htonl(seq);
	generate_rand_bytes(esp + 8, ESPRX_FRAG_INNER);
	esp[8 + ESPRX_FRAG_INNER + 0] = 0;
	esp[8 + ESPRX_FRAG_INNER + 1] = inner_proto;
}

/*
 * Emit one IPv4 fragment carrying `slice_len` bytes of an ESP blob.
 * Protocol stays IPPROTO_ESP on every fragment; IP defrag reassembles
 * by id + saddr + daddr + proto and only then hands the reassembled
 * datagram to the ESP protocol handler.
 */
static size_t build_v4_esp_fragment(uint8_t *buf, uint16_t ident,
				    uint16_t frag_off_units, bool more,
				    const uint8_t *esp_slice, size_t slice_len)
{
	struct iphdr *iph = (struct iphdr *)buf;
	uint16_t frag_off_word = frag_off_units & 0x1fffU;

	if (more)
		frag_off_word |= 0x2000U;	/* IP_MF */

	memset(buf, 0, sizeof(*iph));
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_ESP;
	iph->saddr    = ESPRX_V4_SADDR_BE;
	iph->daddr    = ESPRX_V4_DADDR_BE;
	iph->id       = htons(ident);
	iph->frag_off = htons(frag_off_word);
	iph->tot_len  = htons((uint16_t)(sizeof(*iph) + slice_len));

	memcpy(buf + sizeof(*iph), esp_slice, slice_len);

	iph->check = ip_csum16(iph, sizeof(*iph));
	return sizeof(*iph) + slice_len;
}

/*
 * Emit one IPv6 fragment carrying `slice_len` bytes of an ESP blob.
 * Outer IPv6 next_header points to a Fragment header (44); the Fragment
 * header's next_header carries IPPROTO_ESP so the reassembled datagram
 * lands on the ESP6 protocol handler.  Offset is in 8-byte units per
 * RFC 8200.
 */
static size_t build_v6_esp_fragment(uint8_t *buf, uint32_t ident,
				    uint16_t frag_off_units, bool more,
				    const uint8_t *esp_slice, size_t slice_len)
{
	uint16_t frag_off_word;
	uint16_t payload_len;

	memset(buf, 0, 40U + 8U);
	buf[0] = 0x60;
	buf[6] = 44;			/* next_header = Fragment */
	buf[7] = 64;
	buf[8 + 15]  = 1;		/* saddr = ::1 */
	buf[24 + 15] = 1;		/* daddr = ::1 */

	buf[40] = IPPROTO_ESP;		/* fragment: next_header */
	buf[41] = 0;			/* reserved */
	frag_off_word = (uint16_t)((frag_off_units << 3) & 0xfff8U);
	if (more)
		frag_off_word |= 1U;
	buf[42] = (uint8_t)(frag_off_word >> 8);
	buf[43] = (uint8_t)(frag_off_word & 0xff);
	buf[44] = (uint8_t)(ident >> 24);
	buf[45] = (uint8_t)(ident >> 16);
	buf[46] = (uint8_t)(ident >>  8);
	buf[47] = (uint8_t)(ident      );

	memcpy(buf + 48, esp_slice, slice_len);

	payload_len = (uint16_t)(8U + slice_len);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)(payload_len & 0xff);

	return 48U + slice_len;
}

/*
 * Per-invocation state shared across the esp_crafted_rx_iter_*
 * helpers.  Lives on the orchestrator's stack.  Fields default so
 * teardown can close-or-skip unconditionally regardless of which
 * earlier phase bailed.
 */
struct esp_crafted_rx_iter_ctx {
	struct nl_ctx nl;
	int raw_v4;
	int raw_v6;
	__be32 spi;
	__u32 reqid;
	bool sa_added;
	bool v6;
	struct childdata *child;
	/* v6-only: SPIs of stacked cipher_null/digest_null SAs installed
	 * for the XFRM_MAX_DEPTH secpath path.  stack_depth is the number
	 * successfully installed (0 when v4, or when the base install
	 * loop bailed on the first rejection).  Torn down alongside the
	 * primary SA on teardown. */
	__be32 stack_spi[ESPRX_STACK_DEPTH];
	unsigned int stack_depth;
};

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
	};
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (!lo_brought_up) {
		struct nl_ctx rtnl = { .fd = -1 };
		struct nl_open_opts rtnl_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = 1,
		};

		if (nl_open(&rtnl, &rtnl_opts) == 0) {
			rtnl_bring_lo_up(&rtnl);
			nl_close(&rtnl);
		}
		lo_brought_up = true;
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
		if (ctx->raw_v6 >= 0)
			(void)setsockopt(ctx->raw_v6, IPPROTO_IPV6,
					 IPV6_HDRINCL, &one, sizeof(one));
	} else {
		ctx->raw_v4 = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC,
				     IPPROTO_RAW);
	}
}

/*
 * Emit a large ESP-encapsulated datagram (SPI + seq + 1 KiB inner +
 * trailer) split across two IP fragments to the SA's family.  IP defrag
 * reassembles into a non-linear skb, which ESP decrypt turns into a
 * scatter-gather crypto request; the SG teardown then runs
 * esp_ssg_unref() over managed frag pages.  SPI matches the installed
 * SA most of the time and misses occasionally, mirroring the single-
 * frame path's SPI-lookup mix.
 */
static void esp_crafted_rx_send_frag_pair(struct esp_crafted_rx_iter_ctx *ctx,
					  int fd)
{
	static const struct {
		uint16_t off_units;
		size_t   esp_off;
		size_t   len;
		bool     more;
	} slices[2] = {
		{ 0U,
		  0U,
		  ESPRX_FRAG_SLICE1,
		  true },
		{ (uint16_t)(ESPRX_FRAG_SLICE1 / 8U),
		  ESPRX_FRAG_SLICE1,
		  ESPRX_FRAG_ESP_LEN - ESPRX_FRAG_SLICE1,
		  false },
	};
	uint8_t esp[ESPRX_FRAG_ESP_LEN];
	uint8_t frame[ESPRX_FRAG_FRAME_MAX];
	__be32 spi;
	__u32 seq;
	uint8_t inner_proto;
	unsigned int i;

	spi = ONE_IN(8)
		? htonl((rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN)
		: ctx->spi;
	seq         = pick_esp_seq();
	inner_proto = pick_inner_proto();

	build_esp_blob(esp, spi, seq, inner_proto);

	if (ctx->v6) {
		struct sockaddr_in6 dst;
		uint32_t ident = rand32();

		memset(&dst, 0, sizeof(dst));
		dst.sin6_family = AF_INET6;
		dst.sin6_addr.s6_addr[15] = 1;

		for (i = 0; i < 2; i++) {
			size_t frame_len = build_v6_esp_fragment(frame, ident,
					slices[i].off_units, slices[i].more,
					esp + slices[i].esp_off, slices[i].len);

			if (sendto(fd, frame, frame_len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst)) > 0)
				__atomic_add_fetch(&shm->stats.esp_crafted_rx.packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	} else {
		struct sockaddr_in dst;
		uint16_t ident = (uint16_t)rand32();

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_addr.s_addr = ESPRX_V4_DADDR_BE;

		for (i = 0; i < 2; i++) {
			size_t frame_len = build_v4_esp_fragment(frame, ident,
					slices[i].off_units, slices[i].more,
					esp + slices[i].esp_off, slices[i].len);

			if (sendto(fd, frame, frame_len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst)) > 0)
				__atomic_add_fetch(&shm->stats.esp_crafted_rx.packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Stamp the innermost mip6-shaped extension header at `buf`.  Both
 * variants are exactly 24 bytes (hdr_ext_len=2 in 8-octet units past
 * the first 8) and set next_header=UDP so the header walker resumes
 * on a fixed-size ULP after the extension.  Destination-options form
 * carries a HAO (opt type 0xC9) followed by PadN(2) to reach the
 * 8-octet boundary; routing form carries a type-2 (Mobile IPv6) header
 * with segments_left=1 and the home address set to ::1.  Both are the
 * shapes mip6's destopt/rthdr input handlers dispatch on the way to
 * xfrm6_input_addr().
 */
static size_t emit_inner_mip6_ext(uint8_t *buf, bool use_rthdr2)
{
	memset(buf, 0, 24);
	buf[0] = IPPROTO_UDP;		/* next_header */
	buf[1] = 2;			/* hdr_ext_len: 24 = 8 * (2 + 1) */
	if (use_rthdr2) {
		buf[2]      = 2;	/* routing_type: Type 2 (Mobile IPv6) */
		buf[3]      = 1;	/* segments_left */
		buf[8 + 15] = 1;	/* home address = ::1 */
	} else {
		buf[2]      = 0xC9;	/* HAO option type */
		buf[3]      = 16;	/* HAO opt data len */
		buf[4 + 15] = 1;	/* home address = ::1 */
		buf[20]     = 1;	/* PadN option type */
		buf[21]     = 2;	/* PadN option data len */
	}
	return 24;
}

/*
 * Build an IPv6 frame that stacks `depth` ESP headers ahead of an
 * inner mip6-shaped extension header (destination-options HAO when
 * !use_rthdr2, type-2 routing otherwise) plus a stub UDP header, then
 * emits `depth` ESP trailers in reverse order so each layer's trailer
 * lands after its own payload on the wire.  Innermost trailer's
 * next_header selects DSTOPTS / ROUTING; outer trailers chain ESP.
 * Returns 0 if depth is out of range; total wire length otherwise.
 */
static size_t build_v6_stacked_esp_frame(uint8_t *buf, const __be32 *spis,
					 unsigned int depth, __u32 seq,
					 bool use_rthdr2)
{
	size_t off;
	uint16_t payload_len;
	unsigned int i;
	uint8_t inner_nh;

	if (depth == 0 || depth > ESPRX_STACK_DEPTH)
		return 0;

	memset(buf, 0, ESPRX_STACK_PKT_MAX);

	buf[0]       = 0x60;
	buf[6]       = IPPROTO_ESP;
	buf[7]       = 64;
	buf[8 + 15]  = 1;		/* saddr = ::1 */
	buf[24 + 15] = 1;		/* daddr = ::1 */
	off = 40;

	for (i = 0; i < depth; i++) {
		*(__be32 *)(buf + off + 0) = spis[i];
		*(__be32 *)(buf + off + 4) = htonl(seq + i);
		off += 8;
	}

	off += emit_inner_mip6_ext(buf + off, use_rthdr2);

	/* Stub inner UDP header (dport/sport 0, len=8, csum 0).  Kernel
	 * walks the extension chain to a ULP; the UDP header just gives
	 * that walk a valid-shaped terminator. */
	buf[off + 5] = 8;
	off += 8;

	inner_nh = use_rthdr2 ? IPPROTO_ROUTING : IPPROTO_DSTOPTS;
	for (i = depth; i > 0; i--) {
		buf[off + 0] = 0;
		buf[off + 1] = (i == depth) ? inner_nh : IPPROTO_ESP;
		off += 2;
	}

	payload_len = (uint16_t)(off - 40);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)payload_len;
	return off;
}

/*
 * Install up to ESPRX_STACK_DEPTH additional v6 inbound null-cipher /
 * null-auth ESP SAs, all keyed on ::1 with sequential SPIs.  Runs only
 * on v6 invocations (v4 has no HAO / type-2 routing equivalent driving
 * xfrm6_input_addr()).  Best-effort: any per-SA install rejection stops
 * the loop early, so the emitter picks up whatever depth succeeded and
 * ctx->stack_depth remains an accurate count for the teardown loop.
 */
static void install_stacked_null_esp_sas(struct esp_crafted_rx_iter_ctx *ctx)
{
	unsigned int i;
	__u32 base_spi;

	if (!ctx->v6)
		return;
	base_spi = (rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN;
	/* Skip a SPI hole around the primary SA so the sequential rotate
	 * does not collide with ctx->spi's kernel-side hash bucket. */
	base_spi = ESPRX_SPI_MIN + ((base_spi + ESPRX_STACK_DEPTH + 1U) %
				    (ESPRX_SPI_RANGE - ESPRX_STACK_DEPTH));
	for (i = 0; i < ESPRX_STACK_DEPTH; i++) {
		__be32 spi = htonl(base_spi + i);
		__u32 reqid = ctx->reqid + i + 1U;

		if (install_null_esp_sa(&ctx->nl, spi, reqid, true) != 0)
			return;
		ctx->stack_spi[ctx->stack_depth++] = spi;
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.stacked_sa_install_ok,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Emit one stacked-ESP v6 frame at ::1 through the v6 raw socket.
 * SPIs are the stacked SAs' SPIs so every layer decapsulates; the
 * inner extension form (HAO destopts vs type-2 routing) flips 50/50
 * so mip6's two entry points into xfrm6_input_addr() are both walked.
 * MSG_DONTWAIT keeps the send inside the SIGALRM(1s) safety net.
 */
static void esp_crafted_rx_send_stacked_v6(struct esp_crafted_rx_iter_ctx *ctx,
					   int fd)
{
	uint8_t pkt[ESPRX_STACK_PKT_MAX];
	struct sockaddr_in6 dst;
	size_t len;

	if (ctx->stack_depth == 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family           = AF_INET6;
	dst.sin6_addr.s6_addr[15] = 1;

	len = build_v6_stacked_esp_frame(pkt, ctx->stack_spi, ctx->stack_depth,
					 pick_esp_seq(), ONE_IN(2));
	if (len == 0)
		return;

	if (sendto(fd, pkt, len, MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.stacked_sent_ok,
				   1, __ATOMIC_RELAXED);
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
		seq         = pick_esp_seq();
		inner_proto = pick_inner_proto();
		trunc_len   = pick_inner_trunc_len();

		if (ctx->v6) {
			struct sockaddr_in6 dst;

			memset(&dst, 0, sizeof(dst));
			dst.sin6_family = AF_INET6;
			dst.sin6_addr.s6_addr[15] = 1;	/* ::1 */
			len = build_v6_frame(pkt, spi, seq, inner_proto,
					     trunc_len);
			n = sendto(fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
		} else {
			struct sockaddr_in dst;

			memset(&dst, 0, sizeof(dst));
			dst.sin_family      = AF_INET;
			dst.sin_addr.s_addr = ESPRX_V4_DADDR_BE;
			len = build_v4_frame(pkt, spi, seq, inner_proto,
					     trunc_len);
			n = sendto(fd, pkt, len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
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
