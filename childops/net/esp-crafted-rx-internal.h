#ifndef _CHILDOPS_NET_ESP_CRAFTED_RX_INTERNAL_H
#define _CHILDOPS_NET_ESP_CRAFTED_RX_INTERNAL_H

/*
 * Shared declarations for the esp-crafted-rx translation units.
 *
 * The op was a single ~1300-line .c file.  Splitting the packet
 * builders, fragmented-inner emitter and stacked-ESP path into
 * per-concern translation units lets the parallel make cover more
 * work; this header carries the UAPI fallbacks, the wire-shape
 * constants, and the per-invocation state struct that the split TUs
 * all reach through.
 *
 * UAPI fallbacks: linux/xfrm.h may be absent on a stripped sysroot;
 * the IDs and structure layouts have been stable in the kernel UAPI
 * since 2.6.x so a compile-time shim is safe.  Guarded by
 * __has_include below so the real header wins when present.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <linux/netlink.h>

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

#include "childops-netlink.h"

struct childdata;

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

/* esp-crafted-rx-helpers.c */
__u16 esprx_ip_csum16(const void *data, size_t len);
uint8_t esprx_pick_inner_proto(void);
uint8_t esprx_pick_inner_trunc_len(void);
__u32 esprx_pick_esp_seq(void);

#endif /* _CHILDOPS_NET_ESP_CRAFTED_RX_INTERNAL_H */
