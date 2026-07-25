/*
 * nat-t-churn-internal.h
 *
 * Shared declarations split out of childops/net/xfrm/nat-t-churn.c to let
 * the NAT-T pipeline (setup / SA+policy lifecycle / UDP-encaps traffic /
 * cleanup) live in separate translation units and compile in parallel
 * with the rest of the module.  Private to the TUs that make up
 * nat-t-churn — do not include from anywhere else.
 *
 * Contents:
 *   - the conditional <linux/xfrm.h> include and its UAPI fallback
 *     macros / struct layouts, so every TU in the family sees the same
 *     xfrm symbol values and structure sizes;
 *   - the small set of shared constants the split TUs need to keep in
 *     lockstep (buffer sizes, SPI window, encap port, loopback
 *     endpoints, v6 send-burst tuning);
 *   - the algorithm rotation type (struct nat_t_alg) and encap-choice
 *     enum consumed by both the SA builders and the top-level dispatch;
 *   - forward declarations for the cross-TU function set and extern
 *     declarations for the small pool of file-scope state the pipeline
 *     shares (per-process unsupport latches, per-grandchild lo latch,
 *     iteration counter, rotation tables, v6 documentation address).
 */

#ifndef CHILDOPS_XFRM_NAT_T_CHURN_INTERNAL_H
#define CHILDOPS_XFRM_NAT_T_CHURN_INTERNAL_H

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/sockios.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "kernel/netlink.h"
#include "kernel/socket.h"

/*
 * UAPI fallbacks.  linux/xfrm.h and linux/udp.h are present on every
 * sysroot trinity targets, but the __has_include guard plus these
 * defines keep the file compilable if the build host strips the
 * headers down.  Layouts match the upstream kernel UAPI.
 */
#ifndef XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSA			0x10
#define XFRM_MSG_DELSA			0x11
#endif

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH			1
#define XFRMA_ALG_CRYPT			2
#define XFRMA_ENCAP			4
#define XFRMA_ALG_AUTH_TRUNC		20
#define XFRMA_REPLAY_ESN_VAL		23
#endif

/* Direction + keepalive attributes gate the per-net nat_keepalive
 * worker: the kernel arms it only when (XFRMA_SA_DIR == OUT) coincides
 * with a non-zero XFRMA_NAT_KEEPALIVE_INTERVAL on an encap-bearing SA.
 * UAPI-stable IDs; shim so a stripped <linux/xfrm.h> still builds. */
#ifndef XFRMA_SA_DIR
#define XFRMA_SA_DIR			33
#endif
#ifndef XFRMA_NAT_KEEPALIVE_INTERVAL
#define XFRMA_NAT_KEEPALIVE_INTERVAL	34
#endif
#ifndef XFRM_SA_DIR_OUT
#define XFRM_SA_DIR_IN			1
#define XFRM_SA_DIR_OUT			2
#endif

#ifndef XFRM_MODE_TRANSPORT
#define XFRM_MODE_TRANSPORT		0
#define XFRM_MODE_TUNNEL		1
#endif

#ifndef XFRM_STATE_ESN
#define XFRM_STATE_ESN			128
#endif

#ifndef IPPROTO_ESP
#define IPPROTO_ESP			50
#endif

#ifndef UDP_ENCAP
#define UDP_ENCAP			100
#define UDP_ENCAP_ESPINUDP_NON_IKE	1
#define UDP_ENCAP_ESPINUDP		2
#endif

/* xfrm UAPI structure layouts -- only redefined when linux/xfrm.h is
 * absent.  Layouts match the kernel UAPI exactly. */
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

struct xfrm_algo_auth {
	char			alg_name[64];
	unsigned int		alg_key_len;
	unsigned int		alg_trunc_len;
	char			alg_key[];
};

struct xfrm_algo {
	char			alg_name[64];
	unsigned int		alg_key_len;
	char			alg_key[];
};

struct xfrm_encap_tmpl {
	__u16			encap_type;
	__be16			encap_sport;
	__be16			encap_dport;
	xfrm_address_t		encap_oa;
};

struct xfrm_replay_state_esn {
	unsigned int		bmp_len;
	__u32			oseq;
	__u32			seq;
	__u32			oseq_hi;
	__u32			seq_hi;
	__u32			replay_window;
	__u32			bmp[];
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

#define NAT_T_BUF_BYTES			2048
#define NAT_T_RECV_TIMEO_S		1
#define NAT_T_INNER_PAYLOAD_LEN		96
#define NAT_T_ENCAP_PORT		4500

/* SPI rotation range -- kernel reserves SPI < 256 for ISAKMP. */
#define XFRM_SPI_MIN			0x100U
#define XFRM_SPI_RANGE			0xfff000U

/* Loopback addresses for the SA selector and inner UDP traffic. */
#define NAT_T_SADDR_BE			(__be32)__builtin_bswap32(0x7f000001U)
#define NAT_T_DADDR_BE			(__be32)__builtin_bswap32(0x7f000001U)

enum nat_t_encap_choice {
	NAT_T_ENCAP_ESPINUDP,
	NAT_T_ENCAP_NON_IKE,
	NAT_T_ENCAP_OMIT,	/* tunnel mode only */
};

/* Auth algorithm rotation.  The trailing entry with a deliberately
 * mistyped name is here to keep the kernel's algo lookup error path
 * in the rotation -- without it every iteration would land in the
 * same XFRMA_ALG_AUTH_TRUNC parser branch. */
struct nat_t_alg {
	const char		*name;
	unsigned int		key_bits;
	unsigned int		trunc_bits;	/* auth-only */
};

/* Fake reqid for the v6 SA -- distinct from the v4 path's reqid so
 * the two branches can't accidentally collide on the same template. */
#define NAT_T_V6_REQID			0xc6e6U

/* v6 sendto burst tuning.  BUDGETED+JITTER scales the base; floor/cap
 * clamp the result; the wall-clock cap bounds the burst even if a
 * heavily-overcommited fleet drags the budget multiplier high. */
#define NAT_T_XFRM6_SEND_BASE		5U
#define NAT_T_XFRM6_SEND_FLOOR		16U
#define NAT_T_XFRM6_SEND_CAP		64U
#define NAT_T_XFRM6_SEND_NS_CAP		200000000L	/* 200 ms */

/* Bounded retry on transient SA-install failure (EAGAIN/EBUSY/ENOMEM). */
#define NAT_T_XFRM6_RETRY_CAP		8U

/*
 * Shared file-scope state.  Defined in nat-t-churn-setup.c; every
 * other TU in the family sees the same latches / iteration counter /
 * documentation address via extern.
 */
extern bool ns_unsupported_nat_t;
extern bool ns_unsupported_xfrm6;
extern bool lo_brought_up;
extern __u32 g_iter;
extern const __u8 nat_t_v6_addr[16];

/*
 * Cross-TU function set.  Bodies live in the file named in the
 * comment beside each prototype.
 */
/* nat-t-churn-setup.c */
void warn_once_unsupported(const char *reason, int err);
void bring_lo_up(void);

/* nat-t-churn-sa.c -- algorithm-rotation tables plus their sizes.
 * Cross-TU callers spin an index via rnd_modulo_u32(<name>_n); the
 * paired _n avoids leaking sizeof onto the extern array declarations. */
extern const struct nat_t_alg nat_t_auth_algs[];
extern const struct nat_t_alg nat_t_crypt_algs[];
extern const __u8 nat_t_replay_windows[];
extern const __u32 nat_t_esn_seq_hi_edges[];
extern const size_t nat_t_auth_algs_n;
extern const size_t nat_t_crypt_algs_n;
extern const size_t nat_t_replay_windows_n;
extern const size_t nat_t_esn_seq_hi_edges_n;

/* nat-t-churn-sa.c -- SA attribute assemblers.  The fill / append
 * helpers write directly into the caller's buffer; nat_t_pick_seq_hi() rolls
 * an ESN seq_hi with edge-value bias. */
void nat_t_fill_selector(struct xfrm_selector *sel);
void nat_t_fill_lifetime(struct xfrm_lifetime_cfg *lft);
size_t nat_t_append_auth_trunc(unsigned char *buf, size_t off, size_t cap,
			 const struct nat_t_alg *a);
size_t nat_t_append_crypt(unsigned char *buf, size_t off, size_t cap,
		    const struct nat_t_alg *a);
size_t nat_t_append_encap(unsigned char *buf, size_t off, size_t cap,
		    __u16 encap_type);
size_t nat_t_append_replay_esn(unsigned char *buf, size_t off, size_t cap,
			 __u32 replay_window, __u32 seq_hi);
__u32 nat_t_pick_seq_hi(void);

/* nat-t-churn-sa.c -- XFRM_MSG_NEWSA / XFRM_MSG_DELSA netlink
 * assemblers.  v4 and v6 walk the same attribute set but pick their
 * selector / template / id addresses from NAT_T_[SD]ADDR_BE and
 * nat_t_v6_addr respectively. */
int nat_t_build_newsa(struct nl_ctx *ctx, __be32 spi, __u8 mode, bool esn,
		      enum nat_t_encap_choice encap_choice,
		      __u8 replay_window,
		      const struct nat_t_alg *auth,
		      const struct nat_t_alg *crypt);
int nat_t_build_delsa(struct nl_ctx *ctx, __be32 spi);
int nat_t_build_newsa6(struct nl_ctx *ctx, __be32 spi, __u8 mode, bool esn,
		       enum nat_t_encap_choice encap_choice,
		       __u8 replay_window,
		       const struct nat_t_alg *auth,
		       const struct nat_t_alg *crypt);
int nat_t_build_delsa6(struct nl_ctx *ctx, __be32 spi);

/* nat-t-churn-cleanup.c -- nat_keepalive construct-error and teardown
 * driver.  One call = one NEWSA-that-arms-a-worker plus a matching
 * DELSA, walking both the construct-error cleanup and the successful
 * teardown paths depending on the rolled (direction, encap, interval)
 * triple's coherence. */
void nat_keepalive_err_cycle(struct nl_ctx *ctx);

#endif /* CHILDOPS_XFRM_NAT_T_CHURN_INTERNAL_H */
