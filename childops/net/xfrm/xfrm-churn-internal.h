/*
 * xfrm-churn-internal.h
 *
 * Shared declarations split out of childops/net/xfrm/xfrm-churn.c to let the
 * XFRM netlink builder family (build_sa_msg / build_sa_id_msg /
 * build_newpolicy / build_delpolicy / build_allocspi and their
 * attribute / selector / lifetime helpers) live in their own
 * translation unit and compile in parallel with the rest of the
 * module.  This header is private to the two TUs that make up
 * xfrm-churn — do not include it from anywhere else.
 *
 * Contents:
 *   - the conditional <linux/xfrm.h> / <linux/pfkeyv2.h> includes and
 *     their UAPI fallback macros / struct layouts, so both TUs see
 *     exactly the same xfrm symbol values;
 *   - the small set of shared constants the builders need to keep
 *     synchronised with the core (buffer sizes, SPI window, the
 *     loopback selector endpoints);
 *   - the algorithm catalog types (enum xfrm_alg_kind + struct
 *     xfrm_algo_def) consumed by both the core's algo table and the
 *     builders' attribute emitters;
 *   - forward declarations for the builder entry points, deliberately
 *     widened from file-static to external linkage so the per-phase
 *     drivers in xfrm-churn.c can reference them across the TU
 *     boundary.
 */

#ifndef CHILDOPS_XFRM_CHURN_INTERNAL_H
#define CHILDOPS_XFRM_CHURN_INTERNAL_H

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif
#if __has_include(<linux/pfkeyv2.h>)
#include <linux/pfkeyv2.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "pids.h"

/*
 * UAPI fallbacks.  xfrm.h on stripped sysroots may be absent; the
 * IDs and structure layouts are stable in the kernel UAPI.  If the
 * header is missing entirely the __has_include gate above keeps
 * compilation working and these defines fill in.  Layouts are kept
 * in sync with linux/xfrm.h as of Linux 6.18 (no breaking changes
 * since the UAPI stabilised in 2.6.x).
 */
#ifndef XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSA		0x10
#define XFRM_MSG_DELSA		0x11
#define XFRM_MSG_GETSA		0x12
#define XFRM_MSG_NEWPOLICY	0x13
#define XFRM_MSG_DELPOLICY	0x14
#define XFRM_MSG_ALLOCSPI	0x16
#define XFRM_MSG_UPDSA		0x1f
#endif

/* XFRM_MSG_MAPPING (0x21) was added to the UAPI without a matching entry
 * in net/xfrm/xfrm_compat.c::xfrm_msg_min[], which was sized only through
 * XFRM_MSG_GETAE.  A 32-bit task issuing the new opcode against a 64-bit
 * kernel walked off the end of xfrm_msg_min[] reading garbage as the
 * minimum payload size.  Fixed by upstream commit 28465227c80f.  Sysroot
 * shims so the sweep below compiles against older <linux/xfrm.h>. */
#ifndef XFRM_MSG_MAPPING
#define XFRM_MSG_MAPPING	0x21
#endif

#ifndef XFRM_MSG_SETDEFAULT
#define XFRM_MSG_SETDEFAULT	0x22
#endif

#ifndef XFRM_MSG_GETDEFAULT
#define XFRM_MSG_GETDEFAULT	0x23
#endif

/* End of the compat-table sweep range.  Covers MAPPING + the SETDEFAULT
 * / GETDEFAULT pair added after it; widening this picks up any further
 * UAPI additions whose compat-table entry is missing. */
#define XFRM_COMPAT_SWEEP_MAX	XFRM_MSG_GETDEFAULT

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH		1
#define XFRMA_ALG_CRYPT		2
#define XFRMA_ALG_COMP		3
#define XFRMA_TMPL		5
#define XFRMA_ALG_AEAD		18
#endif

#ifndef XFRMA_REPLAY_ESN_VAL
#define XFRMA_REPLAY_ESN_VAL	23
#endif

#ifndef XFRMA_SA_DIR
#define XFRMA_SA_DIR		33
#endif

#ifndef XFRM_SA_DIR_OUT
#define XFRM_SA_DIR_IN		1
#define XFRM_SA_DIR_OUT		2
#endif

#ifndef XFRM_STATE_ESN
#define XFRM_STATE_ESN		128
#endif

#ifndef XFRM_POLICY_OUT
#define XFRM_POLICY_OUT		1
#endif

#ifndef XFRM_MODE_TRANSPORT
#define XFRM_MODE_TRANSPORT	0
#define XFRM_MODE_TUNNEL	1
#endif

/* iptfs (IP-TFS, RFC 9347) mode landed in v6.14 behind CONFIG_XFRM_IPTFS.
 * UAPI value is fixed at 5; older sysroots without the symbol fall
 * through to this shim.  The mode is rejected with EOPNOTSUPP /
 * EINVAL on kernels without IPTFS support, which the install path
 * latches per-child. */
#ifndef XFRM_MODE_IPTFS
#define XFRM_MODE_IPTFS		5
#endif

#ifndef XFRM_POLICY_ALLOW
#define XFRM_POLICY_ALLOW	0
#endif

#ifndef XFRM_SHARE_ANY
#define XFRM_SHARE_ANY		0
#endif

#ifndef PF_KEY_V2
#define PF_KEY_V2		2
#endif

#ifndef SADB_FLUSH
#define SADB_FLUSH		9
#endif

#ifndef SADB_SATYPE_AH
#define SADB_SATYPE_AH		2
#define SADB_SATYPE_ESP		3
#endif

/* xfrm UAPI structure layouts.  Only redefined when linux/xfrm.h is
 * absent on the build sysroot — matches the kernel layout exactly.
 * The __has_include guard above prevents redefinition when the real
 * header is present, so these are pure compile-time fallbacks. */
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

struct xfrm_algo_aead {
	char			alg_name[64];
	unsigned int		alg_key_len;
	unsigned int		alg_icv_len;
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

struct xfrm_userpolicy_info {
	struct xfrm_selector		sel;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	__u32				priority;
	__u32				index;
	__u8				dir;
	__u8				action;
	__u8				flags;
	__u8				share;
};

struct xfrm_userpolicy_id {
	struct xfrm_selector		sel;
	__u32				index;
	__u8				dir;
};

struct xfrm_user_tmpl {
	struct xfrm_id		id;
	__u16			family;
	xfrm_address_t		saddr;
	__u32			reqid;
	__u8			mode;
	__u8			share;
	__u8			optional;
	__u32			aalgos;
	__u32			ealgos;
	__u32			calgos;
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

struct xfrm_userspi_info {
	struct xfrm_usersa_info		info;
	__u32				min;
	__u32				max;
};
#endif /* !__has_include(<linux/xfrm.h>) */

/* PF_KEYv2 sadb_msg fallback layout — stable since RFC 2367. */
#if !__has_include(<linux/pfkeyv2.h>)
struct sadb_msg {
	__u8			sadb_msg_version;
	__u8			sadb_msg_type;
	__u8			sadb_msg_errno;
	__u8			sadb_msg_satype;
	__u16			sadb_msg_len;
	__u16			sadb_msg_reserved;
	__u32			sadb_msg_seq;
	__u32			sadb_msg_pid;
};
#endif

#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH		51
#endif
#ifndef IPPROTO_COMP
#define IPPROTO_COMP		108
#endif

#define XFRM_BUF_BYTES		2048

/* SPI rotation range.  Kernel reserves SPI < 256 for ISAKMP; we
 * stay clear of that range and rotate within [0x100, 0xffffff]. */
#define XFRM_SPI_MIN		0x100U
#define XFRM_SPI_RANGE		0xfff000U

/* Loopback addresses used for the SA selector and inner UDP traffic.
 * 127.0.0.1 -> 127.0.0.2 keeps everything on lo, no routes needed. */
#define XFRM_SADDR_BE		(__be32)__builtin_bswap32(0x7f000001U)
#define XFRM_DADDR_BE		(__be32)__builtin_bswap32(0x7f000002U)

/* UDP destination port for the inner traffic.  Loopback-only inside
 * a private netns; value functionally arbitrary; a fixed
 * non-privileged port keeps any escaped packet trivially identifiable
 * in a tcpdump trace during triage.  Shared with the socket-attached
 * xfrm policy sub-mode, which connects to the same port to prime
 * sk_dst_cache. */
#define XFRM_INNER_PORT		34571

/* Fixed-size inner-burst count used by the AH+ESN async sub-mode.
 * Same value as the main-flow burst floor so the async-hash
 * post-callback (the codepath upstream commit ec54093e6a8f patches)
 * gets a comparable amount of encrypt-side pressure. */
#define XFRM_PACKET_FLOOR	16U

/* SA reqid rotation range.  Kernel uses reqid as a per-policy bundle
 * cache key — rotating across [1, XFRM_REQID_RANGE] spreads the
 * bundle cache without exhausting the kernel's reqid allocator. */
#define XFRM_REQID_RANGE	16U

/*
 * XFRM algorithm rotation.  Each entry is one transform the kernel
 * can install via XFRM_MSG_NEWSA.  proto picks the IPPROTO (ESP/AH/
 * IPCOMP), and the attr_kind tag picks which XFRMA_ALG_* attribute
 * carries the key material — AEAD goes in XFRMA_ALG_AEAD, classic
 * AH auth-only goes in XFRMA_ALG_AUTH, classic ESP enc+auth goes in
 * paired XFRMA_ALG_CRYPT + XFRMA_ALG_AUTH, IPCOMP goes in
 * XFRMA_ALG_COMP.  modname is the kernel crypto module to modprobe
 * (best-effort) the first time the algo is touched.
 */
enum xfrm_alg_kind {
	XFRM_ALG_AEAD,		/* XFRMA_ALG_AEAD only */
	XFRM_ALG_ESP_CBC,	/* XFRMA_ALG_CRYPT + XFRMA_ALG_AUTH */
	XFRM_ALG_ESP_NULL,	/* XFRMA_ALG_CRYPT (cipher_null) + XFRMA_ALG_AUTH */
	XFRM_ALG_AH,		/* XFRMA_ALG_AUTH only */
	XFRM_ALG_AH_NULL,	/* XFRMA_ALG_AUTH digest_null */
	XFRM_ALG_COMP,		/* XFRMA_ALG_COMP only */
};

struct xfrm_algo_def {
	enum xfrm_alg_kind	kind;
	__u8			proto;		/* IPPROTO_ESP/AH/COMP */
	const char		*enc_name;	/* NULL when kind has no enc */
	unsigned int		enc_key_bits;
	const char		*auth_name;	/* NULL when kind has no auth */
	unsigned int		auth_key_bits;
	unsigned int		auth_trunc_bits;
	unsigned int		aead_icv_bits;	/* AEAD only */
	const char		*modname;	/* best-effort modprobe target */
};

/*
 * Cross-TU builder API.  Defined in childops/net/xfrm/xfrm-churn-builders.c;
 * driven by the per-phase helpers in childops/net/xfrm/xfrm-churn.c.  All
 * builders return 0 on netlink-ack success, a negative errno on
 * kernel rejection, or -EIO on local buffer/encode failure (matches
 * nl_send_recv() conventions in include/childops-netlink.h).
 */
void xfrm_churn_fill_selector(struct xfrm_selector *sel, __u8 proto);
void xfrm_churn_fill_lifetime(struct xfrm_lifetime_cfg *lft);
__u32 pick_sa_seq(void);
int build_sa_msg(struct nl_ctx *ctx, __u16 msg_type,
		 const struct xfrm_algo_def *def,
		 __u32 reqid, __be32 spi, __u8 mode, __u32 seq);
int build_sa_id_msg(struct nl_ctx *ctx, __u16 msg_type,
		    __u8 proto, __be32 spi);
int build_newpolicy(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
		    __u32 reqid, __be32 spi, __u8 mode);
int build_delpolicy(struct nl_ctx *ctx);
int build_allocspi(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
		   __u32 reqid, __u8 mode, __u32 seq);

/*
 * Cross-TU inner-traffic drivers.  Defined in
 * childops/net/xfrm/xfrm-churn-traffic.c.  Each returns the count of
 * successful sends so the caller's burst-stats stay symmetric.  The
 * MSG_ZEROCOPY variant exists to drive esp_output's shared-frag / COW
 * branch (esp4.c:876) that the copying sendto path never reaches.
 */
unsigned int drive_inner_traffic(int udp, unsigned int iters,
				 const struct timespec *t0);
unsigned int drive_inner_traffic_zc(int udp, unsigned int iters,
				    const struct timespec *t0);

/*
 * AH+ESN+async-hash sub-mode.  Defined in
 * childops/net/xfrm/xfrm-churn-ah-esn.c.  Installs an AH SA with
 * XFRM_STATE_ESN + a replay-window attribute and an async-friendly
 * auth algorithm name, drives the inner UDP through it (v4 only),
 * then DELSA.  The (AH, ESN, async-algo) trifecta walks the codepath
 * upstream commit ec54093e6a8f patches.
 */
void install_ah_esn_async_sa(struct nl_ctx *ctx, int udp,
			     struct childdata *child);

/*
 * PF_KEYv2 flush alt path.  Defined in
 * childops/net/xfrm/xfrm-churn-pfkey.c.  Opens AF_KEY and emits a
 * SADB_FLUSH for ESP and AH — drives net/key/af_key.c dispatch and
 * flush paths that share the SAD / SPD with the netlink_xfrm side.
 */
void pfkey_flush_burst(struct childdata *child);

/*
 * Socket-attached xfrm policy sub-mode.  Defined in
 * childops/net/xfrm/xfrm-churn-sk-policy.c.  Drives
 * xfrm_user_policy() through both the accepted-and-inserted branch
 * and the rejection branches on a UDP socket whose sk_dst_cache has
 * been primed by connect().  Short-circuits when the shared
 * ns_unsupported_inet latch (set by the main setup path in
 * xfrm-churn.c) or its own per-child latch has fired.
 */
extern bool ns_unsupported_inet;
void xfrm_sk_policy_churn(struct childdata *child);

/*
 * Compat-table opcode sweep.  Defined in
 * childops/net/xfrm/xfrm-churn-compat-sweep.c.  Iterates
 * XFRM_MSG_NEWSA..XFRM_COMPAT_SWEEP_MAX against an already-open
 * NETLINK_XFRM fd to shake off-end indices out of
 * net/xfrm/xfrm_compat.c::xfrm_msg_min[] and the broader xfrm_user
 * dispatch.  Short-circuits on the shared ns_unsupported_xfrm latch
 * set by the main setup path in xfrm-churn.c when NETLINK_XFRM is
 * absent entirely.
 */
extern bool ns_unsupported_xfrm;
void xfrm_compat_msg_sweep(struct nl_ctx *ctx);

/*
 * ALLOCSPI compat lane.  Defined in
 * childops/net/xfrm/xfrm-churn-compat-sweep.c.  Drives
 * XFRM_MSG_ALLOCSPI through the ia32 compat entry point (int 0x80)
 * against an already-open NETLINK_XFRM fd, sweeping payload length
 * across the 228-byte compat xfrm_userspi_info boundary and both
 * AF_INET / AF_INET6 to exercise the double-alloc_compat() 4-byte
 * off-end read in xfrm_alloc_userspi().  No-op on non-x86_64
 * architectures and on kernels without CONFIG_IA32_EMULATION.
 * Short-circuits on the shared ns_unsupported_xfrm latch.
 */
void xfrm_compat_allocspi_sweep(struct nl_ctx *ctx);

#endif /* CHILDOPS_XFRM_CHURN_INTERNAL_H */
