#pragma once

/*
 * Internal interface shared between the proto-netlink-xfrm-*.c modules
 * (core, ring, attr, emit).  Carries the XFRM UAPI fallbacks (when the
 * build sysroot is missing linux/xfrm.h), the per-process ring slot
 * types, and cross-module function prototypes.
 */

#include <stdbool.h>
#include <stdint.h>

#include <linux/netlink.h>
#include <netinet/in.h>

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

/*
 * UAPI fallbacks.  linux/xfrm.h on stripped sysroots may be absent;
 * the IDs and structure layouts are stable in the kernel UAPI.  The
 * __has_include guard above prevents redefinition when the real
 * header is present.
 */
#ifndef SOL_NETLINK
#define SOL_NETLINK			270
#endif

#ifndef XFRM_MSG_NEWSA
/* values per include/uapi/linux/xfrm.h */
#define XFRM_MSG_NEWSA			0x10
#define XFRM_MSG_DELSA			0x11
#define XFRM_MSG_NEWPOLICY		0x13
#define XFRM_MSG_DELPOLICY		0x14
#define XFRM_MSG_ALLOCSPI		0x16
#define XFRM_MSG_ACQUIRE		0x17
#define XFRM_MSG_EXPIRE			0x18
#define XFRM_MSG_UPDSA			0x1a
#define XFRM_MSG_POLEXPIRE		0x1b
#define XFRM_MSG_FLUSHSA		0x1c
#define XFRM_MSG_FLUSHPOLICY		0x1d
#define XFRM_MSG_NEWAE			0x1e
#define XFRM_MSG_MIGRATE		0x21
#define XFRM_MSG_SETDEFAULT		0x27
#define XFRM_MSG_GETDEFAULT		0x28
#endif

#ifndef XFRM_USERPOLICY_BLOCK
struct xfrm_userpolicy_default {
	__u8 in;
	__u8 fwd;
	__u8 out;
};
#define XFRM_USERPOLICY_UNSPEC		0
#define XFRM_USERPOLICY_BLOCK		1
#define XFRM_USERPOLICY_ACCEPT		2
#endif

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH			1
#define XFRMA_ALG_CRYPT			2
#define XFRMA_ALG_COMP			3
#define XFRMA_ENCAP			4
#define XFRMA_TMPL			5
#define XFRMA_LTIME_VAL			9
#define XFRMA_REPLAY_VAL		10
#define XFRMA_MIGRATE			17
#define XFRMA_ALG_AEAD			18
#define XFRMA_ALG_AUTH_TRUNC		20
#define XFRMA_REPLAY_ESN_VAL		23
#define XFRMA_SA_EXTRA_FLAGS		24
#define XFRMA_OFFLOAD_DEV		28
#define XFRMA_SET_MARK			29
#define XFRMA_SET_MARK_MASK		30
#define XFRMA_IF_ID			31
#endif

#ifndef XFRM_POLICY_OUT
#define XFRM_POLICY_OUT			1
#endif
#ifndef XFRM_POLICY_ALLOW
#define XFRM_POLICY_ALLOW		0
#endif
#ifndef XFRM_SHARE_ANY
#define XFRM_SHARE_ANY			0
#endif

#ifndef XFRM_MODE_TRANSPORT
#define XFRM_MODE_TRANSPORT		0
#define XFRM_MODE_TUNNEL		1
#define XFRM_MODE_ROUTEOPTIMIZATION	2
#define XFRM_MODE_IN_TRIGGER		3
#define XFRM_MODE_BEET			4
#endif

#ifndef XFRM_STATE_ESN
#define XFRM_STATE_NOECN		1
#define XFRM_STATE_DECAP_DSCP		2
#define XFRM_STATE_NOPMTUDISC		4
#define XFRM_STATE_WILDRECV		8
#define XFRM_STATE_AF_UNSPEC		32
#define XFRM_STATE_ALIGN4		64
#define XFRM_STATE_ESN			128
#endif

#ifndef IPPROTO_ESP
#define IPPROTO_ESP			50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH			51
#endif
#ifndef IPPROTO_COMP
#define IPPROTO_COMP			108
#endif

#ifndef UDP_ENCAP_ESPINUDP_NON_IKE
#define UDP_ENCAP_ESPINUDP_NON_IKE	1
#define UDP_ENCAP_ESPINUDP		2
#define UDP_ENCAP_L2TPINUDP		3
#endif

#ifndef IPSEC_PROTO_ANY
#define IPSEC_PROTO_ANY			255
#endif

#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP		1
#endif

/* XFRMNLGRP_* IDs per include/uapi/linux/xfrm.h.  Multicast groups the
 * kernel publishes on NETLINK_XFRM for asynchronous events. */
#ifndef XFRMNLGRP_ACQUIRE
#define XFRMNLGRP_ACQUIRE		1
#define XFRMNLGRP_EXPIRE		2
#define XFRMNLGRP_SA			3
#define XFRMNLGRP_POLICY		4
#endif

/*
 * Compile-time fallbacks for the xfrm UAPI structure layouts we need.
 * Layouts match linux/xfrm.h as of kernel 6.18 (the structures have
 * been stable since the UAPI settled in 2.6.x).  Only used when the
 * real header is missing on the build sysroot.
 */
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

struct xfrm_replay_state {
	__u32			oseq;
	__u32			seq;
	__u32			bitmap;
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

struct xfrm_encap_tmpl {
	__u16			encap_type;
	__be16			encap_sport;
	__be16			encap_dport;
	xfrm_address_t		encap_oa;
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

struct xfrm_usersa_flush {
	__u8				proto;
};

struct xfrm_aevent_id {
	struct xfrm_usersa_id		sa_id;
	xfrm_address_t			saddr;
	__u32				flags;
	__u32				reqid;
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

struct xfrm_user_polexpire {
	struct xfrm_userpolicy_info	pol;
	__u8				hard;
};

struct xfrm_user_migrate {
	xfrm_address_t			old_daddr;
	xfrm_address_t			old_saddr;
	xfrm_address_t			new_daddr;
	xfrm_address_t			new_saddr;
	__u8				proto;
	__u8				mode;
	__u16				reserved;
	__u32				reqid;
	__u16				old_family;
	__u16				new_family;
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

struct xfrm_user_acquire {
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_selector		sel;
	struct xfrm_userpolicy_info	policy;
	__u32				aalgos;
	__u32				ealgos;
	__u32				calgos;
	__u32				seq;
};

struct xfrm_user_offload {
	int				ifindex;
	__u8				flags;
};

enum xfrm_ae_ftype_t {
	XFRM_AE_UNSPEC,
	XFRM_AE_RTHR	= 1,
	XFRM_AE_RVAL	= 2,
	XFRM_AE_LVAL	= 4,
	XFRM_AE_ETHR	= 8,
	XFRM_AE_CR	= 16,
	XFRM_AE_CE	= 32,
	XFRM_AE_CU	= 64,
};
#endif /* !__has_include(<linux/xfrm.h>) */

#define XFRM_BUF_BYTES		2048

/*
 * SA tracking ring.  NEWSA acceptances push (daddr, spi, proto, family,
 * reqid) entries; UPDSA / NEWAE / DELSA target a random entry; DELSA
 * acceptance removes the slot; FLUSHSA acceptance drains every slot.
 * Ring full causes oldest-eviction with a synchronous DELSA so the
 * SAD doesn't grow without bound across thousands of invocations.
 */
#define NR_SA_RING_SLOTS	8

struct xfrm_sa_track {
	bool			used;
	__u8			evict_fail;	/* consecutive DELSA failures */
	__u16			family;		/* AF_INET / AF_INET6 */
	__u8			proto;		/* IPPROTO_ESP / AH / COMP */
	xfrm_address_t		daddr;
	__be32			spi;
	__u32			reqid;
};

/*
 * Policy tracking ring.  NEWPOLICY acceptances push (sel, dir, family)
 * entries; POLEXPIRE targets a random entry; FLUSHPOLICY drains every
 * slot.  Smaller than the SA ring because POLEXPIRE is the only consumer
 * today.  No eviction-emit on push -- a stale slot just gets overwritten;
 * the kernel handles a POLEXPIRE on a no-longer-installed policy by
 * bouncing on ESRCH which is a fine no-op.
 */
#define NR_POLICY_RING_SLOTS	4

struct xfrm_policy_track {
	struct xfrm_selector	sel;
	__u8			dir;
	__u16			family;
	bool			used;
};

/*
 * Cross-module API.  The four proto-netlink-xfrm-*.c TUs are wired
 * together through these externs; nothing here leaks outside the
 * grammar.
 */

/* Core helpers (net/proto/netlink-xfrm.c) */
extern bool unsupported_xfrm;
__u32 xfrm_next_seq(void);
size_t xfrm_nla_put(unsigned char *buf, size_t off, size_t cap,
		    unsigned short type, const void *data, size_t len);
int xfrm_send_recv(int fd, void *msg, size_t len);
bool is_structural_reject(int rc);
void latch_unsupported(int rc);
void mcast_fd_open(void);
void xfrm_drain_mcast(void);
void xfrm_drain_async(int fd);

/* SA + policy ring (net/proto/netlink-xfrm-ring.c) */
unsigned int sa_ring_count(void);
int sa_ring_push(int fd, const struct xfrm_sa_track *entry);
bool sa_ring_pick(struct xfrm_sa_track *out, unsigned int *idx_out);
void sa_ring_drop(unsigned int idx);
void sa_ring_drain(void);
int xfrm_emit_delsa_for(int fd, const struct xfrm_sa_track *t);
unsigned int policy_ring_count(void);
void policy_ring_push(const struct xfrm_policy_track *entry);
bool policy_ring_pick(struct xfrm_policy_track *out, unsigned int *idx_out);
void policy_ring_drain(void);

/* Attribute / selector / address helpers (net/proto/netlink-xfrm-attr.c) */
size_t append_auth_trunc(unsigned char *buf, size_t off, size_t cap);
size_t append_crypt(unsigned char *buf, size_t off, size_t cap);
size_t append_aead(unsigned char *buf, size_t off, size_t cap);
size_t append_comp(unsigned char *buf, size_t off, size_t cap);
size_t append_encap_maybe(unsigned char *buf, size_t off, size_t cap);
size_t append_replay_maybe(unsigned char *buf, size_t off, size_t cap,
			   __u8 *flags_inout);
size_t append_marks_and_if(unsigned char *buf, size_t off, size_t cap);
void fill_addresses(__u16 family, xfrm_address_t *saddr,
		    xfrm_address_t *daddr);
__u8 pick_prefixlen(__u16 family);
__u8 pick_proto(void);
__u8 pick_mode(void);
__u8 pick_sa_proto(void);
__u16 pick_family(void);
void fill_selector(struct xfrm_selector *sel, __u16 family);
void fill_lifetime(struct xfrm_lifetime_cfg *lft);

/* Message builders (net/proto/netlink-xfrm-emit.c) */
int xfrm_emit_newsa(int fd);
int xfrm_emit_allocspi(int fd);
int xfrm_emit_updsa(int fd);
int xfrm_emit_newae(int fd);
int xfrm_emit_delsa_random(int fd);
int xfrm_emit_expire(int fd);
int xfrm_emit_newpolicy(int fd);
int xfrm_emit_delpolicy(int fd);
int xfrm_emit_flushsa(int fd);
int xfrm_emit_flushpolicy(int fd);
int xfrm_emit_migrate(int fd);
int xfrm_emit_polexpire(int fd);
int xfrm_emit_acquire(int fd);
int xfrm_emit_setdefault(int fd);
int xfrm_emit_getdefault(int fd);
