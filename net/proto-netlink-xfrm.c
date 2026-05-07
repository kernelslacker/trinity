/*
 * proto-netlink-xfrm.c -- coherent XFRM (IPsec) netlink grammar.
 *
 * grammar_xfrm is a second AF_NETLINK slot in the per-family grammar
 * registry alongside grammar_netlink (proto-netlink.c).  The two slots
 * cover orthogonal angles of the AF_NETLINK surface:
 *
 *   grammar_netlink  - membership churn + SOL_NETLINK toggle walk over
 *                      a randomly-picked subset of well-supported
 *                      protocols (GENERIC / ROUTE / NETFILTER /
 *                      KOBJECT_UEVENT / AUDIT).  Drives netlink_table_grab
 *                      / nl_groups_alloc / sockopt dispatch.  Pays no
 *                      attention to message shape -- the data leg falls
 *                      back to proto_netlink.gen_msg's per-protocol
 *                      random attribute fuzzer.
 *
 *   grammar_xfrm     - this file.  Pinned to NETLINK_XFRM, walks the
 *                      SA + SP control surface message-by-message
 *                      across NEWSA / UPDSA / NEWAE / DELSA / NEWPOLICY
 *                      / DELPOLICY / FLUSHSA / FLUSHPOLICY with coherent
 *                      attribute pairing inside each message and a
 *                      per-process ring of installed SAs so UPDSA / NEWAE
 *                      / DELSA target a real previously-installed SA
 *                      instead of a random spi the kernel rejects on
 *                      lookup.  This is the layer the random per-syscall
 *                      fuzzer cannot synthesise -- it never assembles
 *                      a NEWSA with paired XFRMA_ALG_AUTH_TRUNC +
 *                      XFRMA_ALG_CRYPT + XFRMA_ENCAP + XFRMA_REPLAY_ESN_VAL
 *                      and follows it with an UPDSA on the same shell.
 *
 * Why a second SFG slot, not (b) extend grammar_netlink, not (c) extend
 * childops/xfrm-churn.c:
 *
 *   (b) is messy.  grammar_netlink is single-purpose: membership churn
 *       + SOL_NETLINK toggle walk + protocol-agnostic data leg.
 *       Branching internally on nl_pid + protocol to dispatch
 *       XFRM-shaped messages would dilute that slot's distribution
 *       (it currently biases SOCK_RAW across 5 protocols) and bury
 *       XFRM-specific attribute assembly inside what is structurally
 *       a generic-netlink walker.
 *
 *   (c) is occupied with a different mission.  childops/xfrm-churn.c
 *       drives live ESP traffic through a freshly-installed SA + SP
 *       bundle inside a private netns -- it exists to open the
 *       teardown-vs-encrypt race window, not to enumerate the XFRM
 *       attribute / message space.  Stuffing deep XFRMA_REPLAY_ESN_VAL
 *       / XFRMA_OFFLOAD_DEV / XFRMA_ENCAP / XFRMA_IF_ID coverage into
 *       it would dilute the live-traffic race that is the whole point
 *       of the op.
 *
 *   (a) -- this file -- fits cleanly.  The SFG registry pattern
 *       (see proto-rxrpc.c, proto-mctp.c, proto-llc.c, proto-mpls.c,
 *       proto-qrtr.c, proto-kcm.c) is one file per coherent walk
 *       angle.  grammar_xfrm registers as a sibling slot to
 *       grammar_netlink at family=PF_NETLINK; the picker treats them
 *       independently.  The shared shm->sfg_unsupported[PF_NETLINK]
 *       latch is intentionally NOT used -- this grammar carries its
 *       own xfrm_unsupported flag so a kernel without
 *       CONFIG_XFRM_USER doesn't disable grammar_netlink's NETLINK_GENERIC
 *       walk on its way down.
 *
 * Coverage shape (one message per data_leg invocation; rotates):
 *
 *   NEWSA      - xfrm_usersa_info plus a coherent attribute set drawn
 *                from XFRMA_ALG_AEAD vs paired XFRMA_ALG_CRYPT +
 *                XFRMA_ALG_AUTH_TRUNC, optional XFRMA_ALG_COMP,
 *                optional XFRMA_ENCAP (ESPINUDP / ESPINUDP_NON_IKE /
 *                NON-NAT), optional XFRMA_REPLAY_VAL or
 *                XFRMA_REPLAY_ESN_VAL with seq_hi / oseq_hi ramped
 *                through 0 / 1 / 0xFFFFFFFE / 0xFFFFFFFF / random and
 *                bmp_len edge values.  XFRMA_OUTPUT_MARK / XFRMA_SET_MARK
 *                / XFRMA_SET_MARK_MASK / XFRMA_IF_ID / XFRMA_SA_EXTRA_FLAGS
 *                rotate independently.  Family AF_INET / AF_INET6 with
 *                proper saddr / daddr sized matches; mode TRANSPORT /
 *                TUNNEL / BEET / RO / IN_TRIGGER; selector prefixlen
 *                rotates including 0 / 32 / 33 (AF_INET) and 0 / 128 /
 *                129 (AF_INET6) edges.  On accept, push (daddr, spi,
 *                proto, family) onto the SA ring for later targeting.
 *
 *   UPDSA      - target a previously-installed SA from the ring,
 *                rebuild the same shell with a fresh random key and
 *                rotated attribute set.  No-op if the ring is empty.
 *
 *   NEWAE      - xfrm_aevent_id targeting a ring SA, with rotated
 *                XFRM_AE_* flags driving XFRMA_REPLAY_VAL /
 *                XFRMA_REPLAY_ESN_VAL / XFRMA_LTIME_VAL parser arms.
 *
 *   DELSA      - target a previously-installed SA from the ring (the
 *                oldest, on a ring-full eviction; otherwise random).
 *                Removes the ring entry on accept.
 *
 *   NEWPOLICY  - xfrm_userpolicy_info OUT direction with XFRMA_TMPL
 *                pointing at a random ring SA when one exists, or a
 *                synthesised template otherwise.  Selectors rotate
 *                across the prefixlen edges and proto matrix (UDP /
 *                TCP / ICMP / any).
 *
 *   DELPOLICY  - xfrm_userpolicy_id OUT.
 *
 *   FLUSHSA    - xfrm_usersa_flush with rotated proto (ESP / AH /
 *                COMP / IPSEC_PROTO_ANY).  On accept, drain the SA
 *                ring -- every entry is now stale.
 *
 *   FLUSHPOLICY - bare nlmsghdr.
 *
 * EXPIRE ack consumption: NETLINK_XFRM multicasts xfrm_user_expire
 * events into the receive buffer when soft / hard lifetimes fire.
 * Without active drainage the socket buffer fills and bind() on the
 * next iteration's fresh socket can succeed but recv() of the ack
 * blocks.  Each iteration drains the inbound side with non-blocking
 * recv() until EAGAIN before the message send.
 *
 * Cleanup discipline: SA ring caps at NR_SA_RING_SLOTS; eviction does
 * a synchronous DELSA on the oldest entry before overwriting the slot
 * (so the SAD doesn't grow without bound under repeated NEWSA runs
 * across thousands of grammar invocations).  On grammar shutdown the
 * fuzzer doesn't get a chance to drain -- the periodic FLUSHSA
 * rotation slot handles that case in steady state.
 *
 * Graceful degradation: the first send that returns -EPERM (no
 * CAP_NET_ADMIN, kernel without CONFIG_XFRM_USER, or kernel-side
 * lockdown) latches xfrm_unsupported and the grammar early-returns on
 * subsequent invocations.  Single outputerr line on the false->true
 * transition matches the uniform pattern from the
 * unsupported_<name>-on-fds-providers refactor.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/netlink.h>

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

#include "net.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

/*
 * UAPI fallbacks.  linux/xfrm.h on stripped sysroots may be absent;
 * the IDs and structure layouts are stable in the kernel UAPI.  The
 * __has_include guard above prevents redefinition when the real
 * header is present.
 */
#ifndef NETLINK_XFRM
#define NETLINK_XFRM			6
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK			270
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK			11
#endif
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK			10
#endif

#ifndef XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSA			0x10
#define XFRM_MSG_DELSA			0x11
#define XFRM_MSG_NEWPOLICY		0x13
#define XFRM_MSG_DELPOLICY		0x14
#define XFRM_MSG_EXPIRE			0x18
#define XFRM_MSG_UPDSA			0x1f
#define XFRM_MSG_FLUSHSA		0x19
#define XFRM_MSG_FLUSHPOLICY		0x1a
#define XFRM_MSG_NEWAE			0x1b
#endif

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH			1
#define XFRMA_ALG_CRYPT			2
#define XFRMA_ALG_COMP			3
#define XFRMA_ENCAP			4
#define XFRMA_TMPL			5
#define XFRMA_LTIME_VAL			9
#define XFRMA_REPLAY_VAL		10
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
	__u16			family;		/* AF_INET / AF_INET6 */
	__u8			proto;		/* IPPROTO_ESP / AH / COMP */
	xfrm_address_t		daddr;
	__be32			spi;
	__u32			reqid;
};

static struct xfrm_sa_track sa_ring[NR_SA_RING_SLOTS];
static unsigned int sa_ring_next;	/* next-write cursor */

/* Latched-once flag: NETLINK_XFRM open or first NEWSA returns -EPERM
 * / -ENOPROTOOPT / -ENOSYS / -EAFNOSUPPORT / -EPROTONOSUPPORT.  Any
 * of those signal "this kernel build / process won't ever drive
 * NETLINK_XFRM successfully" and we early-return on every subsequent
 * grammar invocation. */
static bool unsupported_xfrm;

static __u32 g_xfrm_seq;

static __u32 xfrm_next_seq(void)
{
	return ++g_xfrm_seq;
}

/*
 * Append a netlink attribute (TLV) at offset off in buf.  Returns the
 * new offset on success, 0 on overflow (caller must check).
 */
static size_t xfrm_nla_put(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

/*
 * Drain any inbound multicast / event traffic the kernel queued on
 * this fd.  NETLINK_XFRM emits xfrm_user_expire when soft / hard
 * lifetimes fire and async events on UPDSA acks; without drainage the
 * receive buffer fills and the next iteration's recv() of an ack
 * blocks past the SIGALRM cap.
 */
static void xfrm_drain_async(int fd)
{
	unsigned char buf[1024];
	int n;

	for (n = 0; n < 32; n++) {
		ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (r <= 0)
			break;
	}
}

/*
 * Send a netlink message and consume one ack.  Returns 0 on a positive
 * ack, the negated errno on a kernel rejection, -EIO on local I/O
 * failure.  Latches unsupported_xfrm on the first persistent
 * "structurally won't work" rejection.
 */
static int xfrm_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return 0;
}

/* Transition-once latch.  EPERM / EAFNOSUPPORT / EPROTONOSUPPORT /
 * EOPNOTSUPP from NEWSA all signal "this kernel won't accept any of
 * our control-plane messages on this fd" -- early-return forever. */
static bool is_structural_reject(int rc)
{
	return rc == -EPERM || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP ||
	       rc == -ENOSYS || rc == -ENOPROTOOPT;
}

static void latch_unsupported(int rc)
{
	if (unsupported_xfrm)
		return;
	unsupported_xfrm = true;
	outputerr("xfrm grammar: NETLINK_XFRM rejected with %s -- latching unsupported_xfrm\n",
		  strerror(-rc));
}

/*
 * SA ring management.  Push acquires the next slot; if the slot was
 * already occupied, evict by DELSA before overwriting.  Random pick
 * draws from used slots; returns false when the ring is empty.  Drop
 * clears a single slot.  Drain clears every slot (called after FLUSHSA).
 */
static unsigned int sa_ring_count(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < NR_SA_RING_SLOTS; i++)
		if (sa_ring[i].used)
			n++;
	return n;
}

/* Build XFRM_MSG_DELSA targeting one ring entry.  Used both for direct
 * DELSA rotation and for ring eviction. */
static int xfrm_emit_delsa_for(int fd, const struct xfrm_sa_track *t)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	uid->daddr  = t->daddr;
	uid->spi    = t->spi;
	uid->family = t->family;
	uid->proto  = t->proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

static void sa_ring_push(int fd, const struct xfrm_sa_track *entry)
{
	struct xfrm_sa_track *slot = &sa_ring[sa_ring_next];

	if (slot->used)
		(void)xfrm_emit_delsa_for(fd, slot);

	*slot = *entry;
	slot->used = true;
	sa_ring_next = (sa_ring_next + 1) % NR_SA_RING_SLOTS;
}

static bool sa_ring_pick(struct xfrm_sa_track *out, unsigned int *idx_out)
{
	unsigned int i, count = sa_ring_count();
	unsigned int pick, seen = 0;

	if (count == 0)
		return false;

	pick = rand32() % count;
	for (i = 0; i < NR_SA_RING_SLOTS; i++) {
		if (!sa_ring[i].used)
			continue;
		if (seen == pick) {
			*out = sa_ring[i];
			if (idx_out)
				*idx_out = i;
			return true;
		}
		seen++;
	}
	return false;
}

static void sa_ring_drop(unsigned int idx)
{
	if (idx < NR_SA_RING_SLOTS)
		sa_ring[idx].used = false;
}

static void sa_ring_drain(void)
{
	unsigned int i;

	for (i = 0; i < NR_SA_RING_SLOTS; i++)
		sa_ring[i].used = false;
}

/*
 * Algorithm rotation tables.  Names include deliberately-mistyped
 * entries so the kernel-side request_module / crypto_alloc_*() failure
 * arms get coverage too -- a fuzzer that only ever submits well-formed
 * algorithm names never reaches the rejection paths.
 */
static const char * const auth_trunc_names[] = {
	"hmac(sha256)",
	"hmac(sha384)",
	"hmac(sha1)",
	"hmac(sha512)",
	"aes-xcbc-mac",
	"hmac(sha22)",			/* deliberately invalid -- exercises
					 * crypto_alloc_ahash() rejection arm */
};

static const char * const crypt_names[] = {
	"cbc(aes)",
	"cbc(des3_ede)",
	"ecb(cipher_null)",
	"rfc3686(ctr(aes))",
	"cbc(garbage)",			/* deliberately invalid */
};

static const char * const aead_names[] = {
	"rfc4106(gcm(aes))",
	"rfc4543(gcm(aes))",
	"rfc7539esp(chacha20,poly1305)",
	"rfc4309(ccm(aes))",
	"gcm(no-such-cipher)",		/* deliberately invalid */
};

static const char * const comp_names[] = {
	"deflate",
	"lzs",
	"lzjh",
	"frobnicate",			/* deliberately invalid */
};

/*
 * Append paired XFRMA_ALG_AUTH_TRUNC + XFRMA_ALG_CRYPT attributes.
 * AUTH_TRUNC is the modern variant of XFRMA_ALG_AUTH and carries the
 * trunc_len field separately -- the kernel parser treats them as
 * mutually exclusive but interesting parser arms exist on either path.
 */
static size_t append_auth_trunc(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo_auth *au;
	unsigned char abuf[sizeof(*au) + 64];
	const char *name = auth_trunc_names[rand32() % ARRAY_SIZE(auth_trunc_names)];
	unsigned int key_bits = 128 + ((rand32() & 3) * 64);	/* 128/192/256/320 */
	unsigned int key_bytes = key_bits / 8;

	if (key_bytes > 64)
		key_bytes = 64;

	memset(abuf, 0, sizeof(abuf));
	au = (struct xfrm_algo_auth *)abuf;
	strncpy(au->alg_name, name, sizeof(au->alg_name) - 1);
	au->alg_key_len   = key_bits;
	/* Trunc length: rotate the common suite values plus a few edge
	 * cases (0 = invalid, key_bits + 8 = oversized, key_bits / 2 =
	 * mid-truncation).  Drives the trunc_len validation arm in
	 * xfrm_alg_auth_len() / esp_init_authenc(). */
	{
		static const unsigned int trunc_choices[] = {
			96, 128, 160, 192, 256,
			0,			/* invalid -- exercises rejection */
		};
		au->alg_trunc_len = trunc_choices[rand32() % ARRAY_SIZE(trunc_choices)];
		if ((rand32() & 7) == 0)
			au->alg_trunc_len = key_bits + 8;	/* oversized */
	}
	generate_rand_bytes((unsigned char *)au->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_AUTH_TRUNC,
			    abuf, sizeof(*au) + key_bytes);
}

static size_t append_crypt(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo *enc;
	unsigned char ebuf[sizeof(*enc) + 64];
	const char *name = crypt_names[rand32() % ARRAY_SIZE(crypt_names)];
	unsigned int key_bits = 128 + ((rand32() & 3) * 64);
	unsigned int key_bytes = key_bits / 8;

	if (key_bytes > 64)
		key_bytes = 64;

	memset(ebuf, 0, sizeof(ebuf));
	enc = (struct xfrm_algo *)ebuf;
	strncpy(enc->alg_name, name, sizeof(enc->alg_name) - 1);
	enc->alg_key_len = key_bits;
	generate_rand_bytes((unsigned char *)enc->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_CRYPT,
			    ebuf, sizeof(*enc) + key_bytes);
}

static size_t append_aead(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo_aead *aead;
	unsigned char abuf[sizeof(*aead) + 64];
	const char *name = aead_names[rand32() % ARRAY_SIZE(aead_names)];
	unsigned int key_bits = 160 + ((rand32() & 3) * 32);	/* 160/192/224/256 */
	unsigned int key_bytes = key_bits / 8;
	static const unsigned int icv_choices[] = { 64, 96, 128, 160, 192 };

	if (key_bytes > 64)
		key_bytes = 64;

	memset(abuf, 0, sizeof(abuf));
	aead = (struct xfrm_algo_aead *)abuf;
	strncpy(aead->alg_name, name, sizeof(aead->alg_name) - 1);
	aead->alg_key_len = key_bits;
	aead->alg_icv_len = icv_choices[rand32() % ARRAY_SIZE(icv_choices)];
	generate_rand_bytes((unsigned char *)aead->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_AEAD,
			    abuf, sizeof(*aead) + key_bytes);
}

static size_t append_comp(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo *comp;
	unsigned char cbuf[sizeof(*comp) + 8];
	const char *name = comp_names[rand32() % ARRAY_SIZE(comp_names)];

	memset(cbuf, 0, sizeof(cbuf));
	comp = (struct xfrm_algo *)cbuf;
	strncpy(comp->alg_name, name, sizeof(comp->alg_name) - 1);
	comp->alg_key_len = 0;

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_COMP, cbuf, sizeof(*comp));
}

/*
 * UDP encapsulation: rotates ESPINUDP / ESPINUDP_NON_IKE / L2TP plus
 * the always-allowed "no encap" case (we just don't emit the attr).
 * Source / destination ports rotate across the IPsec-NAT well-known
 * ports (4500, 500) plus an ephemeral-range pick.
 */
static size_t append_encap_maybe(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_encap_tmpl encap;
	static const __u16 encap_types[] = {
		UDP_ENCAP_ESPINUDP,
		UDP_ENCAP_ESPINUDP_NON_IKE,
		UDP_ENCAP_L2TPINUDP,
	};
	static const __u16 ports[] = {
		4500, 500, 1701, 0,
	};

	if ((rand32() & 1) == 0)
		return off;	/* skip half the time -- "no encap" path */

	memset(&encap, 0, sizeof(encap));
	encap.encap_type  = encap_types[rand32() % ARRAY_SIZE(encap_types)];
	encap.encap_sport = htons(ports[rand32() % ARRAY_SIZE(ports)] +
				  (rand32() & 1U ? 1024 + (rand32() & 0xfff) : 0));
	encap.encap_dport = htons(ports[rand32() % ARRAY_SIZE(ports)]);
	encap.encap_oa.a4 = (__be32)htonl(0x7f000001U);

	return xfrm_nla_put(buf, off, cap, XFRMA_ENCAP, &encap, sizeof(encap));
}

/*
 * Replay state: rotate between the legacy 32-bit XFRMA_REPLAY_VAL and
 * the extended-sequence-number XFRMA_REPLAY_ESN_VAL.  ESN deeply fuzzes
 * seq_hi / oseq_hi across the wrap edges (0, 1, 0xfffffffe, 0xffffffff,
 * random) and bmp_len / replay_window across edge values that drive
 * the bmp[] sizing arithmetic.
 */
static size_t append_replay_maybe(unsigned char *buf, size_t off, size_t cap,
				  __u8 *flags_out)
{
	if ((rand32() & 3) == 0) {
		struct xfrm_replay_state legacy;

		memset(&legacy, 0, sizeof(legacy));
		legacy.oseq   = rand32();
		legacy.seq    = rand32();
		legacy.bitmap = rand32();
		return xfrm_nla_put(buf, off, cap, XFRMA_REPLAY_VAL,
				    &legacy, sizeof(legacy));
	}

	if ((rand32() & 1) == 0) {
		/* Extended sequence numbers -- mark XFRM_STATE_ESN on the
		 * containing SA so the kernel parser actually walks the
		 * ESN replay arm. */
		static const __u32 hi_choices[] = {
			0, 1, 0xFFFFFFFEU, 0xFFFFFFFFU,
		};
		static const __u32 win_choices[] = {
			32, 64, 128, 256, 1024, 4096,
		};
		struct xfrm_replay_state_esn *esn;
		unsigned char ebuf[sizeof(*esn) + 128 * sizeof(__u32)];
		__u32 win = win_choices[rand32() % ARRAY_SIZE(win_choices)];
		__u32 bmp_len = (win + 31) / 32;

		if (bmp_len > 128)
			bmp_len = 128;

		memset(ebuf, 0, sizeof(ebuf));
		esn = (struct xfrm_replay_state_esn *)ebuf;
		esn->bmp_len       = bmp_len;
		esn->oseq          = rand32();
		esn->seq           = rand32();
		esn->oseq_hi       = (rand32() & 1)
			? hi_choices[rand32() % ARRAY_SIZE(hi_choices)]
			: rand32();
		esn->seq_hi        = (rand32() & 1)
			? hi_choices[rand32() % ARRAY_SIZE(hi_choices)]
			: rand32();
		esn->replay_window = win;

		if (flags_out)
			*flags_out |= XFRM_STATE_ESN;

		return xfrm_nla_put(buf, off, cap, XFRMA_REPLAY_ESN_VAL,
				    ebuf,
				    sizeof(*esn) + bmp_len * sizeof(__u32));
	}

	return off;	/* leave replay state default */
}

/*
 * Independent XFRMA_SET_MARK / XFRMA_SET_MARK_MASK / XFRMA_IF_ID /
 * XFRMA_OFFLOAD_DEV / XFRMA_SA_EXTRA_FLAGS rotation.  Each rolls a
 * coin to decide whether to emit the attribute, and all five may
 * coexist on a single NEWSA so the parser walks combined-attribute
 * arms.
 */
static size_t append_marks_and_if(unsigned char *buf, size_t off, size_t cap)
{
	if ((rand32() & 1) == 0) {
		__u32 mark = rand32();

		off = xfrm_nla_put(buf, off, cap, XFRMA_SET_MARK,
				   &mark, sizeof(mark));
		if (!off)
			return 0;
	}
	if ((rand32() & 1) == 0) {
		__u32 mask = rand32();

		off = xfrm_nla_put(buf, off, cap, XFRMA_SET_MARK_MASK,
				   &mask, sizeof(mask));
		if (!off)
			return 0;
	}
	if ((rand32() & 3) == 0) {
		__u32 if_id = (rand32() & 0xff) + 1;	/* nonzero, smallish */

		off = xfrm_nla_put(buf, off, cap, XFRMA_IF_ID,
				   &if_id, sizeof(if_id));
		if (!off)
			return 0;
	}
	if ((rand32() & 7) == 0) {
		struct xfrm_user_offload off_attr;

		memset(&off_attr, 0, sizeof(off_attr));
		off_attr.ifindex = (int)(rand32() & 0x7);
		off_attr.flags   = (__u8)(rand32() & 0x3);
		off = xfrm_nla_put(buf, off, cap, XFRMA_OFFLOAD_DEV,
				   &off_attr, sizeof(off_attr));
		if (!off)
			return 0;
	}
	if ((rand32() & 3) == 0) {
		__u32 extra = rand32() & 0x7;

		off = xfrm_nla_put(buf, off, cap, XFRMA_SA_EXTRA_FLAGS,
				   &extra, sizeof(extra));
		if (!off)
			return 0;
	}
	return off;
}

/*
 * Selector + family + addresses.  AF_INET / AF_INET6 chosen by the
 * caller; the AF_INET path uses 127.0.0.0/8 endpoints, AF_INET6 uses
 * ::1 -based endpoints; prefixlen rotates across boundary values
 * including the kernel-side range edges (0 / 32 / 33 for AF_INET, 0 /
 * 128 / 129 for AF_INET6) so the family-specific validation arms get
 * exercised.
 */
static void fill_addresses(__u16 family, xfrm_address_t *saddr,
			   xfrm_address_t *daddr)
{
	memset(saddr, 0, sizeof(*saddr));
	memset(daddr, 0, sizeof(*daddr));

	if (family == AF_INET) {
		saddr->a4 = (__be32)htonl(0x7f000001U + (rand32() & 0xff));
		daddr->a4 = (__be32)htonl(0x7f000002U + (rand32() & 0xff));
	} else {
		/* fe80::1 / fe80::2 plus low-byte rotation */
		saddr->a6[0] = htonl(0xfe800000U);
		saddr->a6[3] = htonl(1U + (rand32() & 0xff));
		daddr->a6[0] = htonl(0xfe800000U);
		daddr->a6[3] = htonl(2U + (rand32() & 0xff));
	}
}

static __u8 pick_prefixlen(__u16 family)
{
	if (family == AF_INET) {
		static const __u8 choices[] = { 0, 8, 16, 24, 32, 33 };

		return choices[rand32() % ARRAY_SIZE(choices)];
	} else {
		static const __u8 choices[] = { 0, 32, 64, 96, 128, 129 };

		return choices[rand32() % ARRAY_SIZE(choices)];
	}
}

static __u8 pick_proto(void)
{
	static const __u8 choices[] = {
		0,			/* "any" */
		IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_ICMPV6,
	};

	return choices[rand32() % ARRAY_SIZE(choices)];
}

static __u8 pick_mode(void)
{
	static const __u8 choices[] = {
		XFRM_MODE_TRANSPORT,
		XFRM_MODE_TUNNEL,
		XFRM_MODE_BEET,
		XFRM_MODE_ROUTEOPTIMIZATION,
		XFRM_MODE_IN_TRIGGER,
	};

	return choices[rand32() % ARRAY_SIZE(choices)];
}

static __u8 pick_sa_proto(void)
{
	static const __u8 choices[] = {
		IPPROTO_ESP, IPPROTO_AH, IPPROTO_COMP,
	};

	return choices[rand32() % ARRAY_SIZE(choices)];
}

static __u16 pick_family(void)
{
	return (rand32() & 1) ? AF_INET : AF_INET6;
}

static void fill_selector(struct xfrm_selector *sel, __u16 family)
{
	memset(sel, 0, sizeof(*sel));
	fill_addresses(family, &sel->saddr, &sel->daddr);
	sel->family       = family;
	sel->prefixlen_s  = pick_prefixlen(family);
	sel->prefixlen_d  = pick_prefixlen(family);
	sel->proto        = pick_proto();
	if (sel->proto == IPPROTO_UDP || sel->proto == IPPROTO_TCP) {
		sel->sport      = htons((__u16)(rand32() & 0xffff));
		sel->sport_mask = htons((__u16)(rand32() & 0xffff));
		sel->dport      = htons((__u16)(rand32() & 0xffff));
		sel->dport_mask = htons((__u16)(rand32() & 0xffff));
	}
}

/*
 * Lifetime: rotate soft / hard byte and packet limits through
 * boundary values (0 = unlimited shorthand on some paths, 1, small,
 * large, ~0).  add_expires / use_expires rotate similarly so the
 * lifetime parser walks each comparison arm.
 */
static void fill_lifetime(struct xfrm_lifetime_cfg *lft)
{
	static const __u64 byte_choices[] = {
		0, 1, 1024, 1U << 20, 1U << 30, ~0ULL,
	};
	static const __u64 pkt_choices[] = {
		0, 1, 64, 1024, 1U << 20, ~0ULL,
	};
	static const __u64 sec_choices[] = {
		0, 1, 60, 3600, 86400, ~0ULL,
	};

	lft->soft_byte_limit          = byte_choices[rand32() % ARRAY_SIZE(byte_choices)];
	lft->hard_byte_limit          = byte_choices[rand32() % ARRAY_SIZE(byte_choices)];
	lft->soft_packet_limit        = pkt_choices[rand32() % ARRAY_SIZE(pkt_choices)];
	lft->hard_packet_limit        = pkt_choices[rand32() % ARRAY_SIZE(pkt_choices)];
	lft->soft_add_expires_seconds = sec_choices[rand32() % ARRAY_SIZE(sec_choices)];
	lft->hard_add_expires_seconds = sec_choices[rand32() % ARRAY_SIZE(sec_choices)];
	lft->soft_use_expires_seconds = sec_choices[rand32() % ARRAY_SIZE(sec_choices)];
	lft->hard_use_expires_seconds = sec_choices[rand32() % ARRAY_SIZE(sec_choices)];
}

/*
 * Build XFRM_MSG_NEWSA.  Picks family / proto / mode / SPI / reqid,
 * builds a coherent attribute set (AEAD vs paired CRYPT+AUTH_TRUNC,
 * optional COMP for IPCOMP, optional ENCAP, optional REPLAY/ESN,
 * optional marks/if/offload/extra-flags), and on accept pushes the
 * (daddr, spi, proto, family, reqid) onto the SA ring for later
 * UPDSA/NEWAE/DELSA targeting.
 */
static int xfrm_emit_newsa(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_sa_track entry;
	__u16 family = pick_family();
	__u8 mode = pick_mode();
	__u8 proto = pick_sa_proto();
	__u32 reqid = (rand32() & 0xff) + 1U;
	__be32 spi = htonl(0x100U + (rand32() % 0xfff000U));
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, family);
	sa->id.proto      = proto;
	sa->id.spi        = spi;
	fill_addresses(family, &sa->saddr, &sa->id.daddr);
	fill_lifetime(&sa->lft);
	sa->reqid         = reqid;
	sa->family        = family;
	sa->mode          = mode;
	sa->replay_window = (__u8)(rand32() % 64);
	sa->flags         = (__u8)(rand32() & 0x7f);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	/* Algorithm choice -- AEAD only on ESP, AUTH-only on AH, COMP
	 * on IPCOMP; otherwise paired CRYPT + AUTH_TRUNC for ESP. */
	if (proto == IPPROTO_AH) {
		off = append_auth_trunc(buf, off, sizeof(buf));
	} else if (proto == IPPROTO_COMP) {
		off = append_comp(buf, off, sizeof(buf));
	} else {
		/* IPPROTO_ESP -- AEAD or paired CRYPT+AUTH_TRUNC. */
		if (rand32() & 1) {
			off = append_aead(buf, off, sizeof(buf));
		} else {
			off = append_crypt(buf, off, sizeof(buf));
			if (off)
				off = append_auth_trunc(buf, off, sizeof(buf));
		}
	}
	if (!off)
		return -EIO;

	off = append_encap_maybe(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	off = append_replay_maybe(buf, off, sizeof(buf), &sa->flags);
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);
	if (rc != 0) {
		if (is_structural_reject(rc))
			latch_unsupported(rc);
		return rc;
	}

	memset(&entry, 0, sizeof(entry));
	entry.family = family;
	entry.proto  = proto;
	entry.daddr  = sa->id.daddr;
	entry.spi    = spi;
	entry.reqid  = reqid;
	sa_ring_push(fd, &entry);
	return 0;
}

/*
 * Build XFRM_MSG_UPDSA targeting a ring SA.  Same shell with a fresh
 * random key + rotated attribute set.  No-op when ring is empty.
 */
static int xfrm_emit_updsa(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_sa_track t;
	size_t off;

	if (!sa_ring_pick(&t, NULL))
		return 0;	/* nothing to update yet */

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_UPDSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, t.family);
	sa->id.proto      = t.proto;
	sa->id.spi        = t.spi;
	sa->id.daddr      = t.daddr;
	memset(&sa->saddr, 0, sizeof(sa->saddr));
	if (t.family == AF_INET)
		sa->saddr.a4 = (__be32)htonl(0x7f000001U);
	else {
		sa->saddr.a6[0] = htonl(0xfe800000U);
		sa->saddr.a6[3] = htonl(1U);
	}
	fill_lifetime(&sa->lft);
	sa->reqid         = t.reqid;
	sa->family        = t.family;
	sa->mode          = pick_mode();
	sa->replay_window = (__u8)(rand32() % 64);
	sa->flags         = (__u8)(rand32() & 0x7f);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	if (t.proto == IPPROTO_AH) {
		off = append_auth_trunc(buf, off, sizeof(buf));
	} else if (t.proto == IPPROTO_COMP) {
		off = append_comp(buf, off, sizeof(buf));
	} else {
		if (rand32() & 1) {
			off = append_aead(buf, off, sizeof(buf));
		} else {
			off = append_crypt(buf, off, sizeof(buf));
			if (off)
				off = append_auth_trunc(buf, off, sizeof(buf));
		}
	}
	if (!off)
		return -EIO;

	off = append_replay_maybe(buf, off, sizeof(buf), &sa->flags);
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Build XFRM_MSG_NEWAE (asynchronous event) targeting a ring SA.
 * Userspace pushes a new replay state / lifetime view into the kernel
 * via this message; the parser walks XFRMA_REPLAY_VAL or
 * XFRMA_REPLAY_ESN_VAL plus optional XFRMA_LTIME_VAL based on the
 * XFRM_AE_RVAL / XFRM_AE_LVAL flag bits.
 */
static int xfrm_emit_newae(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_aevent_id *ae;
	struct xfrm_sa_track t;
	__u8 ignored_flags = 0;
	size_t off;

	if (!sa_ring_pick(&t, NULL))
		return 0;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWAE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	ae = (struct xfrm_aevent_id *)NLMSG_DATA(nlh);
	ae->sa_id.daddr  = t.daddr;
	ae->sa_id.spi    = t.spi;
	ae->sa_id.family = t.family;
	ae->sa_id.proto  = t.proto;
	if (t.family == AF_INET)
		ae->saddr.a4 = (__be32)htonl(0x7f000001U);
	else {
		ae->saddr.a6[0] = htonl(0xfe800000U);
		ae->saddr.a6[3] = htonl(1U);
	}
	ae->reqid = t.reqid;
	ae->flags = (XFRM_AE_RVAL | XFRM_AE_LVAL) &
		    (__u32)((rand32() & 0xff) | XFRM_AE_RVAL);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ae));

	off = append_replay_maybe(buf, off, sizeof(buf), &ignored_flags);
	if (!off)
		return -EIO;

	if (ae->flags & XFRM_AE_LVAL) {
		struct xfrm_lifetime_cur cur;

		memset(&cur, 0, sizeof(cur));
		cur.bytes    = rand32();
		cur.packets  = rand32();
		cur.add_time = rand32();
		cur.use_time = rand32();
		off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_LTIME_VAL,
				   &cur, sizeof(cur));
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

static int xfrm_emit_delsa_random(int fd)
{
	struct xfrm_sa_track t;
	unsigned int idx;
	int rc;

	if (!sa_ring_pick(&t, &idx))
		return 0;

	rc = xfrm_emit_delsa_for(fd, &t);
	if (rc == 0)
		sa_ring_drop(idx);
	return rc;
}

/*
 * Build XFRM_MSG_NEWPOLICY OUT direction with XFRMA_TMPL.  When the
 * SA ring has an entry, point the template at it (so the resolution
 * machinery has a concrete target); otherwise synthesise a template
 * with random reqid + spi + proto so the parser walks anyway.
 */
static int xfrm_emit_newpolicy(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_user_tmpl tmpl;
	struct xfrm_sa_track t;
	__u16 family;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	pol = (struct xfrm_userpolicy_info *)NLMSG_DATA(nlh);
	family = pick_family();
	fill_selector(&pol->sel, family);
	fill_lifetime(&pol->lft);
	pol->priority = (__u32)(rand32() & 0xffff);
	pol->index    = 0;
	pol->dir      = XFRM_POLICY_OUT;
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = (__u8)(rand32() & 0x7);
	pol->share    = XFRM_SHARE_ANY;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pol));

	memset(&tmpl, 0, sizeof(tmpl));
	if (sa_ring_pick(&t, NULL)) {
		tmpl.id.daddr = t.daddr;
		tmpl.id.spi   = t.spi;
		tmpl.id.proto = t.proto;
		tmpl.family   = t.family;
		tmpl.reqid    = t.reqid;
		if (t.family == AF_INET) {
			tmpl.saddr.a4 = (__be32)htonl(0x7f000001U);
		} else {
			tmpl.saddr.a6[0] = htonl(0xfe800000U);
			tmpl.saddr.a6[3] = htonl(1U);
		}
	} else {
		tmpl.id.proto = pick_sa_proto();
		tmpl.id.spi   = htonl(0x100U + (rand32() % 0xfff000U));
		tmpl.family   = family;
		tmpl.reqid    = (rand32() & 0xff) + 1U;
		fill_addresses(family, &tmpl.saddr, &tmpl.id.daddr);
	}
	tmpl.mode     = pick_mode();
	tmpl.share    = XFRM_SHARE_ANY;
	tmpl.optional = (__u8)(rand32() & 1);
	tmpl.aalgos   = (__u32)~0U;
	tmpl.ealgos   = (__u32)~0U;
	tmpl.calgos   = (__u32)~0U;

	off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_TMPL,
			   &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

static int xfrm_emit_delpolicy(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_id *pid;
	__u16 family = pick_family();
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	pid = (struct xfrm_userpolicy_id *)NLMSG_DATA(nlh);
	fill_selector(&pid->sel, family);
	pid->dir = XFRM_POLICY_OUT;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

static int xfrm_emit_flushsa(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_flush *uf;
	static const __u8 proto_choices[] = {
		IPPROTO_ESP, IPPROTO_AH, IPPROTO_COMP, IPSEC_PROTO_ANY,
	};
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_FLUSHSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	uf = (struct xfrm_usersa_flush *)NLMSG_DATA(nlh);
	uf->proto = proto_choices[rand32() % ARRAY_SIZE(proto_choices)];

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uf));
	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);

	/* Whether or not the kernel accepts (a partial-proto flush may
	 * leave some entries), drain the ring -- the next UPDSA / NEWAE
	 * / DELSA on a stale entry would just bounce off ESRCH anyway. */
	if (rc == 0)
		sa_ring_drain();
	return rc;
}

static int xfrm_emit_flushpolicy(int fd)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	size_t off = NLMSG_HDRLEN;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_FLUSHPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();
	nlh->nlmsg_len   = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Message rotation table.  Each grammar invocation rolls one slot.
 * NEWSA / NEWPOLICY get higher weight when the SA ring is empty so
 * the ring fills before UPDSA / NEWAE / DELSA show up; FLUSHSA /
 * FLUSHPOLICY get low weight so they don't dominate.
 */
enum xfrm_msg_kind {
	XMK_NEWSA,
	XMK_UPDSA,
	XMK_NEWAE,
	XMK_DELSA,
	XMK_NEWPOLICY,
	XMK_DELPOLICY,
	XMK_FLUSHSA,
	XMK_FLUSHPOLICY,
	XMK_MAX,
};

/* Weights -- higher = more often.  When ring empty, NEWSA / NEWPOLICY
 * dominate so the ring fills.  When ring non-empty, UPDSA / NEWAE /
 * DELSA become first-class.  FLUSHSA / FLUSHPOLICY stay rare. */
static const unsigned int xmk_weights_empty_ring[XMK_MAX] = {
	[XMK_NEWSA]		= 50,
	[XMK_UPDSA]		= 0,
	[XMK_NEWAE]		= 0,
	[XMK_DELSA]		= 0,
	[XMK_NEWPOLICY]		= 30,
	[XMK_DELPOLICY]		= 5,
	[XMK_FLUSHSA]		= 1,
	[XMK_FLUSHPOLICY]	= 1,
};
static const unsigned int xmk_weights_full_ring[XMK_MAX] = {
	[XMK_NEWSA]		= 20,
	[XMK_UPDSA]		= 20,
	[XMK_NEWAE]		= 15,
	[XMK_DELSA]		= 15,
	[XMK_NEWPOLICY]		= 15,
	[XMK_DELPOLICY]		= 10,
	[XMK_FLUSHSA]		= 2,
	[XMK_FLUSHPOLICY]	= 1,
};

static enum xfrm_msg_kind pick_msg_kind(void)
{
	const unsigned int *weights = sa_ring_count() == 0
		? xmk_weights_empty_ring : xmk_weights_full_ring;
	unsigned int total = 0, pick, accum = 0;
	unsigned int i;

	for (i = 0; i < XMK_MAX; i++)
		total += weights[i];

	if (total == 0)
		return XMK_NEWSA;	/* defensive */

	pick = rand32() % total;
	for (i = 0; i < XMK_MAX; i++) {
		accum += weights[i];
		if (pick < accum)
			return (enum xfrm_msg_kind)i;
	}
	return XMK_NEWSA;
}

static void dispatch_msg_kind(int fd, enum xfrm_msg_kind k)
{
	int rc;

	switch (k) {
	case XMK_NEWSA:		rc = xfrm_emit_newsa(fd); break;
	case XMK_UPDSA:		rc = xfrm_emit_updsa(fd); break;
	case XMK_NEWAE:		rc = xfrm_emit_newae(fd); break;
	case XMK_DELSA:		rc = xfrm_emit_delsa_random(fd); break;
	case XMK_NEWPOLICY:	rc = xfrm_emit_newpolicy(fd); break;
	case XMK_DELPOLICY:	rc = xfrm_emit_delpolicy(fd); break;
	case XMK_FLUSHSA:	rc = xfrm_emit_flushsa(fd); break;
	case XMK_FLUSHPOLICY:	rc = xfrm_emit_flushpolicy(fd); break;
	default:		rc = 0; break;
	}

	if (rc != 0 && is_structural_reject(rc))
		latch_unsupported(rc);
}

/*
 * Grammar callbacks.
 *
 * can_run probes socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM) once and
 * caches the verdict.  A kernel without CONFIG_XFRM_USER fails the
 * socket() with EPROTONOSUPPORT; can_run returns false and
 * sfg_pick_random_active filters us out.  The shared
 * shm->sfg_unsupported[PF_NETLINK] latch is intentionally untouched
 * -- failing here does not affect grammar_netlink (which probes
 * NETLINK_GENERIC).
 */
static bool xfrm_grammar_can_run(void)
{
	int fd;

	if (unsupported_xfrm)
		return false;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) {
		unsupported_xfrm = true;
		return false;
	}
	close(fd);
	return true;
}

static void xfrm_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family   = PF_NETLINK;
	out->type     = SOCK_RAW;
	out->protocol = NETLINK_XFRM;
}

static void xfrm_grammar_configure_pre_bind(int fd, struct socket_triplet *t)
{
	int flags;
	int one = 1;

	(void) t;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* NETLINK_EXT_ACK + NETLINK_CAP_ACK so the kernel includes the
	 * extended attribute on errors -- the parser-side ack-build
	 * paths get coverage on every rejected message. */
	(void) setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK,
			  &one, sizeof(one));
	(void) setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK,
			  &one, sizeof(one));
}

static int xfrm_grammar_bind(int fd, struct socket_triplet *t)
{
	struct sockaddr_nl nl;

	(void) t;

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	nl.nl_pid    = 0;
	/* nl_groups = 0 -- multicast subscription on NETLINK_XFRM
	 * requires CAP_NET_ADMIN at bind time (NL_CFG_F_NONROOT_RECV is
	 * not set on this protocol).  We only need the unicast ack
	 * channel for sync send/recv; xfrm_drain_async stays as a
	 * defensive no-op. */
	nl.nl_groups = 0;

	if (bind(fd, (struct sockaddr *) &nl, sizeof(nl)) < 0)
		return -1;
	return 0;
}

static bool xfrm_grammar_needs_listen_accept(struct socket_triplet *t)
{
	(void) t;
	return false;
}

/*
 * walk_setsockopts is intentionally minimal -- the XFRM-shaped
 * coverage lives in data_leg via the message-rotation walker, and the
 * SOL_NETLINK toggle / membership churn is grammar_netlink's
 * responsibility.  We do exercise NETLINK_EXT_ACK / NETLINK_CAP_ACK
 * toggling and NETLINK_NO_ENOBUFS once each so the SOL_NETLINK arms
 * see at least some coverage on the XFRM-pinned fd shape too.
 */
static void xfrm_grammar_walk_setsockopts(int fd, struct socket_triplet *t,
					  unsigned int n)
{
	int v;
	unsigned int step = 0;

	(void) t;

	if (step++ < n) {
		v = (int)(rand32() & 1);
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK,
				  &v, sizeof(v));
	}
	if (step++ < n) {
		v = (int)(rand32() & 1);
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK,
				  &v, sizeof(v));
	}
	if (step++ < n) {
		v = 1;
		(void) setsockopt(fd, SOL_NETLINK, 5 /* NETLINK_NO_ENOBUFS */,
				  &v, sizeof(v));
	}
}

/*
 * data_leg is where the actual XFRM message-rotation happens.  One
 * message per invocation; the picker weights bias NEWSA / NEWPOLICY
 * up when the ring is empty, then UPDSA / NEWAE / DELSA become
 * first-class once the ring has SAs to target.
 *
 * The fd is a transient: the grammar dispatcher closes it after this
 * callback returns.  All persistent state (SA ring, latches, seq
 * counter) lives in file-scope statics so the next invocation's fresh
 * fd inherits the SAD shape this fd just installed.
 */
static void xfrm_grammar_data_leg(int parent_fd, int child_fd,
				  struct socket_triplet *t)
{
	enum xfrm_msg_kind k;

	(void) child_fd;
	(void) t;

	if (unsupported_xfrm)
		return;

	xfrm_drain_async(parent_fd);
	k = pick_msg_kind();
	dispatch_msg_kind(parent_fd, k);
	xfrm_drain_async(parent_fd);
}

const struct socket_family_grammar grammar_xfrm = {
	.family			= PF_NETLINK,
	.name			= "netlink-xfrm",
	.can_run		= xfrm_grammar_can_run,
	.pick_triplet		= xfrm_grammar_pick_triplet,
	.configure_pre_bind	= xfrm_grammar_configure_pre_bind,
	.bind_or_connect	= xfrm_grammar_bind,
	.walk_setsockopts	= xfrm_grammar_walk_setsockopts,
	.needs_listen_accept	= xfrm_grammar_needs_listen_accept,
	.data_leg		= xfrm_grammar_data_leg,
};
