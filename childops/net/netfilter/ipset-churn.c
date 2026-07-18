/*
 * ipset_churn - exercise NFNL_SUBSYS_IPSET (ip_set) via a bounded,
 * self-cleaning create/add/test/del/list/header/swap/flush/destroy cycle.
 *
 * ip_set is the in-kernel hashtable / bitmap set engine.  Its NFNL
 * dispatcher (net/netfilter/ipset/ip_set_core.c) fans commands out to
 * per-set-type modules (ip_set_hash_ip.c, ip_set_hash_net.c,
 * ip_set_hash_ipport.c, ip_set_bitmap_ip.c) that each parse the
 * IPSET_ATTR_DATA nest against their own policy; the parse gate walks
 * before the CAP_NET_ADMIN check, so write-side commands still exercise
 * the validation path even in unprivileged children.  Historical bug
 * shape is region-allocated bucket resize + concurrent element ops
 * (CVE-2023-42753 hash:ip OOB, CVE-2019-11479 hash:ipport walker).
 *
 * Per invocation: probe once; then BUDGETED outer iterations, each of
 * which (a) creates one or two sets of a randomly-picked type with the
 * TIMEOUT / COUNTERS / COMMENT extensions requested at create time,
 * (b) populates them with ADD entries, (c) queries via TEST / HEADER /
 * LIST (dump), (d) rotates via SWAP when two same-type sets exist,
 * (e) drops entries via DEL, (f) FLUSH one, and (g) DESTROY every
 * tracked set before returning.  Names are tracked in a per-invocation
 * bounded array so teardown is reliable even when create acks with
 * EEXIST or a mid-cycle op fails.
 *
 * Brick-safety: nfnetlink only, no modprobe, no sysfs writes, no
 * persistent state outside process fds.  IPSET_ATTR_TIMEOUT on create
 * arms the kernel GC as a backstop if a child dies with sets still
 * alive.  Names carry the pid + a per-invocation salt so parallel
 * children do not collide on the global set namespace.
 *
 * Latches (per-process): probe latches on NETLINK_NETFILTER absence
 * (nfnl_open EPROTONOSUPPORT) or IPSET_CMD_PROTOCOL returning
 * -EOPNOTSUPP / -EPROTONOSUPPORT (CONFIG_IP_SET=n).  EPERM / EEXIST /
 * ENOENT are counted as benign coverage -- the parse gate ran.
 *
 * Header-gated by __has_include() on the ipset UAPI header; missing
 * header falls to a stub.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/netfilter/nfnetlink.h>) && \
    __has_include(<linux/netfilter/ipset/ip_set.h>)

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "random.h"

/*
 * UAPI fallbacks.  Older sysroots may lack a few of these; the on-wire
 * values are stable and match what ip_set_core.c has always emitted.
 */
#ifndef NFNL_SUBSYS_IPSET
#define NFNL_SUBSYS_IPSET		6
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED			(1 << 15)
#endif
#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER		(1 << 14)
#endif
#ifndef IPSET_MAXNAMELEN
#define IPSET_MAXNAMELEN		32
#endif
#ifndef IPSET_PROTOCOL
#define IPSET_PROTOCOL			7
#endif
#ifndef IPSET_ATTR_IPADDR_IPV4
#define IPSET_ATTR_IPADDR_IPV4		1
#endif
#ifndef IPSET_FLAG_WITH_COUNTERS
#define IPSET_FLAG_WITH_COUNTERS	(1U << 3)
#endif
#ifndef IPSET_FLAG_WITH_COMMENT
#define IPSET_FLAG_WITH_COMMENT		(1U << 4)
#endif

#define IPSET_BUF_BYTES			512
#define IPSET_RECV_TIMEO_S		1
#define IPSET_LOOP_BUDGET		6U
#define IPSET_LOOP_ITERS_BASE		2U
#define IPSET_ADT_BUDGET		6U
#define IPSET_ADT_ITERS_BASE		2U
#define IPSET_MAX_TRACKED		4U
#define IPSET_DEFAULT_TIMEOUT		8U
#define IPSET_LOOPBACK_NET		0x7f010000U	/* 127.1.0.0/16 */
#define IPSET_BITMAP_RANGE_LEN		256U

/*
 * Resize-replay knobs.  A small initial htable (HASHSIZE=64) with a
 * generous MAXELEM plus a mass-add far exceeding the initial capacity
 * forces mtype_resize() to bump htable_bits.  During and after the
 * resize window the interleaved add/del churn exercises the entry-
 * replay path that upstream 'skip ext-destroy on hash-resize replay'
 * guards -- the extension blob attached to a replayed entry must not
 * be freed twice.  Two ext variants (timeout-only, counters-only)
 * widen the extension-lifecycle surface.
 */
#define IPSET_RESIZE_HASHSIZE		64U
#define IPSET_RESIZE_MAXELEM		4096U
#define IPSET_RESIZE_FILL_ENTRIES	384U
#define IPSET_RESIZE_REPLAY_CHURN	64U
#define IPSET_RESIZE_BUDGET		2U
#define IPSET_RESIZE_ITERS_BASE		1U

enum ipset_kind {
	IPSET_KIND_HASH_IP,
	IPSET_KIND_HASH_NET,
	IPSET_KIND_HASH_IPPORT,
	IPSET_KIND_BITMAP_IP,
	IPSET_KIND_NR,
};

/*
 * Extension-variant selector for resize-replay creates.  The upstream
 * fix is about ext blobs being double-destroyed on replay, so exercise
 * both TIMEOUT-only and COUNTERS-only sets (either extension alone is
 * enough to hit the double-destroy path; the two shapes have different
 * per-entry ext data layouts).
 */
enum ipset_ext_variant {
	IPSET_EXT_TIMEOUT,
	IPSET_EXT_COUNTERS,
	IPSET_EXT_NR,
};

struct ipset_type_desc {
	const char	*typename;
	__u8		revision;
	bool		is_bitmap;
};

/*
 * Type descriptors.  revision=1 is broadly accepted -- older kernels
 * expose rev 0-2 and newer ones bump; a rejection on rev bounds is
 * still parse-gate coverage.  is_bitmap picks between the range-based
 * create shape (IP + IP_TO) and the hash sizing shape (HASHSIZE +
 * MAXELEM).
 */
static const struct ipset_type_desc ipset_types[IPSET_KIND_NR] = {
	[IPSET_KIND_HASH_IP]     = { "hash:ip",     1, false },
	[IPSET_KIND_HASH_NET]    = { "hash:net",    1, false },
	[IPSET_KIND_HASH_IPPORT] = { "hash:ip,port", 1, false },
	[IPSET_KIND_BITMAP_IP]   = { "bitmap:ip",   1, true  },
};

/* Per-invocation tracker: names we successfully created and must
 * destroy before returning.  Sized small to bound the leak surface if
 * teardown itself gets a mid-run failure. */
struct ipset_tracker {
	char			names[IPSET_MAX_TRACKED][IPSET_MAXNAMELEN];
	__u8			kinds[IPSET_MAX_TRACKED];
	unsigned int		count;
};

/* Latches (per-process). */
static bool ns_unsupported_ipset;
static bool ipset_probed;

static size_t put_u16_be(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u16 v)
{
	__u16 be = htons(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
}

static size_t put_u32_be(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
}

/*
 * IPSET_ATTR_IP / IP_TO carry an inner IPSET_ATTR_IPADDR nest that
 * holds the addr blob.  Only v4 is emitted here (ip_set families set
 * via nfgen_family=AF_INET), but the nest shape matches what v6 uses.
 */
static size_t put_ipaddr_v4(unsigned char *buf, size_t off, size_t cap,
			    unsigned short outer_type, __u32 addr)
{
	__u32 be = htonl(addr);
	size_t nest_off = off;

	off = nla_nest_start(buf, off, cap, outer_type | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put(buf, off, cap,
		      IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
		      &be, sizeof(be));
	if (!off)
		return 0;
	nla_nest_end(buf, nest_off, off);
	return off;
}

/*
 * Stamp the ip_set common envelope: nfgenmsg + IPSET_ATTR_PROTOCOL +
 * (optional) IPSET_ATTR_SETNAME.  Every ip_set command starts this way
 * -- the dispatcher rejects anything missing IPSET_ATTR_PROTOCOL with
 * -IPSET_ERR_PROTOCOL long before reaching the per-cmd validate.
 */
static size_t ipset_hdr_put(unsigned char *buf, size_t cap,
			    struct nfnl_ctx *ctx, __u8 cmd,
			    __u16 extra_flags, const char *setname)
{
	size_t off;

	off = nfnl_msg_put(buf, 0, cap, nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_IPSET, cmd,
			   extra_flags, AF_INET);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	if (!off)
		return 0;
	if (setname) {
		off = nla_put_str(buf, off, cap, IPSET_ATTR_SETNAME, setname);
		if (!off)
			return 0;
	}
	return off;
}

/*
 * DATA nest for the hash: create variants.  HASHSIZE / MAXELEM size
 * the bucket table; IPSET_ATTR_TIMEOUT arms the timeout extension;
 * CADT_FLAGS requests COUNTERS + COMMENT extensions.  Any rejection
 * still walks the per-type policy.
 */
static size_t put_hash_create_data(unsigned char *buf, size_t off, size_t cap,
				   __u32 cadt_flags)
{
	size_t nest = off;

	off = nla_nest_start(buf, off, cap, IPSET_ATTR_DATA | NLA_F_NESTED);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_HASHSIZE, 64);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_MAXELEM, 256);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_TIMEOUT,
			 IPSET_DEFAULT_TIMEOUT);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_CADT_FLAGS, cadt_flags);
	if (!off)
		return 0;
	nla_nest_end(buf, nest, off);
	return off;
}

/*
 * DATA nest for bitmap:ip create.  Bitmap types are range-parameterised
 * at create time: IPSET_ATTR_IP / IP_TO carry the endpoints as IPADDR
 * nests.  A short 256-address range keeps the kernel bitmap allocation
 * bounded.  TIMEOUT + CADT_FLAGS are optional but drive the same
 * extension-setup path the hash types do.
 */
static size_t put_bitmap_create_data(unsigned char *buf, size_t off, size_t cap,
				     __u32 cadt_flags)
{
	__u32 lo = IPSET_LOOPBACK_NET;
	__u32 hi = IPSET_LOOPBACK_NET + IPSET_BITMAP_RANGE_LEN - 1U;
	size_t nest = off;

	off = nla_nest_start(buf, off, cap, IPSET_ATTR_DATA | NLA_F_NESTED);
	if (!off)
		return 0;
	off = put_ipaddr_v4(buf, off, cap, IPSET_ATTR_IP, lo);
	if (!off)
		return 0;
	off = put_ipaddr_v4(buf, off, cap, IPSET_ATTR_IP_TO, hi);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_TIMEOUT,
			 IPSET_DEFAULT_TIMEOUT);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_CADT_FLAGS, cadt_flags);
	if (!off)
		return 0;
	nla_nest_end(buf, nest, off);
	return off;
}

/*
 * IPSET_CMD_CREATE for kind K with name N.  Sends the type-specific
 * DATA nest and returns the kernel ack: 0 / -EEXIST are treated as
 * "the set exists, safe to track"; anything else is a create failure
 * the caller uses to skip tracking.
 */
static int build_create(struct nfnl_ctx *ctx, const char *name,
			enum ipset_kind kind)
{
	unsigned char buf[IPSET_BUF_BYTES];
	const struct ipset_type_desc *td = &ipset_types[kind];
	__u32 cadt = IPSET_FLAG_WITH_COUNTERS | IPSET_FLAG_WITH_COMMENT;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, IPSET_CMD_CREATE,
			    NLM_F_CREATE, name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  IPSET_ATTR_TYPENAME, td->typename);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf),
			 IPSET_ATTR_REVISION, td->revision);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), IPSET_ATTR_FAMILY, NFPROTO_IPV4);
	if (!off)
		return -EIO;
	off = td->is_bitmap
		? put_bitmap_create_data(buf, off, sizeof(buf), cadt)
		: put_hash_create_data(buf, off, sizeof(buf), cadt);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * DATA nest for hash:ip / hash:net / hash:ip,port ADD/DEL/TEST.  Kind
 * selects the extra attrs: hash:net adds a /CIDR; hash:ip,port adds a
 * PROTO + PORT.  A per-call timeout keeps the entry short-lived.
 */
static size_t put_hash_entry_data(unsigned char *buf, size_t off, size_t cap,
				  enum ipset_kind kind, __u32 ip, __u16 port,
				  __u8 cidr)
{
	size_t nest = off;

	off = nla_nest_start(buf, off, cap, IPSET_ATTR_DATA | NLA_F_NESTED);
	if (!off)
		return 0;
	off = put_ipaddr_v4(buf, off, cap, IPSET_ATTR_IP, ip);
	if (!off)
		return 0;
	if (kind == IPSET_KIND_HASH_NET) {
		off = nla_put_u8(buf, off, cap, IPSET_ATTR_CIDR, cidr);
		if (!off)
			return 0;
	}
	if (kind == IPSET_KIND_HASH_IPPORT) {
		off = nla_put_u8(buf, off, cap, IPSET_ATTR_PROTO, IPPROTO_TCP);
		if (!off)
			return 0;
		off = put_u16_be(buf, off, cap, IPSET_ATTR_PORT, port);
		if (!off)
			return 0;
	}
	off = put_u32_be(buf, off, cap, IPSET_ATTR_TIMEOUT,
			 IPSET_DEFAULT_TIMEOUT);
	if (!off)
		return 0;
	nla_nest_end(buf, nest, off);
	return off;
}

/*
 * DATA nest for bitmap:ip ADD/DEL/TEST.  Only IPSET_ATTR_IP is needed;
 * the address must land inside the range chosen at create time or the
 * per-type validator rejects with -IPSET_ERR_BITMAP_RANGE.
 */
static size_t put_bitmap_entry_data(unsigned char *buf, size_t off, size_t cap,
				    __u32 ip)
{
	size_t nest = off;

	off = nla_nest_start(buf, off, cap, IPSET_ATTR_DATA | NLA_F_NESTED);
	if (!off)
		return 0;
	off = put_ipaddr_v4(buf, off, cap, IPSET_ATTR_IP, ip);
	if (!off)
		return 0;
	nla_nest_end(buf, nest, off);
	return off;
}

/*
 * IPSET_CMD_{ADD,DEL,TEST} on set `name` (of type `kind`) for entry
 * (ip, port, cidr).  Bitmap addresses are pinned into the create-time
 * range; hash entries roll across the loopback /16.  Returns the raw
 * ack -- caller separates "parse OK / benign" from "parse rejected".
 */
static int build_adt(struct nfnl_ctx *ctx, const char *name,
		     enum ipset_kind kind, __u8 cmd, __u16 salt)
{
	unsigned char buf[IPSET_BUF_BYTES];
	__u32 ip;
	__u16 port = (__u16)(20000 + (salt & 0x3fff));
	__u8 cidr = (__u8)(24 + (salt & 0x7));
	size_t off;

	if (kind == IPSET_KIND_BITMAP_IP)
		ip = IPSET_LOOPBACK_NET + (salt % IPSET_BITMAP_RANGE_LEN);
	else
		ip = IPSET_LOOPBACK_NET + ((__u32)salt & 0xffffU);

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, cmd, 0, name);
	if (!off)
		return -EIO;
	off = (kind == IPSET_KIND_BITMAP_IP)
		? put_bitmap_entry_data(buf, off, sizeof(buf), ip)
		: put_hash_entry_data(buf, off, sizeof(buf), kind,
				      ip, port, cidr);
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * IPSET_CMD_DESTROY / _FLUSH / _HEADER share the same wire shape:
 * envelope + IPSET_ATTR_SETNAME, no DATA nest.  Split into a single
 * builder to keep the teardown loop tight.
 */
static int build_setname_only(struct nfnl_ctx *ctx, __u8 cmd,
			      const char *name)
{
	unsigned char buf[IPSET_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, cmd, 0, name);
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * IPSET_CMD_SWAP: envelope + IPSET_ATTR_SETNAME (source) +
 * IPSET_ATTR_TYPENAME (which the kernel reuses as SETNAME2 for the
 * swap partner -- they alias at UAPI enum value 3).  The kernel
 * requires both sets to be the same type + family.
 */
static int build_swap(struct nfnl_ctx *ctx, const char *a, const char *b)
{
	unsigned char buf[IPSET_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, IPSET_CMD_SWAP, 0, a);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IPSET_ATTR_TYPENAME, b);
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * IPSET_CMD_LIST as a dump.  Kernel walks every element in the named
 * set and streams them back; the drain in nfnl_send_recv_dump caps
 * the read window so a giant set cannot pin the child past its SIGALRM.
 */
static int build_list_dump(struct nfnl_ctx *ctx, const char *name)
{
	unsigned char buf[IPSET_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, IPSET_CMD_LIST,
			    NLM_F_DUMP, name);
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv_dump(ctx, buf, off);
}

/*
 * One-time IPSET_CMD_PROTOCOL probe.  Sends the minimal envelope with
 * just IPSET_ATTR_PROTOCOL and inspects the ack.  EOPNOTSUPP /
 * EPROTONOSUPPORT / EAFNOSUPPORT latch ns_unsupported_ipset; anything
 * else means the subsystem is present.
 */
static void probe_ipset(struct nfnl_ctx *ctx)
{
	unsigned char buf[IPSET_BUF_BYTES];
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, IPSET_CMD_PROTOCOL, 0, NULL);
	ipset_probed = true;
	if (!off) {
		ns_unsupported_ipset = true;
		return;
	}
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	rc = nfnl_send_recv(ctx, buf, off);
	if (rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT)
		ns_unsupported_ipset = true;
}

/*
 * Stamp a per-invocation set name.  Format: "tc1i<pid>-<salt>-<slot>",
 * capped at IPSET_MAXNAMELEN-1.  pid + salt keep parallel children on
 * disjoint namespaces; slot separates same-invocation partners.
 */
static void make_set_name(char *out, size_t cap, __u16 salt, unsigned int slot)
{
	int n;

	n = snprintf(out, cap, "tc1i%u-%04x-%u",
		     (unsigned int)getpid() & 0xffffU, salt, slot);
	if (n < 0 || (size_t)n >= cap)
		out[cap - 1] = '\0';
}

static void tracker_add(struct ipset_tracker *tr, const char *name,
			enum ipset_kind kind)
{
	size_t nlen;

	if (tr->count >= IPSET_MAX_TRACKED)
		return;
	nlen = strnlen(name, IPSET_MAXNAMELEN - 1U);
	memcpy(tr->names[tr->count], name, nlen);
	tr->names[tr->count][nlen] = '\0';
	tr->kinds[tr->count] = (__u8)kind;
	tr->count++;
}

/*
 * Create up to two same-type sets and add them to the tracker.  Two
 * sets unlock the SWAP path in iter_swap_flush; a single successful
 * create still exercises ADD / DEL / TEST / LIST / HEADER.
 */
static void iter_create_pair(struct nfnl_ctx *ctx, struct ipset_tracker *tr,
			     enum ipset_kind kind, __u16 salt)
{
	char name[IPSET_MAXNAMELEN];
	unsigned int i;
	int rc;

	for (i = 0; i < 2U && tr->count < IPSET_MAX_TRACKED; i++) {
		make_set_name(name, sizeof(name), salt, i);
		rc = build_create(ctx, name, kind);
		if (rc == 0 || rc == -EEXIST) {
			tracker_add(tr, name, kind);
			__atomic_add_fetch(&shm->stats.ipset_churn.create_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.ipset_churn.create_fail,
					   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Run BUDGETED (add, test, del) triples against every tracked set.
 * The salt varies per triple so hash entries spread across the /16
 * range rather than colliding on a single bucket.
 */
static void iter_adt_burst(struct nfnl_ctx *ctx, struct ipset_tracker *tr)
{
	unsigned int rounds, r, s;

	rounds = BUDGETED(CHILD_OP_IPSET_CHURN, IPSET_ADT_ITERS_BASE);
	if (rounds > IPSET_ADT_BUDGET)
		rounds = IPSET_ADT_BUDGET;
	if (rounds == 0U)
		rounds = 1U;

	for (r = 0; r < rounds; r++) {
		for (s = 0; s < tr->count; s++) {
			__u16 salt = (__u16)(rand32() & 0xffffU);
			enum ipset_kind k = (enum ipset_kind)tr->kinds[s];

			if (build_adt(ctx, tr->names[s], k,
				      IPSET_CMD_ADD, salt) == 0)
				__atomic_add_fetch(&shm->stats.ipset_churn.add_ok,
						   1, __ATOMIC_RELAXED);
			if (build_adt(ctx, tr->names[s], k,
				      IPSET_CMD_TEST, salt) == 0)
				__atomic_add_fetch(&shm->stats.ipset_churn.test_ok,
						   1, __ATOMIC_RELAXED);
			if (build_adt(ctx, tr->names[s], k,
				      IPSET_CMD_DEL, salt) == 0)
				__atomic_add_fetch(&shm->stats.ipset_churn.del_ok,
						   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * IPSET_CMD_HEADER on every tracked set + IPSET_CMD_LIST as a dump on
 * the first.  HEADER exercises the per-type header serializer; LIST
 * drives the element walker (nlmsg_dump path).
 */
static void iter_query(struct nfnl_ctx *ctx, struct ipset_tracker *tr)
{
	unsigned int s;

	if (tr->count == 0U)
		return;

	for (s = 0; s < tr->count; s++) {
		if (build_setname_only(ctx, IPSET_CMD_HEADER,
				       tr->names[s]) == 0)
			__atomic_add_fetch(&shm->stats.ipset_churn.header_ok,
					   1, __ATOMIC_RELAXED);
	}
	if (build_list_dump(ctx, tr->names[0]) == 0)
		__atomic_add_fetch(&shm->stats.ipset_churn.list_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * IPSET_CMD_SWAP two same-kind tracked sets, then IPSET_CMD_FLUSH one.
 * SWAP requires matching type + family, which the tracker guarantees
 * by construction (iter_create_pair uses one kind per invocation).
 * FLUSH on a swap partner exercises the walker with a live set alias.
 */
static void iter_swap_flush(struct nfnl_ctx *ctx, struct ipset_tracker *tr)
{
	if (tr->count >= 2U &&
	    build_swap(ctx, tr->names[0], tr->names[1]) == 0)
		__atomic_add_fetch(&shm->stats.ipset_churn.swap_ok,
				   1, __ATOMIC_RELAXED);

	if (tr->count >= 1U &&
	    build_setname_only(ctx, IPSET_CMD_FLUSH, tr->names[0]) == 0)
		__atomic_add_fetch(&shm->stats.ipset_churn.flush_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Destroy every tracked set, best-effort.  Called on every exit path
 * from the outer loop so a mid-iteration failure cannot leak sets past
 * this childop invocation.  ENOENT is treated as clean coverage --
 * the parse gate walked and simply found nothing to remove.
 */
static void teardown_all(struct nfnl_ctx *ctx, struct ipset_tracker *tr)
{
	unsigned int s;
	int rc;

	for (s = 0; s < tr->count; s++) {
		rc = build_setname_only(ctx, IPSET_CMD_DESTROY, tr->names[s]);
		if (rc == 0 || rc == -ENOENT)
			__atomic_add_fetch(&shm->stats.ipset_churn.destroy_ok,
					   1, __ATOMIC_RELAXED);
	}
	tr->count = 0;
}

/*
 * DATA nest for the resize-driving hash create.  Tiny HASHSIZE forces
 * an early mtype_resize() once the fill loop crosses the load-factor
 * threshold; a large MAXELEM keeps the resize path -- not MAXELEM
 * rejection -- as the observable outcome.  Extension selection is
 * split: TIMEOUT arms per-entry expiry state, COUNTERS arms the
 * pkt/byte counter blob.  Only one ext is armed per set so each
 * variant maps to a distinct ext_type on the kernel side.
 */
static size_t put_hash_create_data_resize(unsigned char *buf, size_t off,
					  size_t cap,
					  enum ipset_ext_variant ev)
{
	size_t nest = off;
	__u32 cadt = 0;

	off = nla_nest_start(buf, off, cap, IPSET_ATTR_DATA | NLA_F_NESTED);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_HASHSIZE,
			 IPSET_RESIZE_HASHSIZE);
	if (!off)
		return 0;
	off = put_u32_be(buf, off, cap, IPSET_ATTR_MAXELEM,
			 IPSET_RESIZE_MAXELEM);
	if (!off)
		return 0;
	if (ev == IPSET_EXT_TIMEOUT) {
		off = put_u32_be(buf, off, cap, IPSET_ATTR_TIMEOUT,
				 IPSET_DEFAULT_TIMEOUT);
		if (!off)
			return 0;
	} else if (ev == IPSET_EXT_COUNTERS) {
		cadt |= IPSET_FLAG_WITH_COUNTERS;
	}
	off = put_u32_be(buf, off, cap, IPSET_ATTR_CADT_FLAGS, cadt);
	if (!off)
		return 0;
	nla_nest_end(buf, nest, off);
	return off;
}

/*
 * IPSET_CMD_CREATE for a resize-target set.  Same envelope as
 * build_create() but wires the resize-tuned DATA nest.  Only hash
 * kinds are meaningful here (bitmap sets do not have an htable to
 * resize); callers pass hash:ip or hash:ip,port.
 */
static int build_create_resize(struct nfnl_ctx *ctx, const char *name,
			       enum ipset_kind kind,
			       enum ipset_ext_variant ev)
{
	unsigned char buf[IPSET_BUF_BYTES];
	const struct ipset_type_desc *td = &ipset_types[kind];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = ipset_hdr_put(buf, sizeof(buf), ctx, IPSET_CMD_CREATE,
			    NLM_F_CREATE, name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  IPSET_ATTR_TYPENAME, td->typename);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf),
			 IPSET_ATTR_REVISION, td->revision);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), IPSET_ATTR_FAMILY, NFPROTO_IPV4);
	if (!off)
		return -EIO;
	off = put_hash_create_data_resize(buf, off, sizeof(buf), ev);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Resize-replay driver.  Builds up to four small hash sets across
 * {hash:ip, hash:ip,port} x {timeout, counters}, then mass-adds
 * IPSET_RESIZE_FILL_ENTRIES distinct entries per set to push
 * htable_bits past the initial value.  Salts are deterministic
 * (0..N) so entries spread across the /16 rather than colliding
 * on one bucket -- essential for tripping the load-factor gate.
 *
 * Once the fill phase completes, the replay-churn phase interleaves
 * ADD / DEL pairs on the freshly-resized sets.  Concurrency comes
 * from sibling trinity children running the same childop in
 * parallel (-C N): while one child's fill loop is still driving
 * mtype_resize(), another child's ADD lands on the same set and is
 * replayed onto the new htable, exercising the ext-destroy path
 * the upstream fix guards.  Even in a single-child run the
 * post-resize ADD / DEL churn walks the same shared code, and the
 * TIMEOUT / COUNTERS extensions ensure real ext blobs are attached
 * to every entry so any lifecycle regression has data to corrupt.
 *
 * All created sets are destroyed by teardown_all() before return.
 */
static void iter_resize(struct nfnl_ctx *ctx)
{
	static const enum ipset_kind kinds[2] = {
		IPSET_KIND_HASH_IP,
		IPSET_KIND_HASH_IPPORT,
	};
	static const enum ipset_ext_variant evs[2] = {
		IPSET_EXT_TIMEOUT,
		IPSET_EXT_COUNTERS,
	};
	struct ipset_tracker tr = { .count = 0 };
	char name[IPSET_MAXNAMELEN];
	__u16 base_salt;
	unsigned int ki, ei, e, r;
	int rc;

	base_salt = (__u16)(rand32() & 0xffffU);
	for (ki = 0; ki < 2U && tr.count < IPSET_MAX_TRACKED; ki++) {
		for (ei = 0; ei < 2U && tr.count < IPSET_MAX_TRACKED; ei++) {
			unsigned int slot = tr.count;

			make_set_name(name, sizeof(name),
				      (__u16)(base_salt + slot), slot);
			rc = build_create_resize(ctx, name, kinds[ki], evs[ei]);
			if (rc == 0 || rc == -EEXIST) {
				tracker_add(&tr, name, kinds[ki]);
				__atomic_add_fetch(&shm->stats.ipset_churn.create_ok,
						   1, __ATOMIC_RELAXED);
			} else {
				__atomic_add_fetch(&shm->stats.ipset_churn.create_fail,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	if (tr.count == 0U)
		return;

	/*
	 * Fill phase: monotonic salts fan entries across the loopback
	 * /16 so bucket load grows evenly.  Exceeding HASHSIZE by an
	 * order of magnitude reliably crosses the load-factor gate
	 * regardless of the kernel's default AHASH_INIT_SIZE.
	 */
	for (r = 0; r < tr.count; r++) {
		enum ipset_kind k = (enum ipset_kind)tr.kinds[r];

		for (e = 0; e < IPSET_RESIZE_FILL_ENTRIES; e++) {
			if (build_adt(ctx, tr.names[r], k,
				      IPSET_CMD_ADD, (__u16)e) == 0)
				__atomic_add_fetch(&shm->stats.ipset_churn.add_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Replay-churn phase: alternate ADD / DEL on the resized sets
	 * with pseudo-random salts, so entries land on freshly rehashed
	 * buckets.  Sibling children hitting the same sets in parallel
	 * turn this into a genuine race against any in-flight resize.
	 */
	for (r = 0; r < IPSET_RESIZE_REPLAY_CHURN; r++) {
		unsigned int s = r % tr.count;
		enum ipset_kind k = (enum ipset_kind)tr.kinds[s];
		__u16 salt = (__u16)(rand32() & 0xffffU);

		if (build_adt(ctx, tr.names[s], k,
			      IPSET_CMD_ADD, salt) == 0)
			__atomic_add_fetch(&shm->stats.ipset_churn.add_ok,
					   1, __ATOMIC_RELAXED);
		if (build_adt(ctx, tr.names[s], k,
			      IPSET_CMD_DEL, salt) == 0)
			__atomic_add_fetch(&shm->stats.ipset_churn.del_ok,
					   1, __ATOMIC_RELAXED);
	}

	teardown_all(ctx, &tr);
}

/*
 * One outer iteration: pick a set type, create a same-kind pair, run
 * the ADT burst, query via HEADER + LIST, swap + flush, destroy.  All
 * per-invocation tracker state stays local so the teardown always
 * matches this iteration's create set.
 */
static void iter_one(struct nfnl_ctx *ctx)
{
	struct ipset_tracker tr = { .count = 0 };
	enum ipset_kind kind;
	__u16 salt;

	kind = (enum ipset_kind)(rand32() % (__u32)IPSET_KIND_NR);
	salt = (__u16)(rand32() & 0xffffU);

	iter_create_pair(ctx, &tr, kind, salt);
	iter_adt_burst(ctx, &tr);
	iter_query(ctx, &tr);
	iter_swap_flush(ctx, &tr);
	teardown_all(ctx, &tr);
}

bool ipset_churn(struct childdata *child)
{
	struct nfnl_ctx nfnl = { .nl = { .fd = -1 } };
	struct nfnl_open_opts opts = {
		.recv_timeo_s = IPSET_RECV_TIMEO_S,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.ipset_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_ipset) {
		__atomic_add_fetch(&shm->stats.ipset_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (nfnl_open(&nfnl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ipset_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!ipset_probed) {
		probe_ipset(&nfnl);
		if (ns_unsupported_ipset) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.ipset_churn.setup_failed,
					   1, __ATOMIC_RELAXED);
			nfnl_close(&nfnl);
			return true;
		}
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	outer_iters = BUDGETED(CHILD_OP_IPSET_CHURN,
			       JITTER_RANGE(IPSET_LOOP_ITERS_BASE));
	if (outer_iters > IPSET_LOOP_BUDGET)
		outer_iters = IPSET_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < outer_iters; i++)
		iter_one(&nfnl);

	{
		unsigned int rz_iters;

		rz_iters = BUDGETED(CHILD_OP_IPSET_CHURN,
				    JITTER_RANGE(IPSET_RESIZE_ITERS_BASE));
		if (rz_iters > IPSET_RESIZE_BUDGET)
			rz_iters = IPSET_RESIZE_BUDGET;
		if (rz_iters == 0U)
			rz_iters = 1U;
		for (i = 0; i < rz_iters; i++)
			iter_resize(&nfnl);
	}

	nfnl_close(&nfnl);
	return true;
}

#else  /* !__has_include(<linux/netfilter/ipset/ip_set.h>) */

bool ipset_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.ipset_churn.runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.ipset_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/netfilter/ipset/ip_set.h>) */
