/*
 * tc-qdisc-churn-builders - tc-nlmsg builder family carved out of
 * childops/tc-qdisc-churn.c.  Pure netlink-message constructors:
 * every helper takes a caller-supplied nl_ctx and emits one rtnl
 * message (RTM_NEWLINK / RTM_NEWQDISC / RTM_NEWTCLASS /
 * RTM_NEWTFILTER and their DEL twins) plus a couple of TCA_OPTIONS
 * payload encoders.  No file-scope state, no policy decisions —
 * the per-iteration latches, rotation tables and driver loop all
 * stay in tc-qdisc-churn.c.  Split off so the two TUs compile in
 * parallel under make -j.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "tc-qdisc-churn-internal.h"

/*
 * RTM_NEWLINK type=dummy with the supplied dev name.  Each iteration
 * gets a fresh dummy device so the qdisc tree is isolated from any
 * other iteration's leftovers.  No IFLA_INFO_DATA — defaults give us
 * a working netif_tx_lock dummy that accepts UDP traffic.
 */
int build_dummy_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;

	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=bridge with the supplied dev name.  No
 * IFLA_INFO_DATA — defaults give us a working bridge that accepts
 * IFLA_MASTER enslavement.  Mirrors build_dummy_create's wrapping
 * of IFLA_LINKINFO + IFLA_INFO_KIND.
 */
int build_bridge_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=veth with peer end created in the same call.
 * IFLA_LINKINFO -> IFLA_INFO_KIND="veth", IFLA_INFO_DATA ->
 * VETH_INFO_PEER which itself wraps a fresh ifinfomsg + IFLA_IFNAME
 * for the peer.  Both ends land in the current netns.
 */
int build_veth_pair(struct nl_ctx *ctx, const char *name,
		    const char *peer)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, p_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	p_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off)
		return -EIO;
	nla_nest_end(buf, p_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_SETLINK with IFLA_MASTER=master_idx.  Enslaves slave_idx to
 * master_idx; for our use the slave is one end of a veth pair and
 * master is a bridge, so this drives the kernel's br_add_if path.
 */
int build_setlink_master(struct nl_ctx *ctx, int slave_idx,
			 int master_idx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	__u32 m = (__u32)master_idx;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = slave_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put(buf, off, sizeof(buf), IFLA_MASTER, &m, sizeof(m));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build a tcmsg-bearing rtnl message with the given msg_type and
 * flags.  Returns the offset past the tcmsg payload header where
 * caller-supplied attributes start.
 */
static size_t tcmsg_hdr(struct nl_ctx *ctx, unsigned char *buf,
			__u16 msg_type, __u16 extra_flags,
			int ifindex, __u32 handle, __u32 parent, __u32 info)
{
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = handle;
	tcm->tcm_parent  = parent;
	tcm->tcm_info    = info;

	return NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));
}

static void tcmsg_finalize(unsigned char *buf, size_t off)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = (__u32)off;
}

/*
 * RTM_NEWQDISC root, TCA_KIND=<kind>.  TCA_OPTIONS is emitted as an
 * empty nested attribute — most qdiscs accept defaults; the few
 * that demand a parameter (taprio, ets) reject with EINVAL which
 * the per-kind latch picks up via the EOPNOTSUPP / ENOENT family
 * mapping in the caller.  Flags select between create, replace,
 * and create-or-replace as the caller requires.
 */
int build_newqdisc(struct nl_ctx *ctx, int ifindex, __u32 handle,
		   __u32 parent, const char *kind, __u16 extra_flags)
{
	unsigned char buf[RTNL_BUF_BYTES];
	size_t off, opts_off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_NEWQDISC, extra_flags, ifindex,
			handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;
	nla_nest_end(buf, opts_off, off);

	tcmsg_finalize(buf, off);
	return nl_send_recv_retry(ctx, buf, off);
}

int build_delqdisc(struct nl_ctx *ctx, int ifindex, __u32 handle,
		   __u32 parent)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_DELQDISC, 0, ifindex, handle, parent, 0);
	tcmsg_finalize(buf, off);
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWTCLASS under (ifindex, parent).  TCA_KIND inherits the
 * qdisc kind (htb, hfsc, etc.) — the kernel rejects with EINVAL if
 * the parent qdisc isn't classful, which the caller has already
 * gated on.  Empty TCA_OPTIONS — defaults are sufficient to install
 * the class; the lookup-side commit path is what we're after, not
 * the per-class scheduling parameters.
 */
int build_newtclass(struct nl_ctx *ctx, int ifindex, __u32 handle,
		    __u32 parent, const char *kind)
{
	unsigned char buf[RTNL_BUF_BYTES];
	size_t off, opts_off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_NEWTCLASS, NLM_F_CREATE | NLM_F_EXCL,
			ifindex, handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;
	nla_nest_end(buf, opts_off, off);

	tcmsg_finalize(buf, off);
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWTFILTER on (ifindex, parent).  tcm_info encodes priority
 * (high 16 bits) and protocol (low 16, htons'd).  Priority 1 is
 * fine; the kernel rejects priority 0 with EINVAL.  Empty
 * TCA_OPTIONS — most cls_* kinds accept this and run their _init /
 * _change codepaths anyway; the few that demand options reject
 * with EINVAL which trips the per-kind latch.
 */
int build_newtfilter(struct nl_ctx *ctx, int ifindex, __u32 parent,
		     const char *kind)
{
	unsigned char buf[RTNL_BUF_BYTES];
	size_t off, opts_off;
	__u32 info = ((__u32)1U << 16) | (__u32)htons(ETH_P_ALL);

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL,
			ifindex, 0, parent, info);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;
	nla_nest_end(buf, opts_off, off);

	tcmsg_finalize(buf, off);
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_DELTFILTER on (ifindex, parent) with no TCA_KIND — kernel
 * treats this as "delete every filter on parent".  Races any
 * in-flight skb classification still draining through the qdisc.
 */
int build_deltfilter(struct nl_ctx *ctx, int ifindex, __u32 parent)
{
	unsigned char buf[256];
	__u32 info = ((__u32)1U << 16) | (__u32)htons(ETH_P_ALL);
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_DELTFILTER, 0, ifindex, 0, parent, info);
	tcmsg_finalize(buf, off);
	return nl_send_recv(ctx, buf, off);
}

/*
 * The TCA_OPTIONS attribute for qdiscs that demand parameters is
 * constructed via per-kind encoders; for kinds whose init accepts
 * empty options the encoder is NULL.  Each encoder writes the
 * payload bytes that go *inside* TCA_OPTIONS — the caller wraps
 * them with a single nla header.
 *
 * Header struct sizes are pinned by the kernel UAPI: tc_red_qopt is
 * 4+4+4+4 bytes (3 u32 + 4 chars); tc_tbf_qopt is 2 * tc_ratespec
 * (12 each) + 3 u32 = 36 bytes.  Numeric values picked for "shaper
 * actually shapes": rate ~1Mbit, modest queue limits.  The codepath
 * we care about is the dequeue / peek interaction with the inner
 * qdisc, which fires regardless of the exact rate/threshold values
 * as long as there are skbs queued and the parent has a token /
 * threshold to gate on.
 */
size_t encode_red_opts(unsigned char *buf, size_t cap)
{
	struct tc_red_qopt opt;

	if (cap < sizeof(opt))
		return 0;
	memset(&opt, 0, sizeof(opt));
	opt.limit     = 60 * 1024;
	opt.qth_min   = 8 * 1024;
	opt.qth_max   = 32 * 1024;
	opt.Wlog      = 2;
	opt.Plog      = 10;
	opt.Scell_log = 8;
	opt.flags     = 0;
	memcpy(buf, &opt, sizeof(opt));
	return sizeof(opt);
}

size_t encode_tbf_opts(unsigned char *buf, size_t cap)
{
	struct tc_tbf_qopt opt;

	if (cap < sizeof(opt))
		return 0;
	memset(&opt, 0, sizeof(opt));
	opt.rate.rate     = 125000;	/* ~1 Mbit/s in bytes/sec */
	opt.rate.cell_log = 3;
	opt.rate.mpu      = 64;
	opt.limit         = 60 * 1024;
	opt.buffer        = 8000;	/* token bucket buffer */
	opt.mtu           = 1500;
	memcpy(buf, &opt, sizeof(opt));
	return sizeof(opt);
}

/*
 * Build a NEWQDISC with a TCA_OPTIONS payload containing one nested
 * attribute of (inner_type, inner_payload).  Used for parents that
 * demand options (red, tbf) — the encoder writes the inner payload
 * bytes; this wraps them as TCA_OPTIONS{ inner_type{ ... } }.  When
 * encoder is NULL emits an empty TCA_OPTIONS, matching build_newqdisc.
 */
int build_newqdisc_opts(struct nl_ctx *ctx, int ifindex, __u32 handle,
			__u32 parent, const char *kind,
			peek_opts_encoder enc,
			unsigned short inner_type, __u16 extra_flags)
{
	unsigned char buf[RTNL_BUF_BYTES];
	size_t off, opts_off, inner_off, inner_len;
	unsigned char inner[256];

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_NEWQDISC, extra_flags, ifindex,
			handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;

	if (enc != NULL) {
		inner_len = enc(inner, sizeof(inner));
		if (inner_len == 0)
			return -EIO;
		inner_off = nla_put(buf, off, sizeof(buf), inner_type,
				    inner, inner_len);
		if (!inner_off)
			return -EIO;
		off = inner_off;
	}

	nla_nest_end(buf, opts_off, off);

	tcmsg_finalize(buf, off);
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * Build a NEWTCLASS with TCA_OPTIONS containing TCA_QFQ_WEIGHT.
 * qfq classes accept defaults but kernel-side qfq_change_class
 * reads weight; supplying a sane non-zero value avoids the EINVAL
 * path and ensures the class is actually installable so the
 * matchall filter has somewhere to point.
 */
int build_qfq_class(struct nl_ctx *ctx, int ifindex, __u32 handle,
		    __u32 parent)
{
	unsigned char buf[RTNL_BUF_BYTES];
	size_t off, opts_off;
	__u32 weight = 1;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(ctx, buf, RTM_NEWTCLASS, NLM_F_CREATE | NLM_F_EXCL,
			ifindex, handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "qfq");
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), TCA_QFQ_WEIGHT,
		      &weight, sizeof(weight));
	if (!off)
		return -EIO;
	nla_nest_end(buf, opts_off, off);

	tcmsg_finalize(buf, off);
	return nl_send_recv_retry(ctx, buf, off);
}
