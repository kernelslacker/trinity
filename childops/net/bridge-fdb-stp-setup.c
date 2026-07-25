/*
 * bridge_fdb_stp - link setup builders.
 *
 * Netlink RTM_NEWLINK / RTM_SETLINK message builders for the bridge
 * device, its enslaved veth ports, and the per-port BR_LEARNING arm.
 * All four are self-contained, take a nl_ctx and return 0 on ack or a
 * negated errno on rejection.  Called by the orchestrator in
 * bridge-fdb-stp.c and by the mass-VLAN sub-mode in
 * bridge-fdb-stp-vlan-mass.c.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "childops-netlink.h"

#include "bridge-fdb-stp-internal.h"

/*
 * RTM_NEWLINK type=bridge with the supplied dev name.  No
 * IFLA_INFO_DATA — defaults are fine for our purposes (STP off,
 * default ageing, default forward delay).  STP gets toggled later
 * via sysfs.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
int bfs_build_bridge_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	size_t li_off;

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
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=veth with VETH_INFO_PEER carrying the peer's
 * ifinfomsg + IFLA_IFNAME.  Distinct peer names per pair so the four
 * veth ends in this op are unambiguously addressable by name.
 */
int bfs_build_veth_create(struct nl_ctx *ctx, const char *name,
		      const char *peer_name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	size_t off;
	size_t li_off, id_off, peer_off;

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

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;

	/* VETH_INFO_PEER's payload starts with an ifinfomsg, then
	 * regular IFLA attributes (IFLA_IFNAME for the peer name). */
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer_name);
	if (!off)
		return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK with IFLA_MASTER=master_ifindex on ifindex.  Enslaves
 * the veth end to the bridge.
 */
int bfs_build_setlink_master(struct nl_ctx *ctx, int ifindex,
			 int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE with IFLA_PROTINFO containing
 * IFLA_BRPORT_LEARNING=1 — arms BR_LEARNING on the port.  This is
 * what makes the receive-path frame ingress drive br_fdb_update
 * (the rx-driven learning path the op exists to exercise).
 */
int bfs_build_setlink_brport_learning(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, pi_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	pi_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     IFLA_PROTINFO | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BRPORT_LEARNING, 1);
	if (!off)
		return -EIO;

	nla_nest_end(buf, pi_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}
