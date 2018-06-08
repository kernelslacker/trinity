#include <sys/types.h>
#include <sys/socket.h> /* old netlink.h is broken */
#include <sys/un.h>
/* For sa_family_t needed by <linux/netlink.h> */
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include "compat.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void netlink_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_nl *nl;
	const unsigned long nl_groups[] = {
		RTNLGRP_NONE, RTNLGRP_LINK, RTNLGRP_NOTIFY, RTNLGRP_NEIGH,
		RTNLGRP_TC, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_MROUTE, RTNLGRP_IPV4_ROUTE,
		RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_MROUTE, RTNLGRP_IPV6_ROUTE,
		RTNLGRP_IPV6_IFINFO, RTNLGRP_DECnet_IFADDR, RTNLGRP_NOP2, RTNLGRP_DECnet_ROUTE,
		RTNLGRP_DECnet_RULE, RTNLGRP_NOP4, RTNLGRP_IPV6_PREFIX, RTNLGRP_IPV6_RULE,
		RTNLGRP_ND_USEROPT, RTNLGRP_PHONET_IFADDR, RTNLGRP_PHONET_ROUTE, RTNLGRP_DCB,
		RTNLGRP_IPV4_NETCONF, RTNLGRP_IPV6_NETCONF, RTNLGRP_MDB, RTNLGRP_MPLS_ROUTE,
		RTNLGRP_NSID, RTNLGRP_MPLS_NETCONF,
	};

	nl = zmalloc(sizeof(struct sockaddr_nl));

	nl->nl_family = PF_NETLINK;
	nl->nl_pid = 0; // destination is always kernel
	nl->nl_groups = RAND_ARRAY(nl_groups);
	*addr = (struct sockaddr *) nl;
	*addrlen = sizeof(struct sockaddr_nl);
}

static const unsigned int netlink_opts[] = {
	NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP, NETLINK_PKTINFO, NETLINK_BROADCAST_ERROR,
	NETLINK_NO_ENOBUFS, NETLINK_RX_RING, NETLINK_TX_RING, NETLINK_LISTEN_ALL_NSID,
	NETLINK_LIST_MEMBERSHIPS, NETLINK_CAP_ACK,
};

#define SOL_NETLINK 270

static void netlink_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NETLINK;
	so->optname = RAND_ARRAY(netlink_opts);
}

static struct socket_triplet netlink_triplets[] = {
	{ .family = PF_NETLINK, .protocol = NETLINK_ROUTE, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_USERSOCK, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_SOCK_DIAG, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_NFLOG, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_XFRM, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_SELINUX, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_ISCSI, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_AUDIT, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_FIB_LOOKUP, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_CONNECTOR, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_NETFILTER, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_IP6_FW, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_DNRTMSG, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_KOBJECT_UEVENT, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_GENERIC, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_SCSITRANSPORT, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_ECRYPTFS, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_RDMA, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_CRYPTO, .type = SOCK_DGRAM },
	{ .family = PF_NETLINK, .protocol = NETLINK_SMC, .type = SOCK_DGRAM },

	{ .family = PF_NETLINK, .protocol = NETLINK_ROUTE, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_USERSOCK, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_SOCK_DIAG, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_NFLOG, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_XFRM, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_SELINUX, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_ISCSI, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_AUDIT, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_FIB_LOOKUP, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_CONNECTOR, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_NETFILTER, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_IP6_FW, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_DNRTMSG, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_KOBJECT_UEVENT, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_GENERIC, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_SCSITRANSPORT, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_ECRYPTFS, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_RDMA, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_CRYPTO, .type = SOCK_RAW },
	{ .family = PF_NETLINK, .protocol = NETLINK_SMC, .type = SOCK_RAW },

/*
  Hm, TBD

	if (st->protocol == NETLINK_SOCK_DIAG)
		st->type = rnd() % 136;
*/
};

const struct netproto proto_netlink = {
	.name = "netlink",
	.setsockopt = netlink_setsockopt,
	.gen_sockaddr = netlink_gen_sockaddr,
	.valid_triplets = netlink_triplets,
	.nr_triplets = ARRAY_SIZE(netlink_triplets),
};
