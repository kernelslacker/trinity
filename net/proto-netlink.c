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


/* Current highest netlink socket. Supports some older kernels. */
#ifdef NETLINK_CRYPTO
#define _NETLINK_MAX NETLINK_CRYPTO
#else
	#ifdef NETLINK_RDMA
	#define _NETLINK_MAX NETLINK_RDMA
	#else
		#define _NETLINK_MAX NETLINK_ECRYPTFS
	#endif /* NETLINK_RDMA */
#endif /* NETLINK_CRYPTO */

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
		RTNLGRP_NSID,
	};

	nl = zmalloc(sizeof(struct sockaddr_nl));

	nl->nl_family = PF_NETLINK;
	nl->nl_pid = 0; // destination is always kernel
	nl->nl_groups = RAND_ARRAY(nl_groups);
	*addr = (struct sockaddr *) nl;
	*addrlen = sizeof(struct sockaddr_nl);
}

static void netlink_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL())
		st->type = SOCK_RAW;
	else
		st->type = SOCK_DGRAM;

	st->protocol = rnd() % (_NETLINK_MAX + 1);

	if (st->protocol == NETLINK_SOCK_DIAG)
		st->type = rnd() % 136;
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

static void gen_netlink(void)
{
	generate_socket(PF_NETLINK, NETLINK_AUDIT, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_CONNECTOR, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_DNRTMSG, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_FIB_LOOKUP, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_GENERIC, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_ISCSI, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_KOBJECT_UEVENT, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_NETFILTER, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_ROUTE, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_SCSITRANSPORT, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_SELINUX, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_SOCK_DIAG, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_USERSOCK, SOCK_DGRAM);
	generate_socket(PF_NETLINK, NETLINK_XFRM, SOCK_DGRAM);

	generate_socket(PF_NETLINK, NETLINK_AUDIT, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_CONNECTOR, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_DNRTMSG, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_FIB_LOOKUP, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_GENERIC, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_ISCSI, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_KOBJECT_UEVENT, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_NETFILTER, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_ROUTE, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_SCSITRANSPORT, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_SELINUX, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_SOCK_DIAG, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_USERSOCK, SOCK_RAW);
	generate_socket(PF_NETLINK, NETLINK_XFRM, SOCK_RAW);
}

const struct netproto proto_netlink = {
	.name = "netlink",
	.socket = netlink_rand_socket,
	.setsockopt = netlink_setsockopt,
	.gen_sockaddr = netlink_gen_sockaddr,
	.generate = gen_netlink,
};
