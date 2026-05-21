#include <sys/types.h>
#include <sys/socket.h> /* old netlink.h is broken */
#include <sys/un.h>
/* For sa_family_t needed by <linux/netlink.h> */
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "compat.h"
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "rnd.h"

static void netlink_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_nl *nl;
	const unsigned long nl_groups[] = {
		RTNLGRP_NONE, RTNLGRP_LINK, RTNLGRP_NOTIFY, RTNLGRP_NEIGH,
		RTNLGRP_TC, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_MROUTE, RTNLGRP_IPV4_ROUTE,
		RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_MROUTE, RTNLGRP_IPV6_ROUTE,
		RTNLGRP_IPV6_IFINFO, RTNLGRP_NOP2,
		RTNLGRP_NOP4, RTNLGRP_IPV6_PREFIX, RTNLGRP_IPV6_RULE,
		RTNLGRP_ND_USEROPT, RTNLGRP_PHONET_IFADDR, RTNLGRP_PHONET_ROUTE, RTNLGRP_DCB,
		RTNLGRP_IPV4_NETCONF, RTNLGRP_IPV6_NETCONF, RTNLGRP_MDB, RTNLGRP_MPLS_ROUTE,
		RTNLGRP_NSID, RTNLGRP_MPLS_NETCONF,
	};

	nl = zmalloc_tracked(sizeof(struct sockaddr_nl));

	nl->nl_family = PF_NETLINK;
	nl->nl_pid = 0; // destination is always kernel
	{
		unsigned long id = RAND_ARRAY(nl_groups);
		nl->nl_groups = id ? (1u << ((id - 1) % 32)) : 0;
	}
	*addr = (struct sockaddr *) nl;
	*addrlen = sizeof(struct sockaddr_nl);
}

static const unsigned int netlink_opts[] = {
	NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP, NETLINK_PKTINFO, NETLINK_BROADCAST_ERROR,
	NETLINK_NO_ENOBUFS, NETLINK_RX_RING, NETLINK_TX_RING, NETLINK_LISTEN_ALL_NSID,
	NETLINK_LIST_MEMBERSHIPS, NETLINK_CAP_ACK, NETLINK_EXT_ACK, NETLINK_GET_STRICT_CHK,
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
		st->type = rnd_modulo_u32(136);
*/
};

/* defined in netlink-msg.c */
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

const struct netproto proto_netlink = {
	.name = "netlink",
	.setsockopt = netlink_setsockopt,
	.gen_sockaddr = netlink_gen_sockaddr,
	.gen_msg = netlink_gen_msg,
	.valid_triplets = netlink_triplets,
	.nr_triplets = ARRAY_SIZE(netlink_triplets),
};

/*
 * grammar_netlink — coherent walk for AF_NETLINK driven by the
 * per-family grammar dispatcher (net/socket-family-grammar.c).
 *
 * walk_setsockopts fires the multicast group-membership churn the
 * design doc calls for: NETLINK_ADD_MEMBERSHIP across N random group
 * ids, NETLINK_DROP_MEMBERSHIP across M of those, then a fixed tail
 * of toggles — NETLINK_BROADCAST_ERROR, NETLINK_NO_ENOBUFS,
 * NETLINK_LISTEN_ALL_NSID, NETLINK_CAP_ACK, NETLINK_GET_STRICT_CHK.
 * These have to land in coherent succession on the same fd to walk
 * the netlink_table_grab / nl_groups_alloc paths the random
 * per-syscall fuzzer can't sequence.
 *
 * pick_triplet biases SOCK_RAW on the protocols whose subsystem
 * reception paths are most interesting (GENERIC, ROUTE, NETFILTER,
 * KOBJECT_UEVENT, AUDIT).  bind_or_connect lands a sockaddr_nl with
 * nl_pid=0 (kernel-assigned) and a 32-bit-random nl_groups so the
 * subsequent ADD_MEMBERSHIP walk modifies a non-zero base.
 *
 * gen_cmsg stays NULL — netlink uses nlmsg framing rather than
 * ancillary cmsg, and the data leg falls through to the framework
 * default which already calls proto_netlink.gen_msg (netlink_gen_msg
 * in netlink-msg.c) for the payload.
 */
static const int netlink_grammar_protos[] = {
	NETLINK_GENERIC,
	NETLINK_ROUTE,
	NETLINK_NETFILTER,
	NETLINK_KOBJECT_UEVENT,
	NETLINK_AUDIT,
};

static bool netlink_grammar_can_run(void)
{
	int fd;

	/* sfg_pick_random_active already gates on shm->sfg_unsupported,
	 * and run_grammar_chain marks the family unsupported when this
	 * returns false — so we only need the live probe here. */
	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static void netlink_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_NETLINK;
	out->type = SOCK_RAW;
	out->protocol = netlink_grammar_protos[
		rnd_modulo_u32(ARRAY_SIZE(netlink_grammar_protos))];
}

static void netlink_grammar_configure_pre_bind(int fd,
					       struct socket_triplet *t)
{
	int flags;

	(void) t;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int netlink_grammar_bind(int fd, struct socket_triplet *t)
{
	struct sockaddr_nl nl;

	(void) t;

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	nl.nl_pid = 0;			/* kernel assigns */
	nl.nl_groups = (unsigned int) rand32();

	if (bind(fd, (struct sockaddr *) &nl, sizeof(nl)) < 0)
		return -1;
	return 0;
}

static void netlink_grammar_walk_setsockopts(int fd,
					     struct socket_triplet *t,
					     unsigned int n)
{
	unsigned int step = 0;
	unsigned int n_add, n_drop, i;
	int one = 1;
	int zero = 0;
	int group;

	(void) t;

	if (n == 0)
		return;

	/* Spend roughly half the budget adding memberships, a quarter
	 * dropping a subset of them, the remainder on the toggle tail. */
	n_add = 1 + (n / 2);
	n_drop = n / 4;

	for (i = 0; i < n_add && step < n; i++, step++) {
		group = 1 + (rnd_modulo_u32(32));
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
				  &group, sizeof(group));
	}

	for (i = 0; i < n_drop && step < n; i++, step++) {
		group = 1 + (rnd_modulo_u32(32));
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
				  &group, sizeof(group));
	}

	if (step++ < n)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_BROADCAST_ERROR,
				  RAND_BOOL() ? &one : &zero, sizeof(int));
	if (step++ < n)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS,
				  RAND_BOOL() ? &one : &zero, sizeof(int));
	if (step++ < n)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID,
				  RAND_BOOL() ? &one : &zero, sizeof(int));
	if (step++ < n)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK,
				  RAND_BOOL() ? &one : &zero, sizeof(int));
	if (step++ < n)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
				  RAND_BOOL() ? &one : &zero, sizeof(int));
}

static bool netlink_grammar_needs_listen_accept(struct socket_triplet *t)
{
	(void) t;
	return false;
}

const struct socket_family_grammar grammar_netlink = {
	.family			= PF_NETLINK,
	.name			= "netlink",
	.can_run		= netlink_grammar_can_run,
	.pick_triplet		= netlink_grammar_pick_triplet,
	.configure_pre_bind	= netlink_grammar_configure_pre_bind,
	.bind_or_connect	= netlink_grammar_bind,
	.walk_setsockopts	= netlink_grammar_walk_setsockopts,
	.needs_listen_accept	= netlink_grammar_needs_listen_accept,
};
