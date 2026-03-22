/*
 * Structured netlink message generation for fuzzing.
 *
 * Builds nlmsghdr messages with protocol-appropriate types and flags,
 * optional nlattr TLVs, and occasional deliberate corruption to test
 * both valid code paths and error handling in the kernel.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/connector.h>
#include <string.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/* Forward declaration — called via gen_msg hook from proto-netlink.c */
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

/* rtnetlink message types (NEW/DEL/GET variants picked at random) */
static const unsigned short rtnl_types[] = {
	RTM_NEWLINK, RTM_GETLINK,
	RTM_NEWADDR, RTM_GETADDR,
	RTM_NEWROUTE, RTM_GETROUTE,
	RTM_NEWNEIGH, RTM_GETNEIGH,
	RTM_NEWRULE, RTM_GETRULE,
	RTM_NEWQDISC, RTM_GETQDISC,
	RTM_NEWTCLASS, RTM_GETTCLASS,
	RTM_NEWTFILTER, RTM_GETTFILTER,
	RTM_NEWACTION, RTM_GETACTION,
	RTM_NEWPREFIX, RTM_GETMULTICAST, RTM_GETANYCAST,
	RTM_NEWNEIGHTBL, RTM_GETNEIGHTBL,
	RTM_NEWADDRLABEL, RTM_GETADDRLABEL,
	RTM_NEWNETCONF, RTM_GETNETCONF,
	RTM_NEWMDB, RTM_GETMDB,
	RTM_NEWNSID, RTM_GETNSID,
	RTM_NEWSTATS, RTM_GETSTATS,
	RTM_NEWCHAIN, RTM_GETCHAIN,
	RTM_NEWNEXTHOP, RTM_GETNEXTHOP,
	RTM_NEWLINKPROP,
	RTM_NEWVLAN, RTM_GETVLAN,
};

static const unsigned short xfrm_types[] = {
	XFRM_MSG_NEWSA, XFRM_MSG_DELSA, XFRM_MSG_GETSA,
	XFRM_MSG_NEWPOLICY, XFRM_MSG_DELPOLICY, XFRM_MSG_GETPOLICY,
	XFRM_MSG_ALLOCSPI, XFRM_MSG_ACQUIRE, XFRM_MSG_EXPIRE,
	XFRM_MSG_UPDPOLICY, XFRM_MSG_UPDSA,
	XFRM_MSG_POLEXPIRE, XFRM_MSG_FLUSHSA, XFRM_MSG_FLUSHPOLICY,
	XFRM_MSG_NEWAE, XFRM_MSG_GETAE,
	XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO,
	XFRM_MSG_MIGRATE,
};

static const unsigned short audit_types[] = {
	AUDIT_GET, AUDIT_SET, AUDIT_LIST_RULES, AUDIT_ADD_RULE,
	AUDIT_DEL_RULE, AUDIT_USER, AUDIT_LOGIN,
	AUDIT_WATCH_INS, AUDIT_WATCH_REM, AUDIT_WATCH_LIST,
	AUDIT_SIGNAL_INFO, AUDIT_TTY_GET, AUDIT_TTY_SET,
};

/* Generate a random set of nlmsg flags biased toward valid combos */
static unsigned short gen_nlmsg_flags(void)
{
	unsigned short flags = NLM_F_REQUEST; /* almost always set */

	if (ONE_IN(10))
		return rand16(); /* pure chaos */

	if (RAND_BOOL())
		flags |= NLM_F_ACK;

	/* GET-style: dump flags */
	if (RAND_BOOL())
		flags |= NLM_F_DUMP;

	/* NEW-style: create/replace flags */
	if (RAND_BOOL()) {
		if (RAND_BOOL())
			flags |= NLM_F_CREATE;
		if (RAND_BOOL())
			flags |= NLM_F_REPLACE;
		if (RAND_BOOL())
			flags |= NLM_F_EXCL;
		if (RAND_BOOL())
			flags |= NLM_F_APPEND;
	}

	return flags;
}

/* Pick an nlmsg_type appropriate for the netlink protocol */
static unsigned short pick_nlmsg_type(int protocol)
{
	/* 1 in 20: completely random type to probe unknown handlers */
	if (ONE_IN(20))
		return rand16();

	switch (protocol) {
	case NETLINK_ROUTE:
		return RAND_ARRAY(rtnl_types);
	case NETLINK_XFRM:
		return RAND_ARRAY(xfrm_types);
	case NETLINK_AUDIT:
		return RAND_ARRAY(audit_types);
	case NETLINK_NETFILTER:
		/* nfnetlink: subsys << 8 | msg. subsys 0-15ish */
		return ((rand() % 16) << 8) | (rand() % 16);
	case NETLINK_GENERIC:
		/* genl: CTRL_CMD range or random family id */
		if (RAND_BOOL())
			return GENL_ID_CTRL;
		return RAND_RANGE(GENL_MIN_ID, GENL_MIN_ID + 64);
	case NETLINK_SOCK_DIAG:
		/* sock_diag message types: SOCK_DIAG_BY_FAMILY=20, etc */
		return RAND_RANGE(16, 24);
	case NETLINK_CONNECTOR:
		return RAND_RANGE(0, 4);
	default:
		/* Unknown protocol: use NLMSG_MIN_TYPE or random */
		if (RAND_BOOL())
			return RAND_RANGE(NLMSG_MIN_TYPE, NLMSG_MIN_TYPE + 32);
		return rand16();
	}
}

/* Append a single nlattr to buf at offset. Returns new offset. */
static size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen)
{
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (offset + NLA_HDRLEN > buflen)
		return offset;

	payload_len = rand() % 64;
	total = NLA_HDRLEN + payload_len;

	/* Align to 4 bytes */
	total = (total + 3) & ~3;
	if (offset + total > buflen)
		total = buflen - offset;

	if (total < NLA_HDRLEN)
		return offset;

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = rand16();

	/* Sometimes set nested/net-byteorder flags */
	if (ONE_IN(4))
		nla.nla_type |= NLA_F_NESTED;
	if (ONE_IN(8))
		nla.nla_type |= NLA_F_NET_BYTEORDER;

	memcpy(buf + offset, &nla, NLA_HDRLEN);

	/* Fill payload with random data */
	if (total > NLA_HDRLEN)
		generate_rand_bytes(buf + offset + NLA_HDRLEN, total - NLA_HDRLEN);

	return offset + total;
}

/*
 * Build a structured netlink message. The caller must free *buf.
 *
 * Structure: [nlmsghdr][protocol body][nlattr...nlattr]
 *
 * The protocol body is a small fixed-size header that varies by
 * protocol (rtnetlink uses struct rtgenmsg/ifinfomsg, xfrm uses
 * xfrm_usersa_info, etc). We fill it with random bytes since the
 * interesting fuzzing is in the attrs and type dispatch.
 */
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	struct nlmsghdr *nlh;
	size_t body_len;
	size_t total_len;
	size_t offset;
	unsigned char *msg;
	int num_attrs;

	/* Protocol body: 4-64 bytes of random data */
	body_len = RAND_RANGE(4, 64);
	/* Space for attrs: 0-512 bytes */
	total_len = NLMSG_HDRLEN + body_len + (rand() % 512);

	/* Cap at a reasonable size */
	if (total_len > 4096)
		total_len = 4096;

	msg = zmalloc(total_len);

	nlh = (struct nlmsghdr *) msg;
	nlh->nlmsg_type = pick_nlmsg_type(triplet->protocol);
	nlh->nlmsg_flags = gen_nlmsg_flags();
	nlh->nlmsg_seq = rand32();
	nlh->nlmsg_pid = RAND_BOOL() ? 0 : rand32();

	/* Fill protocol body with random bytes */
	generate_rand_bytes(msg + NLMSG_HDRLEN, body_len);

	/* Append random nlattr TLVs */
	offset = NLMSG_HDRLEN + body_len;
	num_attrs = rand() % 8;
	while (num_attrs-- > 0 && offset < total_len)
		offset = append_nlattr(msg, offset, total_len);

	/* Set nlmsg_len — usually correct, sometimes corrupted */
	if (ONE_IN(10)) {
		/* Corrupt: too short, too long, zero, or max */
		switch (rand() % 4) {
		case 0: nlh->nlmsg_len = 0; break;
		case 1: nlh->nlmsg_len = NLMSG_HDRLEN - 1; break;
		case 2: nlh->nlmsg_len = total_len * 2; break;
		case 3: nlh->nlmsg_len = rand32(); break;
		}
	} else {
		nlh->nlmsg_len = offset;
	}

	*buf = msg;
	*len = offset; /* actual bytes to send (iov_len) */
}
