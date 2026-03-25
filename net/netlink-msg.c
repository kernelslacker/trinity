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
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/connector.h>
#include <string.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"

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
	case NETLINK_NETFILTER: {
		/* nfnetlink: subsys << 8 | msg.
		 * Use proper NFNL_SUBSYS_* constants for better coverage. */
		static const unsigned char nfnl_subsys[] = {
			NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK_EXP,
			NFNL_SUBSYS_QUEUE, NFNL_SUBSYS_ULOG,
			NFNL_SUBSYS_OSF, NFNL_SUBSYS_IPSET,
			NFNL_SUBSYS_ACCT, NFNL_SUBSYS_CTNETLINK_TIMEOUT,
			NFNL_SUBSYS_CTHELPER, NFNL_SUBSYS_NFTABLES,
			NFNL_SUBSYS_NFT_COMPAT, NFNL_SUBSYS_HOOK,
		};
		unsigned char subsys;

		if (ONE_IN(8))
			subsys = rand() % 16;
		else
			subsys = RAND_ARRAY(nfnl_subsys);
		return (subsys << 8) | (rand() % 16);
	}
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

/* Append a single nlattr to buf at offset. Returns new offset.
 * nla_type_hint is a protocol-appropriate attr type; 0 means random. */
static size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			    unsigned short nla_type_hint)
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

	/* Use the hint most of the time, random for chaos */
	if (nla_type_hint && !ONE_IN(8))
		nla.nla_type = nla_type_hint;
	else
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

/* nlattr types for each rtnetlink message group.
 * Each call picks a random entry from the appropriate list. */
static const unsigned short ifla_attrs[] = {
	IFLA_ADDRESS, IFLA_BROADCAST, IFLA_IFNAME, IFLA_MTU, IFLA_LINK,
	IFLA_QDISC, IFLA_STATS, IFLA_COST, IFLA_PRIORITY, IFLA_MASTER,
	IFLA_PROTINFO, IFLA_TXQLEN, IFLA_MAP, IFLA_WEIGHT, IFLA_OPERSTATE,
	IFLA_LINKMODE, IFLA_LINKINFO, IFLA_NET_NS_PID, IFLA_IFALIAS,
	IFLA_NUM_VF, IFLA_STATS64, IFLA_AF_SPEC, IFLA_GROUP,
	IFLA_NET_NS_FD, IFLA_EXT_MASK, IFLA_PROMISCUITY,
	IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES, IFLA_CARRIER,
	IFLA_PHYS_PORT_ID, IFLA_LINK_NETNSID, IFLA_PROTO_DOWN,
	IFLA_GSO_MAX_SEGS, IFLA_GSO_MAX_SIZE, IFLA_XDP,
	IFLA_NEW_IFINDEX, IFLA_MIN_MTU, IFLA_MAX_MTU,
	IFLA_PROP_LIST, IFLA_ALT_IFNAME, IFLA_PERM_ADDRESS,
};

static const unsigned short ifa_attrs[] = {
	IFA_ADDRESS, IFA_LOCAL, IFA_LABEL, IFA_BROADCAST, IFA_ANYCAST,
	IFA_CACHEINFO, IFA_FLAGS, IFA_RT_PRIORITY, IFA_PROTO,
};

static const unsigned short rta_attrs[] = {
	RTA_DST, RTA_SRC, RTA_IIF, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY,
	RTA_PREFSRC, RTA_METRICS, RTA_MULTIPATH, RTA_FLOW, RTA_CACHEINFO,
	RTA_TABLE, RTA_MARK, RTA_MFC_STATS, RTA_VIA, RTA_NEWDST,
	RTA_PREF, RTA_ENCAP_TYPE, RTA_ENCAP, RTA_EXPIRES, RTA_UID,
	RTA_TTL_PROPAGATE, RTA_IP_PROTO, RTA_SPORT, RTA_DPORT, RTA_NH_ID,
};

static const unsigned short nda_attrs[] = {
	NDA_DST, NDA_LLADDR, NDA_CACHEINFO, NDA_PROBES, NDA_VLAN,
	NDA_PORT, NDA_VNI, NDA_IFINDEX, NDA_MASTER, NDA_LINK_NETNSID,
	NDA_SRC_VNI, NDA_PROTOCOL, NDA_NH_ID, NDA_FLAGS_EXT,
	NDA_NDM_STATE_MASK, NDA_NDM_FLAGS_MASK,
};

static const unsigned short fra_attrs[] = {
	FRA_DST, FRA_SRC, FRA_IIFNAME, FRA_GOTO, FRA_PRIORITY,
	FRA_FWMARK, FRA_FLOW, FRA_TUN_ID, FRA_SUPPRESS_IFGROUP,
	FRA_SUPPRESS_PREFIXLEN, FRA_TABLE, FRA_FWMASK, FRA_OIFNAME,
	FRA_L3MDEV,
};

static const unsigned short tca_attrs[] = {
	TCA_KIND, TCA_OPTIONS, TCA_STATS, TCA_XSTATS, TCA_RATE,
	TCA_FCNT, TCA_STATS2, TCA_STAB, TCA_CHAIN, TCA_HW_OFFLOAD,
	TCA_INGRESS_BLOCK, TCA_EXT_WARN_MSG,
};

/* Pick an nlattr type appropriate for an rtnetlink message group.
 * Returns 0 for unknown groups (caller falls back to random). */
static unsigned short pick_rtnl_attr_type(unsigned short nlmsg_type)
{
	unsigned int group;

	if (nlmsg_type < RTM_BASE || nlmsg_type >= RTM_MAX)
		return 0;

	group = (nlmsg_type - RTM_BASE) / 4;
	switch (group) {
	case 0: return RAND_ARRAY(ifla_attrs);
	case 1: return RAND_ARRAY(ifa_attrs);
	case 2: return RAND_ARRAY(rta_attrs);
	case 3: return RAND_ARRAY(nda_attrs);
	case 4: return RAND_ARRAY(fra_attrs);
	case 5:
	case 6:
	case 7: return RAND_ARRAY(tca_attrs);
	default: return 0;
	}
}

/* genl controller attributes (GENL_ID_CTRL messages) */
static const unsigned short genl_ctrl_attrs[] = {
	CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_VERSION,
	CTRL_ATTR_HDRSIZE, CTRL_ATTR_MAXATTR, CTRL_ATTR_OPS,
	CTRL_ATTR_MCAST_GROUPS, CTRL_ATTR_POLICY, CTRL_ATTR_OP,
};

static unsigned char rand_family(void)
{
	static const unsigned char families[] = {
		AF_INET, AF_INET6, AF_UNSPEC, AF_BRIDGE, AF_MPLS,
		AF_PACKET, AF_DECnet,
	};
	if (ONE_IN(8))
		return rand() % 256;
	return RAND_ARRAY(families);
}

/*
 * Generate a protocol-specific body for rtnetlink messages.
 * The kernel validates these structs before processing attrs, so
 * random bytes get rejected immediately. Using proper structs with
 * fuzzed fields gets past validation into interesting code paths.
 *
 * Returns the body length written. Caller must ensure buf has enough
 * room (at least sizeof(struct tcmsg) = 20 bytes).
 */
static size_t gen_rtnl_body(unsigned char *body, unsigned short nlmsg_type)
{
	/* Map RTM type to its base: RTM_*LINK=16-19, RTM_*ADDR=20-23, etc.
	 * Each group of 4 shares the same body struct. */
	unsigned int group = (nlmsg_type - RTM_BASE) / 4;

	switch (group) {
	case 0: { /* RTM_*LINK: struct ifinfomsg */
		struct ifinfomsg ifi;
		ifi.ifi_family = rand_family();
		ifi.__ifi_pad = 0;
		ifi.ifi_type = rand16();     /* ARPHRD_* */
		ifi.ifi_index = rand32() % 64; /* small interface indices */
		ifi.ifi_flags = rand32();    /* IFF_* */
		ifi.ifi_change = rand32();
		memcpy(body, &ifi, sizeof(ifi));
		return sizeof(ifi);
	}
	case 1: { /* RTM_*ADDR: struct ifaddrmsg */
		struct ifaddrmsg ifa;
		ifa.ifa_family = rand_family();
		ifa.ifa_prefixlen = rand() % 129;
		ifa.ifa_flags = rand() % 256;
		ifa.ifa_scope = rand() % 256;
		ifa.ifa_index = rand32() % 64;
		memcpy(body, &ifa, sizeof(ifa));
		return sizeof(ifa);
	}
	case 2: { /* RTM_*ROUTE: struct rtmsg */
		struct rtmsg rtm;
		rtm.rtm_family = rand_family();
		rtm.rtm_dst_len = rand() % 129;
		rtm.rtm_src_len = rand() % 129;
		rtm.rtm_tos = rand() % 256;
		rtm.rtm_table = rand() % 256;
		rtm.rtm_protocol = rand() % 256;
		rtm.rtm_scope = rand() % 256;
		rtm.rtm_type = rand() % (RTN_MAX + 1);
		rtm.rtm_flags = rand32();
		memcpy(body, &rtm, sizeof(rtm));
		return sizeof(rtm);
	}
	case 3: { /* RTM_*NEIGH: struct ndmsg */
		struct ndmsg ndm;
		ndm.ndm_family = rand_family();
		ndm.ndm_pad1 = 0;
		ndm.ndm_pad2 = 0;
		ndm.ndm_ifindex = rand32() % 64;
		ndm.ndm_state = rand16();
		ndm.ndm_flags = rand() % 256;
		ndm.ndm_type = rand() % 256;
		memcpy(body, &ndm, sizeof(ndm));
		return sizeof(ndm);
	}
	case 4: { /* RTM_*RULE: struct fib_rule_hdr */
		struct fib_rule_hdr frh;
		frh.family = rand_family();
		frh.dst_len = rand() % 129;
		frh.src_len = rand() % 129;
		frh.tos = rand() % 256;
		frh.table = rand() % 256;
		frh.res1 = 0;
		frh.res2 = 0;
		frh.action = rand() % 256;
		frh.flags = rand32();
		memcpy(body, &frh, sizeof(frh));
		return sizeof(frh);
	}
	case 5: /* RTM_*QDISC */
	case 6: /* RTM_*TCLASS */
	case 7: { /* RTM_*TFILTER: struct tcmsg */
		struct tcmsg tc;
		tc.tcm_family = rand_family();
		tc.tcm__pad1 = 0;
		tc.tcm__pad2 = 0;
		tc.tcm_ifindex = rand32() % 64;
		tc.tcm_handle = rand32();
		tc.tcm_parent = rand32();
		tc.tcm_info = rand32();
		memcpy(body, &tc, sizeof(tc));
		return sizeof(tc);
	}
	default: { /* Everything else: struct rtgenmsg (1 byte) */
		struct rtgenmsg gen;
		gen.rtgen_family = rand_family();
		memcpy(body, &gen, sizeof(gen));
		return sizeof(gen);
	}
	}
}

/*
 * Generate body for NETLINK_GENERIC messages.
 * All genl messages have a genlmsghdr (4 bytes) immediately after nlmsghdr.
 * For the controller (GENL_ID_CTRL), we pick from CTRL_CMD_* commands.
 * For other families, we use random cmd values since we don't know
 * which families are loaded at runtime.
 */
static size_t gen_genl_body(unsigned char *body, unsigned short nlmsg_type)
{
	struct genlmsghdr genl;

	if (nlmsg_type == GENL_ID_CTRL) {
		/* Controller commands: GETFAMILY is the most useful */
		genl.cmd = RAND_RANGE(CTRL_CMD_UNSPEC, CTRL_CMD_MAX);
	} else {
		/* Unknown family: random command, biased toward low values */
		if (RAND_BOOL())
			genl.cmd = rand() % 16;
		else
			genl.cmd = rand() % 256;
	}
	genl.version = RAND_BOOL() ? 1 : rand() % 4;
	/* reserved: usually 0, but fuzz it sometimes to test validation */
	genl.reserved = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &genl, sizeof(genl));
	return sizeof(genl);
}

/* Pick an nlattr type for genl controller messages. */
static unsigned short pick_genl_attr_type(unsigned short nlmsg_type)
{
	if (nlmsg_type == GENL_ID_CTRL)
		return RAND_ARRAY(genl_ctrl_attrs);
	return 0; /* unknown family: fall back to random */
}

/*
 * Generate body for NETLINK_NETFILTER messages.
 * nfnetlink messages have a nfgenmsg (4 bytes) after nlmsghdr.
 * The nlmsg_type encodes subsystem << 8 | message.
 * Also improve the type encoding in pick_nlmsg_type() via the
 * nfnl_subsys table to use proper subsystem constants.
 */
static size_t gen_nfnl_body(unsigned char *body)
{
	struct nfgenmsg nfg;
	static const unsigned char nf_families[] = {
		AF_INET, AF_INET6, AF_BRIDGE, AF_UNSPEC,
	};

	if (ONE_IN(8))
		nfg.nfgen_family = rand() % 256;
	else
		nfg.nfgen_family = RAND_ARRAY(nf_families);
	nfg.version = RAND_BOOL() ? NFNETLINK_V0 : rand() % 4;
	nfg.res_id = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &nfg, sizeof(nfg));
	return sizeof(nfg);
}

/*
 * Build a structured netlink message. The caller must free *buf.
 *
 * Structure: [nlmsghdr][protocol body][nlattr...nlattr]
 *
 * For NETLINK_ROUTE, the protocol body is the correct struct for the
 * message type (ifinfomsg, rtmsg, etc.) with fuzzed field values.
 * For other protocols, it's random bytes since the interesting fuzzing
 * is in the message type dispatch.
 *
 * ~1 in 4 messages are multi-message batches (2-4 nlmsghdr chained
 * together) to exercise the kernel's NLMSG_NEXT iteration path.
 */

/* Build a single nlmsghdr at msg+offset. Returns new offset (NLMSG_ALIGN'd). */
static size_t build_one_nlmsg(unsigned char *msg, size_t offset, size_t buflen,
			      struct socket_triplet *triplet)
{
	struct nlmsghdr *nlh;
	unsigned short nlmsg_type;
	size_t body_len;
	size_t msg_start = offset;
	int num_attrs;

	if (offset + NLMSG_HDRLEN + 4 > buflen)
		return offset;

	nlmsg_type = pick_nlmsg_type(triplet->protocol);

	nlh = (struct nlmsghdr *) (msg + offset);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = gen_nlmsg_flags();
	nlh->nlmsg_seq = rand32();
	nlh->nlmsg_pid = RAND_BOOL() ? 0 : rand32();

	offset += NLMSG_HDRLEN;

	/* Generate protocol-appropriate body struct */
	if (triplet->protocol == NETLINK_ROUTE &&
	    nlmsg_type >= RTM_BASE && nlmsg_type < RTM_MAX) {
		body_len = gen_rtnl_body(msg + offset, nlmsg_type);
	} else if (triplet->protocol == NETLINK_GENERIC) {
		body_len = gen_genl_body(msg + offset, nlmsg_type);
	} else if (triplet->protocol == NETLINK_NETFILTER) {
		body_len = gen_nfnl_body(msg + offset);
	} else {
		body_len = RAND_RANGE(4, 64);
		if (offset + body_len > buflen)
			body_len = buflen - offset;
		generate_rand_bytes(msg + offset, body_len);
	}
	offset += body_len;

	/* Append nlattr TLVs with protocol-appropriate types */
	num_attrs = rand() % 8;
	while (num_attrs-- > 0 && offset < buflen) {
		unsigned short attr_hint = 0;

		if (triplet->protocol == NETLINK_ROUTE)
			attr_hint = pick_rtnl_attr_type(nlmsg_type);
		else if (triplet->protocol == NETLINK_GENERIC)
			attr_hint = pick_genl_attr_type(nlmsg_type);
		offset = append_nlattr(msg, offset, buflen, attr_hint);
	}

	/* Set nlmsg_len — usually correct, sometimes corrupted */
	if (ONE_IN(10)) {
		switch (rand() % 4) {
		case 0: nlh->nlmsg_len = 0; break;
		case 1: nlh->nlmsg_len = NLMSG_HDRLEN - 1; break;
		case 2: nlh->nlmsg_len = (offset - msg_start) * 2; break;
		case 3: nlh->nlmsg_len = rand32(); break;
		}
	} else {
		nlh->nlmsg_len = offset - msg_start;
	}

	/* NLMSG_ALIGN for chaining */
	return NLMSG_ALIGN(offset);
}

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	size_t total_len;
	size_t offset;
	unsigned char *msg;
	int num_msgs;

	/* Total buffer: room for up to 4 messages with attrs */
	total_len = NLMSG_HDRLEN + 64 + (rand() % 512);
	/* Multi-message batches need more space */
	if (ONE_IN(4)) {
		num_msgs = RAND_RANGE(2, 4);
		total_len *= num_msgs;
	} else {
		num_msgs = 1;
	}
	if (total_len > 8192)
		total_len = 8192;

	msg = zmalloc(total_len);

	offset = 0;
	while (num_msgs-- > 0 && offset < total_len)
		offset = build_one_nlmsg(msg, offset, total_len, triplet);

	*buf = msg;
	*len = offset;
}
