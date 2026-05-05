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
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/connector.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "net.h"
#include "netlink-attrs.h"
#include "netlink-genl-families.h"
#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

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

	if (RAND_BOOL())
		flags |= NLM_F_ECHO;

	/* GET-style: dump flags */
	if (RAND_BOOL())
		flags |= NLM_F_DUMP;

	if (RAND_BOOL())
		flags |= NLM_F_ATOMIC;

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

	/* DELETE-style: bulk/non-recursive flags */
	if (RAND_BOOL())
		flags |= NLM_F_NONREC;
	if (RAND_BOOL())
		flags |= NLM_F_BULK;

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
		 *
		 * Bias toward (subsys, cmd) pairs from the registry so the
		 * kernel's per-subsys nfnl_callback dispatcher actually
		 * accepts the type byte; the registered cmd set comes from
		 * net/netlink-nfnl-sub-*.c.  Keep an unknown-cmd path with
		 * low probability to keep exercising the
		 * dispatcher-not-registered fast-reject. */
		static const unsigned char nfnl_subsys[] = {
			NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK_EXP,
			NFNL_SUBSYS_QUEUE, NFNL_SUBSYS_ULOG,
			NFNL_SUBSYS_OSF, NFNL_SUBSYS_IPSET,
			NFNL_SUBSYS_ACCT, NFNL_SUBSYS_CTNETLINK_TIMEOUT,
			NFNL_SUBSYS_CTHELPER, NFNL_SUBSYS_NFTABLES,
			NFNL_SUBSYS_NFT_COMPAT, NFNL_SUBSYS_HOOK,
		};
		unsigned char subsys;

		if (!ONE_IN(4)) {
			const struct nfnl_subsys_grammar *sub;

			sub = nfnl_pick_subsys();
			if (sub != NULL)
				return (sub->subsys_id << 8) | nfnl_pick_cmd(sub);
		}
		if (ONE_IN(8))
			subsys = rand() % 16;
		else
			subsys = RAND_ARRAY(nfnl_subsys);
		return (subsys << 8) | (rand() % 16);
	}
	case NETLINK_GENERIC:
		/* genl: prefer a runtime-resolved family id from the
		 * grammar registry when one is available; that gets the
		 * message past the kernel's family demuxer into the
		 * actual per-family parser.  Fall back to GENL_ID_CTRL or
		 * a random nlmsg_type in the dynamic-allocation range to
		 * keep exercising the unknown-family fast-reject path. */
		if (!ONE_IN(4)) {
			struct genl_family_grammar *fam;

			genl_resolve_families();
			fam = genl_pick_resolved_family();
			if (fam != NULL)
				return fam->family_id;
		}
		if (RAND_BOOL())
			return GENL_ID_CTRL;
		return RAND_RANGE(GENL_MIN_ID, GENL_MIN_ID + 64);
	case NETLINK_SOCK_DIAG:
		/* SOCK_DIAG_BY_FAMILY=20, SOCK_DESTROY=21 are the main ones.
		 * Also cover legacy inet_diag range and INET_DIAG_GETSOCK_MAX. */
		if (RAND_BOOL())
			return RAND_BOOL() ? SOCK_DIAG_BY_FAMILY : SOCK_DESTROY;
		return RAND_RANGE(NLMSG_MIN_TYPE, INET_DIAG_GETSOCK_MAX);
	case NETLINK_CONNECTOR:
		return RAND_RANGE(0, 4);
	default:
		/* Unknown protocol: use NLMSG_MIN_TYPE or random */
		if (RAND_BOOL())
			return RAND_RANGE(NLMSG_MIN_TYPE, NLMSG_MIN_TYPE + 32);
		return rand16();
	}
}

/*
 * Generate random IPv4 address, biased toward useful values.
 */
static __u32 rand_ipv4(void)
{
	if (ONE_IN(4))
		return htonl(0x7f000001);	/* 127.0.0.1 */
	if (ONE_IN(4))
		return htonl(RAND_RANGE(0xc0a80001, 0xc0a800fe)); /* 192.168.0.x */
	if (ONE_IN(4))
		return htonl(RAND_RANGE(0x0a000001, 0x0a0000fe)); /* 10.0.0.x */
	return rand32();
}

/*
 * Generate random IPv6 address.
 */
static void rand_ipv6(struct in6_addr *addr)
{
	if (ONE_IN(4)) {
		/* ::1 loopback */
		memset(addr, 0, sizeof(*addr));
		addr->s6_addr[15] = 1;
	} else if (ONE_IN(3)) {
		/* fe80:: link-local */
		memset(addr, 0, sizeof(*addr));
		addr->s6_addr[0] = 0xfe;
		addr->s6_addr[1] = 0x80;
		generate_rand_bytes(&addr->s6_addr[8], 8);
	} else {
		generate_rand_bytes((unsigned char *)addr, sizeof(*addr));
	}
}

/*
 * Write an nlattr header at buf+offset. Returns pointer past the header,
 * or NULL if there's not enough room. Caller fills the payload.
 * After filling, caller must update nla_len if known, and advance offset
 * by NLA_ALIGN(nla_len).
 */
static struct nlattr *start_nlattr(unsigned char *buf, size_t offset,
				   size_t buflen, unsigned short nla_type,
				   size_t payload_len)
{
	struct nlattr nla;
	size_t total = NLA_ALIGN(NLA_HDRLEN + payload_len);

	if (offset + total > buflen)
		return NULL;

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = nla_type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	return (struct nlattr *)(buf + offset);
}

/*
 * Build a chain of nested sub-attributes inside a buffer.
 * Returns the total length of the nested chain (unaligned).
 * This is used for containers like RTA_METRICS, IFLA_LINKINFO, IFLA_AF_SPEC.
 */
static size_t build_nested_attrs(unsigned char *buf, size_t buflen,
				 const unsigned short *attr_types,
				 size_t nr_types, int max_depth)
{
	size_t offset = 0;
	int count = RAND_RANGE(1, 4);

	if (max_depth <= 0)
		count = RAND_RANGE(1, 2);

	while (count-- > 0 && offset + NLA_HDRLEN + 4 <= buflen) {
		unsigned short atype = attr_types[rand() % nr_types];
		size_t payload_len;
		size_t total;

		/* Random payload 4-32 bytes */
		payload_len = RAND_RANGE(4, 32);
		if (payload_len > buflen - offset - NLA_HDRLEN)
			payload_len = buflen - offset - NLA_HDRLEN;

		total = NLA_ALIGN(NLA_HDRLEN + payload_len);
		if (offset + total > buflen)
			break;

		if (!start_nlattr(buf, offset, buflen, atype, payload_len))
			break;
		generate_rand_bytes(buf + offset + NLA_HDRLEN, payload_len);
		offset += total;
	}
	return offset;
}

/* RTAX_* metrics sub-attributes for RTA_METRICS nested container */
static const unsigned short rtax_attrs[] = {
	RTAX_MTU, RTAX_WINDOW, RTAX_RTT, RTAX_RTTVAR,
	RTAX_SSTHRESH, RTAX_CWND, RTAX_ADVMSS, RTAX_REORDERING,
	RTAX_HOPLIMIT, RTAX_INITCWND, RTAX_FEATURES, RTAX_RTO_MIN,
	RTAX_INITRWND, RTAX_QUICKACK,
};

/* Link type names for IFLA_INFO_KIND */
static const char *link_kinds[] = {
	"veth", "bridge", "bond", "vlan", "macvlan",
	"vxlan", "ipvlan", "dummy", "ifb", "gre",
	"gretap", "sit", "ip6tnl", "ip6gre", "vti",
};

/*
 * Generate a structured payload for route attributes (RTA_*).
 * Returns payload length, or 0 for random fallback.
 */
static size_t gen_rta_route_payload(unsigned char *p, size_t avail,
				    unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case RTA_DST:
	case RTA_SRC:
	case RTA_GATEWAY:
	case RTA_PREFSRC:
		if (family == AF_INET6 && avail >= 16) {
			struct in6_addr addr;
			rand_ipv6(&addr);
			memcpy(p, &addr, 16);
			return 16;
		}
		if (avail >= 4) {
			__u32 addr = rand_ipv4();
			memcpy(p, &addr, 4);
			return 4;
		}
		return 0;

	case RTA_OIF:
	case RTA_IIF:
	case RTA_TABLE:
	case RTA_MARK:
	case RTA_NH_ID:
	case RTA_PRIORITY:
		if (avail >= 4) {
			__u32 val = rand32() % 64;
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case RTA_PREF:
	case RTA_TTL_PROPAGATE:
	case RTA_IP_PROTO:
		if (avail >= 1) {
			*p = rand() % 256;
			return 1;
		}
		return 0;

	case RTA_SPORT:
	case RTA_DPORT:
	case RTA_ENCAP_TYPE:
		if (avail >= 2) {
			unsigned short val = rand16();
			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case RTA_UID:
	case RTA_EXPIRES:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case RTA_CACHEINFO:
		if (avail >= sizeof(struct rta_cacheinfo)) {
			struct rta_cacheinfo ci;
			generate_rand_bytes((unsigned char *)&ci, sizeof(ci));
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case RTA_METRICS:
		/* Nested container of RTAX_* sub-attributes */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, rtax_attrs,
						  ARRAY_SIZE(rtax_attrs), 0);
		}
		return 0;

	case RTA_MULTIPATH: {
		/* Array of struct rtnexthop, each optionally followed by RTA_GATEWAY */
		size_t written = 0;
		int nhops = RAND_RANGE(1, 3);

		while (nhops-- > 0 && written + sizeof(struct rtnexthop) <= avail) {
			struct rtnexthop nh;
			size_t nh_start = written;

			nh.rtnh_flags = rand() % 256;
			nh.rtnh_hops = rand() % 256;
			nh.rtnh_ifindex = rand32() % 64;
			nh.rtnh_len = sizeof(struct rtnexthop);

			memcpy(p + written, &nh, sizeof(nh));
			written += sizeof(struct rtnexthop);

			/* Sometimes append an RTA_GATEWAY after the nexthop */
			if (RAND_BOOL() && written + NLA_HDRLEN + 4 <= avail) {
				struct nlattr gw_nla;
				__u32 gw = rand_ipv4();

				gw_nla.nla_len = NLA_HDRLEN + 4;
				gw_nla.nla_type = RTA_GATEWAY;
				memcpy(p + written, &gw_nla, NLA_HDRLEN);
				memcpy(p + written + NLA_HDRLEN, &gw, 4);
				written += NLA_ALIGN(NLA_HDRLEN + 4);
			}

			/* Update rtnh_len to include any trailing attrs */
			nh.rtnh_len = written - nh_start;
			memcpy(p + nh_start, &nh, sizeof(nh.rtnh_len));
		}
		return written;
	}

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for link attributes (IFLA_*).
 */
static size_t gen_rta_link_payload(unsigned char *p, size_t avail,
				   unsigned short nla_type)
{
	switch (nla_type) {
	case IFLA_IFNAME:
	case IFLA_QDISC:
	case IFLA_IFALIAS: {
		static const char *names[] = {
			"eth0", "lo", "br0", "bond0", "veth0",
			"dummy0", "wlan0", "tun0",
		};
		const char *name = RAND_ARRAY(names);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case IFLA_ALT_IFNAME: {
		static const char *alts[] = { "altname0", "renamed1" };
		const char *name = RAND_ARRAY(alts);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case IFLA_MTU:
	case IFLA_MIN_MTU:
	case IFLA_MAX_MTU:
		if (avail >= 4) {
			__u32 val = RAND_RANGE(68, 65535);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_TXQLEN:
		if (avail >= 4) {
			__u32 val = RAND_RANGE(0, 10000);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_GROUP:
	case IFLA_PROMISCUITY:
	case IFLA_NUM_TX_QUEUES:
	case IFLA_NUM_RX_QUEUES:
	case IFLA_NUM_VF:
	case IFLA_GSO_MAX_SEGS:
	case IFLA_GSO_MAX_SIZE:
	case IFLA_NEW_IFINDEX:
	case IFLA_LINK:
	case IFLA_MASTER:
	case IFLA_EXT_MASK:
	case IFLA_LINK_NETNSID:
	case IFLA_NET_NS_PID:
	case IFLA_NET_NS_FD:
		if (avail >= 4) {
			__u32 val = rand32() % 64;
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_ADDRESS:
	case IFLA_BROADCAST:
	case IFLA_PERM_ADDRESS:
		/* MAC address: 6 bytes */
		if (avail >= 6) {
			generate_rand_bytes(p, 6);
			return 6;
		}
		return 0;

	case IFLA_OPERSTATE:
	case IFLA_LINKMODE:
	case IFLA_CARRIER:
	case IFLA_PROTO_DOWN:
		if (avail >= 1) {
			*p = rand() % 8;
			return 1;
		}
		return 0;

	case IFLA_WEIGHT:
	case IFLA_COST:
	case IFLA_PRIORITY:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_LINKINFO:
		/* Nested: IFLA_INFO_KIND (string) + optional IFLA_INFO_DATA */
		if (avail >= NLA_HDRLEN + 8) {
			size_t nested_len = 0;
			const char *kind = RAND_ARRAY(link_kinds);
			size_t kind_len = strlen(kind) + 1;
			size_t kind_total = NLA_ALIGN(NLA_HDRLEN + kind_len);

			/* IFLA_INFO_KIND */
			if (nested_len + kind_total <= avail) {
				if (start_nlattr(p, nested_len, avail,
						 IFLA_INFO_KIND, kind_len)) {
					memcpy(p + nested_len + NLA_HDRLEN,
					       kind, kind_len);
					nested_len += kind_total;
				}
			}

			/* Sometimes add IFLA_INFO_DATA with random nested attrs */
			if (RAND_BOOL() && nested_len + NLA_HDRLEN + 8 <= avail) {
				size_t data_avail = avail - nested_len - NLA_HDRLEN;
				size_t data_len;
				unsigned char sub[128];

				if (data_avail > sizeof(sub))
					data_avail = sizeof(sub);
				data_len = RAND_RANGE(4, data_avail);
				generate_rand_bytes(sub, data_len);

				if (start_nlattr(p, nested_len, avail,
						 IFLA_INFO_DATA | NLA_F_NESTED,
						 data_len)) {
					memcpy(p + nested_len + NLA_HDRLEN,
					       sub, data_len);
					nested_len += NLA_ALIGN(NLA_HDRLEN + data_len);
				}
			}

			return nested_len;
		}
		return 0;

	case IFLA_AF_SPEC: {
		/* Nested: per-address-family containers */
		size_t nested_len = 0;
		int i, count = RAND_RANGE(1, 3);
		static const unsigned char af_types[] = {
			AF_INET, AF_INET6, AF_BRIDGE,
		};

		for (i = 0; i < count && nested_len + NLA_HDRLEN + 8 <= avail; i++) {
			unsigned char af = RAND_ARRAY(af_types);
			size_t inner_avail = avail - nested_len - NLA_HDRLEN;
			size_t inner_len;
			unsigned char inner[64];

			if (inner_avail > sizeof(inner))
				inner_avail = sizeof(inner);
			inner_len = RAND_RANGE(4, inner_avail);
			generate_rand_bytes(inner, inner_len);

			if (start_nlattr(p, nested_len, avail,
					 af | NLA_F_NESTED, inner_len)) {
				memcpy(p + nested_len + NLA_HDRLEN,
				       inner, inner_len);
				nested_len += NLA_ALIGN(NLA_HDRLEN + inner_len);
			}
		}
		return nested_len;
	}

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for address attributes (IFA_*).
 */
static size_t gen_rta_addr_payload(unsigned char *p, size_t avail,
				   unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case IFA_ADDRESS:
	case IFA_LOCAL:
	case IFA_BROADCAST:
	case IFA_ANYCAST:
		if (family == AF_INET6 && avail >= 16) {
			struct in6_addr addr;
			rand_ipv6(&addr);
			memcpy(p, &addr, 16);
			return 16;
		}
		if (avail >= 4) {
			__u32 addr = rand_ipv4();
			memcpy(p, &addr, 4);
			return 4;
		}
		return 0;

	case IFA_LABEL: {
		static const char *labels[] = {
			"eth0", "eth0:1", "lo", "br0",
		};
		const char *label = RAND_ARRAY(labels);
		size_t slen = strlen(label) + 1;

		if (avail >= slen) {
			memcpy(p, label, slen);
			return slen;
		}
		return 0;
	}

	case IFA_CACHEINFO:
		if (avail >= sizeof(struct ifa_cacheinfo)) {
			struct ifa_cacheinfo ci;
			ci.ifa_prefered = rand32();
			ci.ifa_valid = rand32();
			ci.cstamp = rand32();
			ci.tstamp = rand32();
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case IFA_FLAGS:
	case IFA_RT_PRIORITY:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFA_PROTO:
		if (avail >= 1) {
			*p = rand() % 256;
			return 1;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for neighbor attributes (NDA_*).
 */
static size_t gen_rta_neigh_payload(unsigned char *p, size_t avail,
				    unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case NDA_DST:
		if (family == AF_INET6 && avail >= 16) {
			struct in6_addr addr;
			rand_ipv6(&addr);
			memcpy(p, &addr, 16);
			return 16;
		}
		if (avail >= 4) {
			__u32 addr = rand_ipv4();
			memcpy(p, &addr, 4);
			return 4;
		}
		return 0;

	case NDA_LLADDR:
		/* Link-layer address (MAC): 6 bytes */
		if (avail >= 6) {
			generate_rand_bytes(p, 6);
			return 6;
		}
		return 0;

	case NDA_CACHEINFO:
		if (avail >= sizeof(struct nda_cacheinfo)) {
			struct nda_cacheinfo ci;
			ci.ndm_confirmed = rand32();
			ci.ndm_used = rand32();
			ci.ndm_updated = rand32();
			ci.ndm_refcnt = rand32();
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case NDA_PROBES:
	case NDA_IFINDEX:
	case NDA_MASTER:
	case NDA_LINK_NETNSID:
	case NDA_SRC_VNI:
	case NDA_VNI:
	case NDA_NH_ID:
	case NDA_FLAGS_EXT:
	case NDA_NDM_STATE_MASK:
	case NDA_NDM_FLAGS_MASK:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NDA_VLAN:
	case NDA_PORT:
		if (avail >= 2) {
			unsigned short val = rand16();
			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case NDA_PROTOCOL:
		if (avail >= 1) {
			*p = rand() % 256;
			return 1;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for a specific rtnetlink attribute.
 * Dispatches to the appropriate per-group generator based on the
 * rtnetlink message group. Returns the payload length, or 0 for
 * random fallback.
 */
static size_t gen_rta_payload(unsigned char *buf, size_t offset, size_t buflen,
			      unsigned short nla_type, unsigned char family,
			      int rtnl_group)
{
	size_t avail = buflen - offset;
	unsigned char *p = buf + offset;

	switch (rtnl_group) {
	case 0: return gen_rta_link_payload(p, avail, nla_type);
	case 1: return gen_rta_addr_payload(p, avail, nla_type, family);
	case 2: return gen_rta_route_payload(p, avail, nla_type, family);
	case 3: return gen_rta_neigh_payload(p, avail, nla_type, family);
	default: return 0;
	}
}

/*
 * Append a single nlattr to buf at offset. Returns new offset.
 * nla_type_hint is a protocol-appropriate attr type; 0 means random.
 * family is the address family from the body struct (for address sizing).
 */
static size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			    unsigned short nla_type_hint, unsigned char family,
			    int rtnl_group)
{
	struct nlattr nla;
	size_t payload_len;
	size_t structured_len;
	size_t total;
	unsigned short nla_type;

	if (offset + NLA_HDRLEN > buflen)
		return offset;

	/* Decide the attr type first */
	if (nla_type_hint && !ONE_IN(8))
		nla_type = nla_type_hint;
	else
		nla_type = rand16();

	/* Try structured payload generation for known types */
	structured_len = gen_rta_payload(buf, offset + NLA_HDRLEN, buflen,
					nla_type, family, rtnl_group);
	if (structured_len > 0) {
		payload_len = structured_len;
	} else {
		/* Fall back to random bytes */
		payload_len = rand() % 64;
	}

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		total = buflen - offset;
		if (total < NLA_HDRLEN)
			return offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = nla_type;

	/* Sometimes set nested/net-byteorder flags */
	if (ONE_IN(4))
		nla.nla_type |= NLA_F_NESTED;
	if (ONE_IN(8))
		nla.nla_type |= NLA_F_NET_BYTEORDER;

	memcpy(buf + offset, &nla, NLA_HDRLEN);

	/* If we didn't do structured generation, fill with random data */
	if (structured_len == 0 && payload_len > 0)
		generate_rand_bytes(buf + offset + NLA_HDRLEN, payload_len);

	return offset + NLA_ALIGN(NLA_HDRLEN + payload_len);
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

/*
 * Per-family attribute spec tables.
 *
 * Each entry pairs an attribute type with its kernel-side kind (NLA_U8,
 * NLA_STRING, NLA_NESTED, etc.) and an upper bound on the payload
 * length.  This carries enough information for the generator to emit
 * an attribute that survives the family's nla_policy validation gate
 * (nla_parse_nested_deprecated, nla_validate) and reaches the deeper
 * command dispatch where bugs actually live.  Without this, most
 * generated attrs are length-rejected with -EINVAL before any code
 * the family cares about gets to run.
 */
/* genl controller (GENL_ID_CTRL) attributes */
static const struct nla_attr_spec ctrl_specs[] = {
	{ CTRL_ATTR_FAMILY_ID,    NLA_KIND_U16,    2 },
	{ CTRL_ATTR_FAMILY_NAME,  NLA_KIND_STRING, GENL_NAMSIZ },
	{ CTRL_ATTR_VERSION,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_HDRSIZE,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_MAXATTR,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_OPS,          NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_MCAST_GROUPS, NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_POLICY,       NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_OP,           NLA_KIND_U32,    4 },
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
static size_t gen_rtnl_body(unsigned char *body, unsigned short nlmsg_type,
			    unsigned char *out_family)
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
		*out_family = ifi.ifi_family;
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
		*out_family = ifa.ifa_family;
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
		*out_family = rtm.rtm_family;
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
		*out_family = ndm.ndm_family;
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
		*out_family = frh.family;
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
		*out_family = tc.tcm_family;
		memcpy(body, &tc, sizeof(tc));
		return sizeof(tc);
	}
	default: { /* Everything else: struct rtgenmsg (1 byte) */
		struct rtgenmsg gen;
		gen.rtgen_family = rand_family();
		*out_family = gen.rtgen_family;
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
	const struct genl_family_grammar *fam;
	struct genlmsghdr genl;

	if (nlmsg_type == GENL_ID_CTRL) {
		/* Controller commands: GETFAMILY is the most useful */
		genl.cmd = RAND_RANGE(CTRL_CMD_UNSPEC, CTRL_CMD_MAX);
		genl.version = RAND_BOOL() ? 1 : rand() % 4;
	} else if ((fam = genl_lookup_by_id(nlmsg_type)) != NULL) {
		/* Resolved family: pick a known cmd from its grammar so the
		 * family's command dispatcher accepts it.  Use the family's
		 * preferred version when set so the version gate also
		 * passes; the kernel-side check is usually >= so a small
		 * version is fine. */
		genl.cmd = genl_pick_cmd(fam);
		genl.version = fam->default_version ? fam->default_version : 1;
		genl_family_bump_calls(fam);
	} else {
		/* Unknown family: random command, biased toward low values */
		if (RAND_BOOL())
			genl.cmd = rand() % 16;
		else
			genl.cmd = rand() % 256;
		genl.version = RAND_BOOL() ? 1 : rand() % 4;
	}
	/* reserved: usually 0, but fuzz it sometimes to test validation */
	genl.reserved = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &genl, sizeof(genl));
	return sizeof(genl);
}

/* Pick an nlattr type for genl controller messages.  Reads through the
 * ctrl_specs spec table; the legacy flat-attr code path still needs a
 * raw nla_type when nesting a NETLINK_GENERIC controller attr via
 * append_nested_attr_container().  The spec-driven path bypasses this. */
static unsigned short pick_genl_attr_type(unsigned short nlmsg_type)
{
	if (nlmsg_type == GENL_ID_CTRL)
		return ctrl_specs[rand() % ARRAY_SIZE(ctrl_specs)].type;
	return 0; /* unknown family: fall back to random */
}

/*
 * Generate body for NETLINK_NETFILTER messages.
 * nfnetlink messages have a nfgenmsg (4 bytes) after nlmsghdr.
 * The nlmsg_type encodes subsystem << 8 | message.  After building
 * the body, bump the per-subsys dispatch counter so the live
 * subsystem mix is visible in the periodic stats dump and end-of-run
 * summary; bump degrades to a no-op when nlmsg_type's high byte
 * doesn't match any registered subsys.
 */
static size_t gen_nfnl_body(unsigned char *body, unsigned short nlmsg_type)
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
	nfnl_subsys_bump_calls(nfnl_lookup_by_subsys(nlmsg_type >> 8));
	return sizeof(nfg);
}

/* XFRM attribute spec table (XFRMA_*) */
static const struct nla_attr_spec xfrma_specs[] = {
	{ XFRMA_ALG_AUTH,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_CRYPT,       NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_COMP,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_AEAD,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_AUTH_TRUNC,  NLA_KIND_BINARY, 128 },
	{ XFRMA_ENCAP,           NLA_KIND_BINARY, 24 },
	{ XFRMA_TMPL,            NLA_KIND_BINARY, 64 },
	{ XFRMA_SA,              NLA_KIND_NESTED, 0 },
	{ XFRMA_POLICY,          NLA_KIND_NESTED, 0 },
	{ XFRMA_SEC_CTX,         NLA_KIND_BINARY, 32 },
	{ XFRMA_LTIME_VAL,       NLA_KIND_BINARY, 32 },
	{ XFRMA_REPLAY_VAL,      NLA_KIND_BINARY, 16 },
	{ XFRMA_REPLAY_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_ETIMER_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_SRCADDR,         NLA_KIND_BINARY, 16 },
	{ XFRMA_COADDR,          NLA_KIND_BINARY, 16 },
	{ XFRMA_LASTUSED,        NLA_KIND_U64,    8 },
	{ XFRMA_POLICY_TYPE,     NLA_KIND_BINARY, 4 },
	{ XFRMA_MIGRATE,         NLA_KIND_BINARY, 64 },
	{ XFRMA_KMADDRESS,       NLA_KIND_BINARY, 36 },
	{ XFRMA_MARK,            NLA_KIND_BINARY, 8 },
	{ XFRMA_TFCPAD,          NLA_KIND_U32,    4 },
	{ XFRMA_REPLAY_ESN_VAL,  NLA_KIND_BINARY, 32 },
	{ XFRMA_SA_EXTRA_FLAGS,  NLA_KIND_U32,    4 },
	{ XFRMA_PROTO,           NLA_KIND_U8,     1 },
	{ XFRMA_ADDRESS_FILTER,  NLA_KIND_BINARY, 36 },
	{ XFRMA_OFFLOAD_DEV,     NLA_KIND_BINARY, 8 },
	{ XFRMA_SET_MARK,        NLA_KIND_U32,    4 },
	{ XFRMA_SET_MARK_MASK,   NLA_KIND_U32,    4 },
	{ XFRMA_IF_ID,           NLA_KIND_U32,    4 },
	{ XFRMA_MTIMER_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_SA_DIR,          NLA_KIND_U8,     1 },
};

/*
 * Generate body for NETLINK_XFRM messages.
 * Body struct varies by message type. The big structs (xfrm_usersa_info
 * at 224 bytes, xfrm_userpolicy_info at 168 bytes) are filled with
 * random data of the correct size. Getting the size right is what
 * matters — it gets us past the initial copy_from_user length check
 * into the deeper validation code where the interesting bugs live.
 */
static size_t gen_xfrm_body(unsigned char *body, unsigned short nlmsg_type)
{
	size_t body_len;

	switch (nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		body_len = sizeof(struct xfrm_usersa_info);
		break;
	case XFRM_MSG_DELSA:
	case XFRM_MSG_GETSA:
		body_len = sizeof(struct xfrm_usersa_id);
		break;
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_info);
		break;
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_GETPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_id);
		break;
	case XFRM_MSG_ALLOCSPI:
		body_len = sizeof(struct xfrm_userspi_info);
		break;
	case XFRM_MSG_ACQUIRE:
		body_len = sizeof(struct xfrm_user_acquire);
		break;
	case XFRM_MSG_EXPIRE:
		body_len = sizeof(struct xfrm_user_expire);
		break;
	case XFRM_MSG_POLEXPIRE:
		body_len = sizeof(struct xfrm_user_polexpire);
		break;
	case XFRM_MSG_FLUSHSA:
		body_len = sizeof(struct xfrm_usersa_flush);
		break;
	case XFRM_MSG_FLUSHPOLICY:
		body_len = 0; /* no body */
		break;
	case XFRM_MSG_NEWAE:
	case XFRM_MSG_GETAE:
		body_len = sizeof(struct xfrm_aevent_id);
		break;
	case XFRM_MSG_MIGRATE:
		body_len = sizeof(struct xfrm_user_migrate);
		break;
	case XFRM_MSG_GETSADINFO:
	case XFRM_MSG_GETSPDINFO:
		body_len = sizeof(__u32);
		break;
	default:
		/* Unknown xfrm type: random body */
		body_len = RAND_RANGE(4, 32);
		break;
	}

	if (body_len > 0)
		generate_rand_bytes(body, body_len);
	return body_len;
}

/*
 * Generate body for NETLINK_AUDIT messages.
 * Audit is special: it doesn't use nlattr TLVs. Message payloads are
 * either binary structs (audit_status, audit_rule_data) or raw text.
 * The caller should skip nlattr generation for audit messages.
 */
static size_t gen_audit_body(unsigned char *body, unsigned short nlmsg_type,
			     size_t buflen)
{
	size_t body_len;

	switch (nlmsg_type) {
	case AUDIT_GET:
		/* GET takes no body (kernel ignores payload) */
		return 0;
	case AUDIT_SET:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
	case AUDIT_LIST_RULES: {
		/*
		 * audit_rule_data is 1040 bytes base + variable buf[].
		 * Generate the fixed part with fuzzed fields and a small
		 * random buffer extension.
		 */
		size_t extra = rand() % 64;
		body_len = sizeof(struct audit_rule_data) + extra;
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}
	case AUDIT_USER:
	case AUDIT_LOGIN:
		/* Raw text payload */
		body_len = RAND_RANGE(4, 128);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	case AUDIT_TTY_GET:
	case AUDIT_TTY_SET:
	case AUDIT_GET_FEATURE:
	case AUDIT_SET_FEATURE:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_SIGNAL_INFO:
		return 0; /* no body for get requests */
	case AUDIT_TRIM:
		return 0; /* no body */
	case AUDIT_MAKE_EQUIV:
		/* Two paths separated by NUL */
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	default:
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}

	if (body_len > buflen)
		body_len = buflen;
	generate_rand_bytes(body, body_len);
	return body_len;
}

/* sock_diag (INET_DIAG_*) request attribute spec table */
static const struct nla_attr_spec inet_diag_specs[] = {
	{ INET_DIAG_REQ_BYTECODE,        NLA_KIND_BINARY, 256 },
	{ INET_DIAG_REQ_SK_BPF_STORAGES, NLA_KIND_NESTED, 0 },
	{ INET_DIAG_REQ_PROTOCOL,        NLA_KIND_U8,     1 },
};

/*
 * Generate body for NETLINK_SOCK_DIAG messages.
 * Two main message types:
 * - SOCK_DIAG_BY_FAMILY (20): generic sock_diag_req, then the kernel
 *   dispatches to per-family handlers based on sdiag_family.
 * - SOCK_DESTROY (21): inet_diag_req_v2 with socket identification.
 * - Legacy types (< 20): inet_diag_req_v2.
 */
static size_t gen_sockdiag_body(unsigned char *body,
				unsigned short nlmsg_type)
{
	switch (nlmsg_type) {
	case SOCK_DIAG_BY_FAMILY: {
		struct sock_diag_req req;
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rand() % 256;
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	default: {
		/*
		 * SOCK_DESTROY and legacy inet_diag types use
		 * inet_diag_req_v2 (56 bytes). Fill with random data
		 * but set sdiag_family to something useful.
		 */
		struct inet_diag_req_v2 req;
		generate_rand_bytes((unsigned char *)&req, sizeof(req));
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rand() % 256;
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	}
}

/*
 * Build a structured netlink message. The caller must free *buf.
 *
 * Structure: [nlmsghdr][protocol body][nlattr...nlattr]
 *
 * Protocol bodies are generated per-family: rtnetlink uses the correct
 * struct (ifinfomsg, rtmsg, etc.), genl uses genlmsghdr, nfnetlink uses
 * nfgenmsg, xfrm uses per-type structs, audit uses binary structs or
 * text, and sock_diag uses inet_diag_req_v2. Unknown protocols fall
 * back to random bytes.
 *
 * ~1 in 4 messages are multi-message batches (2-4 nlmsghdr chained
 * together) to exercise the kernel's NLMSG_NEXT iteration path.
 */

/*
 * Pick a protocol-appropriate nlattr type for the given netlink protocol
 * and message type.  Returns 0 when the family has no curated table, in
 * which case the caller should fall back to a random type.  Centralised
 * here so both the flat append path and the nested container helper draw
 * from the same per-family tables.
 */
static unsigned short pick_attr_hint(int protocol, unsigned short nlmsg_type)
{
	switch (protocol) {
	case NETLINK_ROUTE:
		return pick_rtnl_attr_type(nlmsg_type);
	case NETLINK_GENERIC:
		return pick_genl_attr_type(nlmsg_type);
	default:
		/* XFRM, SOCK_DIAG, ctnetlink, nftables, genl-ctrl now have
		 * dedicated nla_attr_spec tables consulted directly by
		 * build_one_nlmsg, so they no longer need a raw type pick
		 * here.  Anything that lands in this default returns 0 and
		 * the caller falls back to a random type. */
		return 0;
	}
}

/*
 * Emit a NLA_F_NESTED container at buf+offset.  The outer nlattr carries
 * the NLA_F_NESTED flag and an nla_len that covers a payload of N child
 * nlattrs (1-3) padded to NLA_ALIGNTO.  Each child's type is drawn from
 * the same per-family table used for flat attributes; payloads are sized
 * via the existing structured generators where applicable, falling back
 * to short random blobs.  Children are deliberately one level deep —
 * deeper recursion is left for a follow-up.
 *
 * Returns the new offset.  If there isn't room for a header plus at
 * least one child, the original offset is returned and no bytes are
 * written.  Bumps shm->stats.netlink_nested_attrs_emitted on success so
 * we can confirm in the dump that the new path is actually firing.
 */
static size_t append_nested_attr_container(unsigned char *buf, size_t offset,
					   size_t buflen,
					   unsigned short outer_type,
					   int protocol,
					   unsigned short nlmsg_type,
					   unsigned char body_family,
					   int rtnl_group)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off = 0;
	size_t total;
	int child_count;

	/* Need outer header + at least one minimum-sized child */
	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	/* Cap so a single nested container can't dominate the message */
	if (inner_avail > 256)
		inner_avail = 256;

	child_count = RAND_RANGE(1, 3);
	while (child_count-- > 0 && inner_off + NLA_HDRLEN + 4 <= inner_avail) {
		struct nlattr child;
		unsigned short ctype;
		size_t cpayload;
		size_t structured_len;
		size_t ctotal;

		ctype = pick_attr_hint(protocol, nlmsg_type);
		if (ctype == 0)
			ctype = rand16();

		/* Try the rtnetlink structured payload generator first; it
		 * returns 0 for non-rtnl groups and for types it doesn't know,
		 * in which case we fall back to a short random blob. */
		structured_len = gen_rta_payload(inner, inner_off + NLA_HDRLEN,
						 inner_avail, ctype,
						 body_family, rtnl_group);
		if (structured_len > 0) {
			cpayload = structured_len;
		} else {
			cpayload = RAND_RANGE(4, 32);
			if (cpayload > inner_avail - inner_off - NLA_HDRLEN)
				cpayload = inner_avail - inner_off - NLA_HDRLEN;
		}

		ctotal = NLA_ALIGN(NLA_HDRLEN + cpayload);
		if (inner_off + ctotal > inner_avail)
			break;

		child.nla_len = NLA_HDRLEN + cpayload;
		child.nla_type = ctype;
		memcpy(inner + inner_off, &child, NLA_HDRLEN);
		if (structured_len == 0 && cpayload > 0)
			generate_rand_bytes(inner + inner_off + NLA_HDRLEN,
					    cpayload);
		inner_off += ctotal;
	}

	if (inner_off == 0)
		return offset;

	nla.nla_len = NLA_HDRLEN + inner_off;
	nla.nla_type = outer_type | NLA_F_NESTED;
	memcpy(buf + offset, &nla, NLA_HDRLEN);

	total = NLA_ALIGN(NLA_HDRLEN + inner_off);
	if (offset + total > buflen)
		total = buflen - offset;

	__atomic_add_fetch(&shm->stats.netlink_nested_attrs_emitted, 1,
			   __ATOMIC_RELAXED);

	return offset + total;
}

/*
 * Compute payload length implied by an nla_attr_spec.  Variable-length
 * kinds (STRING, BINARY) draw a length in [4, max_len], or just take
 * max_len when it's already <= 4.
 */
static size_t spec_payload_len(const struct nla_attr_spec *spec)
{
	switch (spec->kind) {
	case NLA_KIND_U8:	return 1;
	case NLA_KIND_U16:	return 2;
	case NLA_KIND_U32:	return 4;
	case NLA_KIND_U64:	return 8;
	case NLA_KIND_FLAG:	return 0;
	case NLA_KIND_STRING:
	case NLA_KIND_BINARY:
		if (spec->max_len > 4)
			return RAND_RANGE(4, spec->max_len);
		return spec->max_len;
	case NLA_KIND_NESTED:
		/* Caller decides — nested kinds get a recursive emission */
		return 0;
	default:
		return 0;
	}
}

/*
 * Fill a payload buffer per spec kind: STRING gets NUL-terminated random
 * lowercase ASCII (the typical shape of names like NFTA_TABLE_NAME or
 * IFLA_INFO_KIND), everything else gets random bytes.
 */
static void spec_fill_payload(unsigned char *p, size_t len,
			      const struct nla_attr_spec *spec)
{
	if (len == 0)
		return;
	if (spec->kind == NLA_KIND_STRING) {
		size_t i;

		for (i = 0; i + 1 < len; i++)
			p[i] = 'a' + (rand() % 26);
		p[len - 1] = '\0';
	} else {
		generate_rand_bytes(p, len);
	}
}

/*
 * Emit a single attribute described by a freshly picked spec, treating
 * NESTED as a small binary payload.  Used inside append_specced_nested
 * so children stay one level deep — matches the depth limit set by
 * commit "net/netlink: add nested NLA_F_NESTED attribute support".
 */
static size_t append_specced_flat(unsigned char *buf, size_t offset,
				  size_t buflen,
				  const struct nla_attr_spec *table,
				  size_t nr_specs)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rand() % nr_specs];

	if (spec->kind == NLA_KIND_NESTED)
		payload_len = 16;	/* placeholder bytes — no recursion */
	else
		payload_len = spec_payload_len(spec);

	/* Cap any single child inside a nested container at 64 bytes so
	 * one greedy STRING/BINARY can't push out the rest of the
	 * children.  The kernel-side nla_strlen / max_len gates only care
	 * about the upper bound of each individual attr, not the sum. */
	if (payload_len > 64)
		payload_len = 64;

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/*
 * Emit a NLA_F_NESTED outer attr whose payload is 1-3 children drawn
 * from the same spec table.  Mirrors append_nested_attr_container() but
 * walks a typed spec table for kind/max_len information.  Increments
 * the same nested counter so the dump output stays consistent across
 * spec-driven and pick_attr_hint-driven nesting.
 */
static size_t append_specced_nested(unsigned char *buf, size_t offset,
				    size_t buflen,
				    unsigned short outer_type,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off = 0;
	size_t total;
	int child_count;

	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	if (inner_avail > 256)
		inner_avail = 256;

	child_count = RAND_RANGE(1, 3);
	while (child_count-- > 0) {
		size_t new_off = append_specced_flat(inner, inner_off,
						     inner_avail,
						     table, nr_specs);
		if (new_off == inner_off)
			break;
		inner_off = new_off;
	}

	if (inner_off == 0)
		return offset;

	nla.nla_len = NLA_HDRLEN + inner_off;
	nla.nla_type = outer_type | NLA_F_NESTED;
	memcpy(buf + offset, &nla, NLA_HDRLEN);

	total = NLA_ALIGN(NLA_HDRLEN + inner_off);
	if (offset + total > buflen)
		total = buflen - offset;

	__atomic_add_fetch(&shm->stats.netlink_nested_attrs_emitted, 1,
			   __ATOMIC_RELAXED);

	return offset + total;
}

/*
 * Top-level entry for spec-driven attribute emission.  Picks a random
 * spec and delegates to the nested or flat path as appropriate.  Used
 * exclusively by build_one_nlmsg for families with a curated
 * nla_attr_spec table; the legacy random-payload append_nlattr() path
 * still serves families without specs.
 */
static size_t append_specced_nlattr(unsigned char *buf, size_t offset,
				    size_t buflen,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rand() % nr_specs];

	if (spec->kind == NLA_KIND_NESTED)
		return append_specced_nested(buf, offset, buflen, spec->type,
					     table, nr_specs);

	payload_len = spec_payload_len(spec);

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/*
 * Return the nla_attr_spec table for a given protocol/nlmsg_type pair,
 * setting *nr_out to its element count.  NULL means the family is not
 * spec-aware and the caller should fall back to the legacy flat-attr
 * generator.  Netfilter dispatches by NFNL_SUBSYS_x nibble of
 * nlmsg_type via the per-subsys grammar registry; generic netlink
 * dispatches by runtime-resolved family_id via the genl registry.
 */
static const struct nla_attr_spec *pick_spec_table(int protocol,
						   unsigned short nlmsg_type,
						   size_t *nr_out)
{
	switch (protocol) {
	case NETLINK_GENERIC: {
		const struct genl_family_grammar *fam;

		if (nlmsg_type == GENL_ID_CTRL) {
			*nr_out = ARRAY_SIZE(ctrl_specs);
			return ctrl_specs;
		}
		fam = genl_lookup_by_id(nlmsg_type);
		if (fam != NULL && fam->n_attrs > 0) {
			*nr_out = fam->n_attrs;
			return fam->attrs;
		}
		return NULL;
	}
	case NETLINK_XFRM:
		*nr_out = ARRAY_SIZE(xfrma_specs);
		return xfrma_specs;
	case NETLINK_NETFILTER: {
		const struct nfnl_subsys_grammar *sub;

		sub = nfnl_lookup_by_subsys(nlmsg_type >> 8);
		if (sub != NULL && sub->n_attrs > 0) {
			*nr_out = sub->n_attrs;
			return sub->attrs;
		}
		return NULL;
	}
	case NETLINK_SOCK_DIAG:
		*nr_out = ARRAY_SIZE(inet_diag_specs);
		return inet_diag_specs;
	default:
		return NULL;
	}
}

/* Build a single nlmsghdr at msg+offset. Returns new offset (NLMSG_ALIGN'd). */
static size_t build_one_nlmsg(unsigned char *msg, size_t offset, size_t buflen,
			      struct socket_triplet *triplet)
{
	struct nlmsghdr *nlh;
	unsigned short nlmsg_type;
	size_t body_len;
	size_t msg_start = offset;
	unsigned char body_family = AF_UNSPEC;
	int rtnl_group = -1;
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
		body_len = gen_rtnl_body(msg + offset, nlmsg_type, &body_family);
		rtnl_group = (nlmsg_type - RTM_BASE) / 4;
	} else if (triplet->protocol == NETLINK_GENERIC) {
		body_len = gen_genl_body(msg + offset, nlmsg_type);
	} else if (triplet->protocol == NETLINK_NETFILTER) {
		body_len = gen_nfnl_body(msg + offset, nlmsg_type);
	} else if (triplet->protocol == NETLINK_XFRM) {
		body_len = gen_xfrm_body(msg + offset, nlmsg_type);
	} else if (triplet->protocol == NETLINK_AUDIT) {
		body_len = gen_audit_body(msg + offset, nlmsg_type,
					  buflen - offset);
	} else if (triplet->protocol == NETLINK_SOCK_DIAG) {
		body_len = gen_sockdiag_body(msg + offset, nlmsg_type);
	} else {
		body_len = RAND_RANGE(4, 64);
		if (offset + body_len > buflen)
			body_len = buflen - offset;
		generate_rand_bytes(msg + offset, body_len);
	}
	offset += body_len;

	/* Append nlattr TLVs with protocol-appropriate types.
	 * Audit messages don't use nlattr — skip for that protocol. */
	num_attrs = (triplet->protocol == NETLINK_AUDIT) ? 0 : rand() % 8;
	if (num_attrs > 0) {
		const struct nla_attr_spec *spec_table;
		size_t nr_specs = 0;

		spec_table = pick_spec_table(triplet->protocol, nlmsg_type,
					     &nr_specs);

		while (num_attrs-- > 0 && offset < buflen) {
			unsigned short attr_hint;
			size_t new_off;

			/* Spec-driven path: families with a curated
			 * nla_attr_spec table (XFRM, ctnetlink, nftables,
			 * genl-ctrl, sock_diag) emit attrs sized to their
			 * per-type kind.  This dramatically lowers the
			 * EINVAL rejection rate at the family's nla_policy
			 * gate. */
			if (spec_table) {
				new_off = append_specced_nlattr(msg, offset,
								buflen,
								spec_table,
								nr_specs);
				if (new_off == offset)
					break;
				offset = new_off;
				continue;
			}

			/* Legacy random-payload path for families without
			 * a spec table — currently NETLINK_ROUTE (which has
			 * its own structured per-group payload generators)
			 * and unknown families. */
			attr_hint = pick_attr_hint(triplet->protocol,
						   nlmsg_type);

			if (ONE_IN(7)) {
				unsigned short outer = attr_hint
					? attr_hint : rand16();

				new_off = append_nested_attr_container(msg,
					offset, buflen, outer,
					triplet->protocol, nlmsg_type,
					body_family, rtnl_group);
				if (new_off > offset) {
					offset = new_off;
					continue;
				}
			}

			offset = append_nlattr(msg, offset, buflen, attr_hint,
					       body_family, rtnl_group);
		}
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

	/* Total buffer: room for messages with protocol body + attrs.
	 * XFRM bodies can be up to 280 bytes, audit_rule_data is 1040 bytes,
	 * so base size must accommodate the largest possible body. */
	total_len = NLMSG_HDRLEN + 1280 + (rand() % 512);
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
