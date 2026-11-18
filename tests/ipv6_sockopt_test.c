/*
 * Self-check for the IPv6 option builders: ipv6_set_opt_hdr()
 * (net/ipv6/ipv6_sockglue.c) keeps an IPV6_RTHDR routing header only of
 * type 4 that seg6_validate_srh() passes, or of type 2 with MIP6 built in,
 * and drops the socket's for a length of 0, so most routing headers drawn
 * are a segment routing header it keeps, or that 0.
 */

#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/icmpv6.h>		/* struct icmp6_filter */
#include <linux/in6.h>		/* IPV6_PMTUDISC_*, IPV6_PREFER_SRC_* */
#include <linux/ipv6.h>		/* IPV6_SRCRT_TYPE_4 */
#include <linux/seg6.h>		/* struct ipv6_sr_hdr, struct sr6_tlv */

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_inet6, struct sockopt */
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "kernel/in6.h"		/* IPV6_RECVERR_RFC4884, ... */

#define IPV6_ROUNDS	20000
#define IPV6_OPTVAL_LEN	4096

/* seg6_validate_srh() (net/ipv6/seg6.c) for a header set by setsockopt(),
 * whose segments_left may not pass first_segment. */
static bool srh_valid(const unsigned char *buf, int len)
{
	const struct ipv6_sr_hdr *srh = (const struct ipv6_sr_hdr *) buf;
	unsigned int tlv_offset;
	int trailing;

	if (len < (int) sizeof(*srh) || srh->type != IPV6_SRCRT_TYPE_4)
		return false;
	if (((srh->hdrlen + 1) << 3) != len)
		return false;
	if (srh->segments_left > srh->first_segment ||
	    srh->first_segment > (srh->hdrlen / 2) - 1)
		return false;

	tlv_offset = sizeof(*srh) + ((srh->first_segment + 1) << 4);
	trailing = len - (int) tlv_offset;
	if (trailing < 0)
		return false;
	while (trailing) {
		const struct sr6_tlv *tlv;

		if (trailing < (int) sizeof(*tlv))
			return false;
		tlv = (const struct sr6_tlv *) (buf + tlv_offset);
		trailing -= sizeof(*tlv) + tlv->len;
		if (trailing < 0)
			return false;
		tlv_offset += sizeof(*tlv) + tlv->len;
	}
	return true;
}

/* ICMPV6_FILTER's block-a-few arm blocks 1 to 8 types, each count as
 * often as the others, so a fair share of its filters block 7 or 8
 * (fewer only where two draws name one type). */
static void icmpv6_filter_check(void)
{
	struct socket_triplet icmp = {
		.family = PF_INET6, .type = SOCK_RAW, .protocol = IPPROTO_ICMPV6,
	};
	unsigned int i, few = 0, most = 0;

	for (i = 0; i < IPV6_ROUNDS; i++) {
		struct icmp6_filter filter;
		struct sockopt so = { .optval = (unsigned long) &filter };
		unsigned int j, blocked = 0;

		icmpv6_setsockopt(&so, &icmp);
		for (j = 0; j < 8; j++)
			blocked += __builtin_popcount(filter.data[j]);
		/* The other arms block no type, all of them, or about half. */
		if (blocked == 0 || blocked > 8)
			continue;
		few++;
		if (blocked >= 7)
			most++;
	}

	if (few == 0)
		BUG("icmpv6: no ICMPV6_FILTER blocks a few types");
	if (most * 8 < few)
		BUG("icmpv6: ICMPV6_FILTER seldom blocks 7 or 8 types");
}

/* The flags do_ipv6_setsockopt() and do_rawv6_setsockopt() turn on for
 * any value but 0. */
static const unsigned int ipv6_flags[] = {
	IPV6_2292PKTINFO, IPV6_2292HOPOPTS, IPV6_2292DSTOPTS, IPV6_2292RTHDR,
	IPV6_2292HOPLIMIT, IPV6_FLOWINFO, IPV6_RECVERR, IPV6_V6ONLY,
	IPV6_FLOWINFO_SEND, IPV6_HDRINCL, IPV6_RECVPKTINFO,
	IPV6_RECVHOPLIMIT, IPV6_RECVHOPOPTS, IPV6_RECVRTHDR,
	IPV6_RECVDSTOPTS, IPV6_RECVPATHMTU, IPV6_DONTFRAG, IPV6_RECVTCLASS,
	IPV6_AUTOFLOWLABEL, IPV6_ORIGDSTADDR, IPV6_TRANSPARENT,
	IPV6_RECVFRAGSIZE, IPV6_MULTICAST_ALL, IPV6_ROUTER_ALERT_ISOLATE,
	IPV6_FREEBIND,
};

/* ip6_sock_set_addr_preferences() takes at most one of each group. */
static bool addr_prefs_taken(int val)
{
	static const int groups[] = {
		IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP |
			IPV6_PREFER_SRC_PUBTMP_DEFAULT,
		IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA,
		IPV6_PREFER_SRC_CGA | IPV6_PREFER_SRC_NONCGA,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(groups); i++)
		if (__builtin_popcount(val & groups[i]) > 1)
			return false;
	return true;
}

/* Whether the kernel takes @val for a ranged int option, or -1 for an
 * option that is none.  An optlen short of an int reads as 0, which
 * almost every option refuses. */
static int ipv6_int_taken(unsigned int optname, int val, unsigned int optlen)
{
	int taken;

	switch (optname) {
	case IPV6_UNICAST_HOPS:
	case IPV6_MULTICAST_HOPS:
	case IPV6_TCLASS:
		taken = val >= -1 && val <= 255;
		break;
	case IPV6_MINHOPCOUNT:
		taken = val >= 0 && val <= 255;
		break;
	case IPV6_MTU_DISCOVER:
		taken = val >= IPV6_PMTUDISC_DONT && val <= IPV6_PMTUDISC_OMIT;
		break;
	case IPV6_MTU:
		taken = val == 0 || val >= 1280;	/* IPV6_MIN_MTU */
		break;
	case IPV6_MULTICAST_LOOP:
	case IPV6_RECVERR_RFC4884:
		taken = val == 0 || val == 1;
		break;
	case IPV6_CHECKSUM:
		taken = val < 0 || !(val & 1);
		break;
	case IPV6_ADDR_PREFERENCES:
		taken = addr_prefs_taken(val);
		break;
	case IPV6_UNICAST_IF:
	case IPV6_MULTICAST_IF:
	case IPV6_ROUTER_ALERT:
		taken = 1;
		break;
	default:
		return -1;
	}
	return optlen >= sizeof(int) && taken;
}

static bool is_ipv6_flag(unsigned int optname)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ipv6_flags); i++)
		if (ipv6_flags[i] == optname)
			return true;
	return false;
}

/* The int options get values the kernel reads as an int, so the flags
 * drawn turn both on and off and most ranged draws are taken. */
static void ipv6_int_check(void)
{
	/* A UDP socket draws IPv6-level options a third of the time. */
	struct socket_triplet udp = {
		.family = PF_INET6, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP,
	};
	static unsigned char optval[IPV6_OPTVAL_LEN];
	unsigned int i, on = 0, off = 0, ranged = 0, taken = 0;

	for (i = 0; i < IPV6_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		int val = 0, t;

		memset(optval, 0, sizeof(optval));
		proto_inet6.setsockopt(&so, &udp);
		if (so.level != SOL_IPV6)
			continue;

		if (so.optlen >= sizeof(int))
			memcpy(&val, optval, sizeof(val));
		if (is_ipv6_flag(so.optname)) {
			if (val != 0)
				on++;
			else
				off++;
			continue;
		}
		t = ipv6_int_taken(so.optname, val, so.optlen);
		if (t < 0)
			continue;
		ranged++;
		taken += t;
	}

	if (on == 0 || off == 0)
		BUG("ipv6: the flag options never turn both on and off");
	if (ranged == 0 || taken < ranged * 3 / 4)
		BUG("ipv6: the ranged int options' values the kernel takes are rare");
}

void ipv6_sockopt_self_check(void);
void ipv6_sockopt_self_check(void)
{
	/* A protocol with no builder of its own draws IPv6-level options
	 * two calls in three. */
	struct socket_triplet raw = {
		.family = PF_INET6, .type = SOCK_RAW, .protocol = IPPROTO_RAW,
	};
	static unsigned char optval[IPV6_OPTVAL_LEN];
	unsigned int i, rthdr = 0, kept = 0;

	for (i = 0; i < IPV6_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };

		memset(optval, 0, sizeof(optval));
		proto_inet6.setsockopt(&so, &raw);
		if (so.level != SOL_IPV6 || so.optname != IPV6_RTHDR)
			continue;

		rthdr++;
		if (so.optlen == 0 || srh_valid(optval, (int) so.optlen))
			kept++;
	}

	if (rthdr == 0)
		BUG("ipv6: no routing header drawn");
	if (kept < rthdr * 3 / 4)
		BUG("ipv6: the routing headers ipv6_set_opt_hdr() keeps are rare");

	icmpv6_filter_check();
	ipv6_int_check();
}
