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
#include <linux/ipv6.h>		/* IPV6_SRCRT_TYPE_4 */
#include <linux/seg6.h>		/* struct ipv6_sr_hdr, struct sr6_tlv */

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_inet6, struct sockopt */

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
}
