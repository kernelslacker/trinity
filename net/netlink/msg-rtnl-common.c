/*
 * msg-rtnl-common.c
 *
 * Shared rtnetlink payload-builder helpers used across the per-family
 * TUs split out of net/netlink/msg-rtnl-payloads.c.  The four
 * generators here (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) previously lived as file-static inside
 * msg-rtnl-payloads.c; widening them to external linkage here lets
 * msg-rtnl-{route,link,neigh,tc,misc}.c reuse the same bodies across
 * the split.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/netlink.h>
#include "msg-rtnl-common.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"

/*
 * Generate random IPv4 address, biased toward useful values.
 */
__u32 rand_ipv4(void)
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
void rand_ipv6(struct in6_addr *addr)
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
struct nlattr *start_nlattr(unsigned char *buf, size_t offset,
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
size_t build_nested_attrs(unsigned char *buf, size_t buflen,
			  const unsigned short *attr_types,
			  size_t nr_types, int max_depth)
{
	size_t offset = 0;
	int count = RAND_RANGE(1, 4);

	if (max_depth <= 0)
		count = RAND_RANGE(1, 2);

	while (count-- > 0 && offset + NLA_HDRLEN + 4 <= buflen) {
		unsigned short atype = attr_types[rnd_modulo_u32(nr_types)];
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
