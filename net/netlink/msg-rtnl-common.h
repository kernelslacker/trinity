/*
 * msg-rtnl-common.h
 *
 * Shared helpers used by the per-family rtnetlink payload builders
 * split out of net/netlink/msg-rtnl-payloads.c.  The four helpers
 * (rand_ipv4, rand_ipv6, start_nlattr, build_nested_attrs) previously
 * lived as file-static in msg-rtnl-payloads.c; widening them to
 * external linkage here lets the per-family TUs
 * (msg-rtnl-{route,link,neigh,tc,misc}.c) reuse the same generators
 * across the split without duplicating their bodies.  This header is
 * private to the msg-rtnl-* TUs — do not include it from anywhere
 * else.
 */

#ifndef NET_NETLINK_MSG_RTNL_COMMON_H
#define NET_NETLINK_MSG_RTNL_COMMON_H

#include <stddef.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/types.h>

/*
 * Generate random IPv4 address, biased toward useful values.
 */
__u32 rand_ipv4(void);

/*
 * Generate random IPv6 address.
 */
void rand_ipv6(struct in6_addr *addr);

/*
 * Write an nlattr header at buf+offset. Returns pointer past the header,
 * or NULL if there's not enough room. Caller fills the payload.
 * After filling, caller must update nla_len if known, and advance offset
 * by NLA_ALIGN(nla_len).
 */
struct nlattr *start_nlattr(unsigned char *buf, size_t offset,
			    size_t buflen, unsigned short nla_type,
			    size_t payload_len);

/*
 * Build a chain of nested sub-attributes inside a buffer.
 * Returns the total length of the nested chain (unaligned).
 * This is used for containers like RTA_METRICS, IFLA_LINKINFO, IFLA_AF_SPEC.
 */
size_t build_nested_attrs(unsigned char *buf, size_t buflen,
			  const unsigned short *attr_types,
			  size_t nr_types, int max_depth);

#endif /* NET_NETLINK_MSG_RTNL_COMMON_H */
