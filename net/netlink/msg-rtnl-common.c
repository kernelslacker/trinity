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
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/netlink.h>
#include "msg-rtnl-common.h"
#include "random.h"
#include "shm.h"
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
 *
 * Each attr is emitted at its kernel-policy-mandated exact width 31/32 of
 * the time.  The remaining 1/32 deliberately uses a random width to exercise
 * the strict-length validation path in validate_nla() — the goal is that
 * malformed is the exception (1/32), not the default (was ~98% before).
 */
size_t build_nested_attrs(unsigned char *buf, size_t buflen,
			  const struct nlattr_width *attrs,
			  size_t nr_types, int max_depth)
{
	size_t offset = 0;
	int count = RAND_RANGE(1, 4);

	if (max_depth <= 0)
		count = RAND_RANGE(1, 2);

	/*
	 * Loop entry gate: offset + NLA_HDRLEN + 1 <= buflen is the
	 * minimum that lets the clamp path below be reached with at
	 * least one payload byte.  Do not relax this further — doing so
	 * would allow the clamp to produce a zero-byte payload, which the
	 * break-on-zero guard below relies on never seeing here.  If you
	 * need to tighten it (e.g. to NLA_HDRLEN + max_width_in_table)
	 * remove the skip-on-clamp guard below instead; see the commit
	 * message for the tradeoff discussion.
	 *
	 * Only count this call if the loop body is actually reachable;
	 * calls with buflen <= NLA_HDRLEN can never emit or truncate an
	 * attr and would dilute the lost_align / build_calls ratio.
	 */
	if (offset + NLA_HDRLEN + 1 <= buflen)
		__atomic_add_fetch(&shm->stats.netlink_nested_attr_build_calls,
				   1, __ATOMIC_RELAXED);
	while (count-- > 0 && offset + NLA_HDRLEN + 1 <= buflen) {
		const struct nlattr_width *aw = &attrs[rnd_modulo_u32(nr_types)];
		unsigned short atype = aw->type;
		size_t payload_len;
		size_t total;

		/*
		 * 1/32: deliberate fault injection — wrong-width payload
		 * to exercise the strict-length validation path.
		 * 31/32: emit the exact kernel-expected width.
		 */
		int exact_width = !ONE_IN(32);
		if (!exact_width)
			payload_len = RAND_RANGE(4, 32);
		else
			payload_len = aw->width;

		if (payload_len == 0)
			payload_len = 4;
		if (payload_len > buflen - offset - NLA_HDRLEN)
			payload_len = buflen - offset - NLA_HDRLEN;
		/*
		 * Skip-on-clamp: if exact_width was requested but the buffer
		 * doesn't have room for aw->width bytes, the clamp above
		 * produced a shorter payload.  Emitting it would send a
		 * wrong-width attribute while exact_width is still true —
		 * the kernel policy rejects it, reintroducing the silent
		 * truncation that the exact-width path was introduced to
		 * prevent.  We skip this pick and move to the next iteration;
		 * note that the while-condition already decremented count, so
		 * this skip consumes one slot — a message that skips every
		 * remaining pick emits fewer attrs than requested.  We do NOT
		 * raise the loop-entry gate to max_width_in_table because
		 * that would discard valid smaller attrs when only a
		 * large-width type happened to be picked.
		 */
		if (exact_width && payload_len < aw->width) {
			__atomic_add_fetch(&shm->stats.netlink_nested_attr_skipped_width,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		if (payload_len == 0)
			break;

		total = NLA_ALIGN(NLA_HDRLEN + payload_len);
		if (offset + total > buflen) {
			__atomic_add_fetch(&shm->stats.netlink_nested_attr_lost_align,
					   1, __ATOMIC_RELAXED);
			break;
		}

		if (!start_nlattr(buf, offset, buflen, atype, payload_len))
			break;
		generate_rand_bytes(buf + offset + NLA_HDRLEN, payload_len);
		/*
		 * min_val guard: if the attribute has a minimum-value
		 * constraint and the payload is exactly 4 bytes (u32),
		 * clamp the generated value up to min_val.
		 * Prevents e.g. RTAX_MTU < IPV4_MIN_MTU (68) reaching the
		 * kernel and triggering an ip_do_fragment softlockup.
		 * Apply unconditionally — the injection path can also
		 * produce a 4-byte payload (RAND_RANGE(4,32) == 4).
		 */
		if (aw->min_val > 0 &&
		    payload_len == sizeof(uint32_t)) {
			uint32_t v;
			memcpy(&v, buf + offset + NLA_HDRLEN, sizeof(v));
			if (v < aw->min_val)
				v = aw->min_val;
			memcpy(buf + offset + NLA_HDRLEN, &v, sizeof(v));
		}
		offset += total;
		if (exact_width)
			__atomic_add_fetch(&shm->stats.netlink_nested_attr_built_width,
					   1, __ATOMIC_RELAXED);
	}
	return offset;
}
