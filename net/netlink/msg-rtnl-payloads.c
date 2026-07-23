/*
 * msg-rtnl-payloads.c
 *
 * Per-rtnetlink-group attribute payload builders, split out of
 * net/netlink/msg.c so the message emitter / dispatcher TU stays
 * focused on protocol-body and dispatch logic and the per-group
 * payload bodies can compile in parallel.  The five generators here
 * (gen_rta_{route,link,addr,neigh,dcb}_payload) are dispatched from
 * the gen_rta_payload switch in msg.c.
 *
 * The four cross-family helpers (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) live in net/netlink/msg-rtnl-common.c and are
 * declared in msg-rtnl-common.h so any per-family TU that is later
 * split out of here can reuse the same bodies without duplication.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/dcbnl.h>
#include <linux/nexthop.h>
#include <linux/netconf.h>
#include <linux/if_bridge.h>
#include <linux/net_namespace.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <string.h>
#include "netlink-attrs.h"
#include "msg-internal.h"
#include "msg-rtnl-common.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"
#include "utils-macros.h"		/* ARRAY_SIZE, RAND_ARRAY */

/* Prototype mirrored from the forward declaration in net/netlink/msg.c;
 * kept here (rather than in msg-internal.h next to its
 * gen_rta_* siblings) to keep the rtnl_addrlabel wire-up confined to
 * the two TUs that actually need it. */
size_t gen_rta_addrlabel_payload(unsigned char *p, size_t avail,
				 unsigned short nla_type);

/*
 * Generate a structured payload for address attributes (IFA_*).
 */
size_t gen_rta_addr_payload(unsigned char *p, size_t avail,
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
			*p = rnd_modulo_u32(256);
			return 1;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for DCB rtnetlink attributes (DCB_ATTR_*).
 * Only the two attrs the kernel demuxer cares about for reaching the
 * per-feature setters get structured payloads here; everything else
 * returns 0 so the caller falls back to a random blob.
 */
size_t gen_rta_dcb_payload(unsigned char *p, size_t avail,
			   unsigned short nla_type)
{
	switch (nla_type) {
	case DCB_ATTR_IFNAME: {
		static const char *names[] = {
			"lo", "eth0", "br0", "veth0", "dummy0",
		};
		const char *name = RAND_ARRAY(names);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case DCB_ATTR_IEEE:
		/* Nested container of DCB_ATTR_IEEE_* sub-attributes;
		 * mirrors RTA_METRICS' use of build_nested_attrs above. */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, dcb_ieee_attrs,
						  dcb_ieee_attrs_n, 0);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for netconf rtnetlink attributes
 * (NETCONFA_*).  Covers the RTM_*NETCONF message group (16).
 * The kernel ipv4 / ipv6 devconf_{ipv4,ipv6}_policy walker pins
 * NETCONFA_IFINDEX at nla_len == sizeof(int); a random-byte payload
 * almost never lands exactly 4 bytes wide, so the message bounces on
 * nla_parse before reaching inet_netconf_get_devconf / its ipv6
 * sibling.  Sizing every NETCONFA_* to its s32 width gets the
 * message past nla_parse into the per-attr handlers, where the
 * meaningful sentinels NETCONFA_IFINDEX_ALL (-1) and
 * NETCONFA_IFINDEX_DEFAULT (-2) pick the all-devices / default
 * arms before the per-ifindex devinet lookup runs.
 */
size_t gen_rta_netconf_payload(unsigned char *p, size_t avail,
			       unsigned short nla_type)
{
	switch (nla_type) {
	case NETCONFA_IFINDEX:
		/* s32 ifindex; the two negative sentinels are real
		 * userland values the kernel handler special-cases
		 * before the per-ifindex devinet lookup, so seed them
		 * alongside small positive values that ride a sibling
		 * ifindex's per-netns slot. */
		if (avail >= 4) {
			__s32 val;

			switch (rnd_modulo_u32(4)) {
			case 0: val = -1; break;
			case 1: val = -2; break;
			default: val = rnd_modulo_u32(64); break;
			}
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NETCONFA_FORWARDING:
	case NETCONFA_RP_FILTER:
	case NETCONFA_MC_FORWARDING:
	case NETCONFA_PROXY_NEIGH:
	case NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN:
	case NETCONFA_INPUT:
	case NETCONFA_BC_FORWARDING:
		/* s32 toggle attrs the ipv4 / ipv6 fill paths emit via
		 * nla_put_s32; the kernel stores them into per-netns /
		 * per-ifa devconf as truthy / zero / negative, so mix
		 * 0 / 1 / -1 / wider values to exercise sign-handling
		 * and range-trim arms in the per-setting writers. */
		if (avail >= 4) {
			__s32 val;

			switch (rnd_modulo_u32(4)) {
			case 0: val = 0; break;
			case 1: val = 1; break;
			case 2: val = -1; break;
			default: val = (__s32)rnd_u32(); break;
			}
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for address-label rtnetlink attributes
 * (IFAL_*).  Covers the RTM_*ADDRLABEL message group (14).  The kernel
 * net/ipv6/addrlabel.c:ip6addrlbl_newdel walker parses ifal_policy,
 * which length-rejects IFAL_ADDRESS (.len = sizeof(struct in6_addr))
 * and IFAL_LABEL (.len = sizeof(u32)) at the wrong-width gate before
 * the per-attr writer runs -- a random-byte payload of length [0, 64)
 * almost never lands at exactly 16 / 4 bytes wide, so the message is
 * rejected at nla_parse before ip6addrlbl_{add,del} runs and the
 * handler additionally requires both attrs present to dispatch.  Size
 * IFAL_ADDRESS to 16 bytes via the existing rand_ipv6 helper
 * (addrlabel is IPv6-only: ip6addrlbl_newdel -EINVALs unless
 * ifal_family == AF_INET6) and IFAL_LABEL to 4 bytes so the parse
 * reaches the per-attr writers.
 */
size_t gen_rta_addrlabel_payload(unsigned char *p, size_t avail,
				 unsigned short nla_type)
{
	switch (nla_type) {
	case IFAL_ADDRESS:
		if (avail >= sizeof(struct in6_addr)) {
			struct in6_addr addr;

			rand_ipv6(&addr);
			memcpy(p, &addr, sizeof(addr));
			return sizeof(addr);
		}
		return 0;

	case IFAL_LABEL:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	default:
		return 0;
	}
}

