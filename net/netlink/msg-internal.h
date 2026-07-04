/*
 * netlink-msg-internal.h
 *
 * Shared declarations split out of net/netlink-msg.c to allow the
 * descriptor tables (per-protocol message-type lists, per-group
 * rtnetlink attribute lists, per-family nla_attr_spec tables and
 * xfrm family-field offsets) to live in their own translation unit
 * and compile in parallel with the message-emitter logic.  This
 * header is private to the two TUs that make up netlink-msg — do
 * not include it from anywhere else.
 *
 * The tables in netlink-msg-tables.c are deliberately widened from
 * file-static to external linkage so the emitters in netlink-msg.c
 * can pick from them across the TU boundary.  Each table is paired
 * with a `_n` size constant so the emitters can index into it without
 * needing the full array type that ARRAY_SIZE() requires; the
 * extern declarations only need the element type.
 *
 * The DCB attribute fallback macros are emitted here because both
 * the table definitions (dcb_attrs, dcb_ieee_attrs) and the emitter
 * (gen_rta_dcb_payload) reference them and must observe the same
 * constant values regardless of how complete the system uapi
 * headers happen to be.
 */

#ifndef NET_NETLINK_MSG_INTERNAL_H
#define NET_NETLINK_MSG_INTERNAL_H

#include <stddef.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include "netlink-attrs.h"

/* DCB rtnetlink attributes — older uapi headers may not expose every
 * symbol (DCB grew incrementally), so guard each constant we touch. */
#ifndef DCB_ATTR_IFNAME
#define DCB_ATTR_IFNAME		1
#endif
#ifndef DCB_ATTR_IEEE
#define DCB_ATTR_IEEE		13
#endif
#ifndef DCB_ATTR_IEEE_ETS
#define DCB_ATTR_IEEE_ETS	1
#endif
#ifndef DCB_ATTR_IEEE_PFC
#define DCB_ATTR_IEEE_PFC	2
#endif
#ifndef DCB_ATTR_IEEE_APP_TABLE
#define DCB_ATTR_IEEE_APP_TABLE	3
#endif

/*
 * Per-message-type family-field offsets within the xfrm body.  The
 * row layout was previously expressed as an anonymous struct literal
 * inside netlink-msg.c; it is named here so the table can be
 * declared extern and referenced from xfrm_pin_family() across the
 * TU boundary.  Field semantics are unchanged: family_offset is the
 * SA / id family byte offset, sel_family_offset is the (optional)
 * selector family byte offset, with ~0u meaning "no selector".
 */
struct xfrm_family_offset {
	unsigned short msg_type;
	unsigned int family_offset;
	unsigned int sel_family_offset;
};

/*
 * Descriptor tables — defined in netlink-msg-tables.c, consumed by
 * the message emitters in netlink-msg.c.  Each table is paired with
 * a `_n` size constant so the emitters can scale a uniform pick
 * across the table without needing the full array type.
 */
extern const unsigned short rtnl_types[];
extern const size_t rtnl_types_n;

extern const unsigned short xfrm_types[];
extern const size_t xfrm_types_n;

extern const unsigned short audit_types[];
extern const size_t audit_types_n;

extern const unsigned short rtax_attrs[];
extern const size_t rtax_attrs_n;

extern const unsigned short dcb_attrs[];
extern const size_t dcb_attrs_n;

extern const unsigned short dcb_ieee_attrs[];
extern const size_t dcb_ieee_attrs_n;

extern const char *link_kinds[];
extern const size_t link_kinds_n;

extern const unsigned short ifla_attrs[];
extern const size_t ifla_attrs_n;

extern const unsigned short ifa_attrs[];
extern const size_t ifa_attrs_n;

extern const unsigned short rta_attrs[];
extern const size_t rta_attrs_n;

extern const unsigned short nda_attrs[];
extern const size_t nda_attrs_n;

extern const unsigned short fra_attrs[];
extern const size_t fra_attrs_n;

extern const unsigned short tca_attrs[];
extern const size_t tca_attrs_n;

extern const unsigned short nha_attrs[];
extern const size_t nha_attrs_n;

extern const unsigned short netconfa_attrs[];
extern const size_t netconfa_attrs_n;

extern const unsigned short ifal_attrs[];
extern const size_t ifal_attrs_n;

extern const unsigned short mdba_attrs[];
extern const size_t mdba_attrs_n;

extern const unsigned short bridge_vlandb_attrs[];
extern const size_t bridge_vlandb_attrs_n;

extern const struct nla_attr_spec ctrl_specs[];
extern const size_t ctrl_specs_n;

extern const struct nla_attr_spec xfrma_specs[];
extern const size_t xfrma_specs_n;

extern const struct xfrm_family_offset xfrm_family_offsets[];
extern const size_t xfrm_family_offsets_n;

extern const struct nla_attr_spec inet_diag_specs[];
extern const size_t inet_diag_specs_n;

/*
 * Per-rtnetlink-group attribute payload builders.  Defined in
 * netlink-msg-rtnl-payloads.c, dispatched from the gen_rta_payload
 * switch in netlink-msg.c.  Each generator returns the payload length
 * it wrote into p, or 0 to signal "fall back to a random blob".
 */
size_t gen_rta_route_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type, unsigned char family);
size_t gen_rta_link_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type);
size_t gen_rta_addr_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type, unsigned char family);
size_t gen_rta_neigh_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type, unsigned char family);
size_t gen_rta_rule_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type, unsigned char family);
size_t gen_rta_dcb_payload(unsigned char *p, size_t avail,
			   unsigned short nla_type);
size_t gen_rta_tc_payload(unsigned char *p, size_t avail,
			  unsigned short nla_type);
size_t gen_rta_nexthop_payload(unsigned char *p, size_t avail,
			       unsigned short nla_type);
size_t gen_rta_netconf_payload(unsigned char *p, size_t avail,
			       unsigned short nla_type);
size_t gen_rta_mdba_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type);
size_t gen_rta_vlandb_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

#endif /* NET_NETLINK_MSG_INTERNAL_H */
