/*
 * msg-internal.h
 *
 * Shared declarations split out of net/netlink/msg-core.c to allow the
 * descriptor tables (per-protocol message-type lists, per-group
 * rtnetlink attribute lists, per-family nla_attr_spec tables and
 * xfrm family-field offsets) to live in their own translation unit
 * and compile in parallel with the message-emitter logic.  This
 * header is private to the two TUs that make up netlink-msg — do
 * not include it from anywhere else.
 *
 * The tables in msg-tables.c are deliberately widened from
 * file-static to external linkage so the emitters in msg-core.c
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
 * inside msg-core.c; it is named here so the table can be
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
 * Descriptor tables — defined in msg-tables.c, consumed by
 * the message emitters in msg-core.c.  Each table is paired with
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
 * msg-rtnl-payloads.c, dispatched from the gen_rta_payload
 * switch in msg-core.c.  Each generator returns the payload length
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

/*
 * Address-family picker shared by the rtnetlink body builders and the
 * sock_diag body builder.  Defined in msg-rtnl-body.c; the widened
 * linkage mirrors the descriptor-table pattern above so both TUs can
 * see the same distribution without duplicating the family list.
 */
unsigned char rand_family(void);

/*
 * Router that maps an RTM_* nlmsg_type to the correct per-group body
 * struct emitter.  Defined in msg-rtnl-body.c, called from
 * build_one_nlmsg in msg-core.c.  out_family receives the body's address
 * family byte so the attribute path can size per-family payloads
 * (RTA_DST length, etc.) consistently with the body.
 */
size_t gen_rtnl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen, unsigned char *out_family);

/*
 * Per-protocol body-struct builders defined in msg-proto-body.c and
 * dispatched from build_one_nlmsg in msg-core.c.  Each writes a
 * family-specific fixed struct (genlmsghdr, nfgenmsg, xfrm_usersa_info,
 * audit_status, sock_diag_req, ...) into body and returns its length.
 * The audit builder writes raw text for some message types instead of
 * a struct; the sock_diag builder shares rand_family() with the
 * rtnetlink builders.
 */
size_t gen_genl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen);
size_t gen_nfnl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen);
size_t gen_xfrm_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen);
size_t gen_audit_body(unsigned char *body, unsigned short nlmsg_type,
		      size_t buflen);
size_t gen_sockdiag_body(unsigned char *body, unsigned short nlmsg_type,
			 size_t buflen);

/*
 * Attribute-type picker for NETLINK_GENERIC.  Defined in
 * msg-proto-body.c, called from pick_attr_hint in msg-core.c.  Reads the
 * ctrl_specs table for GENL_ID_CTRL messages so the legacy flat-attr
 * path can nest a controller attr through
 * append_nested_attr_container(); returns 0 for other families so the
 * caller falls back to a random attr type.
 */
unsigned short pick_genl_attr_type(unsigned short nlmsg_type);

/*
 * Legacy random-payload attribute path.  Defined in msg-attr-random.c
 * and dispatched from iter_nlmsg_attr in msg-core.c for families without a
 * curated nla_attr_spec table (NETLINK_ROUTE plus anything unknown).
 * append_nlattr() writes one flat nlattr; append_nested_attr_container()
 * wraps 1-3 children in a NLA_F_NESTED outer attr.  Both routes size
 * per-rtnl-group structured payloads via the msg-rtnl-payloads
 * generators when the (rtnl_group, nla_type) pair is known and fall
 * back to a short random blob otherwise.
 */
size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen,
		     unsigned short nla_type_hint, unsigned char family,
		     int rtnl_group);
size_t append_nested_attr_container(unsigned char *buf, size_t offset,
				    size_t buflen,
				    unsigned short outer_type,
				    int protocol,
				    unsigned short nlmsg_type,
				    unsigned char body_family,
				    int rtnl_group);

/*
 * Per-rtnetlink-group attribute-type hint picker.  Defined in
 * msg-attr-random.c, called from pick_attr_hint in msg-core.c.  Draws from
 * the shared ifla_attrs / rta_attrs / ... tables in msg-tables.c plus
 * a handful of narrower per-group hint lists that live alongside
 * pick_rtnl_attr_type in msg-attr-random.c.
 */
unsigned short pick_rtnl_attr_type(unsigned short nlmsg_type);

/*
 * pick_attr_hint fans out from msg-core.c to per-family attribute-type
 * pickers; declare it here so append_nested_attr_container in
 * msg-attr-random.c can call back into it when building child
 * attributes for a NLA_F_NESTED container.
 */
unsigned short pick_attr_hint(int protocol, unsigned short nlmsg_type);

/*
 * Spec-driven attribute path.  Defined in msg-attr-spec.c and
 * dispatched from build_one_nlmsg / iter_nlmsg_attr in msg-core.c for
 * families with a curated nla_attr_spec table (XFRM, ctnetlink,
 * nftables, genl-ctrl, sock_diag, ...).  pick_spec_table() returns
 * the (table, count) pair for a given protocol/nlmsg_type or NULL to
 * fall through to the legacy random-payload path in msg-attr-random.c.
 * append_specced_nlattr() emits one attribute using that table,
 * routing NLA_KIND_NESTED entries through an internal 1-3 child
 * container so the depth stays one level deep.
 */
const struct nla_attr_spec *pick_spec_table(int protocol,
					    unsigned short nlmsg_type,
					    size_t *nr_out);
size_t append_specced_nlattr(unsigned char *buf, size_t offset,
			     size_t buflen,
			     const struct nla_attr_spec *table,
			     size_t nr_specs);

#endif /* NET_NETLINK_MSG_INTERNAL_H */
