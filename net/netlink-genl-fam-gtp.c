/*
 * Genetlink family grammar: gtp.
 *
 * The GPRS Tunnelling Protocol control plane is a single generic-
 * netlink family (GTP_GENL_NAME = "gtp") with four user-callable
 * commands (NEWPDP, DELPDP, GETPDP, ECHOREQ) and a flat GTPA_*
 * attribute namespace whose ids carry the per-PDP-context selector
 * (LINK ifindex + VERSION + TID for GTPv0 or I_TEI/O_TEI for GTPv1),
 * the GSN peer + MS endpoint pair (PEER_ADDRESS / MS_ADDRESS for
 * IPv4 or PEER_ADDR6 / MS_ADDR6 for IPv6), the GTPv0 FLOW + the
 * NET_NS_FD selector that the kernel uses to look up the GTP netdev
 * across network namespaces.  The ECHOREQ command additionally
 * triggers a synchronous GTPv0 echo-request packet emission to the
 * resolved PEER_ADDRESS.
 *
 * The per-cmd nla_policy parser lives in drivers/net/gtp.c
 * (gtp_genl_policy + gtp_genl_ops); the post-parse handlers
 * (gtp_genl_new_pdp / _del_pdp / _get_pdp / _send_echo_req) all
 * gate on info->attrs[GTPA_LINK] resolving via dev_get_by_index_rcu
 * to a netdev whose private data identifies a GTP tunnel.  On a
 * fuzz host that doesn't run a GTP tunnel that lookup -ENODEV's
 * out, but only after the full attribute tree has been walked and
 * the version/family arms of the parser have run — which is where
 * the parser bugs actually live.  CVE-2021-3669 (refcount imbalance
 * in gtp_genl_dump_pdp) is the canonical example of the kind of
 * bug reachable through the GETPDP NLM_F_DUMP path even on hosts
 * without a live PDP context, and the per-PDP socket lookup that
 * gtp_encap_enable_socket() drives during NEWPDP is another
 * historically-fertile target.
 *
 * Random nlmsg_type ids essentially never matched the runtime-
 * assigned family_id for "gtp", so the per-cmd parser plus the
 * NEWPDP/DELPDP socket-refcount path have been cold under generic
 * netlink fuzzing; controller-resolved family_id dispatch changes
 * that.  Random LINK ifindex values cause the post-parse handler
 * to bail with -ENODEV, but the parser coverage and the IPv4-vs-
 * IPv6 family arm selection both run before that bail.
 *
 * Per the wireguard / l2tp model, a single flat nla_attr_spec
 * table lists every id in the family's policy.  The kernel's
 * gtp_genl_policy table covers GTPA_LINK..GTPA_FAMILY; GTPA_PAD
 * is not in the policy (it's only emitted by the response builder
 * via nla_put_u64_64bit as the alignment partner for GTPA_TID),
 * so the walker doesn't carry a spec entry for it.  GTPA_FAMILY
 * was appended in 5.10 to disambiguate the IPv4 vs IPv6 PDP arm
 * when both PEER_ADDRESS and PEER_ADDR6 are absent — older host
 * headers stop at GTPA_MS_ADDR6=12, so compat.h carries the
 * numeric fallback under a per-symbol #ifndef gate.
 *
 * Header gating mirrors the wireguard / l2tp families: the
 * upstream <linux/gtp.h> UAPI ships from 4.7 onward, and a build
 * host whose sysroot lacks it entirely silently drops the family
 * from the registry instead of failing the build.  A host whose
 * header predates the late-added GTPA_PAD / GTPA_PEER_ADDR6 /
 * GTPA_MS_ADDR6 / GTPA_FAMILY ids picks up the numeric fallback
 * in compat.h instead.
 */

#if __has_include(<linux/gtp.h>)

#include <linux/gtp.h>

#include "compat.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar gtp_cmds[] = {
	{ GTP_CMD_NEWPDP,	"GTP_CMD_NEWPDP" },
	{ GTP_CMD_DELPDP,	"GTP_CMD_DELPDP" },
	{ GTP_CMD_GETPDP,	"GTP_CMD_GETPDP" },
	{ GTP_CMD_ECHOREQ,	"GTP_CMD_ECHOREQ" },
};

/*
 * Attribute spec follows gtp_genl_policy in drivers/net/gtp.c.
 * GTPA_LINK is the netdev ifindex selector every command gates on.
 * GTPA_VERSION picks the GTPv0 (TID + FLOW) vs GTPv1 (I_TEI + O_TEI)
 * tunnel-id arm.  GTPA_PEER_ADDRESS / GTPA_MS_ADDRESS are __be32
 * IPv4 addresses (the policy declares NLA_U32 because that's the
 * size, not the byte order).  GTPA_PEER_ADDR6 / GTPA_MS_ADDR6 are
 * struct in6_addr blobs — declared here as NLA_KIND_BINARY 16 to
 * match the kernel's .len = sizeof(struct in6_addr) policy entry.
 * GTPA_NET_NS_FD selects the network namespace via fd lookup —
 * random fd values plausibly hit a real but irrelevant fd in this
 * process, exercising get_net_ns_by_fd's reference-handling path.
 * GTPA_FAMILY (u8) defaults to AF_INET via nla_get_u8_default and
 * picks the IPv4 vs IPv6 PDP arm in gtp_genl_new_pdp / _get_pdp.
 */
static const struct nla_attr_spec gtp_attrs[] = {
	{ GTPA_LINK,		NLA_KIND_U32,    4 },
	{ GTPA_VERSION,		NLA_KIND_U32,    4 },
	{ GTPA_TID,		NLA_KIND_U64,    8 },
	{ GTPA_PEER_ADDRESS,	NLA_KIND_U32,    4 },
	{ GTPA_MS_ADDRESS,	NLA_KIND_U32,    4 },
	{ GTPA_FLOW,		NLA_KIND_U16,    2 },
	{ GTPA_NET_NS_FD,	NLA_KIND_U32,    4 },
	{ GTPA_I_TEI,		NLA_KIND_U32,    4 },
	{ GTPA_O_TEI,		NLA_KIND_U32,    4 },
	{ GTPA_PEER_ADDR6,	NLA_KIND_BINARY, 16 },
	{ GTPA_MS_ADDR6,	NLA_KIND_BINARY, 16 },
	{ GTPA_FAMILY,		NLA_KIND_U8,     1 },
};

struct genl_family_grammar fam_gtp = {
	.name = GTP_GENL_NAME,
	.cmds = gtp_cmds,
	.n_cmds = ARRAY_SIZE(gtp_cmds),
	.attrs = gtp_attrs,
	.n_attrs = ARRAY_SIZE(gtp_attrs),
	.default_version = GTP_GENL_VERSION,
};

#endif /* __has_include(<linux/gtp.h>) */
