/*
 * Genetlink family grammar: gtp (GPRS Tunnelling Protocol), targeting
 * gtp_genl_policy and the PDP handlers in drivers/net/gtp.c.  All four ops
 * are GENL_ADMIN_PERM; without a GTP netdev a request that carries the
 * required attributes ends in -ENODEV.
 */

#if __has_include(<linux/gtp.h>)

#include <linux/gtp.h>

#include "netlink-genl-families.h"
#include "utils.h"
#include "kernel/gtp.h"

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
 * GTPA_PAD is not in the policy (the response builder emits it only
 * as the alignment partner of TID), so it has no entry here.
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
