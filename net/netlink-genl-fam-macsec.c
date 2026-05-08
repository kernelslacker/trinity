/*
 * Genetlink family grammar: MACSEC (IEEE 802.1AE).
 *
 * MACsec exposes a single generic-netlink family (MACSEC_GENL_NAME =
 * "macsec") whose eleven commands cover the full receive-channel /
 * security-association lifecycle: GET_TXSC plus the per-RXSC
 * ADD/DEL/UPD triple, the per-TXSA ADD/DEL/UPD triple, the per-RXSA
 * ADD/DEL/UPD triple, and UPD_OFFLOAD for the 5.7-era hardware-offload
 * mode toggle.  The per-cmd nla_policy parsers and the post-parse
 * handlers live in drivers/net/macsec.c, dispatched via the
 * macsec_genl_ops table; every command is GENL_ADMIN_PERM gated and
 * IFINDEX-keyed, so post-parse handlers look the netdev up via
 * macsec_get_dev_from_attrs and bail with -ENODEV when the IFINDEX
 * doesn't resolve to a MACsec interface.  That contract is what makes
 * spec-driven dispatch with a fuzz IFINDEX inert at the post-parse
 * layer: the parser is fully exercised, refcount lookups are
 * attempted, and the dispatcher then drops out cleanly without
 * touching live SA / SC state.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "macsec", so the parser plus the per-SA / per-RXSC
 * dispatchers have been routinely cold under generic netlink fuzzing;
 * the controller-resolved family_id dispatcher addresses real macsec
 * messages whose attribute shapes plausibly survive the per-cmd
 * policy.  The post-parse handlers reach the SA install / delete code
 * paths (macsec_add_rxsa / _txsa / del_rxsa / _txsa) before the
 * IFINDEX gate trips, so coverage of the parser, the validate_*
 * helpers (validate_add_rxsa / _add_rxsc / etc.) and the GCM-AES key
 * sanity checks is preserved.
 *
 * Per the wireguard / tipc / l2tp model, a single flat nla_attr_spec
 * table lists every id used by any nest reachable from this family's
 * commands.  MACsec has eight nested namespaces all reachable from the
 * outer MACSEC_ATTR_* table:
 *
 *   MACSEC_ATTR_RXSC_CONFIG -> macsec_rxsc_attrs (SCI / ACTIVE)
 *   MACSEC_ATTR_SA_CONFIG   -> macsec_sa_attrs (AN/ACTIVE/PN/KEY/
 *                              KEYID/SSCI/SALT, plus a STATS sub-nest)
 *   MACSEC_ATTR_OFFLOAD     -> macsec_offload_attrs (TYPE)
 *   MACSEC_ATTR_SECY        -> macsec_secy_attrs (response-only)
 *   MACSEC_ATTR_TXSC_STATS  -> macsec_txsc_stats_attr (response-only)
 *   MACSEC_ATTR_SECY_STATS  -> macsec_secy_stats_attr (response-only)
 *   MACSEC_ATTR_TXSA_LIST   -> list of macsec_sa_attrs entries (resp)
 *   MACSEC_ATTR_RXSC_LIST   -> list of macsec_rxsc_attrs entries (resp)
 *
 * Numeric ids collide aggressively across the eight nests
 * (MACSEC_ATTR_IFINDEX = MACSEC_SECY_ATTR_SCI = MACSEC_RXSC_ATTR_SCI =
 * MACSEC_SA_ATTR_AN = MACSEC_OFFLOAD_ATTR_TYPE =
 * MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED =
 * MACSEC_SA_STATS_ATTR_IN_PKTS_OK =
 * MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED =
 * MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED = 1, and similarly all the
 * way up).  The kernel only validates each child against the policy of
 * whichever nest is currently being walked, so the collisions are
 * harmless and the single flat table is the same shape l2tp uses for
 * its outer-vs-STATS overlap.
 *
 * Several outer MACSEC_ATTR_* entries (SECY, TXSA_LIST, RXSC_LIST,
 * TXSC_STATS, SECY_STATS) are response-only — the kernel emits them on
 * GET_TXSC dump replies but the input policy doesn't validate them, so
 * they exercise the validator's "ignore on input" branch the same way
 * the OVS dp/flow STATS attrs and L2TP_ATTR_STATS' inner counters do.
 *
 * Header gating mirrors the wireguard / l2tp model: <linux/if_macsec.h>
 * is the upstream UAPI header that ships with kernel headers from 4.6
 * onward.  The XPN (SSCI/SALT) and offload (UPD_OFFLOAD command +
 * MACSEC_ATTR_OFFLOAD + the entire macsec_offload_attrs enum) bits
 * landed in 5.7; per-symbol fallbacks in compat.h carry whichever
 * constants the host header omits.  Build hosts whose sysroot lacks
 * <linux/if_macsec.h> entirely silently drop the family from the
 * registry.
 */

#if __has_include(<linux/if_macsec.h>)

#include <linux/if_macsec.h>

#include "compat.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar macsec_cmds[] = {
	{ MACSEC_CMD_GET_TXSC,		"MACSEC_CMD_GET_TXSC" },
	{ MACSEC_CMD_ADD_RXSC,		"MACSEC_CMD_ADD_RXSC" },
	{ MACSEC_CMD_DEL_RXSC,		"MACSEC_CMD_DEL_RXSC" },
	{ MACSEC_CMD_UPD_RXSC,		"MACSEC_CMD_UPD_RXSC" },
	{ MACSEC_CMD_ADD_TXSA,		"MACSEC_CMD_ADD_TXSA" },
	{ MACSEC_CMD_DEL_TXSA,		"MACSEC_CMD_DEL_TXSA" },
	{ MACSEC_CMD_UPD_TXSA,		"MACSEC_CMD_UPD_TXSA" },
	{ MACSEC_CMD_ADD_RXSA,		"MACSEC_CMD_ADD_RXSA" },
	{ MACSEC_CMD_DEL_RXSA,		"MACSEC_CMD_DEL_RXSA" },
	{ MACSEC_CMD_UPD_RXSA,		"MACSEC_CMD_UPD_RXSA" },
	{ MACSEC_CMD_UPD_OFFLOAD,	"MACSEC_CMD_UPD_OFFLOAD" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/if_macsec.h>.
 * Eight nests all hang off the outer MACSEC_ATTR_* table; outer ids
 * select which nest to walk and inner ids are validated against that
 * nest's policy.  The kernel only matches each child against the
 * policy of whichever nest is currently being parsed, so the ID
 * collisions across nests (every nest starts at id 1) are harmless.
 *
 * Variable-length sizes:
 *   KEY    MACSEC_MAX_KEY_LEN (128, GCM-AES-256 max key)
 *   KEYID  MACSEC_KEYID_LEN (16, 128-bit key identifier)
 *   SALT   MACSEC_SALT_LEN (12, 96-bit XPN salt)
 */
static const struct nla_attr_spec macsec_attrs[] = {
	/* MACSEC_ATTR_* — outer.  IFINDEX is the netdev selector consumed
	 * by every command's macsec_get_dev_from_attrs lookup; the
	 * remaining ids are either nested config payloads (RXSC_CONFIG /
	 * SA_CONFIG / OFFLOAD — the only three the input policy actually
	 * validates) or response-only nests (SECY / *_LIST / *_STATS)
	 * that exercise the validator's ignore-on-input branch. */
	{ MACSEC_ATTR_IFINDEX,				NLA_KIND_U32,    4 },
	{ MACSEC_ATTR_RXSC_CONFIG,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_SA_CONFIG,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_SECY,				NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_TXSA_LIST,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_RXSC_LIST,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_TXSC_STATS,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_SECY_STATS,			NLA_KIND_NESTED, 0 },
	{ MACSEC_ATTR_OFFLOAD,				NLA_KIND_NESTED, 0 },

	/* MACSEC_RXSC_ATTR_* (under MACSEC_ATTR_RXSC_CONFIG).  Validated
	 * by macsec_genl_rxsc_policy; SCI is the 64-bit secure channel
	 * identifier consumed by every RXSC ADD / DEL / UPD path, ACTIVE
	 * toggles the channel state. */
	{ MACSEC_RXSC_ATTR_SCI,				NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_ATTR_ACTIVE,			NLA_KIND_U8,     1 },
	{ MACSEC_RXSC_ATTR_SA_LIST,			NLA_KIND_NESTED, 0 },
	{ MACSEC_RXSC_ATTR_STATS,			NLA_KIND_NESTED, 0 },

	/* MACSEC_SA_ATTR_* (under MACSEC_ATTR_SA_CONFIG).  Validated by
	 * macsec_genl_sa_policy.  KEY is the GCM-AES key (16 or 32 bytes
	 * for AES-128/256, plus salt for the XPN variants); KEYID is the
	 * 128-bit secure-association identifier; SSCI / SALT are the
	 * 5.7-era XPN extensions.  PN sits behind a NLA_POLICY_MIN_LEN(4)
	 * since the kernel accepts u32 (regular) or u64 (XPN). */
	{ MACSEC_SA_ATTR_AN,				NLA_KIND_U8,     1 },
	{ MACSEC_SA_ATTR_ACTIVE,			NLA_KIND_U8,     1 },
	{ MACSEC_SA_ATTR_PN,				NLA_KIND_U64,    8 },
	{ MACSEC_SA_ATTR_KEY,				NLA_KIND_BINARY, MACSEC_MAX_KEY_LEN },
	{ MACSEC_SA_ATTR_KEYID,				NLA_KIND_BINARY, MACSEC_KEYID_LEN },
	{ MACSEC_SA_ATTR_STATS,				NLA_KIND_NESTED, 0 },
	{ MACSEC_SA_ATTR_SSCI,				NLA_KIND_U32,    4 },
	{ MACSEC_SA_ATTR_SALT,				NLA_KIND_BINARY, MACSEC_SALT_LEN },

	/* MACSEC_OFFLOAD_ATTR_* (under MACSEC_ATTR_OFFLOAD).  Validated
	 * by macsec_genl_offload_policy; TYPE picks
	 * MACSEC_OFFLOAD_OFF/PHY/MAC and drives the per-driver offload
	 * dispatcher. */
	{ MACSEC_OFFLOAD_ATTR_TYPE,			NLA_KIND_U8,     1 },

	/* MACSEC_SECY_ATTR_* (under MACSEC_ATTR_SECY) — response-only.
	 * Listed so the validator's ignore-on-input branch is exercised
	 * the same way the OVS dp/flow STATS attrs and L2TP's inner
	 * STATS counters are. */
	{ MACSEC_SECY_ATTR_SCI,				NLA_KIND_U64,    8 },
	{ MACSEC_SECY_ATTR_ENCODING_SA,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_WINDOW,			NLA_KIND_U32,    4 },
	{ MACSEC_SECY_ATTR_CIPHER_SUITE,		NLA_KIND_U64,    8 },
	{ MACSEC_SECY_ATTR_ICV_LEN,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_PROTECT,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_REPLAY,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_OPER,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_VALIDATE,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_ENCRYPT,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_INC_SCI,			NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_ES,				NLA_KIND_U8,     1 },
	{ MACSEC_SECY_ATTR_SCB,				NLA_KIND_U8,     1 },

	/* MACSEC_RXSC_STATS_ATTR_* (under MACSEC_RXSC_ATTR_STATS) —
	 * response-only u64 per-RXSC counters. */
	{ MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK,		NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE,		NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_USING_SA,	NLA_KIND_U64,    8 },
	{ MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNUSED_SA,	NLA_KIND_U64,    8 },

	/* MACSEC_SA_STATS_ATTR_* (under MACSEC_SA_ATTR_STATS) —
	 * response-only u32 per-{RX,TX}SA counters. */
	{ MACSEC_SA_STATS_ATTR_IN_PKTS_OK,		NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_IN_PKTS_INVALID,		NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_VALID,	NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_USING_SA,	NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_IN_PKTS_UNUSED_SA,	NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_OUT_PKTS_PROTECTED,	NLA_KIND_U32,    4 },
	{ MACSEC_SA_STATS_ATTR_OUT_PKTS_ENCRYPTED,	NLA_KIND_U32,    4 },

	/* MACSEC_TXSC_STATS_ATTR_* (under MACSEC_ATTR_TXSC_STATS) —
	 * response-only u64 per-TXSC counters. */
	{ MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED,	NLA_KIND_U64,    8 },
	{ MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED,	NLA_KIND_U64,    8 },
	{ MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED,	NLA_KIND_U64,    8 },
	{ MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED,	NLA_KIND_U64,    8 },

	/* MACSEC_SECY_STATS_ATTR_* (under MACSEC_ATTR_SECY_STATS) —
	 * response-only u64 per-SecY counters. */
	{ MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI,	NLA_KIND_U64,    8 },
	{ MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN,	NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_macsec = {
	.name = MACSEC_GENL_NAME,
	.cmds = macsec_cmds,
	.n_cmds = ARRAY_SIZE(macsec_cmds),
	.attrs = macsec_attrs,
	.n_attrs = ARRAY_SIZE(macsec_attrs),
	.default_version = MACSEC_GENL_VERSION,
};

#endif /* __has_include(<linux/if_macsec.h>) */
