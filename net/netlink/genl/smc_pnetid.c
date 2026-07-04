/*
 * Genetlink family grammar: SMC_PNETID (SMC-R PNET table).
 *
 * The SMC-R / SMC-D shared-memory communications stack maintains a
 * "PNET" table mapping a per-fabric PNETID label to the underlying
 * ethernet netdev plus the RoCE/IB device + port the link rides on.
 * Userspace administers that table through a small generic-netlink
 * family (SMCR_GENL_FAMILY_NAME = "SMC_PNETID") with four user-callable
 * commands: GET (dump the table), ADD (install a NAME -> ETHNAME +
 * IBNAME/IBPORT triple), DEL (remove by NAME), FLUSH (drop every
 * entry).  ADD and DEL gate on CAP_NET_ADMIN; the per-cmd nla_policy
 * walker (smc_pnet_policy in net/smc/smc_pnet.c) runs before the
 * capability check so the validator coverage lands unprivileged --
 * penetrating the family demuxer with a real family_id puts the
 * smc_pnet_add / _remove / _dump parsers plus the netdev / IB-device
 * lookup chains directly in the fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "SMC_PNETID", so the per-cmd policy walker plus the
 * pnetid table edit paths have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real SMC_PNETID messages whose
 * attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the fou / psample / gtp model, a single flat nla_attr_spec table
 * lists every id used by this family's commands.  SMC_PNETID uses a
 * single flat SMC_PNETID_* namespace (no nested containers): three
 * NUL-terminated string selectors (NAME for the PNETID label,
 * ETHNAME for the ethernet netdev, IBNAME for the IB device) plus a
 * u8 IBPORT physical-port selector.  The kernel's policy caps NAME at
 * SMC_MAX_PNETID_LEN (16), ETHNAME at IFNAMSIZ-1 (15), and IBNAME at
 * IB_DEVICE_NAME_MAX-1 (63); the upper bounds below match those caps
 * so the validator's length-check arm sees both in-range and over-cap
 * payloads.
 *
 * Header gating mirrors the fou / psample / gtp families:
 * <linux/smc.h> is the upstream UAPI header carrying every SMC_PNETID_*
 * enum referenced below.  Build hosts lacking the header silently drop
 * the family from the registry instead of failing the build.  The
 * SMC_PNETID_* ids and the SMCR_GENL_FAMILY_NAME / _VERSION macros
 * have been stable since the initial 4.x landing so no per-symbol
 * fallback shims are required.
 */

#if __has_include(<linux/smc.h>)

#include <linux/smc.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar smc_pnetid_cmds[] = {
	{ SMC_PNETID_GET,	"SMC_PNETID_GET" },
	{ SMC_PNETID_ADD,	"SMC_PNETID_ADD" },
	{ SMC_PNETID_DEL,	"SMC_PNETID_DEL" },
	{ SMC_PNETID_FLUSH,	"SMC_PNETID_FLUSH" },
};

/*
 * Attribute spec follows smc_pnet_policy in net/smc/smc_pnet.c.
 * NAME is the SMC_MAX_PNETID_LEN-bounded (16) PNETID label every
 * ADD/DEL gates on.  ETHNAME is an IFNAMSIZ-bounded (16) ethernet
 * netdev name the kernel resolves via dev_get_by_name on ADD.
 * IBNAME is an IB_DEVICE_NAME_MAX-bounded (64) IB device name the
 * kernel resolves via ib_device_lookup_by_name; IBPORT is the u8
 * physical-port selector on that IB device.  The bounds match the
 * kernel's .len caps so the validator's length-check arm sees both
 * in-range and over-cap payloads.
 */
static const struct nla_attr_spec smc_pnetid_attrs[] = {
	{ SMC_PNETID_NAME,	NLA_KIND_STRING, 16 },
	{ SMC_PNETID_ETHNAME,	NLA_KIND_STRING, 16 },
	{ SMC_PNETID_IBNAME,	NLA_KIND_STRING, 64 },
	{ SMC_PNETID_IBPORT,	NLA_KIND_U8,     1 },
};

struct genl_family_grammar fam_smc_pnetid = {
	.name = SMCR_GENL_FAMILY_NAME,
	.cmds = smc_pnetid_cmds,
	.n_cmds = ARRAY_SIZE(smc_pnetid_cmds),
	.attrs = smc_pnetid_attrs,
	.n_attrs = ARRAY_SIZE(smc_pnetid_attrs),
	.default_version = SMCR_GENL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/smc.h>) */
