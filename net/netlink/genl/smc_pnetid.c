/*
 * Genetlink family grammar: SMC_PNETID (SMC-R PNET table), targeting
 * smc_pnet_policy and the handlers in net/smc/smc_pnet.c.  ADD, DEL and
 * FLUSH are GENL_ADMIN_PERM, GET dumps the table.  One flat SMC_PNETID_*
 * namespace.
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
