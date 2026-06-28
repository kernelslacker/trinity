/*
 * Genetlink family grammar: dev-energymodel (energy model performance
 * domain readback).
 *
 * The dev-energymodel subsystem exposes its userspace readback surface
 * through a single generic-netlink family ("dev-energymodel") carrying
 * five command ids; only two of them -- GET_PERF_DOMAINS (do + dump)
 * and GET_PERF_TABLE (do) -- carry a userspace .doit / .dumpit handler
 * in the kernel-side split-ops table.  The other three ids
 * (PERF_DOMAIN_CREATED / _UPDATED / _DELETED) are kernel-emitted
 * notifications posted to the "event" mcgrp and have no inbound
 * handler -- the dispatcher would fast-reject them at the per-cmd
 * table lookup, so they are not enumerated in cmds[] below.  Neither
 * GET_* op carries GENL_ADMIN_PERM: the per-cmd nla_policy walker and
 * the doit handlers both run unprivileged, so penetrating the family
 * demuxer with a real family_id puts every per-cmd parser plus the
 * em_pd_get / em_table_show readback paths directly in the fuzzer's
 * reach.
 *
 * Random nlmsg_type ids essentially never matched the runtime-assigned
 * family_id for "dev-energymodel", so the per-cmd nla_policy walker in
 * kernel/power/em_netlink_autogen.c plus the readback handlers in
 * kernel/power/em_netlink.c have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real dev-energymodel messages
 * whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  Unlike sunrpc / nfsd / handshake -- whose
 * per-cmd namespaces collide at wire id 1 with disagreeing kinds and
 * forced a single-namespace anchor -- dev-energymodel's two request
 * surfaces are conveniently disjoint at the wire level:
 * GET_PERF_DOMAINS takes DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID
 * (wire id 2, u32) from the perf-domain attribute set, while
 * GET_PERF_TABLE takes DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID
 * (wire id 1, u32) from the perf-table attribute set.  Both u32, no
 * id collision, so the flat table carries both request-side perf-
 * domain-id selectors with consistent kinds and no per-command
 * namespace extension is needed.
 *
 * The family carries a nonzero declared version
 * (DEV_ENERGYMODEL_FAMILY_VERSION = 1) so the default_version member
 * is initialised -- the kernel's dispatcher doesn't gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: dev-energymodel has no
 * family-specific fixed header, attributes follow the genlmsghdr
 * directly.
 *
 * Header gating mirrors the sunrpc / nfsd / lockd families:
 * <linux/dev_energymodel.h> is the upstream UAPI header carrying every
 * DEV_ENERGYMODEL_CMD_* and DEV_ENERGYMODEL_A_* enum referenced below.
 * Build hosts lacking the header silently drop the family from the
 * registry instead of failing the build.  Per-symbol #ifndef shims in
 * include/kernel/dev_energymodel.h fill in any ids missing from a
 * stale uapi.
 */

#if __has_include(<linux/dev_energymodel.h>)

#include "kernel/dev_energymodel.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar dev_energymodel_cmds[] = {
	{ DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS, "DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS" },
	{ DEV_ENERGYMODEL_CMD_GET_PERF_TABLE,	"DEV_ENERGYMODEL_CMD_GET_PERF_TABLE" },
};

/*
 * Attribute spec follows the DEV_ENERGYMODEL_A_PERF_DOMAIN_* and
 * DEV_ENERGYMODEL_A_PERF_TABLE_* enums in <linux/dev_energymodel.h>.
 * GET_PERF_DOMAINS' request-side policy (em_netlink_autogen.c) has
 * maxattr = DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID (wire id 2)
 * with a single NLA_U32 entry at that id; GET_PERF_TABLE's policy has
 * maxattr = DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID (wire id 1)
 * also with a single NLA_U32 entry.  Listing both lets the message
 * generator emit either id as a u32 against either command: the
 * matching pair lands in the doit handler, the mismatched pair (wire
 * id 1 against GET_PERF_DOMAINS, or wire id 2 against GET_PERF_TABLE)
 * exercises the per-cmd policy walker's reject branch.
 */
static const struct nla_attr_spec dev_energymodel_attrs[] = {
	{ DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID,	NLA_KIND_U32, 4 },
	{ DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID,	NLA_KIND_U32, 4 },
};

struct genl_family_grammar fam_dev_energymodel = {
	.name = DEV_ENERGYMODEL_FAMILY_NAME,
	.cmds = dev_energymodel_cmds,
	.n_cmds = ARRAY_SIZE(dev_energymodel_cmds),
	.attrs = dev_energymodel_attrs,
	.n_attrs = ARRAY_SIZE(dev_energymodel_attrs),
	.default_version = DEV_ENERGYMODEL_FAMILY_VERSION,
};

#endif /* __has_include(<linux/dev_energymodel.h>) */
