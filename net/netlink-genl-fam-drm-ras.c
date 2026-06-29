/*
 * Genetlink family grammar: drm-ras (DRM Reliability/Availability/
 * Serviceability over generic netlink).
 *
 * The DRM RAS subsystem exposes a generic-netlink control surface
 * carrying three commands: LIST_NODES dumps the set of registered
 * driver-owned RAS nodes, GET_ERROR_COUNTER reads back a specific
 * error counter for a node, and CLEAR_ERROR_COUNTER resets one.  All
 * three carry GENL_ADMIN_PERM; the per-cmd nla_policy walk runs
 * before the capability check, so even unprivileged validator traffic
 * penetrates the family demuxer once family_id resolution lets the
 * message generator address real drm-ras messages.
 *
 * Random nlmsg_type ids essentially never matched the runtime-
 * assigned family_id for "drm-ras", so the per-cmd nla_policy walker
 * plus the three doit/dumpit handlers have been routinely cold under
 * generic netlink fuzzing.  Resolving the family at first
 * NETLINK_GENERIC use lets the message generator emit structurally-
 * valid payloads that plausibly survive the per-cmd policy and reach
 * the dispatch handlers where bugs actually live.
 *
 * drm-ras carries two attribute namespaces in the uapi (node-attrs
 * and error-counter-attrs); the per-command policy switches between
 * them.  The numeric attribute ids overlap (both sets start at 1) and
 * mostly carry the same kind across both sets — only id 2 differs
 * (DEVICE_NAME string vs ERROR_ID u32).  The flat-table model used by
 * the lockd / fou / psample families applies: list both sets and let
 * the per-emission picker land on a plausible id+kind pair for
 * whichever command the dispatcher is feeding the policy walker.
 *
 * Header gating mirrors the nfsd / team / hsr / fou / psample
 * families: <drm/drm_ras.h> is the upstream UAPI header carrying every
 * DRM_RAS_CMD_* and DRM_RAS_A_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry
 * instead of failing the build.  Per-symbol #ifndef shims in
 * include/kernel/drm_ras.h fill in any ids missing from a stale uapi.
 */

#if __has_include(<drm/drm_ras.h>)

#include "kernel/drm_ras.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar drm_ras_cmds[] = {
	{ DRM_RAS_CMD_LIST_NODES,		"DRM_RAS_CMD_LIST_NODES" },
	{ DRM_RAS_CMD_GET_ERROR_COUNTER,	"DRM_RAS_CMD_GET_ERROR_COUNTER" },
	{ DRM_RAS_CMD_CLEAR_ERROR_COUNTER,	"DRM_RAS_CMD_CLEAR_ERROR_COUNTER" },
};

/*
 * Attribute spec covers both uapi sets.  node-attrs carries
 * NODE_ID (u32), DEVICE_NAME (string), NODE_NAME (string),
 * NODE_TYPE (u32); error-counter-attrs carries NODE_ID (u32),
 * ERROR_ID (u32), ERROR_NAME (string), ERROR_VALUE (u32).  Strings
 * are bounded at 64 bytes — generous enough to cover any plausible
 * device / node / error name without inviting greedy oversized
 * payloads.
 */
static const struct nla_attr_spec drm_ras_attrs[] = {
	{ DRM_RAS_A_NODE_ATTRS_NODE_ID,			NLA_KIND_U32,    4  },
	{ DRM_RAS_A_NODE_ATTRS_DEVICE_NAME,		NLA_KIND_STRING, 64 },
	{ DRM_RAS_A_NODE_ATTRS_NODE_NAME,		NLA_KIND_STRING, 64 },
	{ DRM_RAS_A_NODE_ATTRS_NODE_TYPE,		NLA_KIND_U32,    4  },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID,	NLA_KIND_U32,    4  },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID,	NLA_KIND_U32,    4  },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME,	NLA_KIND_STRING, 64 },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE,	NLA_KIND_U32,    4  },
};

struct genl_family_grammar fam_drm_ras = {
	.name = DRM_RAS_FAMILY_NAME,
	.cmds = drm_ras_cmds,
	.n_cmds = ARRAY_SIZE(drm_ras_cmds),
	.attrs = drm_ras_attrs,
	.n_attrs = ARRAY_SIZE(drm_ras_attrs),
	.default_version = DRM_RAS_FAMILY_VERSION,
};

#endif /* __has_include(<drm/drm_ras.h>) */
