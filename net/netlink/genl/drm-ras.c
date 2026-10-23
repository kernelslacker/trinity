/*
 * Genetlink family grammar: drm-ras (DRM Reliability / Availability /
 * Serviceability), targeting drivers/gpu/drm/drm_ras.c and drm_ras_nl.c.
 * All three ops are GENL_ADMIN_PERM; both uapi attribute sets share the
 * one flat table.
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
 * ERROR_ID (u32), ERROR_NAME (string), ERROR_VALUE (u32).  Both sets
 * start at id 1 and agree on kind except id 2 (DEVICE_NAME string vs
 * ERROR_ID u32), so one flat table lists both and an emission lands
 * on a plausible id and kind for whichever command is being parsed.
 * Strings are bounded at 64 bytes — generous enough to cover any
 * plausible device / node / error name without inviting greedy
 * oversized payloads.
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
