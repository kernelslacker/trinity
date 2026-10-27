/*
 * Genetlink family grammar: drm-ras (DRM Reliability / Availability /
 * Serviceability), targeting drivers/gpu/drm/drm_ras.c and drm_ras_nl.c.
 * All five ops are GENL_ADMIN_PERM split ops, each with its own policy,
 * which the genl core applies strictly, so each cmd draws from the table
 * its policy takes.
 */

#if __has_include(<drm/drm_ras.h>)

#include "kernel/drm_ras.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * drm_ras_nl.c's policies, all in the error-counter attribute set:
 * GET_ERROR_COUNTER's doit, CLEAR_ERROR_COUNTER and GET_ERROR_THRESHOLD
 * take NODE_ID and ERROR_ID, GET_ERROR_COUNTER's dumpit only NODE_ID, and
 * SET_ERROR_THRESHOLD the threshold as well.  LIST_NODES, a dumpit with
 * no policy, takes nothing.  The node attributes are reply-only.
 *
 * Each doit answers -EINVAL to a request that lacks any attribute its policy
 * takes, so those are marked required.  The dumpit wants NODE_ID alone, a
 * table of one that every request with an attribute carries.
 */
static const struct nla_attr_spec drm_ras_counter_attrs[] = {
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID,	NLA_KIND_U32, 4,
	  .required = true },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID,	NLA_KIND_U32, 4,
	  .required = true },
};

static const struct nla_attr_spec drm_ras_node_attrs[] = {
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID,	NLA_KIND_U32, 4 },
};

static const struct nla_attr_spec drm_ras_set_threshold_attrs[] = {
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID,	NLA_KIND_U32, 4,
	  .required = true },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID,	NLA_KIND_U32, 4,
	  .required = true },
	{ DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_THRESHOLD, NLA_KIND_U32, 4,
	  .required = true },
};

static const struct genl_cmd_grammar drm_ras_cmds[] = {
	{ DRM_RAS_CMD_LIST_NODES,		"DRM_RAS_CMD_LIST_NODES",
	  genl_no_attrs, 0 },
	{ DRM_RAS_CMD_GET_ERROR_COUNTER,	"DRM_RAS_CMD_GET_ERROR_COUNTER",
	  drm_ras_counter_attrs, ARRAY_SIZE(drm_ras_counter_attrs),
	  drm_ras_node_attrs, ARRAY_SIZE(drm_ras_node_attrs) },
	{ DRM_RAS_CMD_CLEAR_ERROR_COUNTER,	"DRM_RAS_CMD_CLEAR_ERROR_COUNTER",
	  drm_ras_counter_attrs, ARRAY_SIZE(drm_ras_counter_attrs) },
	{ DRM_RAS_CMD_GET_ERROR_THRESHOLD,	"DRM_RAS_CMD_GET_ERROR_THRESHOLD",
	  drm_ras_counter_attrs, ARRAY_SIZE(drm_ras_counter_attrs) },
	{ DRM_RAS_CMD_SET_ERROR_THRESHOLD,	"DRM_RAS_CMD_SET_ERROR_THRESHOLD",
	  drm_ras_set_threshold_attrs, ARRAY_SIZE(drm_ras_set_threshold_attrs) },
};

struct genl_family_grammar fam_drm_ras = {
	.name = DRM_RAS_FAMILY_NAME,
	.cmds = drm_ras_cmds,
	.n_cmds = ARRAY_SIZE(drm_ras_cmds),
	.default_version = DRM_RAS_FAMILY_VERSION,
};

#endif /* __has_include(<drm/drm_ras.h>) */
