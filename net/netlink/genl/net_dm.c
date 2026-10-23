/*
 * Genetlink family grammar: NET_DM (drop monitor), targeting
 * net/core/drop_monitor.c.  START, STOP and CONFIG are GENL_ADMIN_PERM; the
 * policy lists only ALERT_MODE, TRUNC_LEN, QUEUE_LEN, SW_DROPS and
 * HW_DROPS and rejects every other attribute as unsupported.
 */

#if __has_include(<linux/net_dropmon.h>)

#include "kernel/net_dropmon.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * ALERT, PACKET_ALERT, CONFIG_NEW and STATS_NEW are kernel-to-userspace
 * ids with no op, so they are not listed.
 */
static const struct genl_cmd_grammar net_dm_cmds[] = {
	{ NET_DM_CMD_START,	"NET_DM_CMD_START" },
	{ NET_DM_CMD_STOP,	"NET_DM_CMD_STOP" },
	{ NET_DM_CMD_CONFIG,	"NET_DM_CMD_CONFIG" },
	{ NET_DM_CMD_CONFIG_GET,"NET_DM_CMD_CONFIG_GET" },
	{ NET_DM_CMD_STATS_GET,	"NET_DM_CMD_STATS_GET" },
};

/*
 * Attribute spec follows the NET_DM_ATTR_* enum in <linux/net_dropmon.h>.
 * ALERT_MODE is a u8 selector (NET_DM_ALERT_MODE_SUMMARY / _PACKET).
 * TRUNC_LEN / ORIG_LEN / QUEUE_LEN / HW_TRAP_COUNT are u32 scalars.
 * PROTO / ORIGIN are u16 selectors.  PC and TIMESTAMP are u64 scalars.
 * SW_DROPS / HW_DROPS are presence-only flags that toggle the
 * software- vs hardware-drop reporting in CONFIG.  SYMBOL,
 * HW_TRAP_GROUP_NAME, HW_TRAP_NAME, and REASON are kernel-side NUL-
 * terminated strings carrying symbol / trap / drop-reason text;
 * bounding the generator at 64 bytes keeps the emitted payload below
 * the kernel's KSYM_NAME_LEN / DEVLINK_TRAP_GENERIC_NAME_LEN ceilings
 * without sweeping the full string-length range on a hot path.
 * PAYLOAD and FLOW_ACTION_COOKIE are variable-length binary blobs
 * bounded above so a single greedy blob can't eat the whole netlink
 * buffer.  PAD is the alignment partner the kernel emits next to the
 * u64 scalars; it carries no payload, so a 0-byte BINARY entry matches
 * the wire shape.  IN_PORT / STATS / HW_STATS / HW_ENTRIES / HW_ENTRY
 * are nested containers the kernel only emits: net_dm_nl_policy has no
 * entry for them, so they have no sub-policy on input.
 */
static const struct nla_attr_spec net_dm_attrs[] = {
	{ NET_DM_ATTR_ALERT_MODE,		NLA_KIND_U8,     1 },
	{ NET_DM_ATTR_PC,			NLA_KIND_U64,    8 },
	{ NET_DM_ATTR_SYMBOL,			NLA_KIND_STRING, 64 },
	{ NET_DM_ATTR_IN_PORT,			NLA_KIND_NESTED, 0 },
	{ NET_DM_ATTR_TIMESTAMP,		NLA_KIND_U64,    8 },
	{ NET_DM_ATTR_PROTO,			NLA_KIND_U16,    2 },
	{ NET_DM_ATTR_PAYLOAD,			NLA_KIND_BINARY, 64 },
	{ NET_DM_ATTR_PAD,			NLA_KIND_BINARY, 0 },
	{ NET_DM_ATTR_TRUNC_LEN,		NLA_KIND_U32,    4 },
	{ NET_DM_ATTR_ORIG_LEN,			NLA_KIND_U32,    4 },
	{ NET_DM_ATTR_QUEUE_LEN,		NLA_KIND_U32,    4 },
	{ NET_DM_ATTR_STATS,			NLA_KIND_NESTED, 0 },
	{ NET_DM_ATTR_HW_STATS,			NLA_KIND_NESTED, 0 },
	{ NET_DM_ATTR_ORIGIN,			NLA_KIND_U16,    2 },
	{ NET_DM_ATTR_HW_TRAP_GROUP_NAME,	NLA_KIND_STRING, 64 },
	{ NET_DM_ATTR_HW_TRAP_NAME,		NLA_KIND_STRING, 64 },
	{ NET_DM_ATTR_HW_ENTRIES,		NLA_KIND_NESTED, 0 },
	{ NET_DM_ATTR_HW_ENTRY,			NLA_KIND_NESTED, 0 },
	{ NET_DM_ATTR_HW_TRAP_COUNT,		NLA_KIND_U32,    4 },
	{ NET_DM_ATTR_SW_DROPS,			NLA_KIND_FLAG,   0 },
	{ NET_DM_ATTR_HW_DROPS,			NLA_KIND_FLAG,   0 },
	{ NET_DM_ATTR_FLOW_ACTION_COOKIE,	NLA_KIND_BINARY, 64 },
	{ NET_DM_ATTR_REASON,			NLA_KIND_STRING, 64 },
};

struct genl_family_grammar fam_net_dm = {
	/* The uapi header has no NET_DM_GENL_NAME; the kernel registers the
	 * literal. */
	.name = "NET_DM",
	.cmds = net_dm_cmds,
	.n_cmds = ARRAY_SIZE(net_dm_cmds),
	.attrs = net_dm_attrs,
	.n_attrs = ARRAY_SIZE(net_dm_attrs),
};

#endif /* __has_include(<linux/net_dropmon.h>) */
