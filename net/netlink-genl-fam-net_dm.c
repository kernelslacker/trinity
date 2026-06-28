/*
 * Genetlink family grammar: NET_DM (drop monitor).
 *
 * The drop_monitor module exposes its userspace control plane through a
 * single generic-netlink family ("NET_DM") that gates the kernel's drop
 * tracing feed.  Userspace issues NET_DM_CMD_START / NET_DM_CMD_STOP to
 * arm and disarm the tracepoints, NET_DM_CMD_CONFIG to set the alert
 * mode plus the truncation / queue-length knobs, NET_DM_CMD_CONFIG_GET
 * to read the current configuration back, and NET_DM_CMD_STATS_GET to
 * fetch the per-mode dropped-packet counters.  The remaining commands
 * (ALERT, PACKET_ALERT, CONFIG_NEW, STATS_NEW) are kernel-to-userspace
 * notification / reply ids; userspace can still issue them but the cmd
 * dispatcher rejects them after running the per-cmd nla_policy walker.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "NET_DM", so the per-cmd nla_policy walker in
 * net/core/drop_monitor.c plus the mode-switch state machine that
 * gates summary-vs-packet alerting have been routinely cold under
 * generic netlink fuzzing; resolving the family at first NETLINK_GENERIC
 * use lets the message generator address real drop_monitor messages
 * whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the fou / psample model, a single flat nla_attr_spec table lists
 * every id used by this family's commands.  NET_DM uses a single flat
 * NET_DM_ATTR_* namespace; the nominally-nested attrs (IN_PORT, STATS,
 * HW_STATS, HW_ENTRIES, HW_ENTRY) are emitted as empty containers so
 * the kernel's nla_validate accepts them without recursing into a
 * per-sub-namespace policy.  The kernel's net_dm_nl_policy table only
 * validates ALERT_MODE / TRUNC_LEN / QUEUE_LEN / SW_DROPS / HW_DROPS
 * on input — the remainder are response-side payloads emitted by
 * CONFIG_GET / STATS_GET / PACKET_ALERT.  Listing them all here
 * exercises the validator's "ignore on input" branch the same way the
 * fou and psample grammars do.
 *
 * Header gating mirrors the fou / psample families: <linux/net_dropmon.h>
 * is the upstream UAPI header carrying every NET_DM_CMD_* and
 * NET_DM_ATTR_* enum referenced below.  Build hosts lacking the header
 * silently drop the family from the registry instead of failing the
 * build.  Per-symbol #ifndef shims fill in newer NET_DM_ATTR_* on
 * build hosts whose stale uapi predates the packet-mode metadata,
 * hardware-trap, or FLOW_ACTION_COOKIE / REASON additions.
 *
 * The uapi header carries no NET_DM_GENL_NAME macro — the kernel's
 * registration in net/core/drop_monitor.c hardcodes the family name
 * as the literal "NET_DM", so the .name field below does the same.
 */

#if __has_include(<linux/net_dropmon.h>)

#include "kernel/net_dropmon.h"
#include "netlink-genl-families.h"
#include "utils.h"

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
 * are nested containers — emitted as empty containers so the kernel's
 * nla_validate accepts them without recursing into the per-sub-
 * namespace policies (NET_DM_ATTR_PORT_*, NET_DM_ATTR_STATS_*).
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
	.name = "NET_DM",
	.cmds = net_dm_cmds,
	.n_cmds = ARRAY_SIZE(net_dm_cmds),
	.attrs = net_dm_attrs,
	.n_attrs = ARRAY_SIZE(net_dm_attrs),
};

#endif /* __has_include(<linux/net_dropmon.h>) */
