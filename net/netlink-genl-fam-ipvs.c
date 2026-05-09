/*
 * Genetlink family grammar: IPVS (IP Virtual Server).
 *
 * The IPVS subsystem exposes its userspace control plane through a
 * single generic-netlink family ("IPVS") whose command set splits
 * cleanly into a write-side (NEW_/SET_/DEL_SERVICE, NEW_/SET_/DEL_DEST,
 * NEW_/DEL_DAEMON, SET_CONFIG, FLUSH, ZERO) that mutates the per-net
 * virtual-service / real-server / sync-daemon tables, and a read-side
 * (GET_SERVICE, GET_DEST, GET_DAEMON, GET_CONFIG, GET_INFO) that walks
 * the same state without touching it.  Only the read-side is emitted
 * here: per the THERMAL precedent for the THRESHOLD_ADD / DELETE /
 * FLUSH skip, mutating live per-namespace IPVS state from inside the
 * fuzz loop would tear down virtual services and destinations the
 * surrounding host may rely on, so the GET-shape commands are the
 * scope-bounded coverage worth opening up.  IPVS_CMD_SET_INFO is the
 * GET_INFO reply payload and is not callable from userspace, so it is
 * skipped on the same grounds as the THERMAL_GENL_EVENT_* enum.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "IPVS", so the per-cmd nla_policy walker in
 * net/netfilter/ipvs/ip_vs_ctl.c (ip_vs_genl_ops) has been routinely
 * cold under generic netlink fuzzing; resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real IPVS
 * messages whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample / ila /
 * ioam6 / seg6 / thermal model, a single flat nla_attr_spec table lists
 * every id used by this family's commands.  The IPVS top-level policy
 * carries three nominally nested container attrs (SERVICE / DEST /
 * DAEMON) plus three u32 timeout scalars (TIMEOUT_TCP, TIMEOUT_TCP_FIN,
 * TIMEOUT_UDP) the GET_CONFIG / SET_CONFIG pair share.  Each container
 * is emitted as an empty NLA_KIND_NESTED placeholder so the kernel's
 * nla_validate accepts the message without recursing into a per-sub-
 * policy that we haven't built — the GET handlers tolerate missing
 * nested content for the dump-shape commands; the IPVS_SVC_ATTR_* /
 * IPVS_DEST_ATTR_* / IPVS_DAEMON_ATTR_* sub-namespaces are needed only
 * for the mutation commands, which are the ones we deliberately skip.
 *
 * Header gating mirrors the thermal / psample / ila / fou / hsr / seg6
 * families: <linux/ip_vs.h> is the upstream UAPI header carrying every
 * IPVS_CMD_* and IPVS_CMD_ATTR_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry instead
 * of failing the build.  Per-symbol #ifndef shims fill in any IPVS_CMD_*
 * / IPVS_CMD_ATTR_* on build hosts whose stale uapi predates them; the
 * fallback values match the upstream uapi enum ordering so the wire-
 * format ids the kernel parses match the ones the generator emits.
 */

#if __has_include(<linux/ip_vs.h>)

#include <linux/ip_vs.h>

#include "netlink-genl-families.h"
#include "utils.h"

#ifndef IPVS_CMD_GET_SERVICE
#define IPVS_CMD_GET_SERVICE		4
#endif
#ifndef IPVS_CMD_GET_DEST
#define IPVS_CMD_GET_DEST		8
#endif
#ifndef IPVS_CMD_GET_DAEMON
#define IPVS_CMD_GET_DAEMON		11
#endif
#ifndef IPVS_CMD_GET_CONFIG
#define IPVS_CMD_GET_CONFIG		13
#endif
#ifndef IPVS_CMD_GET_INFO
#define IPVS_CMD_GET_INFO		15
#endif

#ifndef IPVS_CMD_ATTR_SERVICE
#define IPVS_CMD_ATTR_SERVICE		1
#endif
#ifndef IPVS_CMD_ATTR_DEST
#define IPVS_CMD_ATTR_DEST		2
#endif
#ifndef IPVS_CMD_ATTR_DAEMON
#define IPVS_CMD_ATTR_DAEMON		3
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_TCP
#define IPVS_CMD_ATTR_TIMEOUT_TCP	4
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_TCP_FIN
#define IPVS_CMD_ATTR_TIMEOUT_TCP_FIN	5
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_UDP
#define IPVS_CMD_ATTR_TIMEOUT_UDP	6
#endif

static const struct genl_cmd_grammar ipvs_cmds[] = {
	{ IPVS_CMD_GET_SERVICE,	"IPVS_CMD_GET_SERVICE" },
	{ IPVS_CMD_GET_DEST,	"IPVS_CMD_GET_DEST" },
	{ IPVS_CMD_GET_DAEMON,	"IPVS_CMD_GET_DAEMON" },
	{ IPVS_CMD_GET_CONFIG,	"IPVS_CMD_GET_CONFIG" },
	{ IPVS_CMD_GET_INFO,	"IPVS_CMD_GET_INFO" },
};

/*
 * Attribute spec follows the IPVS_CMD_ATTR_* enum in <linux/ip_vs.h>.
 * SERVICE / DEST / DAEMON are the three top-level nested containers
 * the per-cmd policy keys on; emitting them as empty NLA_KIND_NESTED
 * placeholders lets the validator accept the message without recursing
 * into the IPVS_SVC_ATTR_* / IPVS_DEST_ATTR_* / IPVS_DAEMON_ATTR_*
 * sub-namespaces the mutation commands require.  TIMEOUT_TCP /
 * TIMEOUT_TCP_FIN / TIMEOUT_UDP are u32 millisecond selectors the
 * GET_CONFIG path emits on dump and SET_CONFIG validates on input;
 * listing them here exercises the validator's ignore-on-input branch
 * for GET_CONFIG the same way the OVS dp/flow STATS attrs and the
 * L2TP STATS sub-namespace do.
 */
static const struct nla_attr_spec ipvs_attrs[] = {
	{ IPVS_CMD_ATTR_SERVICE,	NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_DEST,		NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_DAEMON,		NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_TIMEOUT_TCP,	NLA_KIND_U32,    4 },
	{ IPVS_CMD_ATTR_TIMEOUT_TCP_FIN, NLA_KIND_U32,   4 },
	{ IPVS_CMD_ATTR_TIMEOUT_UDP,	NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_ipvs = {
	.name = "IPVS",
	.cmds = ipvs_cmds,
	.n_cmds = ARRAY_SIZE(ipvs_cmds),
	.attrs = ipvs_attrs,
	.n_attrs = ARRAY_SIZE(ipvs_attrs),
};

#endif /* __has_include(<linux/ip_vs.h>) */
