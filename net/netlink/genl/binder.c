/*
 * Genetlink family grammar: binder (Android binder IPC transaction-
 * report netlink family).
 *
 * The binder driver's userspace-visible netlink surface today is a
 * single genl family ("binder") that exposes one command,
 * BINDER_CMD_REPORT, plus a "report" multicast group that the kernel
 * emits transaction-failure notifications into via
 * binder_netlink_report() in drivers/android/binder.c.  The upstream
 * kernel's genl_split_ops table is empty (drivers/android/
 * binder_netlink.c), so a doit send from userspace bounces at the
 * family-demuxer's op lookup with -EOPNOTSUPP -- which is the coverage
 * this grammar targets: the family_id resolver, version check, and the
 * per-cmd validator gate all run before the op lookup, so a fuzzer
 * with the correct family_id exercises real code even without a
 * user-facing doit handler.
 *
 * As multicast listeners can also SEND on the socket (the kernel
 * simply won't dispatch), any future addition of a doit / dumpit
 * handler in binder_nl_ops[] transparently gains coverage from this
 * grammar without changes here.
 *
 * Per the psp / nl802154 / ieee802154 pattern, the grammar registers
 * unconditionally: include/kernel/binder_netlink.h ships #ifndef
 * fallbacks for every id, so build hosts whose sysroot predates the
 * uapi header still compile.  Runtime CTRL_CMD_GETFAMILY decides
 * whether the loaded kernel actually exposes the family.
 *
 * Attribute set: the BINDER_A_REPORT_* namespace from
 * <linux/android/binder_netlink.h>.  Per binder.c's
 * binder_netlink_report() emitter, ERROR / FROM_PID / FROM_TID /
 * TO_PID / TO_TID / FLAGS / CODE / DATA_SIZE are all u32, CONTEXT is a
 * NUL-terminated string, and IS_REPLY is presence-only (nla_put_flag).
 * The grammar sizes each entry to match those kernel-side puts so any
 * eventual validator dispatch sees plausibly-shaped input.  All attrs
 * live in a single flat namespace -- no nested containers.
 */

#include "kernel/binder_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar binder_cmds[] = {
	{ BINDER_CMD_REPORT, "BINDER_CMD_REPORT" },
};

static const struct nla_attr_spec binder_attrs[] = {
	{ BINDER_A_REPORT_ERROR,     NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_CONTEXT,   NLA_KIND_STRING, 32 },
	{ BINDER_A_REPORT_FROM_PID,  NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_FROM_TID,  NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_TO_PID,    NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_TO_TID,    NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_IS_REPLY,  NLA_KIND_FLAG,   0 },
	{ BINDER_A_REPORT_FLAGS,     NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_CODE,      NLA_KIND_U32,    4 },
	{ BINDER_A_REPORT_DATA_SIZE, NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_binder = {
	.name = BINDER_FAMILY_NAME,
	.cmds = binder_cmds,
	.n_cmds = ARRAY_SIZE(binder_cmds),
	.attrs = binder_attrs,
	.n_attrs = ARRAY_SIZE(binder_attrs),
	.default_version = BINDER_FAMILY_VERSION,
};
