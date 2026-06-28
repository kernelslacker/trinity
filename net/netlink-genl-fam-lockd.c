/*
 * Genetlink family grammar: lockd (kernel NFS lock manager control
 * plane).
 *
 * The lockd subsystem exposes a small userspace control surface
 * through a single generic-netlink family ("lockd") carrying two
 * commands: SERVER_GET reads back the current grace period and
 * TCP/UDP listener ports, SERVER_SET reconfigures them.  Both run
 * through the same per-cmd nla_policy walker before the doit handler;
 * SERVER_SET is GENL_ADMIN_PERM but the policy parse happens before
 * the capability check, so even unprivileged validator traffic
 * penetrates the family demuxer once family_id resolution lets the
 * message generator address real lockd messages.
 *
 * Random nlmsg_type ids essentially never matched the runtime-
 * assigned family_id for "lockd", so the per-cmd nla_policy walker in
 * fs/lockd/netlink.c plus the two doit handlers have been routinely
 * cold under generic netlink fuzzing.  Resolving the family at first
 * NETLINK_GENERIC use lets the message generator emit structurally-
 * valid SERVER_GET / SERVER_SET payloads that plausibly survive the
 * per-cmd policy and reach the dispatch handlers where bugs actually
 * live.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  lockd carries a single LOCKD_A_SERVER_*
 * namespace (GRACETIME / TCP_PORT / UDP_PORT) with consistent kinds
 * across both commands, so the flat-table model applies cleanly with
 * no per-command namespace extension needed.
 *
 * The family carries a nonzero declared version (LOCKD_FAMILY_VERSION
 * = 1) so the default_version member is initialised -- the kernel's
 * dispatcher doesn't gate on the genlmsghdr.version byte today, but
 * matching the declared family version keeps the message generator
 * honest against any future version-gated dispatch.  hdrsize stays 0:
 * lockd has no family-specific fixed header, attributes follow the
 * genlmsghdr directly.
 *
 * Header gating mirrors the nfsd / team / hsr / fou / psample
 * families: <linux/lockd_netlink.h> is the upstream UAPI header
 * carrying every LOCKD_CMD_* and LOCKD_A_* enum referenced below.
 * Build hosts lacking the header silently drop the family from the
 * registry instead of failing the build.  Per-symbol #ifndef shims in
 * include/kernel/lockd_netlink.h fill in any ids missing from a stale
 * uapi.
 */

#if __has_include(<linux/lockd_netlink.h>)

#include "kernel/lockd_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar lockd_cmds[] = {
	{ LOCKD_CMD_SERVER_SET, "LOCKD_CMD_SERVER_SET" },
	{ LOCKD_CMD_SERVER_GET, "LOCKD_CMD_SERVER_GET" },
};

/*
 * Attribute spec follows the LOCKD_A_SERVER_* enum in
 * <linux/lockd_netlink.h>.  GRACETIME is a u32 seconds counter; the
 * TCP and UDP listener ports are u16 wire-encoded port numbers.  Both
 * commands accept the same set of attributes (SERVER_GET responds
 * with the current values, SERVER_SET ingests them), so a single flat
 * table covers the whole family with no per-command namespace needed.
 */
static const struct nla_attr_spec lockd_attrs[] = {
	{ LOCKD_A_SERVER_GRACETIME,	NLA_KIND_U32, 4 },
	{ LOCKD_A_SERVER_TCP_PORT,	NLA_KIND_U16, 2 },
	{ LOCKD_A_SERVER_UDP_PORT,	NLA_KIND_U16, 2 },
};

struct genl_family_grammar fam_lockd = {
	.name = LOCKD_FAMILY_NAME,
	.cmds = lockd_cmds,
	.n_cmds = ARRAY_SIZE(lockd_cmds),
	.attrs = lockd_attrs,
	.n_attrs = ARRAY_SIZE(lockd_attrs),
	.default_version = LOCKD_FAMILY_VERSION,
};

#endif /* __has_include(<linux/lockd_netlink.h>) */
