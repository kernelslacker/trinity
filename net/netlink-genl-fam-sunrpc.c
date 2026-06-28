/*
 * Genetlink family grammar: sunrpc (kernel SUNRPC cache upcall control
 * plane).
 *
 * The sunrpc subsystem exposes a userspace cache-upcall control surface
 * through a single generic-netlink family ("sunrpc") carrying six
 * commands: CACHE_NOTIFY is a kernel-emitted event over the "exportd"
 * mcgrp; paired *_GET_REQS / *_SET_REQS commands dump pending ip_map /
 * unix_gid cache requests and post responses back; CACHE_FLUSH walks a
 * u32 cache-type bitmask and flushes the matching caches.  All five
 * *_REQS / CACHE_FLUSH commands are GENL_ADMIN_PERM gated but the per-
 * cmd nla_policy walker runs before the capability check, so the
 * validator coverage lands unprivileged -- penetrating the family
 * demuxer with a real family_id puts every per-cmd parser directly in
 * the fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "sunrpc", so the per-cmd nla_policy walker in
 * net/sunrpc/netlink.c plus the cache-upcall dispatch handlers have
 * been routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address real sunrpc messages whose attribute shapes plausibly survive
 * the per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  sunrpc unusually carries six distinct top-level
 * attribute namespaces -- SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE (u32 at id
 * 1), SUNRPC_A_IP_MAP_REQS_REQUESTS (NESTED at id 1), SUNRPC_A_UNIX_
 * GID_REQS_REQUESTS (NESTED at id 1), SUNRPC_A_CACHE_FLUSH_MASK (u32
 * at id 1), and the inner SUNRPC_A_IP_MAP_* / SUNRPC_A_UNIX_GID_*
 * namespaces that only ever appear nested inside REQUESTS -- whose ids
 * all start at 1 with disagreeing nla_kind values (U32 vs NESTED vs
 * U64).  The flat table cannot disambiguate overlapping keys, so
 * following the handshake / dpll / ovpn precedent only the NESTED-
 * anchored REQUESTS surface is enumerated here: ip-map-reqs and unix-
 * gid-reqs share wire id 1 NESTED with identical multi-attr semantics,
 * so a single entry covers the four *_REQS commands' outer validators
 * with one consistent kind.  The CACHE_NOTIFY (u32 CACHE_TYPE) and
 * CACHE_FLUSH (u32 MASK) outer surfaces and the inner ip-map / unix-
 * gid sub-attribute namespaces belong in a future grammar extension
 * that carries a per-command attribute namespace; their cmds are still
 * in the cmds[] table below so the family demuxer and the version
 * check are exercised for every command, only the per-cmd attr-policy
 * walker stays cold for the two u32-anchored commands until the
 * per-command namespace lands.
 *
 * The NESTED REQUESTS entry follows the handshake CERTIFICATE / psample
 * TUNNEL / ovpn PEER precedent: the generator emits an
 * NLA_F_NESTED-flagged attr with 1-3 placeholder children drawn from
 * the same flat table, so the kernel's outer ip-map-reqs / unix-gid-
 * reqs nla_validate accepts the wrapper without the children needing
 * to satisfy the per-nest sub-policy.  The per-entry handler iterates
 * the inner ip-map / unix-gid sub-policy walker over each placeholder
 * child, exercising the sub-parser's reject paths even when the
 * payload bytes don't shape into a valid sub-attribute.
 *
 * The family carries a nonzero declared version (SUNRPC_FAMILY_VERSION
 * = 1) so the default_version member is initialised -- the kernel's
 * dispatcher doesn't gate on the genlmsghdr.version byte today, but
 * matching the declared family version keeps the message generator
 * honest against any future version-gated dispatch.  hdrsize stays 0:
 * sunrpc has no family-specific fixed header, attributes follow the
 * genlmsghdr directly.
 *
 * Header gating mirrors the nfsd / lockd / team / hsr / fou / psample
 * families: <linux/sunrpc_netlink.h> is the upstream UAPI header
 * carrying every SUNRPC_CMD_* and SUNRPC_A_* enum referenced below.
 * Build hosts lacking the header silently drop the family from the
 * registry instead of failing the build.  Per-symbol #ifndef shims in
 * include/kernel/sunrpc_netlink.h fill in any ids missing from a stale
 * uapi.
 */

#if __has_include(<linux/sunrpc_netlink.h>)

#include "kernel/sunrpc_netlink.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar sunrpc_cmds[] = {
	{ SUNRPC_CMD_CACHE_NOTIFY,	  "SUNRPC_CMD_CACHE_NOTIFY" },
	{ SUNRPC_CMD_IP_MAP_GET_REQS,	  "SUNRPC_CMD_IP_MAP_GET_REQS" },
	{ SUNRPC_CMD_IP_MAP_SET_REQS,	  "SUNRPC_CMD_IP_MAP_SET_REQS" },
	{ SUNRPC_CMD_UNIX_GID_GET_REQS,	  "SUNRPC_CMD_UNIX_GID_GET_REQS" },
	{ SUNRPC_CMD_UNIX_GID_SET_REQS,	  "SUNRPC_CMD_UNIX_GID_SET_REQS" },
	{ SUNRPC_CMD_CACHE_FLUSH,	  "SUNRPC_CMD_CACHE_FLUSH" },
};

/*
 * Attribute spec follows the SUNRPC_A_IP_MAP_REQS_* enum in
 * <linux/sunrpc_netlink.h>.  REQUESTS is wire id 1 NESTED (multi-attr)
 * for IP_MAP_GET_REQS / IP_MAP_SET_REQS, and the matching
 * SUNRPC_A_UNIX_GID_REQS_REQUESTS reuses wire id 1 NESTED with
 * identical semantics for UNIX_GID_GET_REQS / UNIX_GID_SET_REQS -- a
 * single id 1 NESTED entry therefore covers all four outer *_REQS
 * validators with one consistent kind, so we list only the ip-map-reqs
 * symbolic id (the wire id is what the generator emits; the unix-gid-
 * reqs cmd parsers accept the same shape).
 *
 * Not enumerated: SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE (id 1, U32) for
 * CACHE_NOTIFY, SUNRPC_A_CACHE_FLUSH_MASK (id 1, U32) for CACHE_FLUSH,
 * and the inner SUNRPC_A_IP_MAP_* / SUNRPC_A_UNIX_GID_* namespaces
 * (ids 1..6 / 1..5) that only ever appear nested inside REQUESTS --
 * all of them disagree with the NESTED-anchored ip-map-reqs / unix-
 * gid-reqs surface on kind at id 1, and a single flat table cannot
 * carry both kinds at one wire id.  Per the handshake precedent the
 * larger surface (four *_REQS commands sharing one NESTED kind)
 * anchors the grammar and the others wait on a per-command attribute
 * namespace extension.
 */
static const struct nla_attr_spec sunrpc_attrs[] = {
	{ SUNRPC_A_IP_MAP_REQS_REQUESTS,	NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_sunrpc = {
	.name = SUNRPC_FAMILY_NAME,
	.cmds = sunrpc_cmds,
	.n_cmds = ARRAY_SIZE(sunrpc_cmds),
	.attrs = sunrpc_attrs,
	.n_attrs = ARRAY_SIZE(sunrpc_attrs),
	.default_version = SUNRPC_FAMILY_VERSION,
};

#endif /* __has_include(<linux/sunrpc_netlink.h>) */
