/*
 * Genetlink family grammar: handshake (kernel TLS handshake upcall).
 *
 * The handshake subsystem exposes its userspace control plane through
 * a single generic-netlink family ("handshake") covering the three
 * upcall-protocol commands: READY (kernel-to-userspace event posted
 * to multicast subscribers when a new handshake request is queued),
 * ACCEPT (a userspace handler retrieves the next queued request and
 * receives the listener socket fd plus the per-handshake policy
 * envelope), and DONE (the handler reports completion status back to
 * the kernel).  The two user-callable commands -- ACCEPT and DONE --
 * both carry GENL_ADMIN_PERM (CAP_NET_ADMIN gated), but the per-cmd
 * nla_policy walker runs before the capability check so the validator
 * coverage lands unprivileged -- penetrating the family demuxer with
 * a real family_id puts every per-cmd parser plus the handshake-req
 * queue lookup paths directly in the fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-
 * assigned family_id for "handshake", so the per-cmd policy walker
 * plus the queue / accept / done dispatch chains have been routinely
 * cold under generic netlink fuzzing; resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real
 * handshake messages whose attribute shapes plausibly survive the
 * per-cmd policy.
 *
 * READY is listed as a "notify" op in the YAML and the kernel does
 * not register a .doit / .dumpit handler for it -- the dispatcher
 * rejects an inbound READY with -EOPNOTSUPP.  It is kept in the cmds
 * table because the fast-reject path is itself an interesting
 * coverage surface: the family demuxer accepts the family_id, the
 * version check passes, and the per-cmd table lookup runs before the
 * EOPNOTSUPP return -- a worthwhile shape distinct from a random
 * nlmsg_type fast-reject at the controller layer.
 *
 * The family is split into three attribute namespaces in the YAML --
 * HANDSHAKE_A_X509_* (CERT/PRIVKEY for the nested X509 container),
 * HANDSHAKE_A_ACCEPT_* (the ACCEPT request + reply payloads), and
 * HANDSHAKE_A_DONE_* (the DONE request payload) -- whose id values
 * overlap starting at 1.  The flat nla_attr_spec table the registry
 * consumes cannot disambiguate overlapping keys, so following the
 * ovpn / dpll precedent only the HANDSHAKE_A_ACCEPT_* surface is
 * enumerated here: it is the larger of the three namespaces, and it
 * is the one a userspace handler interacts with at request-arrival
 * time.  The HANDSHAKE_A_DONE_* and HANDSHAKE_A_X509_* tables belong
 * in a future grammar extension that carries a per-command attribute
 * namespace; the DONE command is still in the cmds[] table above and
 * will start exercising the done parser once the per-command
 * namespace lands.
 *
 * The family carries a nonzero declared version
 * (HANDSHAKE_FAMILY_VERSION = 1) so the default_version member is
 * initialised -- the kernel's dispatcher doesn't gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: handshake has no
 * family-specific fixed header, attributes follow the genlmsghdr
 * directly.
 *
 * Header gating mirrors the dpll / ovpn / nbd families:
 * <linux/handshake.h> is the upstream UAPI header carrying every
 * HANDSHAKE_CMD_* / HANDSHAKE_A_* enum referenced below.  Per-symbol
 * #ifndef shims in include/kernel/handshake.h fill in the ids on
 * build hosts whose installed uapi predates this family.  Build
 * hosts lacking the header entirely silently drop the family from
 * the registry instead of failing the build.
 *
 * arch.h is included unconditionally above the __has_include guard
 * so the translation unit is never empty even on build hosts whose
 * uapi lacks <linux/handshake.h> -- the toolchain emits no
 * compile-unit-empty warning and the registry-side ifdef'd extern
 * stays consistent with the absent strong symbol.
 */

#include "arch.h"

#if __has_include(<linux/handshake.h>)

#include "kernel/handshake.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * handshake exposes three commands: READY (notify-only, kernel
 * rejects on input but the per-cmd lookup still runs -- worthwhile
 * coverage), ACCEPT (handler dequeues a pending request, GENL_ADMIN_
 * PERM), and DONE (handler reports completion, GENL_ADMIN_PERM).
 * The two user-callable cmds run the nla_policy walker before the
 * capability check, so listing every id exercises both per-cmd
 * parsers symmetrically under the unprivileged fuzzer.
 */
static const struct genl_cmd_grammar handshake_cmds[] = {
	{ HANDSHAKE_CMD_READY,	"HANDSHAKE_CMD_READY" },
	{ HANDSHAKE_CMD_ACCEPT,	"HANDSHAKE_CMD_ACCEPT" },
	{ HANDSHAKE_CMD_DONE,	"HANDSHAKE_CMD_DONE" },
};

/*
 * Attribute spec follows the HANDSHAKE_A_ACCEPT_* enum in
 * <linux/handshake.h>.  SOCKFD is a uapi-s32 listener-socket fd that
 * the kernel sets on the reply side and that ACCEPT request messages
 * leave unset; emitting it as a four-byte scalar lets the validator
 * see both sign-extensions and the kernel's bad-fd rejection path.
 * HANDLER_CLASS is a u32 enum (NONE / TLSHD / MAX) the ACCEPT request
 * keys on to pick a queue; emitting random four-byte values exercises
 * the unknown-class rejection branch alongside the in-range values.
 * MESSAGE_TYPE is a u32 enum (UNSPEC / CLIENTHELLO / SERVERHELLO)
 * the kernel emits on the reply.  TIMEOUT is a u32 timeout in
 * milliseconds emitted on the reply.  AUTH_MODE is a u32 enum
 * (UNSPEC / UNAUTH / PSK / X509) the kernel emits on the reply.
 * PEER_IDENTITY is a u32 keyring-key serial (multi-attr) the kernel
 * emits on the reply.  CERTIFICATE is a nested HANDSHAKE_A_X509_*
 * container (multi-attr) -- emitted as an empty NLA_KIND_NESTED
 * entry following the psample-TUNNEL / ovpn-PEER precedent so the
 * kernel's nla_validate accepts it at the outer level without
 * recursing into the per-nest sub-policy.  PEERNAME is a string
 * server-name hint emitted on the reply.  KEYRING is a u32 keyring
 * serial the kernel emits on the reply.
 *
 * Most of these are response-side payloads (the ACCEPT request body
 * only carries HANDLER_CLASS); listing them all here exercises the
 * validator's "ignore on input" branch the same way the fou /
 * psample / ovpn / dpll grammars do.  The HANDSHAKE_A_DONE_* and
 * HANDSHAKE_A_X509_* enums share id 1..N with this namespace and a
 * single flat table cannot disambiguate the overlapping keys -- they
 * are not enumerated here.
 */
static const struct nla_attr_spec handshake_attrs[] = {
	{ HANDSHAKE_A_ACCEPT_SOCKFD,		NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_HANDLER_CLASS,	NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_MESSAGE_TYPE,	NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_TIMEOUT,		NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_AUTH_MODE,		NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_PEER_IDENTITY,	NLA_KIND_U32,    4 },
	{ HANDSHAKE_A_ACCEPT_CERTIFICATE,	NLA_KIND_NESTED, 0 },
	{ HANDSHAKE_A_ACCEPT_PEERNAME,		NLA_KIND_STRING, 64 },
	{ HANDSHAKE_A_ACCEPT_KEYRING,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_handshake = {
	.name = HANDSHAKE_FAMILY_NAME,
	.cmds = handshake_cmds,
	.n_cmds = ARRAY_SIZE(handshake_cmds),
	.attrs = handshake_attrs,
	.n_attrs = ARRAY_SIZE(handshake_attrs),
	.default_version = HANDSHAKE_FAMILY_VERSION,
};

#endif /* __has_include(<linux/handshake.h>) */
