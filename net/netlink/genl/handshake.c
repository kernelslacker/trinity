/*
 * Genetlink family grammar: handshake (kernel TLS handshake upcalls),
 * targeting the policies and handlers in net/handshake/.  Only the
 * HANDSHAKE_A_ACCEPT_* attribute namespace is listed; the reasons for
 * that and for the permission split sit at the two tables below.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/handshake.h>)

#include "kernel/handshake.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * READY is a kernel-to-user notification with no doit or dumpit, so the
 * demuxer answers -EOPNOTSUPP; it stays so that rejection is exercised.
 * ACCEPT and DONE are GENL_ADMIN_PERM, which the genl core checks before
 * the nla_policy walker runs, so a child that passes that check reaches
 * both parsers.
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
 * container (multi-attr) the kernel emits on the reply; the ACCEPT
 * request policy ends at HANDLER_CLASS, so it has no sub-policy on
 * input.  PEERNAME is a string server-name hint emitted on the reply.
 * KEYRING is a u32 keyring serial the kernel emits on the reply.
 *
 * Most of these are response-side payloads (the ACCEPT request body
 * only carries HANDLER_CLASS); listing them all here exercises the
 * validator's "ignore on input" branch the same way the fou /
 * psample / ovpn / dpll grammars do.  The HANDSHAKE_A_DONE_* and
 * HANDSHAKE_A_X509_* enums share id 1..N with this namespace and a
 * single flat table cannot disambiguate the overlapping keys, so only
 * ACCEPT_* -- the largest namespace, and the one a handler meets at
 * request arrival -- is listed.  DONE's own attributes are not modelled
 * until the grammar carries per-command attribute namespaces.
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
