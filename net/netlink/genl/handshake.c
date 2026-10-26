/*
 * Genetlink family grammar: handshake (kernel TLS handshake upcalls),
 * targeting the policies and handlers in net/handshake/.  ACCEPT and DONE
 * have a policy each, and so a table each; the tables say what they take.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/handshake.h>)

#include "kernel/handshake.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Both ops validate strictly, so an id their policy has no slot for costs
 * an -EINVAL.  ACCEPT's policy has one slot, id 2 HANDLER_CLASS (a u32 of
 * at most 1); the other HANDSHAKE_A_ACCEPT_* ids are what its reply
 * carries.  DONE's has ids 1 to 3: STATUS (a u32 of at most MAX_ERRNO),
 * SOCKFD and REMOTE_AUTH (s32).
 */
static const struct nla_attr_spec handshake_accept_attrs[] = {
	{ HANDSHAKE_A_ACCEPT_HANDLER_CLASS,	NLA_KIND_U32, 4 },
};

static const struct nla_attr_spec handshake_done_attrs[] = {
	{ HANDSHAKE_A_DONE_STATUS,		NLA_KIND_U32, 4 },
	{ HANDSHAKE_A_DONE_SOCKFD,		NLA_KIND_U32, 4 },
	{ HANDSHAKE_A_DONE_REMOTE_AUTH,		NLA_KIND_U32, 4 },
};

/*
 * READY is a kernel-to-user notification with no doit or dumpit, so the
 * demuxer answers -EOPNOTSUPP; it stays so that rejection is exercised.
 * ACCEPT and DONE are GENL_ADMIN_PERM, which the genl core checks before
 * the nla_policy walker runs, so a child that passes that check reaches
 * both parsers.
 */
static const struct genl_cmd_grammar handshake_cmds[] = {
	{ HANDSHAKE_CMD_READY,	"HANDSHAKE_CMD_READY", genl_no_attrs },
	{ HANDSHAKE_CMD_ACCEPT,	"HANDSHAKE_CMD_ACCEPT",
	  handshake_accept_attrs, ARRAY_SIZE(handshake_accept_attrs) },
	{ HANDSHAKE_CMD_DONE,	"HANDSHAKE_CMD_DONE",
	  handshake_done_attrs, ARRAY_SIZE(handshake_done_attrs) },
};

struct genl_family_grammar fam_handshake = {
	.name = HANDSHAKE_FAMILY_NAME,
	.cmds = handshake_cmds,
	.n_cmds = ARRAY_SIZE(handshake_cmds),
	.default_version = HANDSHAKE_FAMILY_VERSION,
};

#endif /* __has_include(<linux/handshake.h>) */
