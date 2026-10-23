/*
 * Genetlink family grammar: SEG6 (IPv6 Segment Routing), targeting
 * net/ipv6/seg6.c.  All four ops are GENL_ADMIN_PERM.  One flat
 * SEG6_ATTR_* namespace; HMACINFO is a policy entry only.
 */

#if __has_include(<linux/seg6_genl.h>)

#include "kernel/seg6_genl.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar seg6_cmds[] = {
	{ SEG6_CMD_SETHMAC,	"SEG6_CMD_SETHMAC" },
	{ SEG6_CMD_DUMPHMAC,	"SEG6_CMD_DUMPHMAC" },
	{ SEG6_CMD_SET_TUNSRC,	"SEG6_CMD_SET_TUNSRC" },
	{ SEG6_CMD_GET_TUNSRC,	"SEG6_CMD_GET_TUNSRC" },
};

/*
 * Attribute spec follows the SEG6_ATTR_* enum in <linux/seg6_genl.h>.
 * DST is a 16-byte IPv6 destination address (the kernel's seg6_genl_
 * policy caps the binary payload at sizeof(struct in6_addr)); SET_TUNSRC
 * keys on it via nla_get_in6_addr() to atomically swap the per-net
 * tun_src.  DSTLEN is a 4-byte prefix-length scalar (the kernel's
 * policy declares it NLA_S32 but the wire size matches NLA_KIND_U32,
 * and the validator's signedness check is byte-pattern only).
 * HMACKEYID is a u32 secret-table key (a zero key is rejected by
 * SETHMAC); SECRETLEN / ALGID are u8 selectors carrying the
 * 1..SEG6_HMAC_SECRET_LEN-byte secret length and the SEG6_HMAC_ALGO_*
 * algorithm id (1=SHA1, 2=SHA256).  SECRET is the variable-length
 * binary payload bounded above at SEG6_HMAC_SECRET_LEN (64) so a
 * single greedy blob can't eat the whole netlink buffer; setting
 * SECRETLEN==0 drops the SECRET requirement and triggers the delete
 * path through seg6_hmac_info_del().  HMACINFO is a bare NLA_NESTED in
 * seg6_genl_policy that the kernel neither parses nor emits: SETHMAC and
 * the DUMPHMAC replies carry the HMAC fields as flat top-level attrs.
 */
static const struct nla_attr_spec seg6_attrs[] = {
	{ SEG6_ATTR_DST,		NLA_KIND_BINARY, 16 },
	{ SEG6_ATTR_DSTLEN,		NLA_KIND_U32,    4 },
	{ SEG6_ATTR_HMACKEYID,		NLA_KIND_U32,    4 },
	{ SEG6_ATTR_SECRET,		NLA_KIND_BINARY, 64 },
	{ SEG6_ATTR_SECRETLEN,		NLA_KIND_U8,     1 },
	{ SEG6_ATTR_ALGID,		NLA_KIND_U8,     1 },
	{ SEG6_ATTR_HMACINFO,		NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_seg6 = {
	.name = "SEG6",
	.cmds = seg6_cmds,
	.n_cmds = ARRAY_SIZE(seg6_cmds),
	.attrs = seg6_attrs,
	.n_attrs = ARRAY_SIZE(seg6_attrs),
};

#endif /* __has_include(<linux/seg6_genl.h>) */
