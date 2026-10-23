/*
 * Genetlink family grammar: NetLabel, four families (NLBL_MGMT,
 * NLBL_CIPSOv4, NLBL_UNLBL, NLBL_CALIPSO), targeting net/netlabel/.  Each
 * carries its own flat nla_attr_spec table of the NLBL_*_A_* ids that its
 * commands' policies use.
 */

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * NetLabel ships no uapi header: its ids live in kernel-internal headers,
 * so include/kernel/netlabel.h is their only definition and the families
 * need no __has_include() guard.  The family-name strings must match
 * include/net/netlabel.h byte for byte, since the controller dump is
 * compared with strcmp(): "NLBL_CIPSOv4" has a lowercase v and the
 * unlabeled family is "NLBL_UNLBL".
 */
#include "kernel/netlabel.h"

/* ---- NLBL_MGMT ---- */

static const struct genl_cmd_grammar nlbl_mgmt_cmds[] = {
	{ NLBL_MGMT_C_ADD,		"NLBL_MGMT_C_ADD" },
	{ NLBL_MGMT_C_REMOVE,		"NLBL_MGMT_C_REMOVE" },
	{ NLBL_MGMT_C_LISTALL,		"NLBL_MGMT_C_LISTALL" },
	{ NLBL_MGMT_C_ADDDEF,		"NLBL_MGMT_C_ADDDEF" },
	{ NLBL_MGMT_C_REMOVEDEF,	"NLBL_MGMT_C_REMOVEDEF" },
	{ NLBL_MGMT_C_LISTDEF,		"NLBL_MGMT_C_LISTDEF" },
	{ NLBL_MGMT_C_PROTOCOLS,	"NLBL_MGMT_C_PROTOCOLS" },
	{ NLBL_MGMT_C_VERSION,		"NLBL_MGMT_C_VERSION" },
};

/*
 * Mgmt policy lives in net/netlabel/netlabel_mgmt.c::netlbl_mgmt_genl_policy.
 * DOMAIN is a NUL-terminated LSM domain string (e.g. an SELinux type
 * name); 64 bytes is generous for the typical SELinux/SMACK shape.
 * PROTOCOL / VERSION / CV4DOI / CLPDOI are u32 selectors.  IPV4ADDR /
 * IPV4MASK are 4-byte struct in_addr; IPV6ADDR / IPV6MASK are 16-byte
 * struct in6_addr.  ADDRSELECTOR opens an inner nest holding one
 * address + mask + protocol triple; SELECTORLIST is an outer nest of
 * ADDRSELECTOR entries.  FAMILY is u16 (AF_INET / AF_INET6).
 */
static const struct nla_attr_spec nlbl_mgmt_attrs[] = {
	{ NLBL_MGMT_A_DOMAIN,		NLA_KIND_STRING, 64 },
	{ NLBL_MGMT_A_PROTOCOL,		NLA_KIND_U32,    4 },
	{ NLBL_MGMT_A_VERSION,		NLA_KIND_U32,    4 },
	{ NLBL_MGMT_A_CV4DOI,		NLA_KIND_U32,    4 },
	{ NLBL_MGMT_A_IPV6ADDR,		NLA_KIND_BINARY, 16 },
	{ NLBL_MGMT_A_IPV6MASK,		NLA_KIND_BINARY, 16 },
	{ NLBL_MGMT_A_IPV4ADDR,		NLA_KIND_BINARY, 4 },
	{ NLBL_MGMT_A_IPV4MASK,		NLA_KIND_BINARY, 4 },
	{ NLBL_MGMT_A_ADDRSELECTOR,	NLA_KIND_NESTED, 0 },
	{ NLBL_MGMT_A_SELECTORLIST,	NLA_KIND_NESTED, 0 },
	{ NLBL_MGMT_A_FAMILY,		NLA_KIND_U16,    2 },
	{ NLBL_MGMT_A_CLPDOI,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_nlbl_mgmt = {
	.name = NLBL_MGMT_GENL_NAME,
	.cmds = nlbl_mgmt_cmds,
	.n_cmds = ARRAY_SIZE(nlbl_mgmt_cmds),
	.attrs = nlbl_mgmt_attrs,
	.n_attrs = ARRAY_SIZE(nlbl_mgmt_attrs),
	.default_version = NETLBL_PROTO_VERSION,
};

/* ---- NLBL_CIPSOv4 ---- */

static const struct genl_cmd_grammar nlbl_cipsov4_cmds[] = {
	{ NLBL_CIPSOV4_C_ADD,		"NLBL_CIPSOV4_C_ADD" },
	{ NLBL_CIPSOV4_C_REMOVE,	"NLBL_CIPSOV4_C_REMOVE" },
	{ NLBL_CIPSOV4_C_LIST,		"NLBL_CIPSOV4_C_LIST" },
	{ NLBL_CIPSOV4_C_LISTALL,	"NLBL_CIPSOV4_C_LISTALL" },
};

/*
 * CIPSOv4 policy lives in net/netlabel/netlabel_cipso_v4.c::netlbl_cipsov4_genl_policy.
 * DOI is the u32 Domain Of Interpretation selector.  MTYPE picks the
 * mapping table type (CIPSO_V4_MAP_TRANS / _PASS / _LOCAL).  TAG is a
 * u8 CIPSO tag id meant to live inside a TAGLST nest.  The MLS
 * mapping is the densest sub-grammar in the family: TAGLST holds a
 * list of TAG u8s; MLSLVLLST holds a list of MLSLVL nests, each
 * carrying a (MLSLVLLOC, MLSLVLREM) u32 pair; MLSCATLST holds a list
 * of MLSCAT nests, each carrying a (MLSCATLOC, MLSCATREM) u32 pair.
 * All five nests are bare NLA_NESTED in netlbl_cipsov4_genl_policy; the
 * ADD handlers re-apply that same policy to each nest with
 * nla_validate_nested_deprecated(), so the inner and outer ids form one
 * NLBL_CIPSOV4_A_* namespace and do not overlap.
 */
static const struct nla_attr_spec nlbl_cipsov4_attrs[] = {
	{ NLBL_CIPSOV4_A_DOI,		NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_MTYPE,		NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_TAG,		NLA_KIND_U8,     1 },
	{ NLBL_CIPSOV4_A_TAGLST,	NLA_KIND_NESTED, 0 },
	{ NLBL_CIPSOV4_A_MLSLVLLOC,	NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_MLSLVLREM,	NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_MLSLVL,	NLA_KIND_NESTED, 0 },
	{ NLBL_CIPSOV4_A_MLSLVLLST,	NLA_KIND_NESTED, 0 },
	{ NLBL_CIPSOV4_A_MLSCATLOC,	NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_MLSCATREM,	NLA_KIND_U32,    4 },
	{ NLBL_CIPSOV4_A_MLSCAT,	NLA_KIND_NESTED, 0 },
	{ NLBL_CIPSOV4_A_MLSCATLST,	NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_nlbl_cipsov4 = {
	.name = NLBL_CIPSOV4_GENL_NAME,
	.cmds = nlbl_cipsov4_cmds,
	.n_cmds = ARRAY_SIZE(nlbl_cipsov4_cmds),
	.attrs = nlbl_cipsov4_attrs,
	.n_attrs = ARRAY_SIZE(nlbl_cipsov4_attrs),
	.default_version = NETLBL_PROTO_VERSION,
};

/* ---- NLBL_UNLBL ---- */

static const struct genl_cmd_grammar nlbl_unlabel_cmds[] = {
	{ NLBL_UNLABEL_C_ACCEPT,	"NLBL_UNLABEL_C_ACCEPT" },
	{ NLBL_UNLABEL_C_LIST,		"NLBL_UNLABEL_C_LIST" },
	{ NLBL_UNLABEL_C_STATICADD,	"NLBL_UNLABEL_C_STATICADD" },
	{ NLBL_UNLABEL_C_STATICREMOVE,	"NLBL_UNLABEL_C_STATICREMOVE" },
	{ NLBL_UNLABEL_C_STATICLIST,	"NLBL_UNLABEL_C_STATICLIST" },
	{ NLBL_UNLABEL_C_STATICADDDEF,	"NLBL_UNLABEL_C_STATICADDDEF" },
	{ NLBL_UNLABEL_C_STATICREMOVEDEF, "NLBL_UNLABEL_C_STATICREMOVEDEF" },
	{ NLBL_UNLABEL_C_STATICLISTDEF,	"NLBL_UNLABEL_C_STATICLISTDEF" },
};

/*
 * Unlabeled policy lives in net/netlabel/netlabel_unlabeled.c::netlbl_unlabel_genl_policy.
 * ACPTFLG is a u8 boolean toggle.  IPV4ADDR/MASK are 4-byte struct
 * in_addr; IPV6ADDR/MASK are 16-byte struct in6_addr.  IFACE is a
 * NUL-terminated network interface name (IFNAMSIZ - 1 = 15).  SECCTX
 * is a binary LSM security-context blob — typical SELinux contexts
 * fit comfortably in 64 bytes ("system_u:object_r:foo_t:s0:c0.c1023"
 * is ~36).
 */
static const struct nla_attr_spec nlbl_unlabel_attrs[] = {
	{ NLBL_UNLABEL_A_ACPTFLG,	NLA_KIND_U8,     1 },
	{ NLBL_UNLABEL_A_IPV6ADDR,	NLA_KIND_BINARY, 16 },
	{ NLBL_UNLABEL_A_IPV6MASK,	NLA_KIND_BINARY, 16 },
	{ NLBL_UNLABEL_A_IPV4ADDR,	NLA_KIND_BINARY, 4 },
	{ NLBL_UNLABEL_A_IPV4MASK,	NLA_KIND_BINARY, 4 },
	{ NLBL_UNLABEL_A_IFACE,		NLA_KIND_STRING, 15 },
	{ NLBL_UNLABEL_A_SECCTX,	NLA_KIND_BINARY, 64 },
};

struct genl_family_grammar fam_nlbl_unlabel = {
	.name = NLBL_UNLABEL_GENL_NAME,
	.cmds = nlbl_unlabel_cmds,
	.n_cmds = ARRAY_SIZE(nlbl_unlabel_cmds),
	.attrs = nlbl_unlabel_attrs,
	.n_attrs = ARRAY_SIZE(nlbl_unlabel_attrs),
	.default_version = NETLBL_PROTO_VERSION,
};

/* ---- NLBL_CALIPSO ---- */

static const struct genl_cmd_grammar nlbl_calipso_cmds[] = {
	{ NLBL_CALIPSO_C_ADD,		"NLBL_CALIPSO_C_ADD" },
	{ NLBL_CALIPSO_C_REMOVE,	"NLBL_CALIPSO_C_REMOVE" },
	{ NLBL_CALIPSO_C_LIST,		"NLBL_CALIPSO_C_LIST" },
	{ NLBL_CALIPSO_C_LISTALL,	"NLBL_CALIPSO_C_LISTALL" },
};

/*
 * CALIPSO policy lives in net/netlabel/netlabel_calipso.c::calipso_genl_policy.
 * Just two attrs: DOI is the u32 Domain Of Interpretation selector,
 * MTYPE picks the mapping table type (CALIPSO_MAP_PASS is the only
 * upstream-implemented variant; the parser still walks both).
 */
static const struct nla_attr_spec nlbl_calipso_attrs[] = {
	{ NLBL_CALIPSO_A_DOI,		NLA_KIND_U32,    4 },
	{ NLBL_CALIPSO_A_MTYPE,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_nlbl_calipso = {
	.name = NLBL_CALIPSO_GENL_NAME,
	.cmds = nlbl_calipso_cmds,
	.n_cmds = ARRAY_SIZE(nlbl_calipso_cmds),
	.attrs = nlbl_calipso_attrs,
	.n_attrs = ARRAY_SIZE(nlbl_calipso_attrs),
	.default_version = NETLBL_PROTO_VERSION,
};
