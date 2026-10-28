/*
 * NETLINK_NETFILTER subsystem grammar: cthelper (NFNL_SUBSYS_CTHELPER),
 * targeting net/netfilter/nfnetlink_cthelper.c.  NFCTH_TUPLE and NFCTH_POLICY
 * are untyped in nfnl_cthelper_policy and parsed by the handlers (POLICY is
 * a two-level nest), each of which first demands capable(CAP_NET_ADMIN) in
 * the initial user namespace.
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cthelper.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * NEW, GET and DEL find a helper by strncmp()ing its name and comparing its
 * tuple, so a command finds what NEW made only if it carries the same name
 * and tuple.  Every name is this one word, short of the 15 characters the
 * policy's NLA_NUL_STRING takes (NF_CT_HELPER_NAME_LEN lives in a
 * kernel-internal header), and the tuple keeps to IPv4 and IPv6, which
 * NLA_POLICY_MAX(NLA_BE16, NFPROTO_IPV6) takes, and TCP and UDP, the
 * transports a userspace helper serves, though any L4 number makes one.
 * An expectation policy's name is the word too: updating a helper answers
 * -EBUSY to a policy whose names are not the ones it has.
 */
static const char cthelper_word[] = "trinity";
static const unsigned int cthelper_l3protos[] = { NFPROTO_IPV4, NFPROTO_IPV6 };
static const unsigned int cthelper_l4protos[] = { IPPROTO_TCP, IPPROTO_UDP };

/* Creating and updating a helper act on these two and pass over any other
 * status. */
static const unsigned int cthelper_statuses[] = {
	NFCT_HELPER_STATUS_DISABLED, NFCT_HELPER_STATUS_ENABLED,
};

/*
 * The kernel's NF_CT_MAX_EXPECT_CLASSES and NF_CT_EXPECT_MAX_CNT, and the 32
 * bytes of nf_conn_help's data, also kernel-internal: the bounds of SET_NUM,
 * which nfnl_cthelper_parse_expect_policy() refuses at 0, of EXPECT_MAX,
 * where 0 is the default of 255, and of PRIV_DATA_LEN.
 */
#define CTHELPER_CLASSES_MAX	4
#define CTHELPER_EXPECT_MAX	255
#define CTHELPER_DATA_LEN_MAX	32

static const struct nla_attr_spec cthelper_tuple_attrs[] = {
	{ NFCTH_TUPLE_L3PROTONUM, NLA_KIND_BE16_ONEOF, 0, 0,
	  .oneof = cthelper_l3protos, .n_oneof = ARRAY_SIZE(cthelper_l3protos),
	  .required = true },
	{ NFCTH_TUPLE_L4PROTONUM, NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = cthelper_l4protos, .n_oneof = ARRAY_SIZE(cthelper_l4protos),
	  .required = true },
};

static const struct nla_attr_spec cthelper_expect_attrs[] = {
	{ NFCTH_POLICY_NAME,           NLA_KIND_STRING_WORD, 0, 0,
	  .word = cthelper_word, .required = true },
	{ NFCTH_POLICY_EXPECT_MAX,     NLA_KIND_BE32_RANGE, CTHELPER_EXPECT_MAX,
	  0, .required = true },
	{ NFCTH_POLICY_EXPECT_TIMEOUT, NLA_KIND_U32, 4, .required = true },
};

/*
 * SET_NUM counts the SETs the policy must hold, which a mark cannot tie to
 * the count, so all four are marked: the handlers pass over a SET past it.
 */
#define CTHELPER_EXPECT_SET(type) \
	{ type, NLA_KIND_NESTED, 0, 0, cthelper_expect_attrs, \
	  ARRAY_SIZE(cthelper_expect_attrs), .required = true }

static const struct nla_attr_spec cthelper_policy_attrs[] = {
	{ NFCTH_POLICY_SET_NUM, NLA_KIND_BE32_RANGE, CTHELPER_CLASSES_MAX, 1,
	  .required = true },
	CTHELPER_EXPECT_SET(NFCTH_POLICY_SET1),
	CTHELPER_EXPECT_SET(NFCTH_POLICY_SET2),
	CTHELPER_EXPECT_SET(NFCTH_POLICY_SET3),
	CTHELPER_EXPECT_SET(NFCTH_POLICY_SET4),
};

/*
 * NEW answers -EINVAL without the name or the tuple, and
 * nfnl_cthelper_create() without the policy or PRIV_DATA_LEN; updating a
 * helper that has the name and tuple already takes both as optional, and
 * answers -EBUSY to either unless it matches what the helper has.  GET and
 * DEL read the name and the tuple and need neither: without them GET answers
 * the first helper, a dump reads nothing, and DEL deletes every helper.
 */
static const struct nla_attr_spec cthelper_new_attrs[] = {
	{ NFCTH_NAME,          NLA_KIND_STRING_WORD, 0, 0,
	  .word = cthelper_word, .required = true },
	{ NFCTH_TUPLE,         NLA_KIND_NESTED, 0, 0,
	  cthelper_tuple_attrs, ARRAY_SIZE(cthelper_tuple_attrs),
	  .required = true },
	{ NFCTH_QUEUE_NUM,     NLA_KIND_U32,    4 },
	{ NFCTH_POLICY,        NLA_KIND_NESTED, 0, 0,
	  cthelper_policy_attrs, ARRAY_SIZE(cthelper_policy_attrs),
	  .required = true },
	{ NFCTH_PRIV_DATA_LEN, NLA_KIND_BE32_RANGE, CTHELPER_DATA_LEN_MAX, 0,
	  .required = true },
	{ NFCTH_STATUS,        NLA_KIND_BE32_ONEOF, 0, 0,
	  .oneof = cthelper_statuses, .n_oneof = ARRAY_SIZE(cthelper_statuses) },
};

static const struct nla_attr_spec cthelper_find_attrs[] = {
	{ NFCTH_NAME,          NLA_KIND_STRING_WORD, 0, 0,
	  .word = cthelper_word },
	{ NFCTH_TUPLE,         NLA_KIND_NESTED, 0, 0,
	  cthelper_tuple_attrs, ARRAY_SIZE(cthelper_tuple_attrs) },
};

static const struct nfnl_cmd_grammar cthelper_cmds[] = {
	{ NFNL_MSG_CTHELPER_NEW, "NFNL_MSG_CTHELPER_NEW", false,
	  cthelper_new_attrs, ARRAY_SIZE(cthelper_new_attrs) },
	{ NFNL_MSG_CTHELPER_GET, "NFNL_MSG_CTHELPER_GET", false,
	  cthelper_find_attrs, ARRAY_SIZE(cthelper_find_attrs) },
	{ NFNL_MSG_CTHELPER_DEL, "NFNL_MSG_CTHELPER_DEL", false,
	  cthelper_find_attrs, ARRAY_SIZE(cthelper_find_attrs) },
};

struct nfnl_subsys_grammar sub_cthelper = {
	.name = "cthelper",
	.subsys_id = NFNL_SUBSYS_CTHELPER,
	.cmds = cthelper_cmds,
	.n_cmds = ARRAY_SIZE(cthelper_cmds),
};
