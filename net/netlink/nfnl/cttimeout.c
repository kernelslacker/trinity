/*
 * NETLINK_NETFILTER subsystem grammar: cttimeout
 * (NFNL_SUBSYS_CTNETLINK_TIMEOUT), targeting
 * net/netfilter/nfnetlink_cttimeout.c.  CTA_TIMEOUT_DATA is a bare NLA_NESTED
 * that only NEW and DEFAULT_SET parse, through ctnl_timeout_parse_policy()
 * against the L4 policy that CTA_TIMEOUT_L4PROTO picks.
 */

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * NEW, DEFAULT_SET and DEFAULT_GET look L4PROTO up with nf_ct_l4proto_find()
 * and answer -EOPNOTSUPP unless the tracker it returns has that l4proto.
 * ICMP, TCP and UDP always have a tracker, GRE, ICMPv6 and SCTP when the
 * kernel is built with them, and the generic one answers to 255; any other
 * number lands on the generic tracker and fails that test.
 */
static const unsigned int cttimeout_l4protos[] = {
	IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_GRE, IPPROTO_ICMPV6,
	IPPROTO_SCTP, 255,
};

/*
 * No handler checks L3PROTO.  It is stored as the policy's l3num, which
 * nf_ct_set_timeout() compares with the family of the xt_CT rule or
 * openvswitch flow that names the policy, and NEW with NLM_F_REPLACE with
 * the one it stored, so the numbers worth sending are those families, IPv4
 * and IPv6.  The handlers read it with ntohs(nla_get_be16()), though the
 * policy only types it NLA_U16.
 */
static const unsigned int cttimeout_l3protos[] = { NFPROTO_IPV4, NFPROTO_IPV6 };

/*
 * GET, DELETE and the NLM_F_REPLACE arm of NEW find a timeout by strncmp()ing
 * its name, so a command finds what NEW made only if it carries the same
 * string.  Every name is this one word, which NEW's policy, an NLA_NUL_STRING
 * of up to CTNL_TIMEOUT_NAME_MAX - 1 characters, takes; the draw in eight
 * that is random letters makes another timeout or misses.
 */
static const char cttimeout_word[] = "trinity";

/*
 * DATA is parsed against the policy of the L4 protocol that L4PROTO picks,
 * and each of those is a run of NLA_U32 timeouts numbered from 1: TCP has the
 * most, 11, SCTP 9, UDP and GRE 2, and ICMP, ICMPv6 and the generic tracker
 * 1 (the uapi header still has DCCP's 7, though the kernel no longer has the
 * tracker).  An id past a policy's last is skipped, so one table of 11 serves
 * them all, and no timeout is one that a handler needs.
 */
static const struct nla_attr_spec cttimeout_data_attrs[] = {
	{ CTA_TIMEOUT_TCP_SYN_SENT,   NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_SYN_RECV,   NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_ESTABLISHED, NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_FIN_WAIT,   NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_CLOSE_WAIT, NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_LAST_ACK,   NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_TIME_WAIT,  NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_CLOSE,      NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_SYN_SENT2,  NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_RETRANS,    NLA_KIND_U32, 4 },
	{ CTA_TIMEOUT_TCP_UNACK,      NLA_KIND_U32, 4 },
};

/*
 * All five callbacks carry cttimeout_nla_policy but read different parts of
 * it, so each has a table of its own, which marks .required what the handler
 * answers -EINVAL without.  NEW needs all four of its attributes.  GET needs
 * the name unless it is a dump.  DELETE takes a name, and without one deletes
 * every timeout, so its name is not marked.  DEFAULT_SET needs L4PROTO and
 * DATA and DEFAULT_GET L3PROTO and L4PROTO; neither reads a NAME, because
 * they act on the netns's default timeouts for the protocol, not on a
 * timeout object.
 */
static const struct nla_attr_spec cttimeout_new_attrs[] = {
	{ CTA_TIMEOUT_NAME,   NLA_KIND_STRING_WORD, 0, 0,
	  .word = cttimeout_word, .required = true },
	{ CTA_TIMEOUT_L3PROTO, NLA_KIND_BE16_ONEOF, 0, 0,
	  .oneof = cttimeout_l3protos, .n_oneof = ARRAY_SIZE(cttimeout_l3protos),
	  .required = true },
	{ CTA_TIMEOUT_L4PROTO, NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = cttimeout_l4protos, .n_oneof = ARRAY_SIZE(cttimeout_l4protos),
	  .required = true },
	{ CTA_TIMEOUT_DATA,   NLA_KIND_NESTED, 0, 0,
	  cttimeout_data_attrs, ARRAY_SIZE(cttimeout_data_attrs),
	  .required = true },
};

static const struct nla_attr_spec cttimeout_get_attrs[] = {
	{ CTA_TIMEOUT_NAME,   NLA_KIND_STRING_WORD, 0, 0,
	  .word = cttimeout_word, .required = true },
};

static const struct nla_attr_spec cttimeout_delete_attrs[] = {
	{ CTA_TIMEOUT_NAME,   NLA_KIND_STRING_WORD, 0, 0,
	  .word = cttimeout_word },
};

static const struct nla_attr_spec cttimeout_default_set_attrs[] = {
	{ CTA_TIMEOUT_L4PROTO, NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = cttimeout_l4protos, .n_oneof = ARRAY_SIZE(cttimeout_l4protos),
	  .required = true },
	{ CTA_TIMEOUT_DATA,   NLA_KIND_NESTED, 0, 0,
	  cttimeout_data_attrs, ARRAY_SIZE(cttimeout_data_attrs),
	  .required = true },
};

static const struct nla_attr_spec cttimeout_default_get_attrs[] = {
	{ CTA_TIMEOUT_L3PROTO, NLA_KIND_BE16_ONEOF, 0, 0,
	  .oneof = cttimeout_l3protos, .n_oneof = ARRAY_SIZE(cttimeout_l3protos),
	  .required = true },
	{ CTA_TIMEOUT_L4PROTO, NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = cttimeout_l4protos, .n_oneof = ARRAY_SIZE(cttimeout_l4protos),
	  .required = true },
};

static const struct nfnl_cmd_grammar cttimeout_cmds[] = {
	{ IPCTNL_MSG_TIMEOUT_NEW,         "IPCTNL_MSG_TIMEOUT_NEW", false,
	  cttimeout_new_attrs, ARRAY_SIZE(cttimeout_new_attrs) },
	{ IPCTNL_MSG_TIMEOUT_GET,         "IPCTNL_MSG_TIMEOUT_GET", false,
	  cttimeout_get_attrs, ARRAY_SIZE(cttimeout_get_attrs) },
	{ IPCTNL_MSG_TIMEOUT_DELETE,      "IPCTNL_MSG_TIMEOUT_DELETE", false,
	  cttimeout_delete_attrs, ARRAY_SIZE(cttimeout_delete_attrs) },
	{ IPCTNL_MSG_TIMEOUT_DEFAULT_SET, "IPCTNL_MSG_TIMEOUT_DEFAULT_SET", false,
	  cttimeout_default_set_attrs, ARRAY_SIZE(cttimeout_default_set_attrs) },
	{ IPCTNL_MSG_TIMEOUT_DEFAULT_GET, "IPCTNL_MSG_TIMEOUT_DEFAULT_GET", false,
	  cttimeout_default_get_attrs, ARRAY_SIZE(cttimeout_default_get_attrs) },
};

struct nfnl_subsys_grammar sub_cttimeout = {
	.name = "cttimeout",
	.subsys_id = NFNL_SUBSYS_CTNETLINK_TIMEOUT,
	.cmds = cttimeout_cmds,
	.n_cmds = ARRAY_SIZE(cttimeout_cmds),
};
