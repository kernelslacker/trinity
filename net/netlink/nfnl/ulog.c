/*
 * NETLINK_NETFILTER subsystem grammar: ulog (NFNL_SUBSYS_ULOG), targeting
 * nfulnl_recv_config() in net/netfilter/nfnetlink_log.c.  Only
 * NFULNL_MSG_CONFIG is listed (PACKET is kernel-to-user; its callback is
 * nfulnl_recv_unsupp()); the command byte of NFULA_CFG_CMD picks BIND,
 * UNBIND or the PF_BIND / PF_UNBIND logger registration.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar ulog_cmds[] = {
	{ NFULNL_MSG_CONFIG, "NFULNL_MSG_CONFIG" },
};

/*
 * CMD and MODE are NLA_UNSPEC with a minimum .len in nfula_cfg_policy;
 * BINARY_FIXED2 at exactly the struct size always clears it, and the random
 * bytes still fuzz .command and .copy_mode.
 */
static const struct nla_attr_spec ulog_attrs[] = {
	{ NFULA_CFG_CMD, NLA_KIND_BINARY_FIXED2,
	  sizeof(struct nfulnl_msg_config_cmd),
	  sizeof(struct nfulnl_msg_config_cmd) },
	{ NFULA_CFG_MODE, NLA_KIND_BINARY_FIXED2,
	  sizeof(struct nfulnl_msg_config_mode),
	  sizeof(struct nfulnl_msg_config_mode) },
	{ NFULA_CFG_NLBUFSIZ, NLA_KIND_U32, 0, 0 },
	{ NFULA_CFG_TIMEOUT,  NLA_KIND_U32, 0, 0 },
	{ NFULA_CFG_QTHRESH,  NLA_KIND_U32, 0, 0 },
	{ NFULA_CFG_FLAGS,    NLA_KIND_U16, 0, 0 },
};

struct nfnl_subsys_grammar sub_ulog = {
	.name = "ulog",
	.subsys_id = NFNL_SUBSYS_ULOG,
	.cmds = ulog_cmds,
	.n_cmds = ARRAY_SIZE(ulog_cmds),
	.attrs = ulog_attrs,
	.n_attrs = ARRAY_SIZE(ulog_attrs),
};
