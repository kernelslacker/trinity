/*
 * NETLINK_NETFILTER subsystem grammar: ulog (NFNL_SUBSYS_ULOG).
 *
 * nfnetlink_log is the userspace control plane for the iptables/nft
 * NFLOG target -- userspace daemons (ulogd) bind a log group, configure
 * copy mode + flags + buffering, and then read packets out via the
 * NFULNL_MSG_PACKET notification path.  Lives in
 * net/netfilter/nfnetlink_log.c, gated by CONFIG_NETFILTER_NETLINK_LOG.
 * Registered with nfnetlink_subsystem_register() under subsys_id
 * NFNL_SUBSYS_ULOG (4), so messages route through the standard
 * nfnetlink dispatcher.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted the
 * ULOG subsys byte (already biased into nfnl_subsys[]) paired with a
 * random cmd + empty/garbage payload, so the per-cmd validate gate
 * inside nfnetlink_log.c short-circuited at cmd-validate or
 * nla_parse before reaching nfulnl_recv_config().
 *
 * Command set: focus on NFULNL_MSG_CONFIG -- the control-plane verb
 * that carries the rich attribute set.  NFULNL_MSG_PACKET is the
 * kernel->user notification path and not user-callable, so emitting
 * it would just bounce at the dispatcher.
 *
 * Attribute set: the six attributes nfula_cfg_policy[] accepts --
 *   NFULA_CFG_CMD: struct nfulnl_msg_config_cmd (binary, fixed size,
 *     1 byte packed).  The dispatcher branches on .command
 *     (NONE/BIND/UNBIND/PF_BIND/PF_UNBIND) so a length-matching blob
 *     lets every command sub-arm run.
 *   NFULA_CFG_MODE: struct nfulnl_msg_config_mode (binary, fixed,
 *     __attribute__((packed)) -- 6 bytes).  Carries copy_mode + range.
 *   NFULA_CFG_NLBUFSIZ / NFULA_CFG_TIMEOUT / NFULA_CFG_QTHRESH: __u32 each.
 *   NFULA_CFG_FLAGS: __u16.
 * BINARY_FIXED2 pins both ends of the size sweep so every emission
 * passes nla_validate's NLA_UNSPEC .len check and reaches the handler;
 * the bytes themselves stay random so .command, .copy_mode, flag bits
 * and group ids fuzz freely.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar ulog_cmds[] = {
	{ NFULNL_MSG_CONFIG, "NFULNL_MSG_CONFIG" },
};

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
