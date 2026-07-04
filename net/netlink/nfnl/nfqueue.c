/*
 * NETLINK_NETFILTER subsystem grammar: nfqueue (NFNL_SUBSYS_QUEUE).
 *
 * nfnetlink_queue is the userspace control plane for the iptables/nft
 * NFQUEUE target -- userspace daemons (nfq, nfqnl_test, suricata-nfq)
 * bind a queue number, configure copy mode + flags, and then read
 * packets out / write verdicts back.  Lives in
 * net/netfilter/nfnetlink_queue.c, gated by CONFIG_NETFILTER_NETLINK_QUEUE.
 * Registered with nfnetlink_subsystem_register() under subsys_id
 * NFNL_SUBSYS_QUEUE (3), so messages route through the standard
 * nfnetlink dispatcher.
 *
 * Without this grammar, Trinity's nfnetlink generator emitted the
 * QUEUE subsys byte (already biased into nfnl_subsys[]) paired with a
 * random cmd + empty/garbage payload, so the per-cmd validate gate
 * inside nfnetlink_queue.c short-circuited at cmd-validate or
 * nla_parse before reaching nfqnl_recv_config() / verdict_recv().
 *
 * Command set: focus on NFQNL_MSG_CONFIG -- the control-plane verb
 * that carries the rich attribute set.  NFQNL_MSG_VERDICT and
 * NFQNL_MSG_VERDICT_BATCH need a queue that's already been bound and
 * a matching packet id (NFQA_PACKET_HDR.packet_id from a prior
 * NFQNL_MSG_PACKET delivery); pointing the fuzzer at them from cold
 * just bounces at the nfqa_verdict_policy length gate.  NFQNL_MSG_PACKET
 * is kernel->user and not user-callable.
 *
 * Attribute set: the five attributes nfqa_cfg_policy[] accepts --
 *   NFQA_CFG_CMD: struct nfqnl_msg_config_cmd (binary, fixed size).
 *     The dispatcher branches on .command (BIND/UNBIND/PF_BIND/PF_UNBIND)
 *     so a length-matching blob lets every command sub-arm run.
 *   NFQA_CFG_PARAMS: struct nfqnl_msg_config_params (binary, fixed,
 *     __attribute__((packed)) -- 5 bytes).  Carries copy_mode + range.
 *   NFQA_CFG_QUEUE_MAXLEN / NFQA_CFG_FLAGS / NFQA_CFG_MASK: __be32 each.
 * BINARY_FIXED2 pins both ends of the size sweep so every emission
 * passes nla_validate's NLA_UNSPEC .len check and reaches the handler;
 * the bytes themselves stay random so .command, .copy_mode, flag bits
 * and queue ids fuzz freely.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

static const struct nfnl_cmd_grammar nfqueue_cmds[] = {
	{ NFQNL_MSG_CONFIG, "NFQNL_MSG_CONFIG" },
};

static const struct nla_attr_spec nfqueue_attrs[] = {
	{ NFQA_CFG_CMD, NLA_KIND_BINARY_FIXED2,
	  sizeof(struct nfqnl_msg_config_cmd),
	  sizeof(struct nfqnl_msg_config_cmd) },
	{ NFQA_CFG_PARAMS, NLA_KIND_BINARY_FIXED2,
	  sizeof(struct nfqnl_msg_config_params),
	  sizeof(struct nfqnl_msg_config_params) },
	{ NFQA_CFG_QUEUE_MAXLEN, NLA_KIND_U32, 0, 0 },
	{ NFQA_CFG_FLAGS,        NLA_KIND_U32, 0, 0 },
	{ NFQA_CFG_MASK,         NLA_KIND_U32, 0, 0 },
};

struct nfnl_subsys_grammar sub_nfqueue = {
	.name = "nfqueue",
	.subsys_id = NFNL_SUBSYS_QUEUE,
	.cmds = nfqueue_cmds,
	.n_cmds = ARRAY_SIZE(nfqueue_cmds),
	.attrs = nfqueue_attrs,
	.n_attrs = ARRAY_SIZE(nfqueue_attrs),
};
