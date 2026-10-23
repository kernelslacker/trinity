/*
 * NETLINK_NETFILTER subsystem grammar: nfqueue (NFNL_SUBSYS_QUEUE), targeting
 * nfqnl_recv_config() in net/netfilter/nfnetlink_queue.c.  The command byte
 * of NFQA_CFG_CMD picks BIND or UNBIND (PF_BIND and PF_UNBIND are obsolete
 * no-ops); other attributes apply only to a queue this socket has bound.
 */

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include "netlink-attrs.h"
#include "netlink-nfnl-subsystems.h"
#include "utils.h"

/*
 * Not listed: VERDICT and VERDICT_BATCH, which answer -ENODEV until this
 * socket has bound a queue and -ENOENT without a queued packet id (only a
 * kernel NFQNL_MSG_PACKET delivers one), and PACKET, which is kernel-to-user
 * (nfqnl_recv_unsupp()).
 */
static const struct nfnl_cmd_grammar nfqueue_cmds[] = {
	{ NFQNL_MSG_CONFIG, "NFQNL_MSG_CONFIG" },
};

/*
 * CMD and PARAMS are NLA_UNSPEC with a minimum .len in nfqa_cfg_policy;
 * BINARY_FIXED2 at exactly the struct size always clears it, and the random
 * bytes still fuzz .command and .copy_mode.
 */
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
