/*
 * NETLINK_RDMA requests to the RDMA device interface, nldev
 * (drivers/infiniband/core/nldev.c).  The type is
 * RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, op), the attributes follow the nlmsghdr
 * with no fixed header, and a request draws from the attributes its op's
 * handler reads, typed as nldev_policy types them.
 */

#include <linux/genetlink.h>	/* GENL_CMD_CAP_DO, GENL_CMD_CAP_DUMP */
#include <linux/netlink.h>
#include <stddef.h>

#include "kernel/rdma_netlink.h"
#include "msg-internal.h"
#include "netlink-attrs.h"
#include "utils.h"		/* ARRAY_SIZE */

#define DO	GENL_CMD_CAP_DO
#define DUMP	GENL_CMD_CAP_DUMP

/* IB_DEVICE_NAME_MAX, which bounds RDMA_NLDEV_ATTR_DEV_NAME. */
#define NLDEV_DEV_NAME_MAX	64

/*
 * ib_device_get_by_index() finds a device by the index xa_alloc_cyclic()
 * gave it, counting from 0, so a host's devices sit at the bottom and each
 * rxe or siw link a run adds takes the next one up.
 */
#define DEV_INDEX(req) \
	{ RDMA_NLDEV_ATTR_DEV_INDEX, NLA_KIND_U32_RANGE, 7, 0, .required = req }
/* rdma_is_port_valid() takes 1 to the device's port count, mostly 1 or 2. */
#define PORT_INDEX(req) \
	{ RDMA_NLDEV_ATTR_PORT_INDEX, NLA_KIND_U32_RANGE, 2, 1, .required = req }
/* rdma_restrack_get_byid() finds a resource by an id its xarray numbers
 * from 0. */
#define RES_ID(attr, req) \
	{ attr, NLA_KIND_U32_RANGE, 63, 0, .required = req }
#define DRIVER_DETAILS \
	{ RDMA_NLDEV_ATTR_DRIVER_DETAILS, NLA_KIND_U8_RANGE, 1, 0 }
#define STAT_RES(values, req) \
	{ RDMA_NLDEV_ATTR_STAT_RES, NLA_KIND_U32_ONEOF, 0, 0, \
	  .oneof = values, .n_oneof = ARRAY_SIZE(values), .required = req }
#define STAT_MODE(req) \
	{ RDMA_NLDEV_ATTR_STAT_MODE, NLA_KIND_U32_RANGE, \
	  RDMA_COUNTER_MODE_MANUAL, 0, .required = req }
#define COUNTER_ID(req) \
	{ RDMA_NLDEV_ATTR_STAT_COUNTER_ID, NLA_KIND_U32_RANGE, 63, 0, \
	  .required = req }

/* The table of a handler that reads no attribute; nothing is drawn from
 * it, since a NULL table sends a request to the random attributes. */
static const struct nla_attr_spec nldev_no_attrs[1];

static const struct nla_attr_spec nldev_dev_attrs[] = {
	DEV_INDEX(true),
};

static const struct nla_attr_spec nldev_port_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(true),
};

static const struct nla_attr_spec nldev_details_attrs[] = {
	DEV_INDEX(true),
	DRIVER_DETAILS,
};

/*
 * The rename and the DIM switch.  RDMA_NLDEV_NET_NS_FD is left out: a drawn
 * number is seldom a netns fd, and the handler tries the move it asks for
 * ahead of both.
 */
static const struct nla_attr_spec nldev_set_attrs[] = {
	DEV_INDEX(true),
	{ RDMA_NLDEV_ATTR_DEV_NAME,	NLA_KIND_STRING, NLDEV_DEV_NAME_MAX, 1 },
	{ RDMA_NLDEV_ATTR_DEV_DIM,	NLA_KIND_U8_RANGE, 1, 0 },
};

static const char *const nldev_link_types[] = { "rxe", "siw" };

/* lo, which every netns has, and the links the rtnl grammar makes. */
static const char *const nldev_netdev_names[] = {
	"lo", "eth0", "veth0", "dummy0", "br0",
};

/* rxe and siw each add one device over a netdev. */
static const struct nla_attr_spec nldev_newlink_attrs[] = {
	{ RDMA_NLDEV_ATTR_DEV_NAME,	NLA_KIND_STRING, NLDEV_DEV_NAME_MAX, 1,
	  .required = true },
	{ RDMA_NLDEV_ATTR_LINK_TYPE,	NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = nldev_link_types, .n_words = ARRAY_SIZE(nldev_link_types),
	  .required = true },
	{ RDMA_NLDEV_ATTR_NDEV_NAME,	NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = nldev_netdev_names,
	  .n_words = ARRAY_SIZE(nldev_netdev_names), .required = true },
};

static const struct nla_attr_spec nldev_sys_set_attrs[] = {
	{ RDMA_NLDEV_SYS_ATTR_NETNS_MODE,		NLA_KIND_U8_RANGE, 1, 0 },
	{ RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE,	NLA_KIND_U8_RANGE, 1, 0 },
};

/* A QP or a CM ID is found on a port; res_get_common_doit() refuses a port
 * for the resources it keeps per device. */
static const struct nla_attr_spec nldev_res_qp_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_LQPN, true),
};

static const struct nla_attr_spec nldev_res_cm_id_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_CM_IDN, true),
};

static const struct nla_attr_spec nldev_res_cq_attrs[] = {
	DEV_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_CQN, true),
};

static const struct nla_attr_spec nldev_res_mr_attrs[] = {
	DEV_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_MRN, true),
};

static const struct nla_attr_spec nldev_res_pd_attrs[] = {
	DEV_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_PDN, true),
};

static const struct nla_attr_spec nldev_res_ctx_attrs[] = {
	DEV_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_CTXN, true),
};

static const struct nla_attr_spec nldev_res_srq_attrs[] = {
	DEV_INDEX(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_SRQN, true),
};

static const struct nla_attr_spec nldev_res_dump_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(false),
	DRIVER_DETAILS,
};

/* The ib_clients that report a chardev: rdma_cm's is global, the others
 * are a device's. */
static const char *const nldev_chardev_types[] = {
	"uverbs", "umad", "issm", "rdma_cm",
};

static const struct nla_attr_spec nldev_chardev_attrs[] = {
	{ RDMA_NLDEV_ATTR_CHARDEV_TYPE,	NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = nldev_chardev_types,
	  .n_words = ARRAY_SIZE(nldev_chardev_types), .required = true },
	DEV_INDEX(false),
	PORT_INDEX(false),
};

/* Only a QP's counters can be bound or unbound; the statistics read an
 * MR's too. */
static const unsigned int nldev_stat_res_qp[] = { RDMA_NLDEV_ATTR_RES_QP };
static const unsigned int nldev_stat_res[] = {
	RDMA_NLDEV_ATTR_RES_QP, RDMA_NLDEV_ATTR_RES_MR,
};

/* nldev_stat_set_counter_dynamic_doit() reads each child as a u32 counter
 * index, whatever its type. */
static const struct nla_attr_spec nldev_hwcounter_attrs[] = {
	{ RDMA_NLDEV_ATTR_STAT_HWCOUNTER_INDEX,	NLA_KIND_U32_RANGE, 63, 0 },
};

/* A port's automatic binding, a QP bound to a counter, and the optional
 * hardware counters switched on and off. */
static const struct nla_attr_spec nldev_stat_set_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(true),
	STAT_RES(nldev_stat_res_qp, true),
	STAT_MODE(true),
	{ RDMA_NLDEV_ATTR_STAT_AUTO_MODE_MASK,	NLA_KIND_U32_MASK,
	  RDMA_COUNTER_MASK_QP_TYPE | RDMA_COUNTER_MASK_PID },
	RES_ID(RDMA_NLDEV_ATTR_RES_LQPN, false),
	COUNTER_ID(false),
	{ RDMA_NLDEV_ATTR_STAT_OPCOUNTER_ENABLED, NLA_KIND_U8_RANGE, 1, 0 },
	{ RDMA_NLDEV_ATTR_STAT_HWCOUNTERS,	NLA_KIND_NESTED, 0, 0,
	  .nest = nldev_hwcounter_attrs,
	  .n_nest = ARRAY_SIZE(nldev_hwcounter_attrs) },
};

/* Without a resource, the port's default counters; with a QP, its binding
 * mode or a counter; with an MR, its statistics, which take no port. */
static const struct nla_attr_spec nldev_stat_get_attrs[] = {
	DEV_INDEX(true),
	PORT_INDEX(true),
	STAT_RES(nldev_stat_res, false),
	STAT_MODE(false),
	COUNTER_ID(false),
	RES_ID(RDMA_NLDEV_ATTR_RES_MRN, false),
};

static const struct nla_attr_spec nldev_stat_dump_attrs[] = {
	STAT_RES(nldev_stat_res, true),
	DEV_INDEX(true),
	PORT_INDEX(false),
	DRIVER_DETAILS,
};

static const struct nla_attr_spec nldev_stat_del_attrs[] = {
	STAT_RES(nldev_stat_res_qp, true),
	DEV_INDEX(true),
	PORT_INDEX(true),
	COUNTER_ID(true),
	RES_ID(RDMA_NLDEV_ATTR_RES_LQPN, true),
};

static const unsigned int nldev_dev_types[] = { RDMA_DEVICE_TYPE_SMI };

/* A sub-device of the parent DEV_INDEX names. */
static const struct nla_attr_spec nldev_newdev_attrs[] = {
	DEV_INDEX(true),
	{ RDMA_NLDEV_ATTR_DEV_NAME,	NLA_KIND_STRING, NLDEV_DEV_NAME_MAX, 1,
	  .required = true },
	{ RDMA_NLDEV_ATTR_DEV_TYPE,	NLA_KIND_U8_ONEOF, 0, 0,
	  .oneof = nldev_dev_types, .n_oneof = ARRAY_SIZE(nldev_dev_types),
	  .required = true },
};

/*
 * The pool a pinned count is for, which the handler parses strictly against
 * nldev_policy.  KERNEL_VENDOR_KEY is left out, since the handler refuses
 * it.  The access flags are the IB_ACCESS_* bits ib_check_mr_access()
 * takes: the ten mandatory ones and RELAXED_ORDERING, the first optional.
 */
static const struct nla_attr_spec nldev_frmr_key_attrs[] = {
	{ RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ATS,		NLA_KIND_U8_RANGE, 1, 0 },
	{ RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ACCESS_FLAGS,	NLA_KIND_U32_MASK,
	  0x3ff | (1U << 20) },
	{ RDMA_NLDEV_ATTR_FRMR_POOL_KEY_VENDOR_KEY,	NLA_KIND_U64, 8 },
	{ RDMA_NLDEV_ATTR_FRMR_POOL_KEY_NUM_DMA_BLOCKS, NLA_KIND_U64, 8 },
};

/* The handler sets an aging period ahead of a pinned count, and makes a
 * memory region for each pinned handle the pool lacks; 0 is refused for
 * the period. */
static const struct nla_attr_spec nldev_frmr_set_attrs[] = {
	DEV_INDEX(true),
	{ RDMA_NLDEV_ATTR_FRMR_POOLS_AGING_PERIOD,	NLA_KIND_U32_RANGE,
	  600, 0 },
	{ RDMA_NLDEV_ATTR_FRMR_POOL_PINNED_HANDLES,	NLA_KIND_U32_RANGE,
	  64, 0 },
	{ RDMA_NLDEV_ATTR_FRMR_POOL_KEY,		NLA_KIND_NESTED, 0, 0,
	  .nest = nldev_frmr_key_attrs,
	  .n_nest = ARRAY_SIZE(nldev_frmr_key_attrs) },
};

/* nldev_cb_table: the ops with a handler, and which handlers they have. */
const struct rdma_nldev_op rdma_nldev_ops[] = {
	{ RDMA_NLDEV_CMD_GET,		DO | DUMP,
	  nldev_dev_attrs, ARRAY_SIZE(nldev_dev_attrs), nldev_no_attrs, 0 },
	{ RDMA_NLDEV_CMD_GET_CHARDEV,	DO,
	  nldev_chardev_attrs, ARRAY_SIZE(nldev_chardev_attrs) },
	{ RDMA_NLDEV_CMD_SET,		DO,
	  nldev_set_attrs, ARRAY_SIZE(nldev_set_attrs) },
	{ RDMA_NLDEV_CMD_NEWLINK,	DO,
	  nldev_newlink_attrs, ARRAY_SIZE(nldev_newlink_attrs) },
	{ RDMA_NLDEV_CMD_DELLINK,	DO,
	  nldev_dev_attrs, ARRAY_SIZE(nldev_dev_attrs) },
	{ RDMA_NLDEV_CMD_PORT_GET,	DO | DUMP,
	  nldev_port_attrs, ARRAY_SIZE(nldev_port_attrs),
	  nldev_dev_attrs, ARRAY_SIZE(nldev_dev_attrs) },
	{ RDMA_NLDEV_CMD_RES_GET,	DO | DUMP,
	  nldev_details_attrs, ARRAY_SIZE(nldev_details_attrs),
	  nldev_no_attrs, 0 },
	{ RDMA_NLDEV_CMD_RES_QP_GET,	DO | DUMP,
	  nldev_res_qp_attrs, ARRAY_SIZE(nldev_res_qp_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_CM_ID_GET,	DO | DUMP,
	  nldev_res_cm_id_attrs, ARRAY_SIZE(nldev_res_cm_id_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_CQ_GET,	DO | DUMP,
	  nldev_res_cq_attrs, ARRAY_SIZE(nldev_res_cq_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_MR_GET,	DO | DUMP,
	  nldev_res_mr_attrs, ARRAY_SIZE(nldev_res_mr_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_PD_GET,	DO | DUMP,
	  nldev_res_pd_attrs, ARRAY_SIZE(nldev_res_pd_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_CTX_GET,	DO | DUMP,
	  nldev_res_ctx_attrs, ARRAY_SIZE(nldev_res_ctx_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_SRQ_GET,	DO | DUMP,
	  nldev_res_srq_attrs, ARRAY_SIZE(nldev_res_srq_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_QP_GET_RAW, DO | DUMP,
	  nldev_res_qp_attrs, ARRAY_SIZE(nldev_res_qp_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_CQ_GET_RAW, DO | DUMP,
	  nldev_res_cq_attrs, ARRAY_SIZE(nldev_res_cq_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_MR_GET_RAW, DO | DUMP,
	  nldev_res_mr_attrs, ARRAY_SIZE(nldev_res_mr_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_RES_SRQ_GET_RAW, DO | DUMP,
	  nldev_res_srq_attrs, ARRAY_SIZE(nldev_res_srq_attrs),
	  nldev_res_dump_attrs, ARRAY_SIZE(nldev_res_dump_attrs) },
	{ RDMA_NLDEV_CMD_SYS_GET,	DO,
	  nldev_no_attrs, 0 },
	{ RDMA_NLDEV_CMD_SYS_SET,	DO,
	  nldev_sys_set_attrs, ARRAY_SIZE(nldev_sys_set_attrs) },
	{ RDMA_NLDEV_CMD_STAT_SET,	DO,
	  nldev_stat_set_attrs, ARRAY_SIZE(nldev_stat_set_attrs) },
	{ RDMA_NLDEV_CMD_STAT_GET,	DO | DUMP,
	  nldev_stat_get_attrs, ARRAY_SIZE(nldev_stat_get_attrs),
	  nldev_stat_dump_attrs, ARRAY_SIZE(nldev_stat_dump_attrs) },
	{ RDMA_NLDEV_CMD_STAT_DEL,	DO,
	  nldev_stat_del_attrs, ARRAY_SIZE(nldev_stat_del_attrs) },
	{ RDMA_NLDEV_CMD_STAT_GET_STATUS, DO,
	  nldev_port_attrs, ARRAY_SIZE(nldev_port_attrs) },
	{ RDMA_NLDEV_CMD_NEWDEV,	DO,
	  nldev_newdev_attrs, ARRAY_SIZE(nldev_newdev_attrs) },
	{ RDMA_NLDEV_CMD_DELDEV,	DO,
	  nldev_dev_attrs, ARRAY_SIZE(nldev_dev_attrs) },
	{ RDMA_NLDEV_CMD_FRMR_POOLS_GET, DUMP,
	  NULL, 0, nldev_details_attrs, ARRAY_SIZE(nldev_details_attrs) },
	{ RDMA_NLDEV_CMD_FRMR_POOLS_SET, DO,
	  nldev_frmr_set_attrs, ARRAY_SIZE(nldev_frmr_set_attrs) },
};
const size_t rdma_nldev_ops_n = ARRAY_SIZE(rdma_nldev_ops);

const struct rdma_nldev_op *rdma_nldev_lookup(unsigned short nlmsg_type)
{
	size_t i;

	if (RDMA_NL_GET_CLIENT(nlmsg_type) != RDMA_NL_NLDEV)
		return NULL;
	for (i = 0; i < rdma_nldev_ops_n; i++) {
		if (rdma_nldev_ops[i].op == RDMA_NL_GET_OP(nlmsg_type))
			return &rdma_nldev_ops[i];
	}
	return NULL;
}
