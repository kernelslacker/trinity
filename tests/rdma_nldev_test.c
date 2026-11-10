/*
 * Self-check for the NETLINK_RDMA requests.  netlink_gen_msg() runs for
 * NETLINK_RDMA, and each request is held to a model of nldev written from
 * drivers/infiniband/core/nldev.c: whether rdma_nl_rcv_msg() routes it to a
 * handler of the op its type names, whether that handler's parse takes its
 * attributes, and whether the ones the handler cannot do without are there.
 * The RNG helpers it reaches are the fakes in genl_ops_test.c; no netlink
 * socket is opened.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "kernel/rdma_netlink.h"	/* the nldev ops and attributes */
#include "socketinfo.h"		/* struct socket_triplet */
#include "utils-macros.h"	/* ARRAY_SIZE */

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

#define ROUNDS		80000

/*
 * As in rtnl_gen_test.c, only a lone message whose nlmsg_len is intact says
 * where its attributes end, and one as long as the smallest buffer may hold
 * an attribute cut short to fit, so both are left out.
 */
#define SMALLEST_BUFFER	(NLMSG_HDRLEN + 1280)

/* RDMA_NLDEV_ATTR_MAX as of 7.4; a strict parse refuses an id past it. */
#define ATTR_SLOTS	119

#define DEV		RDMA_NLDEV_ATTR_DEV_INDEX
#define PORT		RDMA_NLDEV_ATTR_PORT_INDEX

enum { P_NONE, P_U8, P_U32, P_U64, P_STR, P_NEST };

struct slot {
	unsigned char type;
	unsigned char len;	/* the most a P_STR's string holds */
};

/* nldev_policy, for the attributes nldev's handlers read. */
static const struct slot policy[ATTR_SLOTS] = {
	[RDMA_NLDEV_ATTR_CHARDEV_TYPE]		= { P_STR, 32 },
	[RDMA_NLDEV_ATTR_DEV_DIM]		= { P_U8 },
	[RDMA_NLDEV_ATTR_DEV_INDEX]		= { P_U32 },
	[RDMA_NLDEV_ATTR_DEV_NAME]		= { P_STR, 64 },
	[RDMA_NLDEV_ATTR_DEV_TYPE]		= { P_U8 },
	[RDMA_NLDEV_ATTR_DRIVER_DETAILS]	= { P_U8 },
	[RDMA_NLDEV_ATTR_LINK_TYPE]		= { P_STR, 16 },
	[RDMA_NLDEV_ATTR_NDEV_NAME]		= { P_STR, 16 },
	[RDMA_NLDEV_ATTR_PORT_INDEX]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_CM_IDN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_CQN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_CTXN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_LQPN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_MRN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_PDN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_RES_SRQN]		= { P_U32 },
	[RDMA_NLDEV_ATTR_STAT_AUTO_MODE_MASK]	= { P_U32 },
	[RDMA_NLDEV_ATTR_STAT_COUNTER_ID]	= { P_U32 },
	[RDMA_NLDEV_ATTR_STAT_HWCOUNTERS]	= { P_NEST },
	[RDMA_NLDEV_ATTR_STAT_HWCOUNTER_INDEX]	= { P_U32 },
	[RDMA_NLDEV_ATTR_STAT_MODE]		= { P_U32 },
	[RDMA_NLDEV_ATTR_STAT_OPCOUNTER_ENABLED] = { P_U8 },
	[RDMA_NLDEV_ATTR_STAT_RES]		= { P_U32 },
	[RDMA_NLDEV_NET_NS_FD]			= { P_U32 },
	[RDMA_NLDEV_SYS_ATTR_NETNS_MODE]	= { P_U8 },
	[RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE] = { P_U8 },
	[RDMA_NLDEV_ATTR_FRMR_POOL_KEY]		= { P_NEST },
	[RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ATS]	= { P_U8 },
	[RDMA_NLDEV_ATTR_FRMR_POOL_KEY_ACCESS_FLAGS] = { P_U32 },
	[RDMA_NLDEV_ATTR_FRMR_POOL_KEY_VENDOR_KEY] = { P_U64 },
	[RDMA_NLDEV_ATTR_FRMR_POOL_KEY_NUM_DMA_BLOCKS] = { P_U64 },
	[RDMA_NLDEV_ATTR_FRMR_POOLS_AGING_PERIOD] = { P_U32 },
	[RDMA_NLDEV_ATTR_FRMR_POOL_PINNED_HANDLES] = { P_U32 },
};

/*
 * A handler: whether it parses with nlmsg_parse(), which is strict, or
 * __nlmsg_parse(..., NL_VALIDATE_LIBERAL); the attributes it returns
 * -EINVAL without; at least one of which it needs, when any[0] is set; and
 * the one it returns -EINVAL with, res_get_common_doit()'s port for a
 * resource it keeps per device.  The GET and RES_GET dumpits parse nothing.
 */
struct handler {
	bool present, parses, strict;
	unsigned short need[5];
	unsigned short any[2];
	unsigned short refuse;
};

#define LIBERAL(...)	{ true, true, false, { __VA_ARGS__ } }
#define STRICT(...)	{ true, true, true, { __VA_ARGS__ } }
#define NO_PARSE	{ true, false, false }
#define NONE		{ false }
#define PER_DEV(id)	{ true, true, false, { DEV, id }, .refuse = PORT }

struct op_model {
	unsigned short op;
	const char *name;
	struct handler doit, dump;
};

/* nldev_cb_table.  STAT_GET's doit is held to what its default-counter and
 * QP-mode arms both need. */
static const struct op_model ops[] = {
	{ RDMA_NLDEV_CMD_GET, "GET", LIBERAL(DEV), NO_PARSE },
	{ RDMA_NLDEV_CMD_GET_CHARDEV, "GET_CHARDEV",
	  LIBERAL(RDMA_NLDEV_ATTR_CHARDEV_TYPE), NONE },
	{ RDMA_NLDEV_CMD_SET, "SET", STRICT(DEV), NONE },
	{ RDMA_NLDEV_CMD_NEWLINK, "NEWLINK",
	  STRICT(RDMA_NLDEV_ATTR_DEV_NAME, RDMA_NLDEV_ATTR_LINK_TYPE,
		 RDMA_NLDEV_ATTR_NDEV_NAME), NONE },
	{ RDMA_NLDEV_CMD_DELLINK, "DELLINK", STRICT(DEV), NONE },
	{ RDMA_NLDEV_CMD_PORT_GET, "PORT_GET", LIBERAL(DEV, PORT), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_SYS_GET, "SYS_GET", { true, true, false }, NONE },
	{ RDMA_NLDEV_CMD_SYS_SET, "SYS_SET",
	  { true, true, true, .any = { RDMA_NLDEV_SYS_ATTR_NETNS_MODE,
			RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE } }, NONE },
	{ RDMA_NLDEV_CMD_RES_GET, "RES_GET", LIBERAL(DEV), NO_PARSE },
	{ RDMA_NLDEV_CMD_RES_QP_GET, "RES_QP_GET",
	  LIBERAL(DEV, PORT, RDMA_NLDEV_ATTR_RES_LQPN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_CM_ID_GET, "RES_CM_ID_GET",
	  LIBERAL(DEV, PORT, RDMA_NLDEV_ATTR_RES_CM_IDN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_CQ_GET, "RES_CQ_GET",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_CQN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_MR_GET, "RES_MR_GET",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_MRN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_PD_GET, "RES_PD_GET",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_PDN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_STAT_SET, "STAT_SET",
	  { true, true, true, { DEV, PORT },
	    .any = { RDMA_NLDEV_ATTR_STAT_MODE,
		     RDMA_NLDEV_ATTR_STAT_HWCOUNTERS } }, NONE },
	{ RDMA_NLDEV_CMD_STAT_GET, "STAT_GET",
	  LIBERAL(DEV, PORT), LIBERAL(RDMA_NLDEV_ATTR_STAT_RES, DEV) },
	{ RDMA_NLDEV_CMD_STAT_DEL, "STAT_DEL",
	  STRICT(RDMA_NLDEV_ATTR_STAT_RES, DEV, PORT,
		 RDMA_NLDEV_ATTR_STAT_COUNTER_ID, RDMA_NLDEV_ATTR_RES_LQPN),
	  NONE },
	{ RDMA_NLDEV_CMD_RES_QP_GET_RAW, "RES_QP_GET_RAW",
	  LIBERAL(DEV, PORT, RDMA_NLDEV_ATTR_RES_LQPN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_CQ_GET_RAW, "RES_CQ_GET_RAW",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_CQN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_MR_GET_RAW, "RES_MR_GET_RAW",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_MRN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_CTX_GET, "RES_CTX_GET",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_CTXN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_RES_SRQ_GET, "RES_SRQ_GET",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_SRQN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_STAT_GET_STATUS, "STAT_GET_STATUS",
	  LIBERAL(DEV, PORT), NONE },
	{ RDMA_NLDEV_CMD_RES_SRQ_GET_RAW, "RES_SRQ_GET_RAW",
	  PER_DEV(RDMA_NLDEV_ATTR_RES_SRQN), LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_NEWDEV, "NEWDEV",
	  STRICT(DEV, RDMA_NLDEV_ATTR_DEV_NAME, RDMA_NLDEV_ATTR_DEV_TYPE),
	  NONE },
	{ RDMA_NLDEV_CMD_DELDEV, "DELDEV", STRICT(DEV), NONE },
	{ RDMA_NLDEV_CMD_FRMR_POOLS_GET, "FRMR_POOLS_GET", NONE, LIBERAL(DEV) },
	{ RDMA_NLDEV_CMD_FRMR_POOLS_SET, "FRMR_POOLS_SET", STRICT(DEV), NONE },
};

struct op_tally {
	unsigned int msgs, reached, doits;
};

struct tallies {
	unsigned int msgs, nldev;
	struct op_tally ops[ARRAY_SIZE(ops)];
	unsigned int routed[2], parsed[2];	/* by handler: liberal, strict */
	unsigned int one_kind, one_kind_bits;	/* the dump bits of single-handler ops */
	unsigned int devs, devs_small;		/* DEV_INDEX, and those under 8 */
	unsigned int ports, ports_valid;	/* PORT_INDEX, and 1 or 2 */
	unsigned int sets, set_dims, dims, dims_valid;
};

/* What a parse of an attribute stream found. */
struct stream {
	bool takes;
	bool seen[ATTR_SLOTS];
	uint32_t value[ATTR_SLOTS];	/* the last u32 or u8 of each id */
};

static bool nest_takes(const unsigned char *p, size_t len, unsigned int type);

/*
 * One attribute as validate_nla() in lib/nlattr.c sees it.  A strict parse
 * refuses an id the policy has no slot for, an NLA_F_NESTED flag that does
 * not match an NLA_NESTED slot, and a fixed-width scalar of any other
 * length; a liberal one ignores an unknown id and refuses a scalar only
 * when it is short.  A string needs a NUL within the slot's length and one.
 */
static bool attr_takes(const struct nlattr *nla, bool strict)
{
	unsigned int type = nla->nla_type & NLA_TYPE_MASK;
	const unsigned char *data = (const unsigned char *) nla + NLA_HDRLEN;
	size_t len = nla->nla_len - NLA_HDRLEN;
	bool flagged = (nla->nla_type & NLA_F_NESTED) != 0;
	const struct slot *slot;
	size_t width, n;

	if (type >= ATTR_SLOTS || policy[type].type == P_NONE)
		return !strict;
	slot = &policy[type];
	if (strict && flagged != (slot->type == P_NEST))
		return false;

	switch (slot->type) {
	case P_U8:
	case P_U32:
	case P_U64:
		width = slot->type == P_U8 ? 1 : slot->type == P_U32 ? 4 : 8;
		return strict ? len == width : len >= width;
	case P_STR:
		n = len < slot->len + 1u ? len : slot->len + 1u;
		return n != 0 && memchr(data, '\0', n) != NULL;
	default:
		return len == 0 || (len >= NLA_HDRLEN && nest_takes(data, len, type));
	}
}

/* Walk an attribute stream as __nla_validate_parse() does, noting each id
 * and the value of each scalar.  A strict parse refuses bytes left over. */
static void parse_stream(const unsigned char *p, size_t len, bool strict,
			 struct stream *s)
{
	memset(s, 0, sizeof(*s));
	s->takes = true;
	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *) p;
		unsigned int type = nla->nla_type & NLA_TYPE_MASK;
		size_t total;

		if (nla->nla_len < NLA_HDRLEN || nla->nla_len > len)
			break;
		if (!attr_takes(nla, strict))
			s->takes = false;
		if (type < ATTR_SLOTS) {
			s->seen[type] = true;
			if (nla->nla_len == NLA_HDRLEN + 4)
				memcpy(&s->value[type], p + NLA_HDRLEN, 4);
			else if (nla->nla_len == NLA_HDRLEN + 1)
				s->value[type] = p[NLA_HDRLEN];
		}
		total = NLA_ALIGN(nla->nla_len);
		if (total >= len) {
			len = 0;
			break;
		}
		p += total;
		len -= total;
	}
	if (strict && len != 0)
		s->takes = false;
}

/*
 * The children of a nest whose handler reads them: the memory-region pool
 * key, which nldev_frmr_pools_set_pinned() parses strictly against
 * nldev_policy, and the hardware counters, each of which
 * nldev_stat_set_counter_dynamic_doit() reads as a u32, whatever its id.
 */
static bool nest_takes(const unsigned char *p, size_t len, unsigned int type)
{
	struct stream inner;

	if (type == RDMA_NLDEV_ATTR_FRMR_POOL_KEY) {
		parse_stream(p, len, true, &inner);
		return inner.takes;
	}
	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *) p;
		size_t total;

		if (nla->nla_len != NLA_HDRLEN + 4 || nla->nla_len > len)
			return false;
		total = NLA_ALIGN(nla->nla_len);
		if (total >= len)
			return true;
		p += total;
		len -= total;
	}
	return len == 0;
}

static const struct op_model *find_op(unsigned short nlmsg_type,
				      unsigned int *index)
{
	unsigned int i;

	if (RDMA_NL_GET_CLIENT(nlmsg_type) != RDMA_NL_NLDEV)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		if (ops[i].op == RDMA_NL_GET_OP(nlmsg_type)) {
			*index = i;
			return &ops[i];
		}
	}
	return NULL;
}

/* Whether the handler a request is routed to runs past its parse and the
 * attribute checks that follow it. */
static bool handler_runs(const struct handler *h, const struct stream *s)
{
	unsigned int i;

	if (!h->parses)
		return true;
	if (!s->takes)
		return false;
	for (i = 0; i < ARRAY_SIZE(h->need) && h->need[i] != 0; i++) {
		if (!s->seen[h->need[i]])
			return false;
	}
	if (h->any[0] != 0 && !s->seen[h->any[0]] && !s->seen[h->any[1]])
		return false;
	return h->refuse == 0 || !s->seen[h->refuse];
}

static void tally_values(struct tallies *t, const struct op_model *op,
			 const struct stream *s, bool runs)
{
	if (s->seen[DEV]) {
		t->devs++;
		t->devs_small += s->value[DEV] < 8;
	}
	if (s->seen[PORT]) {
		t->ports++;
		t->ports_valid += s->value[PORT] == 1 || s->value[PORT] == 2;
	}
	if (op->op != RDMA_NLDEV_CMD_SET)
		return;
	t->sets++;
	if (s->seen[RDMA_NLDEV_ATTR_DEV_DIM]) {
		t->dims++;
		t->dims_valid += s->value[RDMA_NLDEV_ATTR_DEV_DIM] <= 1;
		/* ib_device_set_dim() runs when nothing ahead of it is asked. */
		t->set_dims += runs && !s->seen[RDMA_NLDEV_ATTR_DEV_NAME] &&
			       !s->seen[RDMA_NLDEV_NET_NS_FD];
	}
}

/*
 * rdma_nl_rcv_skb() passes a request on only with NLM_F_REQUEST, and
 * rdma_nl_rcv_msg() routes it to the op's dumpit on either dump bit and to
 * its doit otherwise, answering -EINVAL when that handler is missing.
 */
static void tally_msg(struct tallies *t, const struct nlmsghdr *nlh)
{
	const unsigned char *attrs = (const unsigned char *) nlh + NLMSG_HDRLEN;
	size_t attrs_len = nlh->nlmsg_len - NLMSG_HDRLEN;
	bool dump = (nlh->nlmsg_flags & NLM_F_DUMP) != 0;
	const struct op_model *op;
	const struct handler *h;
	struct op_tally *ot;
	struct stream s;
	unsigned int i;
	bool runs;

	t->msgs++;
	op = find_op(nlh->nlmsg_type, &i);
	if (op == NULL)
		return;
	t->nldev++;
	ot = &t->ops[i];
	ot->msgs++;
	ot->doits += !dump;
	if (op->doit.present != op->dump.present) {
		t->one_kind++;
		t->one_kind_bits += op->dump.present ?
			(nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP : !dump;
	}

	h = dump ? &op->dump : &op->doit;
	parse_stream(attrs, attrs_len, h->strict, &s);
	if (h->present && h->parses) {
		t->routed[h->strict]++;
		t->parsed[h->strict] += s.takes;
	}
	runs = (nlh->nlmsg_flags & NLM_F_REQUEST) && h->present &&
	       handler_runs(h, &s);
	ot->reached += runs;
	tally_values(t, op, &s, runs);
}

static void run_rounds(struct tallies *t)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_RDMA,
	};
	unsigned int round;

	for (round = 0; round < ROUNDS; round++) {
		const struct nlmsghdr *nlh;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len >= NLMSG_HDRLEN && len < SMALLEST_BUFFER &&
		    nlh->nlmsg_len >= NLMSG_HDRLEN &&
		    NLMSG_ALIGN(nlh->nlmsg_len) == len)
			tally_msg(t, nlh);
		free(buf);
	}
}

/* A fraction of whole that part is, held to [lo, hi]. */
static void expect_fraction(unsigned int part, unsigned int whole, double lo,
			    double hi, const char *what, const char *bug)
{
	if (whole < 500 || part < whole * lo || part > whole * hi) {
		fprintf(stderr, "%s: %u of %u, want a fraction in [%.2f, %.2f]\n",
			what, part, whole, lo, hi);
		BUG(bug);
	}
}

void rdma_nldev_self_check(void);
void rdma_nldev_self_check(void)
{
	static struct tallies t;
	unsigned int i;

	run_rounds(&t);

	/* The one type in twenty that is random seldom names an op. */
	expect_fraction(t.nldev, t.msgs, 0.90, 1.0, "nldev ops",
			"a NETLINK_RDMA request names no nldev op");
	expect_fraction(t.one_kind_bits, t.one_kind, 0.88, 1.0,
			"single-handler dump bits",
			"an op's dump bits route it to a handler it lacks");
	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		const struct op_tally *ot = &t.ops[i];

		expect_fraction(ot->reached, ot->msgs, 0.50, 1.0, ops[i].name,
				"an nldev request stops short of its handler");
		if (ops[i].doit.present && ops[i].dump.present)
			expect_fraction(ot->doits, ot->msgs, 0.30, 0.70,
					ops[i].name,
					"an op with both handlers favours one");
	}
	expect_fraction(t.parsed[0], t.routed[0], 0.95, 1.0, "liberal parses",
			"a liberal nldev parse refuses a request");
	expect_fraction(t.parsed[1], t.routed[1], 0.95, 1.0, "strict parses",
			"a strict nldev parse refuses a request");
	expect_fraction(t.devs_small, t.devs, 0.80, 1.0, "DEV_INDEX",
			"DEV_INDEX seldom names a device a host has");
	expect_fraction(t.ports_valid, t.ports, 0.80, 1.0, "PORT_INDEX",
			"PORT_INDEX seldom names a port a device has");
	expect_fraction(t.dims_valid, t.dims, 0.80, 1.0, "DEV_DIM",
			"DEV_DIM is seldom a switch ib_device_set_dim() takes");
	expect_fraction(t.set_dims, t.sets, 0.10, 1.0, "SET's DIM arm",
			"SET seldom reaches ib_device_set_dim()");
}
