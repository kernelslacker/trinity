/*
 * Self-check for the genl op shapes.  The op list in the controller's
 * GETFAMILY reply lands in each registered family's cmd_caps, and
 * netlink_gen_msg() sets NLM_F_DUMP to suit the cmd it picks and keeps
 * most requests inside the genl core's header check.  The reply is
 * canned and arrives over a unix socketpair standing in for the
 * NETLINK_GENERIC socket; no netlink socket is opened.  Which attribute
 * table a cmd draws from is checked on a grammar of the test's own, and the
 * attributes of the strict families' cmds against mirrors of their kernel
 * policies.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "netlink-genl-families.h"
#include "random.h"		/* rand16, generate_rand_bytes, set_rand_bitmask */
#include "rnd.h"
#include "socketinfo.h"		/* struct socket_triplet */
#include "text-payloads.h"	/* gen_cpu_list_string */
#include "utils.h"		/* ARRAY_SIZE */

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

extern struct genl_family_grammar fam_taskstats;
extern struct genl_family_grammar fam_nlbl_calipso;
extern struct genl_family_grammar fam_nlbl_cipsov4;
extern struct genl_family_grammar fam_nlbl_mgmt;
extern struct genl_family_grammar fam_nlbl_unlabel;
extern struct genl_family_grammar fam_devlink;
extern struct genl_family_grammar fam_binder;

#define CMD_CAPS	(GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP)

/* Past GENL_MIN_ID + 64, where the generator's unknown-family ids stop. */
#define ID_DO_ONLY	700
#define ID_DUMP_ONLY	701
#define ID_BOTH		702
#define ID_NO_OPS	703
#define ID_EDGE		704
#define ID_TRUNCATED	705
#define ID_OPS_FIRST	706
#define ID_HANDSHAKE	710
#define ID_VDPA		711
#define ID_WIREGUARD	712
#define ID_DPLL		713
#define ID_NFSD		714
#define ID_DRM_RAS	715
#define ID_LOCKD	716
#define ID_SUNRPC	717
#define ID_PSP		718
#define ID_NETDEV	719
#define ID_ETHTOOL	720
#define ID_OVS_DATAPATH	721
#define ID_OVS_VPORT	722
#define ID_OVS_METER	723
#define ID_OVS_CT_LIMIT	724
#define ID_TIPC		725
#define ID_OVS_FLOW	726
#define ID_OVS_PACKET	727
#define ID_UNREGISTERED	900

/* Each family whose flags are tallied wants some 3000 messages, and every
 * family in the canned reply takes a share of the rounds. */
#define ROUNDS		50000

/* The flag bits the generator's own draws can set.  A random word lies
 * within them one time in 512. */
#define DRAWN_FLAGS	(NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO | NLM_F_DUMP | \
			 NLM_F_CREATE | NLM_F_APPEND)

/* The draws that are not the dump pair.  NLM_F_ATOMIC is NLM_F_CREATE's
 * bit; REPLACE, EXCL, NONREC and BULK are the dump pair's bits, so a word
 * with one of them cannot be told from a dump. */
#define MODIFIER_FLAGS	(NLM_F_CREATE | NLM_F_APPEND)

/* A run of netlink bytes under construction, zeroed so padding is. */
struct reply {
	unsigned char buf[8192];
	size_t len;
};

struct op {
	unsigned int id;
	unsigned int flags;
};

static struct reply canned;
static const struct reply *serve;	/* what socket() hands out; NULL turns netlink away */
static int peer_fd = -1;

/*
 * The resolver's socket: a unix datagram socketpair with the canned reply
 * already queued on its end.  Netlink is refused otherwise, so nothing
 * here can reach a real netlink socket.
 */
int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
	int sv[2];

	if (domain != AF_NETLINK)
		return __real_socket(domain, type, protocol);

	if (serve == NULL || protocol != NETLINK_GENERIC) {
		errno = EPROTONOSUPPORT;
		return -1;
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0)
		BUG("genl ops: cannot make the socketpair");
	if (send(sv[1], serve->buf, serve->len, 0) != (ssize_t) serve->len)
		BUG("genl ops: cannot queue the canned reply");
	peer_fd = sv[1];
	serve = NULL;
	return sv[0];
}

/* RNG helpers netlink_gen_msg() reaches.  rand16() is uniform here, so a
 * chaos flags word has both dump bits set one time in four. */
unsigned short rand16(void)
{
	return rnd_u32() & 0xffff;
}

void generate_rand_bytes(unsigned char *ptr, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		ptr[i] = rnd_u32() & 0xff;
}

/* Asked by the rtnetlink link builder, which this test builds none of,
 * and by sanitisers other tests run: the pidfd group's info sanitiser,
 * content with no bits, and mmap's flags draw, whose test sets
 * fake_rand_bitmask_draws for a random subset of the values. */
bool fake_rand_bitmask_draws;

unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values)
{
	unsigned long mask = 0;
	unsigned int i;

	if (!fake_rand_bitmask_draws)
		return 0;
	for (i = 0; i < num; i++) {
		if (RAND_BOOL())
			mask |= values[i];
	}
	return mask;
}

unsigned int gen_cpu_list_string(char *buf, unsigned int buflen)
{
	return snprintf(buf, buflen, "0-3");
}

/* ---------- Building the reply ---------------------------------------- */

/* Append an attribute whose payload is data, padded as netlink pads. */
static void put_attr(struct reply *r, unsigned short type, const void *data,
		     size_t len)
{
	struct nlattr nla = { .nla_len = NLA_HDRLEN + len, .nla_type = type };

	memcpy(r->buf + r->len, &nla, sizeof(nla));
	memcpy(r->buf + r->len + NLA_HDRLEN, data, len);
	r->len += NLA_ALIGN(NLA_HDRLEN + len);
}

/* Append a NEWFAMILY message whose attributes are body. */
static void put_msg(struct reply *r, const struct reply *body)
{
	struct nlmsghdr nlh = {
		.nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + body->len,
		.nlmsg_type = GENL_ID_CTRL,
		.nlmsg_flags = NLM_F_MULTI,
	};
	struct genlmsghdr genl = { .cmd = CTRL_CMD_NEWFAMILY, .version = 2 };

	memcpy(r->buf + r->len, &nlh, sizeof(nlh));
	memcpy(r->buf + r->len + NLMSG_HDRLEN, &genl, sizeof(genl));
	memcpy(r->buf + r->len + NLMSG_HDRLEN + GENL_HDRLEN, body->buf, body->len);
	r->len += NLMSG_ALIGN(nlh.nlmsg_len);
}

/* One op nest, as ctrl_fill_info() writes it: the nest's own type is the
 * op's index, its children the id and the flags. */
static void put_op(struct reply *list, unsigned short index, const struct op *op)
{
	struct reply kids = { .len = 0 };

	put_attr(&kids, CTRL_ATTR_OP_ID, &op->id, sizeof(op->id));
	put_attr(&kids, CTRL_ATTR_OP_FLAGS, &op->flags, sizeof(op->flags));
	put_attr(list, index, kids.buf, kids.len);
}

/* A family whose op list holds every cmd of its grammar, all with flags. */
static void put_grammar_family(struct reply *r,
			       const struct genl_family_grammar *fam,
			       unsigned short id, unsigned int flags)
{
	struct reply body = { .len = 0 };
	struct reply list = { .len = 0 };
	unsigned int i;

	put_attr(&body, CTRL_ATTR_FAMILY_NAME, fam->name, strlen(fam->name) + 1);
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	for (i = 0; i < fam->n_cmds; i++) {
		struct op op = { .id = fam->cmds[i].cmd, .flags = flags };

		put_op(&list, i + 1, &op);
	}
	put_attr(&body, CTRL_ATTR_OPS, list.buf, list.len);
	put_msg(r, &body);
}

/*
 * An op list that pushes on the parser's limits: flag bits past the two
 * handlers, ids at and past the end of a u8, and three nests it must not
 * record.  Those are one with no id, one whose id is two bytes, and one
 * whose length runs past the end of the op list.  The attribute after the
 * list gives that last nest room to reach into without leaving the
 * message, so only a check against the list itself rejects it.
 */
static void put_edge_family(struct reply *r, const struct genl_family_grammar *fam,
			    unsigned short id)
{
	static const struct op ops[] = {
		/* Bits other than the two handlers are not kept. */
		{ 10, GENL_CMD_CAP_DO | GENL_CMD_CAP_HASPOL | GENL_ADMIN_PERM },
		{ 11, GENL_CMD_CAP_DUMP | GENL_UNS_ADMIN_PERM },
		{ 12, CMD_CAPS },
		/* One id listed twice adds up. */
		{ 13, GENL_CMD_CAP_DO },
		{ 13, GENL_CMD_CAP_DUMP },
		/* Listed, but with no handler to send a request to. */
		{ 14, 0 },
		{ 15, GENL_CMD_CAP_HASPOL },
		/* A u8 holds up to 255; the rest must not wrap round to 0, 17
		 * or 20. */
		{ 255, GENL_CMD_CAP_DUMP },
		{ 256, GENL_CMD_CAP_DO },
		{ 256 + 17, GENL_CMD_CAP_DO },
		{ 0xffffff00U + 20, GENL_CMD_CAP_DO },
	};
	static const unsigned char pad[96];
	const unsigned short short_id = 30;
	const unsigned int do_flag = GENL_CMD_CAP_DO;
	const unsigned int overlong_id = 50;
	struct reply body = { .len = 0 };
	struct reply list = { .len = 0 };
	struct reply kids = { .len = 0 };
	unsigned short claim;
	size_t nest, i;

	put_attr(&body, CTRL_ATTR_FAMILY_NAME, fam->name, strlen(fam->name) + 1);
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	for (i = 0; i < ARRAY_SIZE(ops); i++)
		put_op(&list, i + 1, &ops[i]);

	put_attr(&kids, CTRL_ATTR_OP_FLAGS, &do_flag, sizeof(do_flag));
	put_attr(&list, 20, kids.buf, kids.len);

	kids = (struct reply) { .len = 0 };
	put_attr(&kids, CTRL_ATTR_OP_ID, &short_id, sizeof(short_id));
	put_attr(&kids, CTRL_ATTR_OP_FLAGS, &do_flag, sizeof(do_flag));
	put_attr(&list, 21, kids.buf, kids.len);

	kids = (struct reply) { .len = 0 };
	put_attr(&kids, CTRL_ATTR_OP_ID, &overlong_id, sizeof(overlong_id));
	put_attr(&kids, CTRL_ATTR_OP_FLAGS, &do_flag, sizeof(do_flag));
	nest = list.len;
	put_attr(&list, 22, kids.buf, kids.len);
	claim = list.len - nest + 64;
	memcpy(list.buf + nest, &claim, sizeof(claim));

	put_attr(&body, CTRL_ATTR_OPS, list.buf, list.len);
	put_attr(&body, 99, pad, sizeof(pad));
	put_msg(r, &body);
}

/* An op list whose own length runs past the end of the message. */
static void put_truncated_family(struct reply *r,
				 const struct genl_family_grammar *fam,
				 unsigned short id)
{
	static const struct op op = { 5, GENL_CMD_CAP_DO };
	struct reply body = { .len = 0 };
	struct reply list = { .len = 0 };
	unsigned short claim;
	size_t ops_at;

	put_attr(&body, CTRL_ATTR_FAMILY_NAME, fam->name, strlen(fam->name) + 1);
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	put_op(&list, 1, &op);
	ops_at = body.len;
	put_attr(&body, CTRL_ATTR_OPS, list.buf, list.len);
	claim = body.len - ops_at + 4096;
	memcpy(body.buf + ops_at, &claim, sizeof(claim));
	put_msg(r, &body);
}

/* The op list ahead of the name and the id. */
static void put_ops_first_family(struct reply *r,
				 const struct genl_family_grammar *fam,
				 unsigned short id)
{
	static const struct op ops[] = {
		{ 5, GENL_CMD_CAP_DUMP },
		{ 6, GENL_CMD_CAP_DO },
	};
	struct reply body = { .len = 0 };
	struct reply list = { .len = 0 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ops); i++)
		put_op(&list, i + 1, &ops[i]);
	put_attr(&body, CTRL_ATTR_OPS, list.buf, list.len);
	put_attr(&body, CTRL_ATTR_FAMILY_NAME, fam->name, strlen(fam->name) + 1);
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	put_msg(r, &body);
}

/* ---------- The families whose attributes are checked ----------------- */

/*
 * A slot of a kernel nla_policy as far as the generator shapes it: the
 * attribute's id, the payload lengths it takes and, for a nest, the policy
 * its children meet.  A scalar that the policy bounds with a mask or a
 * range says so, and so does one that its handler bounds where the policy
 * leaves it a plain NLA_U32; the generator draws inside the bound most of the
 * time, so a draw outside it is tallied rather than refused: the reject
 * arm wants some.  An array whose handler counts its elements against a
 * cap, or a nest whose parser takes a few children at most, is bounded the
 * same way, by a range of counts.  Other values are not the generator's to
 * shape and are not modelled.  A slot that the handler needs says so, and
 * the generator puts it in most streams of its policy and leaves it out of
 * some; one that the handler refuses twice says so, and is in a stream
 * once at most.  seen counts what the generator emitted, so a slot it
 * never reaches shows up.
 */
enum slot_kind { SK_BYTES, SK_SINT, SK_STRING, SK_NEST, SK_ARRAY };

/* NLA_POLICY_MASK: hi holds the bits a value may set.  NLA_POLICY_RANGE:
 * lo to hi, both inclusive; MAX and MIN are ranges that start at 0 and end
 * at the top of the type.  An array's range is of its elements, a nest's of
 * its children, from 1. */
enum slot_bound { SB_NONE, SB_MASK, SB_RANGE };

struct slot {
	unsigned short id;
	unsigned char kind;
	unsigned short min, max;	/* payload length; a string's max 0 is any */
	struct slot *nest;		/* SK_NEST, SK_ARRAY: the children's policy */
	unsigned int n_nest;
	unsigned int seen;
	unsigned char bound;		/* a scalar's bound, host order, or a count's */
	/* Wide enough for an NLA_UINT's 8-byte form; a byte's and a u32's
	 * bounds fit, as do the or/and/min/max of the draws inside one. */
	uint64_t lo, hi;
	unsigned int in_bound;		/* draws inside it, and what they span: */
	uint64_t or_all, and_all, min_v, max_v;
	bool required;			/* its handler needs it */
	bool once;			/* and refuses it twice */
	unsigned int streams;		/* the streams of its policy built, */
	unsigned int present;		/* and the ones that held it */
};

/* Each takes designated initializers after its own arguments, as in
 * S_U32(id, .required = true). */
#define S_BLOB(id, lo, hi, ...)	{ id, SK_BYTES, lo, hi, ##__VA_ARGS__ }
#define S_FLAG(id, ...)		S_BLOB(id, 0, 0, ##__VA_ARGS__)
#define S_U8(id, ...)		S_BLOB(id, 1, 1, ##__VA_ARGS__)
#define S_U16(id, ...)		S_BLOB(id, 2, 2, ##__VA_ARGS__)
#define S_U32(id, ...)		S_BLOB(id, 4, 4, ##__VA_ARGS__)
#define S_U64(id, ...)		S_BLOB(id, 8, 8, ##__VA_ARGS__)
#define S_SINT(id, ...)		{ id, SK_SINT, ##__VA_ARGS__ }
#define S_STR(id, hi, ...)	{ id, SK_STRING, 1, hi, ##__VA_ARGS__ }
#define S_NEST(id, tbl, ...) \
	{ id, SK_NEST, 0, 0, tbl, ARRAY_SIZE(tbl), ##__VA_ARGS__ }
#define S_ARRAY(id, tbl, ...) \
	{ id, SK_ARRAY, 0, 0, tbl, ARRAY_SIZE(tbl), ##__VA_ARGS__ }
#define S_NEST_MAX(id, tbl, cap, ...) \
	{ id, SK_NEST, 0, 0, tbl, ARRAY_SIZE(tbl), .bound = SB_RANGE, \
	  .lo = 1, .hi = cap, ##__VA_ARGS__ }
#define S_ARRAY_MAX(id, tbl, cap, ...) \
	{ id, SK_ARRAY, 0, 0, tbl, ARRAY_SIZE(tbl), .bound = SB_RANGE, \
	  .lo = 1, .hi = cap, ##__VA_ARGS__ }
#define S_U32_MASK(id, bits, ...) \
	{ id, SK_BYTES, 4, 4, .bound = SB_MASK, .hi = bits, ##__VA_ARGS__ }
#define S_U32_RANGE(id, from, to, ...) \
	{ id, SK_BYTES, 4, 4, .bound = SB_RANGE, .lo = from, .hi = to, ##__VA_ARGS__ }
#define S_U16_RANGE(id, from, to, ...) \
	{ id, SK_BYTES, 2, 2, .bound = SB_RANGE, .lo = from, .hi = to, ##__VA_ARGS__ }
#define S_U8_RANGE(id, from, to, ...) \
	{ id, SK_BYTES, 1, 1, .bound = SB_RANGE, .lo = from, .hi = to, ##__VA_ARGS__ }
/* An NLA_UINT takes 4 or 8 bytes, host order, and its bound is a u32's. */
#define S_UINT_RANGE(id, from, to, ...) \
	{ id, SK_BYTES, 4, 8, .bound = SB_RANGE, .lo = from, .hi = to, ##__VA_ARGS__ }
#define S_UINT_MASK(id, bits, ...) \
	{ id, SK_BYTES, 4, 8, .bound = SB_MASK, .hi = bits, ##__VA_ARGS__ }

/*
 * What a cmd's request takes.  A cmd with one row is checked the same
 * whether the request is a dump or not; a dump row, which has to follow the
 * cmd's other row, is for the dumpit whose policy differs.
 */
struct cmd_policy {
	unsigned char cmd;
	bool dump;
	struct slot *slots;
	unsigned int n_slots;	/* 0: the cmd takes no attribute */
	unsigned int msgs;	/* messages checked against it */
};

#define P_CMD(cmd, tbl)		{ cmd, false, tbl, ARRAY_SIZE(tbl) }
#define P_CMD_NONE(cmd)		{ cmd }
#define P_DUMP(cmd, tbl)	{ cmd, true, tbl, ARRAY_SIZE(tbl) }
#define P_DUMP_NONE(cmd)	{ cmd, true }

struct policy_family {
	struct genl_family_grammar *fam;
	unsigned short id;
	struct cmd_policy *cmds;
	unsigned int n_cmds;
};

#if __has_include(<linux/handshake.h>)
#include "kernel/handshake.h"

extern struct genl_family_grammar fam_handshake;

/* net/handshake/genl.c: handshake_accept_nl_policy, handshake_done_nl_policy */
static struct slot handshake_accept[] = {
	S_U32_RANGE(HANDSHAKE_A_ACCEPT_HANDLER_CLASS, 0, 1),
};
static struct slot handshake_done[] = {
	S_U32_RANGE(HANDSHAKE_A_DONE_STATUS, 0, 4095),
	S_U32(HANDSHAKE_A_DONE_SOCKFD, .required = true),
	S_U32(HANDSHAKE_A_DONE_REMOTE_AUTH),
};
static struct cmd_policy handshake_cmds[] = {
	P_CMD_NONE(HANDSHAKE_CMD_READY),
	P_CMD(HANDSHAKE_CMD_ACCEPT, handshake_accept),
	P_CMD(HANDSHAKE_CMD_DONE, handshake_done),
};
#endif

#if __has_include(<linux/vdpa.h>)
#include "kernel/vdpa.h"

extern struct genl_family_grammar fam_vdpa;

/*
 * drivers/vdpa/vdpa.c: vdpa_nl_policy, which every op shares, as far as each
 * op's handler reads it; no dumpit reads any, so a dump takes all eight.
 */
static struct slot vdpa_policy[] = {
	S_STR(VDPA_ATTR_MGMTDEV_BUS_NAME, 0),
	S_STR(VDPA_ATTR_MGMTDEV_DEV_NAME, 0),
	S_STR(VDPA_ATTR_DEV_NAME, 0),
	S_BLOB(VDPA_ATTR_DEV_NET_CFG_MACADDR, 6, 6),
	S_U16(VDPA_ATTR_DEV_NET_CFG_MAX_VQP),
	S_U16_RANGE(VDPA_ATTR_DEV_NET_CFG_MTU, 68, UINT16_MAX),
	S_U32(VDPA_ATTR_DEV_QUEUE_INDEX),
	S_U64(VDPA_ATTR_DEV_FEATURES),
};
static struct slot vdpa_mgmtdev_get[] = {
	S_STR(VDPA_ATTR_MGMTDEV_BUS_NAME, 0),
	S_STR(VDPA_ATTR_MGMTDEV_DEV_NAME, 0, .required = true),
};
static struct slot vdpa_dev_new[] = {
	S_STR(VDPA_ATTR_MGMTDEV_BUS_NAME, 0),
	S_STR(VDPA_ATTR_MGMTDEV_DEV_NAME, 0, .required = true),
	S_STR(VDPA_ATTR_DEV_NAME, 0, .required = true),
	S_BLOB(VDPA_ATTR_DEV_NET_CFG_MACADDR, 6, 6),
	S_U16(VDPA_ATTR_DEV_NET_CFG_MAX_VQP),
	S_U16_RANGE(VDPA_ATTR_DEV_NET_CFG_MTU, 68, UINT16_MAX),
	S_U64(VDPA_ATTR_DEV_FEATURES),
};
static struct slot vdpa_dev_name[] = {
	S_STR(VDPA_ATTR_DEV_NAME, 0),
};
static struct slot vdpa_dev_vstats[] = {
	S_STR(VDPA_ATTR_DEV_NAME, 0, .required = true),
	S_U32(VDPA_ATTR_DEV_QUEUE_INDEX, .required = true),
};
static struct slot vdpa_dev_attr_set[] = {
	S_STR(VDPA_ATTR_DEV_NAME, 0, .required = true),
	S_BLOB(VDPA_ATTR_DEV_NET_CFG_MACADDR, 6, 6),
};
static struct cmd_policy vdpa_cmds[] = {
	P_CMD(VDPA_CMD_MGMTDEV_GET, vdpa_mgmtdev_get),
	P_DUMP(VDPA_CMD_MGMTDEV_GET, vdpa_policy),
	P_CMD(VDPA_CMD_DEV_NEW, vdpa_dev_new),
	P_CMD(VDPA_CMD_DEV_DEL, vdpa_dev_name),
	P_CMD(VDPA_CMD_DEV_GET, vdpa_dev_name),
	P_DUMP(VDPA_CMD_DEV_GET, vdpa_policy),
	P_CMD(VDPA_CMD_DEV_CONFIG_GET, vdpa_dev_name),
	P_DUMP(VDPA_CMD_DEV_CONFIG_GET, vdpa_policy),
	P_CMD(VDPA_CMD_DEV_VSTATS_GET, vdpa_dev_vstats),
	P_CMD(VDPA_CMD_DEV_ATTR_SET, vdpa_dev_attr_set),
};
#endif

#if __has_include(<linux/nfsd_netlink.h>)
#include "kernel/nfsd_netlink.h"

extern struct genl_family_grammar fam_nfsd;

/* fs/nfsd/netlink.c: the nfsd_*_nl_policy tables */
static struct slot nfsd_fslocation[] = {
	S_STR(NFSD_A_FSLOCATION_HOST, 0, .required = true),
	S_STR(NFSD_A_FSLOCATION_PATH, 0, .required = true),
};
static struct slot nfsd_fslocations[] = {
	S_NEST(NFSD_A_FSLOCATIONS_LOCATION, nfsd_fslocation),
};
static struct slot nfsd_auth_flavor[] = {
	S_U32(NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR),
	S_U32_MASK(NFSD_A_AUTH_FLAVOR_FLAGS, 0x3ffff),
};
static struct slot nfsd_svc_export[] = {
	S_U64(NFSD_A_SVC_EXPORT_SEQNO),
	S_STR(NFSD_A_SVC_EXPORT_CLIENT, 0, .required = true),
	S_STR(NFSD_A_SVC_EXPORT_PATH, 0, .required = true),
	S_FLAG(NFSD_A_SVC_EXPORT_NEGATIVE),
	S_U64(NFSD_A_SVC_EXPORT_EXPIRY, .required = true),
	S_U32(NFSD_A_SVC_EXPORT_ANON_UID),
	S_U32(NFSD_A_SVC_EXPORT_ANON_GID),
	S_NEST(NFSD_A_SVC_EXPORT_FSLOCATIONS, nfsd_fslocations),
	S_BLOB(NFSD_A_SVC_EXPORT_UUID, 0, 0xffff),
	S_NEST(NFSD_A_SVC_EXPORT_SECINFO, nfsd_auth_flavor),
	S_U32_MASK(NFSD_A_SVC_EXPORT_XPRTSEC, 0x7),
	S_U32_MASK(NFSD_A_SVC_EXPORT_FLAGS, 0x3ffff),
	S_U32(NFSD_A_SVC_EXPORT_FSID),
};
static struct slot nfsd_expkey[] = {
	S_U64(NFSD_A_EXPKEY_SEQNO),
	S_STR(NFSD_A_EXPKEY_CLIENT, 0, .required = true),
	S_U8(NFSD_A_EXPKEY_FSIDTYPE, .required = true),
	S_BLOB(NFSD_A_EXPKEY_FSID, 0, 0xffff, .required = true),
	S_FLAG(NFSD_A_EXPKEY_NEGATIVE),
	S_U64(NFSD_A_EXPKEY_EXPIRY, .required = true),
	S_STR(NFSD_A_EXPKEY_PATH, 0),
};
static struct slot nfsd_version[] = {
	S_U32(NFSD_A_VERSION_MAJOR, .required = true),
	S_U32(NFSD_A_VERSION_MINOR),
	S_FLAG(NFSD_A_VERSION_ENABLED),
};
static struct slot nfsd_sock[] = {
	S_BLOB(NFSD_A_SOCK_ADDR, 0, 0xffff, .required = true),
	S_STR(NFSD_A_SOCK_TRANSPORT_NAME, 0, .required = true),
};
static struct slot nfsd_threads_set[] = {
	S_U32(NFSD_A_SERVER_THREADS, .required = true),
	/* nfsd_nl_threads_set_doit() refuses either time outside [10, 3600] */
	S_U32_RANGE(NFSD_A_SERVER_GRACETIME, 10, 3600),
	S_U32_RANGE(NFSD_A_SERVER_LEASETIME, 10, 3600),
	S_STR(NFSD_A_SERVER_SCOPE, 0),
	S_U32(NFSD_A_SERVER_MIN_THREADS),
	S_BLOB(NFSD_A_SERVER_FH_KEY, 16, 16),
};
static struct slot nfsd_version_set[] = {
	S_NEST(NFSD_A_SERVER_PROTO_VERSION, nfsd_version),
};
static struct slot nfsd_listener_set[] = {
	S_NEST(NFSD_A_SERVER_SOCK_ADDR, nfsd_sock),
	S_FLAG(NFSD_A_SERVER_SOCK_USERSPACE_RPCBIND),
};
static struct slot nfsd_pool_mode_set[] = {
	S_STR(NFSD_A_POOL_MODE_MODE, 0),
};
static struct slot nfsd_svc_export_set_reqs[] = {
	S_NEST(NFSD_A_SVC_EXPORT_REQS_REQUESTS, nfsd_svc_export),
};
static struct slot nfsd_expkey_set_reqs[] = {
	S_NEST(NFSD_A_EXPKEY_REQS_REQUESTS, nfsd_expkey),
};
static struct slot nfsd_cache_flush[] = {
	S_U32_MASK(NFSD_A_CACHE_FLUSH_MASK, 0x3),
};
static struct slot nfsd_unlock_ip[] = {
	S_BLOB(NFSD_A_UNLOCK_IP_ADDRESS, 16, 0xffff),
};
static struct slot nfsd_unlock_filesystem[] = {
	S_STR(NFSD_A_UNLOCK_FILESYSTEM_PATH, 0),
};
static struct slot nfsd_unlock_export[] = {
	S_STR(NFSD_A_UNLOCK_EXPORT_PATH, 0),
};
/* The ops with no policy get a reject-all one, so take no attribute. */
static struct cmd_policy nfsd_cmds[] = {
	P_CMD_NONE(NFSD_CMD_RPC_STATUS_GET),
	P_CMD(NFSD_CMD_THREADS_SET, nfsd_threads_set),
	P_CMD_NONE(NFSD_CMD_THREADS_GET),
	P_CMD(NFSD_CMD_VERSION_SET, nfsd_version_set),
	P_CMD_NONE(NFSD_CMD_VERSION_GET),
	P_CMD(NFSD_CMD_LISTENER_SET, nfsd_listener_set),
	P_CMD_NONE(NFSD_CMD_LISTENER_GET),
	P_CMD(NFSD_CMD_POOL_MODE_SET, nfsd_pool_mode_set),
	P_CMD_NONE(NFSD_CMD_POOL_MODE_GET),
	P_CMD_NONE(NFSD_CMD_CACHE_NOTIFY),
	P_CMD_NONE(NFSD_CMD_SVC_EXPORT_GET_REQS),
	P_CMD(NFSD_CMD_SVC_EXPORT_SET_REQS, nfsd_svc_export_set_reqs),
	P_CMD_NONE(NFSD_CMD_EXPKEY_GET_REQS),
	P_CMD(NFSD_CMD_EXPKEY_SET_REQS, nfsd_expkey_set_reqs),
	P_CMD(NFSD_CMD_CACHE_FLUSH, nfsd_cache_flush),
	P_CMD(NFSD_CMD_UNLOCK_IP, nfsd_unlock_ip),
	P_CMD(NFSD_CMD_UNLOCK_FILESYSTEM, nfsd_unlock_filesystem),
	P_CMD(NFSD_CMD_UNLOCK_EXPORT, nfsd_unlock_export),
	P_CMD_NONE(NFSD_CMD_SERVER_STATS_GET),
};
#endif

#if __has_include(<linux/dpll.h>)
#include "kernel/dpll.h"

extern struct genl_family_grammar fam_dpll;

/* drivers/dpll/dpll_nl.c: the dpll_*_nl_policy tables */
static struct slot dpll_parent_device[] = {
	S_U32(DPLL_A_PIN_PARENT_ID, .required = true),
	S_U32_RANGE(DPLL_A_PIN_DIRECTION, 1, 2),
	S_U32(DPLL_A_PIN_PRIO),
	S_U32_RANGE(DPLL_A_PIN_STATE, 1, 3),
	S_U32_RANGE(DPLL_A_PIN_OPERSTATE, 1, 4),
	S_U64(DPLL_A_PIN_PHASE_OFFSET),
	S_SINT(DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET),
	S_SINT(DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT),
};
static struct slot dpll_parent_pin[] = {
	S_U32(DPLL_A_PIN_PARENT_ID, .required = true),
	S_U32_RANGE(DPLL_A_PIN_STATE, 1, 3),
};
static struct slot dpll_reference_sync[] = {
	S_U32(DPLL_A_PIN_ID, .required = true),
	S_U32_RANGE(DPLL_A_PIN_STATE, 1, 3, .required = true),
};
/* The ID_GET lookups refuse an attribute given twice. */
static struct slot dpll_device_id_get[] = {
	S_STR(DPLL_A_MODULE_NAME, 0, .once = true),
	S_U64(DPLL_A_CLOCK_ID, .once = true),
	S_U32_RANGE(DPLL_A_TYPE, 1, 3, .once = true),
};
static struct slot dpll_device_get[] = {
	S_U32(DPLL_A_ID),
};
static struct slot dpll_device_set[] = {
	S_U32(DPLL_A_ID, .required = true),
	S_U32_RANGE(DPLL_A_MODE, 1, 2),
	S_U32_RANGE(DPLL_A_PHASE_OFFSET_MONITOR, 0, 1),
	S_U32(DPLL_A_PHASE_OFFSET_AVG_FACTOR),
	S_U32_RANGE(DPLL_A_FREQUENCY_MONITOR, 0, 1),
};
static struct slot dpll_pin_id_get[] = {
	S_STR(DPLL_A_PIN_MODULE_NAME, 0, .once = true),
	S_U64(DPLL_A_PIN_CLOCK_ID, .once = true),
	S_STR(DPLL_A_PIN_BOARD_LABEL, 0, .once = true),
	S_STR(DPLL_A_PIN_PANEL_LABEL, 0, .once = true),
	S_STR(DPLL_A_PIN_PACKAGE_LABEL, 0, .once = true),
	S_U32_RANGE(DPLL_A_PIN_TYPE, 1, 6, .once = true),
};
static struct slot dpll_pin_get[] = {
	S_U32(DPLL_A_PIN_ID),
};
static struct slot dpll_pin_set[] = {
	S_U32(DPLL_A_PIN_ID, .required = true),
	S_U64(DPLL_A_PIN_FREQUENCY),
	S_NEST(DPLL_A_PIN_PARENT_DEVICE, dpll_parent_device),
	S_NEST(DPLL_A_PIN_PARENT_PIN, dpll_parent_pin),
	S_U32(DPLL_A_PIN_PHASE_ADJUST),
	S_U64(DPLL_A_PIN_ESYNC_FREQUENCY),
	S_NEST(DPLL_A_PIN_REFERENCE_SYNC, dpll_reference_sync),
};
/* The dumpits of DEVICE_GET and PIN_GET have no policy, so take nothing. */
static struct cmd_policy dpll_cmds[] = {
	P_CMD(DPLL_CMD_DEVICE_ID_GET, dpll_device_id_get),
	P_CMD(DPLL_CMD_DEVICE_GET, dpll_device_get),
	P_DUMP_NONE(DPLL_CMD_DEVICE_GET),
	P_CMD(DPLL_CMD_DEVICE_SET, dpll_device_set),
	P_CMD(DPLL_CMD_PIN_ID_GET, dpll_pin_id_get),
	P_CMD(DPLL_CMD_PIN_GET, dpll_pin_get),
	P_DUMP_NONE(DPLL_CMD_PIN_GET),
	P_CMD(DPLL_CMD_PIN_SET, dpll_pin_set),
};
#endif

#if __has_include(<linux/wireguard.h>)
#include "kernel/wireguard.h"

extern struct genl_family_grammar fam_wireguard;

/* drivers/net/wireguard/generated/netlink.c: the wireguard_*_nl_policy tables */
static struct slot wireguard_allowedip[] = {
	S_U16(WGALLOWEDIP_A_FAMILY, .required = true),
	S_BLOB(WGALLOWEDIP_A_IPADDR, 4, 0xffff, .required = true),
	S_U8(WGALLOWEDIP_A_CIDR_MASK, .required = true),
	S_U32_MASK(WGALLOWEDIP_A_FLAGS, 0x1),
};
static struct slot wireguard_peer[] = {
	S_BLOB(WGPEER_A_PUBLIC_KEY, WG_KEY_LEN, WG_KEY_LEN, .required = true),
	S_BLOB(WGPEER_A_PRESHARED_KEY, WG_KEY_LEN, WG_KEY_LEN),
	S_U32_MASK(WGPEER_A_FLAGS, 0x7),
	S_BLOB(WGPEER_A_ENDPOINT, 16, 0xffff),
	S_U16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL),
	S_BLOB(WGPEER_A_LAST_HANDSHAKE_TIME, 16, 16),
	S_U64(WGPEER_A_RX_BYTES),
	S_U64(WGPEER_A_TX_BYTES),
	S_ARRAY(WGPEER_A_ALLOWEDIPS, wireguard_allowedip),
	/* set_peer() answers -EPFNOSUPPORT to any version but 1 */
	S_U32_RANGE(WGPEER_A_PROTOCOL_VERSION, 1, 1),
};
static struct slot wireguard_get_device[] = {
	S_U32(WGDEVICE_A_IFINDEX),
	S_STR(WGDEVICE_A_IFNAME, 15),
};
static struct slot wireguard_set_device[] = {
	S_U32(WGDEVICE_A_IFINDEX),
	S_STR(WGDEVICE_A_IFNAME, 15),
	S_BLOB(WGDEVICE_A_PRIVATE_KEY, WG_KEY_LEN, WG_KEY_LEN),
	S_BLOB(WGDEVICE_A_PUBLIC_KEY, WG_KEY_LEN, WG_KEY_LEN),
	S_U32_MASK(WGDEVICE_A_FLAGS, 0x1),
	S_U16(WGDEVICE_A_LISTEN_PORT),
	S_U32(WGDEVICE_A_FWMARK),
	S_ARRAY(WGDEVICE_A_PEERS, wireguard_peer),
};
static struct cmd_policy wireguard_cmds[] = {
	P_CMD(WG_CMD_GET_DEVICE, wireguard_get_device),
	P_CMD(WG_CMD_SET_DEVICE, wireguard_set_device),
};
#endif

#if __has_include(<drm/drm_ras.h>)
#include "kernel/drm_ras.h"

extern struct genl_family_grammar fam_drm_ras;

/* drivers/gpu/drm/drm_ras_nl.c: the drm_ras_*_nl_policy tables */
static struct slot drm_ras_counter[] = {
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, .required = true),
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, .required = true),
};
static struct slot drm_ras_counter_dump[] = {
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID),
};
static struct slot drm_ras_clear_counter[] = {
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, .required = true),
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, .required = true),
};
static struct slot drm_ras_get_threshold[] = {
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, .required = true),
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, .required = true),
};
static struct slot drm_ras_set_threshold[] = {
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, .required = true),
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, .required = true),
	S_U32(DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_THRESHOLD, .required = true),
};
/* LIST_NODES is a dumpit with no policy, so takes nothing. */
static struct cmd_policy drm_ras_cmds[] = {
	P_CMD_NONE(DRM_RAS_CMD_LIST_NODES),
	P_CMD(DRM_RAS_CMD_GET_ERROR_COUNTER, drm_ras_counter),
	P_DUMP(DRM_RAS_CMD_GET_ERROR_COUNTER, drm_ras_counter_dump),
	P_CMD(DRM_RAS_CMD_CLEAR_ERROR_COUNTER, drm_ras_clear_counter),
	P_CMD(DRM_RAS_CMD_GET_ERROR_THRESHOLD, drm_ras_get_threshold),
	P_CMD(DRM_RAS_CMD_SET_ERROR_THRESHOLD, drm_ras_set_threshold),
};
#endif

#if __has_include(<linux/lockd_netlink.h>)
#include "kernel/lockd_netlink.h"

extern struct genl_family_grammar fam_lockd;

/* fs/lockd/netlink.c: lockd_server_set_nl_policy.  lockd_nl_server_set_doit()
 * answers -EINVAL without GRACETIME or with one past nlm_grace_period_max,
 * 240 seconds. */
static struct slot lockd_server_set[] = {
	S_U32_RANGE(LOCKD_A_SERVER_GRACETIME, 0, 240, .required = true),
	S_U16(LOCKD_A_SERVER_TCP_PORT),
	S_U16(LOCKD_A_SERVER_UDP_PORT),
};
/* SERVER_GET has no policy, so the genl core gives it a reject-all one. */
static struct cmd_policy lockd_cmds[] = {
	P_CMD(LOCKD_CMD_SERVER_SET, lockd_server_set),
	P_CMD_NONE(LOCKD_CMD_SERVER_GET),
};
#endif

#if __has_include(<linux/sunrpc_netlink.h>)
#include "kernel/sunrpc_netlink.h"

extern struct genl_family_grammar fam_sunrpc;

/* net/sunrpc/netlink.c: the sunrpc_*_nl_policy tables.  The parsers of an
 * entry in net/sunrpc/svcauth_unix.c answer -EINVAL to an ip_map without
 * its CLASS, ADDR or EXPIRY and to a unix_gid without its UID or EXPIRY. */
static struct slot sunrpc_ip_map[] = {
	S_U64(SUNRPC_A_IP_MAP_SEQNO),
	S_STR(SUNRPC_A_IP_MAP_CLASS, 0, .required = true),
	S_STR(SUNRPC_A_IP_MAP_ADDR, 0, .required = true),
	S_STR(SUNRPC_A_IP_MAP_DOMAIN, 0),
	S_FLAG(SUNRPC_A_IP_MAP_NEGATIVE),
	S_U64(SUNRPC_A_IP_MAP_EXPIRY, .required = true),
};
static struct slot sunrpc_unix_gid[] = {
	S_U64(SUNRPC_A_UNIX_GID_SEQNO),
	S_U32(SUNRPC_A_UNIX_GID_UID, .required = true),
	S_U32(SUNRPC_A_UNIX_GID_GIDS),
	S_FLAG(SUNRPC_A_UNIX_GID_NEGATIVE),
	S_U64(SUNRPC_A_UNIX_GID_EXPIRY, .required = true),
};
static struct slot sunrpc_ip_map_set_reqs[] = {
	S_NEST(SUNRPC_A_IP_MAP_REQS_REQUESTS, sunrpc_ip_map),
};
static struct slot sunrpc_unix_gid_set_reqs[] = {
	S_NEST(SUNRPC_A_UNIX_GID_REQS_REQUESTS, sunrpc_unix_gid),
};
static struct slot sunrpc_cache_flush[] = {
	S_U32_MASK(SUNRPC_A_CACHE_FLUSH_MASK, 0x3),
};
/* The GET_REQS dumpits have no policy, so take nothing. */
static struct cmd_policy sunrpc_cmds[] = {
	P_CMD_NONE(SUNRPC_CMD_CACHE_NOTIFY),
	P_CMD_NONE(SUNRPC_CMD_IP_MAP_GET_REQS),
	P_CMD(SUNRPC_CMD_IP_MAP_SET_REQS, sunrpc_ip_map_set_reqs),
	P_CMD_NONE(SUNRPC_CMD_UNIX_GID_GET_REQS),
	P_CMD(SUNRPC_CMD_UNIX_GID_SET_REQS, sunrpc_unix_gid_set_reqs),
	P_CMD(SUNRPC_CMD_CACHE_FLUSH, sunrpc_cache_flush),
};
#endif

#include "kernel/psp.h"

extern struct genl_family_grammar fam_psp;

/* net/psp/psp-nl-gen.c: the psp_*_nl_policy tables, whose device ids are
 * NLA_POLICY_MIN(NLA_U32, 1).  The pre_doits of net/psp/psp_nl.c answer
 * -EINVAL without the DEV_ID or the SOCK_FD they look up, and an assoc
 * whose socket has no device yet without ASSOC_DEV_ID; the doits do the
 * same without ASSOC_VERSION, TX_KEY and the KEY and SPI in it, and the
 * DEV_IFINDEX a device is (dis)associated with. */
static struct slot psp_keys[] = {
	S_BLOB(PSP_A_KEYS_KEY, 0, 0xffff, .required = true),
	S_U32(PSP_A_KEYS_SPI, .required = true),
};
static struct slot psp_dev_get[] = {
	S_U32_RANGE(PSP_A_DEV_ID, 1, UINT32_MAX),
};
static struct slot psp_dev_set[] = {
	S_U32_RANGE(PSP_A_DEV_ID, 1, UINT32_MAX, .required = true),
	S_U32_MASK(PSP_A_DEV_PSP_VERSIONS_ENA, 0xf),
};
static struct slot psp_key_rotate[] = {
	S_U32_RANGE(PSP_A_DEV_ID, 1, UINT32_MAX),
};
static struct slot psp_rx_assoc[] = {
	S_U32_RANGE(PSP_A_ASSOC_DEV_ID, 1, UINT32_MAX, .required = true),
	S_U32_RANGE(PSP_A_ASSOC_VERSION, 0, 3, .required = true),
	S_U32(PSP_A_ASSOC_SOCK_FD, .required = true),
};
static struct slot psp_tx_assoc[] = {
	S_U32_RANGE(PSP_A_ASSOC_DEV_ID, 1, UINT32_MAX, .required = true),
	S_U32_RANGE(PSP_A_ASSOC_VERSION, 0, 3, .required = true),
	S_NEST(PSP_A_ASSOC_TX_KEY, psp_keys, .required = true),
	S_U32(PSP_A_ASSOC_SOCK_FD, .required = true),
};
static struct slot psp_get_stats[] = {
	S_U32_RANGE(PSP_A_STATS_DEV_ID, 1, UINT32_MAX),
};
static struct slot psp_dev_assoc[] = {
	S_U32_RANGE(PSP_A_DEV_ID, 1, UINT32_MAX, .required = true),
	S_U32(PSP_A_DEV_IFINDEX, .required = true),
	S_U32(PSP_A_DEV_NSID),
};
static struct slot psp_dev_disassoc[] = {
	S_U32_RANGE(PSP_A_DEV_ID, 1, UINT32_MAX, .required = true),
	S_U32(PSP_A_DEV_IFINDEX, .required = true),
	S_U32(PSP_A_DEV_NSID),
};
/* The dumpits of DEV_GET and GET_STATS have no policy, so take nothing. */
static struct cmd_policy psp_cmds[] = {
	P_CMD(PSP_CMD_DEV_GET, psp_dev_get),
	P_DUMP_NONE(PSP_CMD_DEV_GET),
	P_CMD(PSP_CMD_DEV_SET, psp_dev_set),
	P_CMD(PSP_CMD_KEY_ROTATE, psp_key_rotate),
	P_CMD(PSP_CMD_RX_ASSOC, psp_rx_assoc),
	P_CMD(PSP_CMD_TX_ASSOC, psp_tx_assoc),
	P_CMD(PSP_CMD_GET_STATS, psp_get_stats),
	P_DUMP_NONE(PSP_CMD_GET_STATS),
	P_CMD(PSP_CMD_DEV_ASSOC, psp_dev_assoc),
	P_CMD(PSP_CMD_DEV_DISASSOC, psp_dev_disassoc),
};

#if __has_include(<linux/netdev.h>)
#include "kernel/netdev.h"

extern struct genl_family_grammar fam_netdev;

/*
 * net/core/netdev-genl-gen.c: the netdev_*_nl_policy tables.  An NLA_UINT
 * takes 4 or 8 bytes, host order, and its bounds are mirrored as
 * NLA_KIND_UINT_*; RX_PAGE_SIZE's floor is the kernel's PAGE_SIZE, 4096
 * on the 4 KiB-page kernels this table targets.  The handlers in
 * net/core/netdev-genl.c and page_pool_user.c answer -EINVAL without
 * what they look up: a queue's id, type and ifindex, a lease's ifindex and
 * queue, a dmabuf's ifindex, fd and queues, a NAPI id, a page pool id.
 */
static struct slot netdev_queue_id[] = {
	S_U32(NETDEV_A_QUEUE_ID, .required = true),
	S_U32_RANGE(NETDEV_A_QUEUE_TYPE, 0, 1, .required = true),
};
static struct slot netdev_page_pool_info[] = {
	S_UINT_RANGE(NETDEV_A_PAGE_POOL_ID, 1, UINT32_MAX, .required = true),
	S_U32_RANGE(NETDEV_A_PAGE_POOL_IFINDEX, 1, INT32_MAX),
};
static struct slot netdev_lease[] = {
	S_U32_RANGE(NETDEV_A_LEASE_IFINDEX, 1, UINT32_MAX, .required = true),
	S_NEST(NETDEV_A_LEASE_QUEUE, netdev_queue_id, .required = true),
	S_U32_RANGE(NETDEV_A_LEASE_NETNS_ID, 0, INT32_MAX),
};
static struct slot netdev_dev_get[] = {
	S_U32_RANGE(NETDEV_A_DEV_IFINDEX, 1, UINT32_MAX),
};
static struct slot netdev_page_pool_get_do[] = {
	S_UINT_RANGE(NETDEV_A_PAGE_POOL_ID, 1, UINT32_MAX),
};
static struct slot netdev_page_pool_get_dump[] = {
	S_U32_RANGE(NETDEV_A_PAGE_POOL_IFINDEX, 1, INT32_MAX),
};
static struct slot netdev_page_pool_stats_get[] = {
	S_NEST(NETDEV_A_PAGE_POOL_STATS_INFO, netdev_page_pool_info),
};
static struct slot netdev_queue_get_do[] = {
	S_U32_RANGE(NETDEV_A_QUEUE_IFINDEX, 1, UINT32_MAX, .required = true),
	S_U32_RANGE(NETDEV_A_QUEUE_TYPE, 0, 1, .required = true),
	S_U32(NETDEV_A_QUEUE_ID, .required = true),
};
static struct slot netdev_queue_get_dump[] = {
	S_U32_RANGE(NETDEV_A_QUEUE_IFINDEX, 1, UINT32_MAX),
};
static struct slot netdev_napi_get_do[] = {
	S_U32(NETDEV_A_NAPI_ID),
};
static struct slot netdev_napi_get_dump[] = {
	S_U32_RANGE(NETDEV_A_NAPI_IFINDEX, 1, UINT32_MAX),
};
static struct slot netdev_qstats_get[] = {
	S_U32_RANGE(NETDEV_A_QSTATS_IFINDEX, 1, UINT32_MAX),
	S_UINT_MASK(NETDEV_A_QSTATS_SCOPE, 0x1),
};
static struct slot netdev_bind_rx[] = {
	S_U32_RANGE(NETDEV_A_DMABUF_IFINDEX, 1, UINT32_MAX, .required = true),
	S_U32(NETDEV_A_DMABUF_FD, .required = true),
	S_NEST(NETDEV_A_DMABUF_QUEUES, netdev_queue_id, .required = true),
	S_U32_RANGE(NETDEV_A_DMABUF_RX_PAGE_SIZE, 4096, UINT32_MAX),
};
static struct slot netdev_napi_set[] = {
	S_U32(NETDEV_A_NAPI_ID, .required = true),
	S_U32_RANGE(NETDEV_A_NAPI_DEFER_HARD_IRQS, 0, INT32_MAX),
	S_SINT(NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT),
	S_SINT(NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT),
	S_U32_RANGE(NETDEV_A_NAPI_THREADED, 0, 2),
};
static struct slot netdev_bind_tx[] = {
	S_U32_RANGE(NETDEV_A_DMABUF_IFINDEX, 1, UINT32_MAX, .required = true),
	S_U32(NETDEV_A_DMABUF_FD, .required = true),
};
static struct slot netdev_queue_create[] = {
	S_U32_RANGE(NETDEV_A_QUEUE_IFINDEX, 1, UINT32_MAX, .required = true),
	S_U32_RANGE(NETDEV_A_QUEUE_TYPE, 0, 1, .required = true),
	S_NEST(NETDEV_A_QUEUE_LEASE, netdev_lease, .required = true),
};
/* The dumpit of DEV_GET has no policy, so takes nothing. */
static struct cmd_policy netdev_cmds[] = {
	P_CMD(NETDEV_CMD_DEV_GET, netdev_dev_get),
	P_DUMP_NONE(NETDEV_CMD_DEV_GET),
	P_CMD(NETDEV_CMD_PAGE_POOL_GET, netdev_page_pool_get_do),
	P_DUMP(NETDEV_CMD_PAGE_POOL_GET, netdev_page_pool_get_dump),
	P_CMD(NETDEV_CMD_PAGE_POOL_STATS_GET, netdev_page_pool_stats_get),
	P_CMD(NETDEV_CMD_QUEUE_GET, netdev_queue_get_do),
	P_DUMP(NETDEV_CMD_QUEUE_GET, netdev_queue_get_dump),
	P_CMD(NETDEV_CMD_QUEUE_CREATE, netdev_queue_create),
	P_CMD(NETDEV_CMD_NAPI_GET, netdev_napi_get_do),
	P_DUMP(NETDEV_CMD_NAPI_GET, netdev_napi_get_dump),
	P_CMD(NETDEV_CMD_NAPI_SET, netdev_napi_set),
	P_CMD(NETDEV_CMD_QSTATS_GET, netdev_qstats_get),
	P_CMD(NETDEV_CMD_BIND_RX, netdev_bind_rx),
	P_CMD(NETDEV_CMD_BIND_TX, netdev_bind_tx),
};
#endif

#if __has_include(<linux/ethtool_netlink_generated.h>)
#include "kernel/ethtool.h"		/* ETHTOOL_MAC_STATS_SRC_PMAC, ETH_SS_PHY_INTERFACES */
#include "kernel/ethtool_netlink_generated.h"

extern struct genl_family_grammar fam_ethtool;

/*
 * net/ethtool: the header policies the read-side cmds nest,
 * ethnl_header_policy, ethnl_header_policy_stats, whose FLAGS mask takes
 * ETHTOOL_FLAG_STATS as well (ETHTOOL_FLAGS_STATS, against
 * ETHTOOL_FLAGS_BASIC), and ethnl_header_policy_phy, and the
 * ethnl_*_get_policy tables.  Most cmds' policy is the HEADER alone, so
 * those rows share a table.  DEV_INDEX is bounded to lo's, LOOPBACK_IFINDEX,
 * since the header's DEV_NAME is "lo" and ethnl_parse_header_dev_get()
 * refuses an index that names another device.
 */
static struct slot ethtool_header[] = {
	S_U32_RANGE(ETHTOOL_A_HEADER_DEV_INDEX, 1, 1),
	S_STR(ETHTOOL_A_HEADER_DEV_NAME, 127),
	S_U32_MASK(ETHTOOL_A_HEADER_FLAGS, 0x3),
};
static struct slot ethtool_header_stats[] = {
	S_U32_RANGE(ETHTOOL_A_HEADER_DEV_INDEX, 1, 1),
	S_STR(ETHTOOL_A_HEADER_DEV_NAME, 127),
	S_U32_MASK(ETHTOOL_A_HEADER_FLAGS, 0x7),
};
static struct slot ethtool_header_phy[] = {
	S_U32_RANGE(ETHTOOL_A_HEADER_DEV_INDEX, 1, 1),
	S_STR(ETHTOOL_A_HEADER_DEV_NAME, 127),
	S_U32_MASK(ETHTOOL_A_HEADER_FLAGS, 0x3),
	S_U32_RANGE(ETHTOOL_A_HEADER_PHY_INDEX, 1, UINT32_MAX),
};
/* get_stringset_policy takes any NLA_U32, and strset_parse_request() answers
 * an id from ETH_SS_COUNT up -EOPNOTSUPP.  There are 24 string sets, 0 to
 * ETH_SS_PHY_INTERFACES, in the kernel this was written from. */
static struct slot ethtool_stringset[] = {
	S_U32_RANGE(ETHTOOL_A_STRINGSET_ID, 0, ETH_SS_PHY_INTERFACES),
};
static struct slot ethtool_stringsets[] = {
	S_NEST(ETHTOOL_A_STRINGSETS_STRINGSET, ethtool_stringset),
};
/* net/ethtool/ts.h: ethnl_ts_hwtst_prov_policy, whose INDEX is a range from 0
 * to INT_MAX, since phc_index is an int and -1 means no PHC, and whose
 * QUALIFIER is NLA_POLICY_MAX(NLA_U32, HWTSTAMP_PROVIDER_QUALIFIER_CNT - 1),
 * the count being 2. */
static struct slot ethtool_ts_provider[] = {
	S_U32_RANGE(ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX, 0, INT_MAX),
	S_U32_RANGE(ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER, 0, 1),
};
/* net/ethtool/bitset.c: bitset_policy and bit_policy.  SIZE is capped at
 * ETHNL_MAX_BITSET_SIZE, 32767, and the compact form's VALUE and MASK are
 * each DIV_ROUND_UP(SIZE, 32) words long, a coupling between two
 * attributes no slot expresses, so the blobs are capped at 64 bytes. */
static struct slot ethtool_bit[] = {
	S_U32(ETHTOOL_A_BITSET_BIT_INDEX),
	S_STR(ETHTOOL_A_BITSET_BIT_NAME, 32),
	S_FLAG(ETHTOOL_A_BITSET_BIT_VALUE),
};
static struct slot ethtool_bitset[] = {
	S_FLAG(ETHTOOL_A_BITSET_NOMASK),
	S_U32_RANGE(ETHTOOL_A_BITSET_SIZE, 0, 32767),
	S_ARRAY(ETHTOOL_A_BITSET_BITS, ethtool_bit),
	S_BLOB(ETHTOOL_A_BITSET_VALUE, 0, 64),
	S_BLOB(ETHTOOL_A_BITSET_MASK, 0, 64),
};
static struct slot ethtool_get[] = {
	S_NEST(ETHTOOL_A_LINKINFO_HEADER, ethtool_header),
};
static struct slot ethtool_get_stats[] = {
	S_NEST(ETHTOOL_A_LINKSTATE_HEADER, ethtool_header_stats),
};
static struct slot ethtool_get_phy[] = {
	S_NEST(ETHTOOL_A_PSE_HEADER, ethtool_header_phy),
};
static struct slot ethtool_strset_get[] = {
	S_NEST(ETHTOOL_A_STRSET_HEADER, ethtool_header_phy),
	S_NEST(ETHTOOL_A_STRSET_STRINGSETS, ethtool_stringsets),
	S_FLAG(ETHTOOL_A_STRSET_COUNTS_ONLY),
};
/* Every doit but STRSET_GET's refuses a request without its header, so
 * a table of more than the header marks it. */
static struct slot ethtool_pause_get[] = {
	S_NEST(ETHTOOL_A_PAUSE_HEADER, ethtool_header_stats, .required = true),
	S_U32_RANGE(ETHTOOL_A_PAUSE_STATS_SRC, 0, ETHTOOL_MAC_STATS_SRC_PMAC),
};
static struct slot ethtool_tsinfo_get[] = {
	S_NEST(ETHTOOL_A_TSINFO_HEADER, ethtool_header_stats, .required = true),
	S_NEST(ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER, ethtool_ts_provider),
};
/* eeprom_parse_request() answers -EINVAL without OFFSET, LENGTH, PAGE or
 * I2C_ADDRESS, and the policy bounds that last to
 * ETH_MODULE_MAX_I2C_ADDRESS, 0x7f. */
static struct slot ethtool_module_eeprom_get[] = {
	S_NEST(ETHTOOL_A_MODULE_EEPROM_HEADER, ethtool_header, .required = true),
	S_U32_RANGE(ETHTOOL_A_MODULE_EEPROM_OFFSET, 0, 255, .required = true),
	S_U32_RANGE(ETHTOOL_A_MODULE_EEPROM_LENGTH, 1, 128, .required = true),
	S_U8(ETHTOOL_A_MODULE_EEPROM_PAGE, .required = true),
	S_U8(ETHTOOL_A_MODULE_EEPROM_BANK),
	S_U8_RANGE(ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, 0, 0x7f, .required = true),
};
static struct slot ethtool_stats_get[] = {
	S_NEST(ETHTOOL_A_STATS_HEADER, ethtool_header, .required = true),
	S_U32_RANGE(ETHTOOL_A_STATS_SRC, 0, ETHTOOL_MAC_STATS_SRC_PMAC),
};
static struct slot ethtool_rss_get[] = {
	S_NEST(ETHTOOL_A_RSS_HEADER, ethtool_header, .required = true),
	S_U32(ETHTOOL_A_RSS_CONTEXT),
	S_U32(ETHTOOL_A_RSS_START_CONTEXT),
};
/* net/ethtool/port.c: ethnl_port_get_policy, whose PORT_ID is
 * NLA_POLICY_MIN(NLA_U32, 1).  The doit needs both attributes, the header
 * for ethnl_parse_header_dev_get() and the id for port_parse_request(); the
 * dump, whose ethnl_port_dump_start() answers -EINVAL to a PORT_ID, takes
 * the header alone, which ethtool_get is. */
static struct slot ethtool_port_get[] = {
	S_NEST(ETHTOOL_A_PORT_HEADER, ethtool_header, .required = true),
	S_U32_RANGE(ETHTOOL_A_PORT_ID, 1, UINT32_MAX, .required = true),
};
/* net/ethtool/linkinfo.c: ethnl_linkinfo_set_policy, whose PORT, PHYADDR
 * and TP_MDIX_CTRL are plain NLA_U8s that ethnl_set_linkinfo assigns
 * un-narrowed.  The header is required, by GENL_REQ_ATTR_CHECK in
 * ethnl_default_set_doit. */
static struct slot ethtool_linkinfo_set[] = {
	S_NEST(ETHTOOL_A_LINKINFO_HEADER, ethtool_header, .required = true),
	S_U8(ETHTOOL_A_LINKINFO_PORT),
	S_U8(ETHTOOL_A_LINKINFO_PHYADDR),
	S_U8(ETHTOOL_A_LINKINFO_TP_MDIX_CTRL),
};
/* net/ethtool/linkmodes.c: ethnl_linkmodes_set_policy, whose AUTONEG,
 * DUPLEX and MASTER_SLAVE_CFG are plain NLA_U8s, SPEED a plain NLA_U32,
 * OURS a bitset, and LANES NLA_POLICY_RANGE(NLA_U32, 1, 8). */
static struct slot ethtool_linkmodes_set[] = {
	S_NEST(ETHTOOL_A_LINKMODES_HEADER, ethtool_header, .required = true),
	S_U8(ETHTOOL_A_LINKMODES_AUTONEG),
	S_NEST(ETHTOOL_A_LINKMODES_OURS, ethtool_bitset),
	S_U32(ETHTOOL_A_LINKMODES_SPEED),
	S_U8(ETHTOOL_A_LINKMODES_DUPLEX),
	S_U8(ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG),
	S_U32_RANGE(ETHTOOL_A_LINKMODES_LANES, 1, 8),
};
/* net/ethtool/debug.c: ethnl_debug_set_policy, whose MSGMASK is a
 * bitset parsed by ethnl_parse_bitset(). */
static struct slot ethtool_debug_set[] = {
	S_NEST(ETHTOOL_A_DEBUG_HEADER, ethtool_header, .required = true),
	S_NEST(ETHTOOL_A_DEBUG_MSGMASK, ethtool_bitset),
};
/* net/ethtool/wol.c: ethnl_wol_set_policy, whose SOPASS is an NLA_BINARY
 * of at most SOPASS_MAX, 6, bytes. */
static struct slot ethtool_wol_set[] = {
	S_NEST(ETHTOOL_A_WOL_HEADER, ethtool_header, .required = true),
	S_NEST(ETHTOOL_A_WOL_MODES, ethtool_bitset),
	S_BLOB(ETHTOOL_A_WOL_SOPASS, 0, SOPASS_MAX),
};
static struct cmd_policy ethtool_cmds[] = {
	P_CMD(ETHTOOL_MSG_STRSET_GET, ethtool_strset_get),
	P_CMD(ETHTOOL_MSG_LINKINFO_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_LINKINFO_SET, ethtool_linkinfo_set),
	P_CMD(ETHTOOL_MSG_LINKMODES_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_LINKMODES_SET, ethtool_linkmodes_set),
	P_CMD(ETHTOOL_MSG_LINKSTATE_GET, ethtool_get_stats),
	P_CMD(ETHTOOL_MSG_DEBUG_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_DEBUG_SET, ethtool_debug_set),
	P_CMD(ETHTOOL_MSG_WOL_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_WOL_SET, ethtool_wol_set),
	P_CMD(ETHTOOL_MSG_FEATURES_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PRIVFLAGS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_RINGS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_CHANNELS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_COALESCE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PAUSE_GET, ethtool_pause_get),
	P_CMD(ETHTOOL_MSG_EEE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_TSINFO_GET, ethtool_tsinfo_get),
	P_CMD(ETHTOOL_MSG_TUNNEL_INFO_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_FEC_GET, ethtool_get_stats),
	P_CMD(ETHTOOL_MSG_MODULE_EEPROM_GET, ethtool_module_eeprom_get),
	P_CMD(ETHTOOL_MSG_STATS_GET, ethtool_stats_get),
	P_CMD(ETHTOOL_MSG_PHC_VCLOCKS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_MODULE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PSE_GET, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_RSS_GET, ethtool_rss_get),
	P_CMD(ETHTOOL_MSG_PLCA_GET_CFG, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_PLCA_GET_STATUS, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_MM_GET, ethtool_get_stats),
	P_CMD(ETHTOOL_MSG_PHY_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_TSCONFIG_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_MSE_GET, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_PORT_GET, ethtool_port_get),
	P_DUMP(ETHTOOL_MSG_PORT_GET, ethtool_get),
};
#endif

#if __has_include(<linux/openvswitch.h>)
#include "kernel/openvswitch.h"

extern struct genl_family_grammar fam_ovs_datapath;

/*
 * net/openvswitch/datapath.c: datapath_policy, the one policy of the ops,
 * which validate liberally, so an id with no slot is ignored and takes any
 * length.  The two stats have none, and PER_CPU_PIDS has none either but
 * ovs_dp_change() reads it.
 */
static struct slot ovs_datapath[] = {
	S_STR(OVS_DP_ATTR_NAME, 15),
	S_U32(OVS_DP_ATTR_UPCALL_PID),
	S_BLOB(OVS_DP_ATTR_STATS, 0, 0xffff),
	S_BLOB(OVS_DP_ATTR_MEGAFLOW_STATS, 0, 0xffff),
	S_U32(OVS_DP_ATTR_USER_FEATURES),
	S_U32_RANGE(OVS_DP_ATTR_MASKS_CACHE_SIZE, 0, 4096),
	S_BLOB(OVS_DP_ATTR_PER_CPU_PIDS, 0, 0xffff),
	S_U32_RANGE(OVS_DP_ATTR_IFINDEX, 0, INT32_MAX),
};
/* What ovs_dp_cmd_new() and its ovs_dp_change() read, NAME and UPCALL_PID
 * without which it answers -EINVAL. */
static struct slot ovs_datapath_new[] = {
	S_STR(OVS_DP_ATTR_NAME, 15, .required = true),
	S_U32(OVS_DP_ATTR_UPCALL_PID, .required = true),
	S_U32(OVS_DP_ATTR_USER_FEATURES),
	S_U32_RANGE(OVS_DP_ATTR_MASKS_CACHE_SIZE, 0, 4096),
	S_BLOB(OVS_DP_ATTR_PER_CPU_PIDS, 0, 0xffff),
	S_U32_RANGE(OVS_DP_ATTR_IFINDEX, 0, INT32_MAX),
};
static struct cmd_policy ovs_datapath_cmds[] = {
	P_CMD(OVS_DP_CMD_NEW, ovs_datapath_new),
	P_CMD(OVS_DP_CMD_DEL, ovs_datapath),
	P_CMD(OVS_DP_CMD_GET, ovs_datapath),
	P_CMD(OVS_DP_CMD_SET, ovs_datapath),
};

extern struct genl_family_grammar fam_ovs_vport;

/*
 * net/openvswitch/datapath.c: vport_policy, which the ops share.  UPCALL_PID
 * has a slot but no type, so takes any length, and STATS one with a length,
 * so exactly that of struct ovs_vport_stats.  OPTIONS and UPCALL_STATS are
 * bare nests; their children are the legacy tunnel options and the two
 * counters of a reply.
 */
static struct slot ovs_vport_vxlan_ext[] = {
	S_U32(OVS_VXLAN_EXT_GBP),
};
static struct slot ovs_vport_tunnel[] = {
	S_U16(OVS_TUNNEL_ATTR_DST_PORT),
	S_NEST(OVS_TUNNEL_ATTR_EXTENSION, ovs_vport_vxlan_ext),
};
static struct slot ovs_vport_upcall[] = {
	S_U64(OVS_VPORT_UPCALL_ATTR_SUCCESS),
	S_U64(OVS_VPORT_UPCALL_ATTR_FAIL),
};
static struct slot ovs_vport[] = {
	S_U32(OVS_VPORT_ATTR_PORT_NO),
	S_U32(OVS_VPORT_ATTR_TYPE),
	S_STR(OVS_VPORT_ATTR_NAME, 15),
	S_NEST(OVS_VPORT_ATTR_OPTIONS, ovs_vport_tunnel),
	S_BLOB(OVS_VPORT_ATTR_UPCALL_PID, 0, 0xffff),
	S_BLOB(OVS_VPORT_ATTR_STATS, sizeof(struct ovs_vport_stats),
	       sizeof(struct ovs_vport_stats)),
	S_U32_RANGE(OVS_VPORT_ATTR_IFINDEX, 0, INT32_MAX),
	S_U32(OVS_VPORT_ATTR_NETNSID),
	S_NEST(OVS_VPORT_ATTR_UPCALL_STATS, ovs_vport_upcall),
};
/* What ovs_vport_cmd_new() reads, NAME, TYPE and UPCALL_PID without which
 * it answers -EINVAL. */
static struct slot ovs_vport_new[] = {
	S_U32(OVS_VPORT_ATTR_PORT_NO),
	S_U32(OVS_VPORT_ATTR_TYPE, .required = true),
	S_STR(OVS_VPORT_ATTR_NAME, 15, .required = true),
	S_BLOB(OVS_VPORT_ATTR_UPCALL_PID, 0, 0xffff, .required = true),
	S_U32_RANGE(OVS_VPORT_ATTR_IFINDEX, 0, INT32_MAX),
};
static struct cmd_policy ovs_vport_cmds[] = {
	P_CMD(OVS_VPORT_CMD_NEW, ovs_vport_new),
	P_CMD(OVS_VPORT_CMD_DEL, ovs_vport),
	P_CMD(OVS_VPORT_CMD_GET, ovs_vport),
	P_CMD(OVS_VPORT_CMD_SET, ovs_vport),
};

extern struct genl_family_grammar fam_ovs_meter;

/*
 * net/openvswitch/meter.c: meter_policy and band_policy.  STATS has a slot
 * with a length and no type, so exactly that of struct ovs_flow_stats.
 * BANDS is a nest of band nests, which dp_meter_create() walks and refuses
 * past DP_MAX_BANDS, 1, or when a band lacks its TYPE, RATE or BURST.
 */
static struct slot ovs_meter_band[] = {
	S_U32(OVS_BAND_ATTR_TYPE, .required = true),
	S_U32(OVS_BAND_ATTR_RATE, .required = true),
	S_U32(OVS_BAND_ATTR_BURST, .required = true),
	S_BLOB(OVS_BAND_ATTR_STATS, sizeof(struct ovs_flow_stats),
	       sizeof(struct ovs_flow_stats)),
};
static struct slot ovs_meter[] = {
	S_U32(OVS_METER_ATTR_ID),
	S_FLAG(OVS_METER_ATTR_KBPS),
	S_BLOB(OVS_METER_ATTR_STATS, sizeof(struct ovs_flow_stats),
	       sizeof(struct ovs_flow_stats)),
	S_ARRAY_MAX(OVS_METER_ATTR_BANDS, ovs_meter_band, 1),
	S_U64(OVS_METER_ATTR_USED),
	S_FLAG(OVS_METER_ATTR_CLEAR),
	S_U32(OVS_METER_ATTR_MAX_METERS),
	S_U32(OVS_METER_ATTR_MAX_BANDS),
};
/* What ovs_meter_cmd_set() and its dp_meter_create() read, ID and BANDS
 * without which they answer -EINVAL; GET and DEL read ID alone. */
static struct slot ovs_meter_set[] = {
	S_U32(OVS_METER_ATTR_ID, .required = true),
	S_FLAG(OVS_METER_ATTR_KBPS),
	S_BLOB(OVS_METER_ATTR_STATS, sizeof(struct ovs_flow_stats),
	       sizeof(struct ovs_flow_stats)),
	S_ARRAY_MAX(OVS_METER_ATTR_BANDS, ovs_meter_band, 1, .required = true),
	S_FLAG(OVS_METER_ATTR_CLEAR),
};
static struct slot ovs_meter_id[] = {
	S_U32(OVS_METER_ATTR_ID),
};
static struct cmd_policy ovs_meter_cmds[] = {
	P_CMD(OVS_METER_CMD_FEATURES, ovs_meter),
	P_CMD(OVS_METER_CMD_SET, ovs_meter_set),
	P_CMD(OVS_METER_CMD_DEL, ovs_meter_id),
	P_CMD(OVS_METER_CMD_GET, ovs_meter_id),
};

extern struct genl_family_grammar fam_ovs_ct_limit;

/*
 * net/openvswitch/conntrack.c: ct_limit_policy.  ZONE_LIMIT is typed a nest
 * but holds a packed array of struct ovs_zone_limit, not attributes, and a
 * nest that is not empty takes four bytes at least.
 */
static struct slot ovs_ct_limit[] = {
	S_BLOB(OVS_CT_LIMIT_ATTR_ZONE_LIMIT, NLA_HDRLEN, 0xffff),
};
/* SET and DEL answer -EINVAL without ZONE_LIMIT; GET reads all limits
 * when it is absent, so only those two mark it. */
static struct slot ovs_ct_limit_set_del[] = {
	S_BLOB(OVS_CT_LIMIT_ATTR_ZONE_LIMIT, NLA_HDRLEN, 0xffff,
	       .required = true),
};
static struct cmd_policy ovs_ct_limit_cmds[] = {
	P_CMD(OVS_CT_LIMIT_CMD_SET, ovs_ct_limit_set_del),
	P_CMD(OVS_CT_LIMIT_CMD_DEL, ovs_ct_limit_set_del),
	P_CMD(OVS_CT_LIMIT_CMD_GET, ovs_ct_limit),
};

extern struct genl_family_grammar fam_ovs_flow;

/*
 * net/openvswitch/flow_netlink.c: the namespaces a flow's nests are parsed
 * in, each attribute as long as its table gives it: ovs_key_lens for a key
 * or a mask, ovs_tunnel_key_lens, the NSH key's, the action_lens of
 * __ovs_nla_copy_actions(), and the nests the actions open, conntrack.c's
 * ovs_ct_attr_lens and NAT lengths among them.  A variable-length one takes
 * what its parser does: an MPLS key one to three labels, GENEVE and ERSPAN
 * options up to IP_TUNNEL_OPTS_MAX, an MD2 up to NSH_CTX_HDRS_MAX_LEN.  A
 * SET or SET_MASKED action holds one key, the latter's value and mask.
 * OUTPUT is below DP_MAX_PORTS, TRUNC at least ETH_HLEN and a userspace
 * PID not 0.  The handlers need a tunnel key's TTL, a userspace action's
 * PID, a sample's PROBABILITY and ACTIONS, a CHECK_PKT_LEN's PKT_LEN and
 * both branches, a PSAMPLE's GROUP and a NEW flow's KEY and ACTIONS.  The
 * key parser refuses a key given twice, and a SAMPLE's and a DEC_TTL's
 * parsers an attribute.
 */
#define S_FIXED(id, s, ...) \
	S_BLOB(id, sizeof(struct s), sizeof(struct s), ##__VA_ARGS__)
#define S_MASKED(id, s, ...) \
	S_BLOB(id, 2 * sizeof(s), 2 * sizeof(s), ##__VA_ARGS__)
static struct slot ovs_vxlan_ext[] = {
	S_U32(OVS_VXLAN_EXT_GBP),
};
static struct slot ovs_tunnel_key[] = {
	S_U64(OVS_TUNNEL_KEY_ATTR_ID),
	S_U32(OVS_TUNNEL_KEY_ATTR_IPV4_SRC),
	S_U32(OVS_TUNNEL_KEY_ATTR_IPV4_DST),
	S_U8(OVS_TUNNEL_KEY_ATTR_TOS),
	S_U8(OVS_TUNNEL_KEY_ATTR_TTL, .required = true),
	S_FLAG(OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT),
	S_FLAG(OVS_TUNNEL_KEY_ATTR_CSUM),
	S_U16(OVS_TUNNEL_KEY_ATTR_TP_SRC),
	S_U16(OVS_TUNNEL_KEY_ATTR_TP_DST),
	S_FLAG(OVS_TUNNEL_KEY_ATTR_OAM),
	S_BLOB(OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, 0, 252),
	S_NEST(OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS, ovs_vxlan_ext),
	S_BLOB(OVS_TUNNEL_KEY_ATTR_IPV6_SRC, 16, 16),
	S_BLOB(OVS_TUNNEL_KEY_ATTR_IPV6_DST, 16, 16),
	S_BLOB(OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS, 0, 255),
	S_FLAG(OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE),
};
static struct slot ovs_nsh_key[] = {
	S_FIXED(OVS_NSH_KEY_ATTR_BASE, ovs_nsh_key_base),
	S_FIXED(OVS_NSH_KEY_ATTR_MD1, ovs_nsh_key_md1),
	S_BLOB(OVS_NSH_KEY_ATTR_MD2, 1, 244),
};
/* A key's entries, ENCAP apart: the key a VLAN's payload carries, in the
 * same namespace, draws from these, without an ENCAP of its own. */
#define OVS_KEY_SLOTS \
	S_U32(OVS_KEY_ATTR_PRIORITY, .once = true), \
	S_U32(OVS_KEY_ATTR_IN_PORT, .once = true), \
	S_FIXED(OVS_KEY_ATTR_ETHERNET, ovs_key_ethernet, .once = true), \
	S_U16(OVS_KEY_ATTR_VLAN, .once = true), \
	S_U16(OVS_KEY_ATTR_ETHERTYPE, .once = true), \
	S_FIXED(OVS_KEY_ATTR_IPV4, ovs_key_ipv4, .once = true), \
	S_FIXED(OVS_KEY_ATTR_IPV6, ovs_key_ipv6, .once = true), \
	S_FIXED(OVS_KEY_ATTR_TCP, ovs_key_tcp, .once = true), \
	S_FIXED(OVS_KEY_ATTR_UDP, ovs_key_udp, .once = true), \
	S_FIXED(OVS_KEY_ATTR_ICMP, ovs_key_icmp, .once = true), \
	S_FIXED(OVS_KEY_ATTR_ICMPV6, ovs_key_icmpv6, .once = true), \
	S_FIXED(OVS_KEY_ATTR_ARP, ovs_key_arp, .once = true), \
	S_FIXED(OVS_KEY_ATTR_ND, ovs_key_nd, .once = true), \
	S_U32(OVS_KEY_ATTR_SKB_MARK, .once = true), \
	S_NEST(OVS_KEY_ATTR_TUNNEL, ovs_tunnel_key, .once = true), \
	S_FIXED(OVS_KEY_ATTR_SCTP, ovs_key_sctp, .once = true), \
	S_U16(OVS_KEY_ATTR_TCP_FLAGS, .once = true), \
	S_U32(OVS_KEY_ATTR_DP_HASH, .once = true), \
	S_U32(OVS_KEY_ATTR_RECIRC_ID, .once = true), \
	S_BLOB(OVS_KEY_ATTR_MPLS, 4, 12, .once = true), \
	S_U32(OVS_KEY_ATTR_CT_STATE, .once = true), \
	S_U16(OVS_KEY_ATTR_CT_ZONE, .once = true), \
	S_U32(OVS_KEY_ATTR_CT_MARK, .once = true), \
	S_FIXED(OVS_KEY_ATTR_CT_LABELS, ovs_key_ct_labels, .once = true), \
	S_FIXED(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4, ovs_key_ct_tuple_ipv4, \
		.once = true), \
	S_FIXED(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6, ovs_key_ct_tuple_ipv6, \
		.once = true), \
	S_NEST(OVS_KEY_ATTR_NSH, ovs_nsh_key, .once = true), \
	S_FIXED(OVS_KEY_ATTR_IPV6_EXTHDRS, ovs_key_ipv6_exthdrs, .once = true)
static struct slot ovs_encap_key[] = {
	OVS_KEY_SLOTS,
};
static struct slot ovs_key[] = {
	OVS_KEY_SLOTS,
	S_NEST(OVS_KEY_ATTR_ENCAP, ovs_encap_key, .once = true),
};
static struct slot ovs_set_key[] = {
	S_U32(OVS_KEY_ATTR_PRIORITY),
	S_U32(OVS_KEY_ATTR_SKB_MARK),
	S_U32(OVS_KEY_ATTR_CT_MARK),
	S_FIXED(OVS_KEY_ATTR_CT_LABELS, ovs_key_ct_labels),
	S_FIXED(OVS_KEY_ATTR_ETHERNET, ovs_key_ethernet),
	S_NEST(OVS_KEY_ATTR_TUNNEL, ovs_tunnel_key),
	S_FIXED(OVS_KEY_ATTR_IPV4, ovs_key_ipv4),
	S_FIXED(OVS_KEY_ATTR_IPV6, ovs_key_ipv6),
	S_FIXED(OVS_KEY_ATTR_TCP, ovs_key_tcp),
	S_FIXED(OVS_KEY_ATTR_UDP, ovs_key_udp),
	S_FIXED(OVS_KEY_ATTR_MPLS, ovs_key_mpls),
	S_FIXED(OVS_KEY_ATTR_SCTP, ovs_key_sctp),
};
static struct slot ovs_set_masked_key[] = {
	S_MASKED(OVS_KEY_ATTR_PRIORITY, uint32_t),
	S_MASKED(OVS_KEY_ATTR_SKB_MARK, uint32_t),
	S_MASKED(OVS_KEY_ATTR_CT_MARK, uint32_t),
	S_MASKED(OVS_KEY_ATTR_CT_LABELS, struct ovs_key_ct_labels),
	S_MASKED(OVS_KEY_ATTR_ETHERNET, struct ovs_key_ethernet),
	S_MASKED(OVS_KEY_ATTR_IPV4, struct ovs_key_ipv4),
	S_MASKED(OVS_KEY_ATTR_IPV6, struct ovs_key_ipv6),
	S_MASKED(OVS_KEY_ATTR_TCP, struct ovs_key_tcp),
	S_MASKED(OVS_KEY_ATTR_UDP, struct ovs_key_udp),
	S_MASKED(OVS_KEY_ATTR_MPLS, struct ovs_key_mpls),
	S_MASKED(OVS_KEY_ATTR_SCTP, struct ovs_key_sctp),
};
static struct slot ovs_userspace[] = {
	S_U32_RANGE(OVS_USERSPACE_ATTR_PID, 1, UINT32_MAX, .required = true),
	S_BLOB(OVS_USERSPACE_ATTR_USERDATA, 0, 0xffff),
	S_U32(OVS_USERSPACE_ATTR_EGRESS_TUN_PORT),
	S_FLAG(OVS_USERSPACE_ATTR_ACTIONS),
};
static struct slot ovs_nat[] = {
	S_FLAG(OVS_NAT_ATTR_SRC),
	S_FLAG(OVS_NAT_ATTR_DST),
	S_BLOB(OVS_NAT_ATTR_IP_MIN, 4, 16),
	S_BLOB(OVS_NAT_ATTR_IP_MAX, 4, 16),
	S_U16(OVS_NAT_ATTR_PROTO_MIN),
	S_U16(OVS_NAT_ATTR_PROTO_MAX),
	S_FLAG(OVS_NAT_ATTR_PERSISTENT),
	S_FLAG(OVS_NAT_ATTR_PROTO_HASH),
	S_FLAG(OVS_NAT_ATTR_PROTO_RANDOM),
};
static struct slot ovs_ct[] = {
	S_FLAG(OVS_CT_ATTR_COMMIT),
	S_U16(OVS_CT_ATTR_ZONE),
	S_BLOB(OVS_CT_ATTR_MARK, 8, 8),
	S_BLOB(OVS_CT_ATTR_LABELS, 2 * OVS_CT_LABELS_LEN, 2 * OVS_CT_LABELS_LEN),
	S_STR(OVS_CT_ATTR_HELPER, 15),
	S_NEST(OVS_CT_ATTR_NAT, ovs_nat),
	S_FLAG(OVS_CT_ATTR_FORCE_COMMIT),
	S_U32(OVS_CT_ATTR_EVENTMASK),
	S_STR(OVS_CT_ATTR_TIMEOUT, 31),
};
static struct slot ovs_psample[] = {
	S_U32(OVS_PSAMPLE_ATTR_GROUP, .required = true),
	S_BLOB(OVS_PSAMPLE_ATTR_COOKIE, 0, OVS_PSAMPLE_COOKIE_MAX_SIZE),
};
#define OVS_LEAF_ACTION_SLOTS \
	S_U32_RANGE(OVS_ACTION_ATTR_OUTPUT, 0, 65534), \
	S_NEST(OVS_ACTION_ATTR_USERSPACE, ovs_userspace), \
	S_NEST_MAX(OVS_ACTION_ATTR_SET, ovs_set_key, 1), \
	S_FIXED(OVS_ACTION_ATTR_PUSH_VLAN, ovs_action_push_vlan), \
	S_FLAG(OVS_ACTION_ATTR_POP_VLAN), \
	S_U32(OVS_ACTION_ATTR_RECIRC), \
	S_FIXED(OVS_ACTION_ATTR_HASH, ovs_action_hash), \
	S_FIXED(OVS_ACTION_ATTR_PUSH_MPLS, ovs_action_push_mpls), \
	S_U16(OVS_ACTION_ATTR_POP_MPLS), \
	S_NEST_MAX(OVS_ACTION_ATTR_SET_MASKED, ovs_set_masked_key, 1), \
	S_NEST(OVS_ACTION_ATTR_CT, ovs_ct), \
	S_U32_RANGE(OVS_ACTION_ATTR_TRUNC, 14, UINT32_MAX), \
	S_FIXED(OVS_ACTION_ATTR_PUSH_ETH, ovs_action_push_eth), \
	S_FLAG(OVS_ACTION_ATTR_POP_ETH), \
	S_FLAG(OVS_ACTION_ATTR_CT_CLEAR), \
	S_NEST(OVS_ACTION_ATTR_PUSH_NSH, ovs_nsh_key), \
	S_FLAG(OVS_ACTION_ATTR_POP_NSH), \
	S_U32(OVS_ACTION_ATTR_METER), \
	S_FIXED(OVS_ACTION_ATTR_ADD_MPLS, ovs_action_add_mpls), \
	S_U32(OVS_ACTION_ATTR_DROP), \
	S_NEST(OVS_ACTION_ATTR_PSAMPLE, ovs_psample)
static struct slot ovs_leaf_action[] = {
	OVS_LEAF_ACTION_SLOTS,
};
static struct slot ovs_sample[] = {
	S_U32(OVS_SAMPLE_ATTR_PROBABILITY, .required = true, .once = true),
	S_NEST(OVS_SAMPLE_ATTR_ACTIONS, ovs_leaf_action, .required = true,
	       .once = true),
};
static struct slot ovs_check_pkt_len[] = {
	S_U16(OVS_CHECK_PKT_LEN_ATTR_PKT_LEN, .required = true),
	S_NEST(OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER, ovs_leaf_action,
	       .required = true),
	S_NEST(OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL, ovs_leaf_action,
	       .required = true),
};
static struct slot ovs_dec_ttl[] = {
	S_NEST(OVS_DEC_TTL_ATTR_ACTION, ovs_leaf_action, .once = true),
};
static struct slot ovs_action[] = {
	OVS_LEAF_ACTION_SLOTS,
	S_NEST(OVS_ACTION_ATTR_SAMPLE, ovs_sample),
	S_NEST(OVS_ACTION_ATTR_CLONE, ovs_leaf_action),
	S_NEST(OVS_ACTION_ATTR_CHECK_PKT_LEN, ovs_check_pkt_len),
	S_NEST(OVS_ACTION_ATTR_DEC_TTL, ovs_dec_ttl),
};
/* flow_policy, under which UFID is one byte at least. */
static struct slot ovs_flow_new[] = {
	S_NEST(OVS_FLOW_ATTR_KEY, ovs_key, .required = true),
	S_NEST(OVS_FLOW_ATTR_MASK, ovs_key),
	S_NEST(OVS_FLOW_ATTR_ACTIONS, ovs_action, .required = true),
	S_FLAG(OVS_FLOW_ATTR_PROBE),
	S_BLOB(OVS_FLOW_ATTR_UFID, 1, 0xffff),
	S_U32(OVS_FLOW_ATTR_UFID_FLAGS),
};
static struct slot ovs_flow_set[] = {
	S_NEST(OVS_FLOW_ATTR_KEY, ovs_key),
	S_NEST(OVS_FLOW_ATTR_MASK, ovs_key),
	S_NEST(OVS_FLOW_ATTR_ACTIONS, ovs_action),
	S_FLAG(OVS_FLOW_ATTR_CLEAR),
	S_FLAG(OVS_FLOW_ATTR_PROBE),
	S_BLOB(OVS_FLOW_ATTR_UFID, 1, 0xffff),
	S_U32(OVS_FLOW_ATTR_UFID_FLAGS),
};
static struct slot ovs_flow_get[] = {
	S_NEST(OVS_FLOW_ATTR_KEY, ovs_key),
	S_FLAG(OVS_FLOW_ATTR_PROBE),
	S_BLOB(OVS_FLOW_ATTR_UFID, 1, 0xffff),
	S_U32(OVS_FLOW_ATTR_UFID_FLAGS),
};
static struct slot ovs_flow_dump[] = {
	S_U32(OVS_FLOW_ATTR_UFID_FLAGS),
};
static struct cmd_policy ovs_flow_cmds[] = {
	P_CMD(OVS_FLOW_CMD_NEW, ovs_flow_new),
	P_CMD(OVS_FLOW_CMD_DEL, ovs_flow_get),
	P_CMD(OVS_FLOW_CMD_GET, ovs_flow_get),
	P_DUMP(OVS_FLOW_CMD_GET, ovs_flow_dump),
	P_CMD(OVS_FLOW_CMD_SET, ovs_flow_set),
};

extern struct genl_family_grammar fam_ovs_packet;

/* net/openvswitch/datapath.c: packet_policy, under which PACKET is
 * ETH_HLEN bytes at least.  ovs_packet_cmd_execute() answers -EINVAL
 * without PACKET, KEY or ACTIONS, the last two a flow's key and actions. */
static struct slot ovs_packet_execute[] = {
	S_BLOB(OVS_PACKET_ATTR_PACKET, ETH_HLEN, 0xffff, .required = true),
	S_NEST(OVS_PACKET_ATTR_KEY, ovs_key, .required = true),
	S_NEST(OVS_PACKET_ATTR_ACTIONS, ovs_action, .required = true),
	S_FLAG(OVS_PACKET_ATTR_PROBE),
	S_U16(OVS_PACKET_ATTR_MRU),
	S_U64(OVS_PACKET_ATTR_HASH),
	S_U32(OVS_PACKET_ATTR_UPCALL_PID),
};
static struct cmd_policy ovs_packet_cmds[] = {
	P_CMD(OVS_PACKET_CMD_EXECUTE, ovs_packet_execute),
};
#endif

#if __has_include(<linux/tipc_netlink.h>)
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/tipc_netlink.h>

extern struct genl_family_grammar fam_tipc;

/*
 * net/tipc/netlink.c: tipc_nl_policy, which every op shares and validates
 * liberally, and the tipc_nl_*_policy tables the handlers parse its nests
 * under.  MULTI_REMOTEIP has no slot in the UDP policy but the media code
 * reads it.  Each op reads one nest, or none, and the handler of a bearer,
 * link or media op answers -EINVAL to a nest without its NAME, PUBL_GET's
 * to a SOCK nest without REF, LINK_GET's dumpit to a LINK nest without
 * BROADCAST and MON_PEER_GET's to a MON nest without REF.  KEY_SET parses
 * its NODE nest strictly.  What only replies carry is not listed.
 */
/* tipc_nl_parse_link_prop() bounds PRIO, TOL and WIN, the broadcast link
 * BROADCAST_RATIO, and the policy MTU. */
static struct slot tipc_prop[] = {
	S_U32_RANGE(TIPC_NLA_PROP_PRIO, 0, TIPC_MAX_LINK_PRI),
	S_U32_RANGE(TIPC_NLA_PROP_TOL, TIPC_MIN_LINK_TOL, TIPC_MAX_LINK_TOL),
	S_U32_RANGE(TIPC_NLA_PROP_WIN, TIPC_DEF_LINK_WIN, TIPC_MAX_LINK_WIN),
	S_U32_RANGE(TIPC_NLA_PROP_MTU, 0, 65535),
	S_U32(TIPC_NLA_PROP_BROADCAST),
	S_U32_RANGE(TIPC_NLA_PROP_BROADCAST_RATIO, 1, 100),
};
/* tipc_udp_enable() wants both addresses, a UDP bearer's add the remote
 * one, and both its UDP_OPTS. */
static struct slot tipc_udp[] = {
	S_BLOB(TIPC_NLA_UDP_LOCAL, 0, sizeof(struct sockaddr_storage),
	       .required = true),
	S_BLOB(TIPC_NLA_UDP_REMOTE, 0, sizeof(struct sockaddr_storage),
	       .required = true),
	S_FLAG(TIPC_NLA_UDP_MULTI_REMOTEIP),
};
static struct slot tipc_bearer[] = {
	S_STR(TIPC_NLA_BEARER_NAME, TIPC_MAX_BEARER_NAME, .required = true),
	S_NEST(TIPC_NLA_BEARER_PROP, tipc_prop),
};
static struct slot tipc_bearer_udp[] = {
	S_STR(TIPC_NLA_BEARER_NAME, TIPC_MAX_BEARER_NAME, .required = true),
	S_NEST(TIPC_NLA_BEARER_PROP, tipc_prop),
	S_U32(TIPC_NLA_BEARER_DOMAIN),
	S_NEST(TIPC_NLA_BEARER_UDP_OPTS, tipc_udp, .required = true),
};
static struct slot tipc_sock[] = {
	S_U32(TIPC_NLA_SOCK_REF),
};
static struct slot tipc_link[] = {
	S_STR(TIPC_NLA_LINK_NAME, TIPC_MAX_LINK_NAME, .required = true),
	S_NEST(TIPC_NLA_LINK_PROP, tipc_prop),
};
static struct slot tipc_link_bcast[] = {
	S_FLAG(TIPC_NLA_LINK_BROADCAST),
};
static struct slot tipc_media[] = {
	S_STR(TIPC_NLA_MEDIA_NAME, 0, .required = true),
	S_NEST(TIPC_NLA_MEDIA_PROP, tipc_prop),
};
static struct slot tipc_net[] = {
	S_U32(TIPC_NLA_NET_ID),
	S_U32(TIPC_NLA_NET_ADDR),
	S_U64(TIPC_NLA_NET_NODEID),
	S_U64(TIPC_NLA_NET_NODEID_W1),
};
static struct slot tipc_mon[] = {
	S_U32(TIPC_NLA_MON_ACTIVATION_THRESHOLD),
};
static struct slot tipc_mon_peer[] = {
	S_U32(TIPC_NLA_MON_REF),
};
static struct slot tipc_node_key[] = {
	S_BLOB(TIPC_NLA_NODE_ID, 0, TIPC_NODEID_LEN),
	S_BLOB(TIPC_NLA_NODE_KEY, 0, TIPC_AEAD_KEY_SIZE_MAX),
	S_FLAG(TIPC_NLA_NODE_KEY_MASTER),
	S_U32(TIPC_NLA_NODE_REKEYING),
};
static struct slot tipc_bearer_req[] = { S_NEST(TIPC_NLA_BEARER, tipc_bearer) };
static struct slot tipc_bearer_udp_req[] = {
	S_NEST(TIPC_NLA_BEARER, tipc_bearer_udp),
};
static struct slot tipc_sock_req[] = { S_NEST(TIPC_NLA_SOCK, tipc_sock) };
static struct slot tipc_link_req[] = { S_NEST(TIPC_NLA_LINK, tipc_link) };
static struct slot tipc_link_dump[] = { S_NEST(TIPC_NLA_LINK, tipc_link_bcast) };
static struct slot tipc_media_req[] = { S_NEST(TIPC_NLA_MEDIA, tipc_media) };
static struct slot tipc_net_req[] = { S_NEST(TIPC_NLA_NET, tipc_net) };
static struct slot tipc_mon_req[] = { S_NEST(TIPC_NLA_MON, tipc_mon) };
static struct slot tipc_mon_peer_req[] = { S_NEST(TIPC_NLA_MON, tipc_mon_peer) };
static struct slot tipc_node_req[] = { S_NEST(TIPC_NLA_NODE, tipc_node_key) };
static struct cmd_policy tipc_cmds[] = {
	P_CMD(TIPC_NL_BEARER_ENABLE, tipc_bearer_udp_req),
	P_CMD(TIPC_NL_BEARER_DISABLE, tipc_bearer_req),
	P_CMD(TIPC_NL_BEARER_GET, tipc_bearer_req),
	P_DUMP_NONE(TIPC_NL_BEARER_GET),
	P_CMD(TIPC_NL_BEARER_SET, tipc_bearer_req),
	P_CMD(TIPC_NL_BEARER_ADD, tipc_bearer_udp_req),
	P_CMD(TIPC_NL_UDP_GET_REMOTEIP, tipc_bearer_req),
	P_CMD_NONE(TIPC_NL_NET_GET),
	P_CMD(TIPC_NL_NET_SET, tipc_net_req),
	P_CMD(TIPC_NL_PEER_REMOVE, tipc_net_req),
	P_CMD_NONE(TIPC_NL_NODE_GET),
	P_CMD(TIPC_NL_LINK_GET, tipc_link_req),
	P_DUMP(TIPC_NL_LINK_GET, tipc_link_dump),
	P_CMD(TIPC_NL_LINK_SET, tipc_link_req),
	P_CMD(TIPC_NL_LINK_RESET_STATS, tipc_link_req),
	P_CMD_NONE(TIPC_NL_NAME_TABLE_GET),
	P_CMD(TIPC_NL_PUBL_GET, tipc_sock_req),
	P_CMD_NONE(TIPC_NL_SOCK_GET),
	P_CMD(TIPC_NL_MEDIA_GET, tipc_media_req),
	P_DUMP_NONE(TIPC_NL_MEDIA_GET),
	P_CMD(TIPC_NL_MEDIA_SET, tipc_media_req),
	P_CMD_NONE(TIPC_NL_MON_GET),
	P_CMD(TIPC_NL_MON_SET, tipc_mon_req),
	P_CMD(TIPC_NL_MON_PEER_GET, tipc_mon_peer_req),
	P_CMD(TIPC_NL_KEY_SET, tipc_node_req),
	P_CMD_NONE(TIPC_NL_KEY_FLUSH),
	P_CMD_NONE(TIPC_NL_ADDR_LEGACY_GET),
};
#endif

static struct policy_family policy_families[] = {
#if __has_include(<linux/handshake.h>)
	{ &fam_handshake, ID_HANDSHAKE, handshake_cmds, ARRAY_SIZE(handshake_cmds) },
#endif
#if __has_include(<linux/vdpa.h>)
	{ &fam_vdpa, ID_VDPA, vdpa_cmds, ARRAY_SIZE(vdpa_cmds) },
#endif
#if __has_include(<linux/wireguard.h>)
	{ &fam_wireguard, ID_WIREGUARD, wireguard_cmds, ARRAY_SIZE(wireguard_cmds) },
#endif
#if __has_include(<linux/dpll.h>)
	{ &fam_dpll, ID_DPLL, dpll_cmds, ARRAY_SIZE(dpll_cmds) },
#endif
#if __has_include(<linux/nfsd_netlink.h>)
	{ &fam_nfsd, ID_NFSD, nfsd_cmds, ARRAY_SIZE(nfsd_cmds) },
#endif
#if __has_include(<drm/drm_ras.h>)
	{ &fam_drm_ras, ID_DRM_RAS, drm_ras_cmds, ARRAY_SIZE(drm_ras_cmds) },
#endif
#if __has_include(<linux/lockd_netlink.h>)
	{ &fam_lockd, ID_LOCKD, lockd_cmds, ARRAY_SIZE(lockd_cmds) },
#endif
#if __has_include(<linux/sunrpc_netlink.h>)
	{ &fam_sunrpc, ID_SUNRPC, sunrpc_cmds, ARRAY_SIZE(sunrpc_cmds) },
#endif
	{ &fam_psp, ID_PSP, psp_cmds, ARRAY_SIZE(psp_cmds) },
#if __has_include(<linux/netdev.h>)
	{ &fam_netdev, ID_NETDEV, netdev_cmds, ARRAY_SIZE(netdev_cmds) },
#endif
#if __has_include(<linux/ethtool_netlink_generated.h>)
	{ &fam_ethtool, ID_ETHTOOL, ethtool_cmds, ARRAY_SIZE(ethtool_cmds) },
#endif
#if __has_include(<linux/openvswitch.h>)
	{ &fam_ovs_datapath, ID_OVS_DATAPATH, ovs_datapath_cmds,
	  ARRAY_SIZE(ovs_datapath_cmds) },
	{ &fam_ovs_vport, ID_OVS_VPORT, ovs_vport_cmds,
	  ARRAY_SIZE(ovs_vport_cmds) },
	{ &fam_ovs_meter, ID_OVS_METER, ovs_meter_cmds,
	  ARRAY_SIZE(ovs_meter_cmds) },
	{ &fam_ovs_flow, ID_OVS_FLOW, ovs_flow_cmds, ARRAY_SIZE(ovs_flow_cmds) },
	{ &fam_ovs_packet, ID_OVS_PACKET, ovs_packet_cmds,
	  ARRAY_SIZE(ovs_packet_cmds) },
	{ &fam_ovs_ct_limit, ID_OVS_CT_LIMIT, ovs_ct_limit_cmds,
	  ARRAY_SIZE(ovs_ct_limit_cmds) },
#endif
#if __has_include(<linux/tipc_netlink.h>)
	{ &fam_tipc, ID_TIPC, tipc_cmds, ARRAY_SIZE(tipc_cmds) },
#endif
};

/* Every cmd of these families, each with the flags of a doit and a dumpit. */
static void put_policy_families(struct reply *r)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++)
		put_grammar_family(r, policy_families[i].fam,
				   policy_families[i].id, CMD_CAPS);
}

/*
 * genl_resolve_families() asks once per process, so the one reply carries
 * every case below.
 */
static void build_reply(struct reply *r)
{
	static const struct op unregistered_op = { 1, GENL_CMD_CAP_DO };
	const unsigned short unregistered_id = ID_UNREGISTERED;
	const unsigned short no_ops_id = ID_NO_OPS;
	struct nlmsghdr done = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(int)),
		.nlmsg_type = NLMSG_DONE,
		.nlmsg_flags = NLM_F_MULTI,
	};
	struct reply body = { .len = 0 };
	struct reply list = { .len = 0 };

	/* A family we do not register changes nothing. */
	put_attr(&body, CTRL_ATTR_FAMILY_NAME, "no_such_family", sizeof("no_such_family"));
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &unregistered_id, sizeof(unregistered_id));
	put_op(&list, 1, &unregistered_op);
	put_attr(&body, CTRL_ATTR_OPS, list.buf, list.len);
	put_msg(r, &body);

	put_grammar_family(r, &fam_taskstats, ID_DO_ONLY, GENL_CMD_CAP_DO);
	put_grammar_family(r, &fam_nlbl_calipso, ID_DUMP_ONLY, GENL_CMD_CAP_DUMP);
	put_grammar_family(r, &fam_nlbl_cipsov4, ID_BOTH, CMD_CAPS);

	body = (struct reply) { .len = 0 };
	put_attr(&body, CTRL_ATTR_FAMILY_NAME, fam_nlbl_mgmt.name,
		 strlen(fam_nlbl_mgmt.name) + 1);
	put_attr(&body, CTRL_ATTR_FAMILY_ID, &no_ops_id, sizeof(no_ops_id));
	put_msg(r, &body);

	put_edge_family(r, &fam_nlbl_unlabel, ID_EDGE);
	put_truncated_family(r, &fam_devlink, ID_TRUNCATED);
	put_ops_first_family(r, &fam_binder, ID_OPS_FIRST);
	put_policy_families(r);

	memcpy(r->buf + r->len, &done, sizeof(done));
	r->len += NLMSG_LENGTH(sizeof(int));
}

/* ---------- Checking what the resolver recorded ----------------------- */

static void expect_caps(const struct genl_family_grammar *fam,
			unsigned short id, const unsigned char want[256],
			const char *what)
{
	unsigned int cmd;

	if (!fam->resolved || fam->family_id != id) {
		fprintf(stderr, "%s: resolved %d as id %u, want %u\n",
			what, fam->resolved, fam->family_id, id);
		BUG("genl ops: a family in the reply did not resolve");
	}
	for (cmd = 0; cmd < 256; cmd++) {
		if (fam->cmd_caps[cmd] == want[cmd])
			continue;
		fprintf(stderr, "%s: cmd %u has caps %#x, want %#x\n",
			what, cmd, fam->cmd_caps[cmd], want[cmd]);
		BUG("genl ops: a cmd's handlers were recorded wrongly");
	}
}

/* The family's grammar cmds carry caps and nothing else does. */
static void expect_grammar_caps(const struct genl_family_grammar *fam,
				unsigned short id, unsigned char caps)
{
	unsigned char want[256] = { 0 };
	unsigned int i;

	for (i = 0; i < fam->n_cmds; i++)
		want[fam->cmds[i].cmd] = caps;
	expect_caps(fam, id, want, fam->name);
}

static void check_reply_parsed(void)
{
	unsigned char want[256] = { 0 };
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
	} req;

	expect_grammar_caps(&fam_taskstats, ID_DO_ONLY, GENL_CMD_CAP_DO);
	expect_grammar_caps(&fam_nlbl_calipso, ID_DUMP_ONLY, GENL_CMD_CAP_DUMP);
	expect_grammar_caps(&fam_nlbl_cipsov4, ID_BOTH, CMD_CAPS);
	expect_grammar_caps(&fam_nlbl_mgmt, ID_NO_OPS, 0);

	want[10] = GENL_CMD_CAP_DO;
	want[11] = GENL_CMD_CAP_DUMP;
	want[12] = CMD_CAPS;
	want[13] = CMD_CAPS;
	want[255] = GENL_CMD_CAP_DUMP;
	expect_caps(&fam_nlbl_unlabel, ID_EDGE, want, "edge ops");

	memset(want, 0, sizeof(want));
	expect_caps(&fam_devlink, ID_TRUNCATED, want, "op list past the message");

	want[5] = GENL_CMD_CAP_DUMP;
	want[6] = GENL_CMD_CAP_DO;
	expect_caps(&fam_binder, ID_OPS_FIRST, want, "op list before the name");

	if (genl_lookup_by_id(ID_UNREGISTERED) != NULL)
		BUG("genl ops: an unregistered family resolved");

	/* The request the resolver sent down the fake socket. */
	if (recv(peer_fd, &req, sizeof(req), MSG_DONTWAIT) != (ssize_t) sizeof(req) ||
	    req.nlh.nlmsg_type != GENL_ID_CTRL ||
	    (req.nlh.nlmsg_flags & NLM_F_DUMP) != NLM_F_DUMP ||
	    req.genl.cmd != CTRL_CMD_GETFAMILY)
		BUG("genl ops: the resolver did not send GETFAMILY with NLM_F_DUMP");
}

/* ---------- Checking the flags the generator picks -------------------- */

struct tally {
	const char *what;
	unsigned int id;
	double lo, hi;		/* fraction of messages with both dump bits */
	unsigned int msgs;
	unsigned int dump;
	unsigned int pass;	/* flags and reserved word clear the header check */
	unsigned int drawn;	/* flags within DRAWN_FLAGS */
	unsigned int modifiers;	/* ... that carry MODIFIER_FLAGS */
	unsigned int reserved;	/* reserved word not 0 */
	unsigned int drawn_reserved;	/* ... on a message with drawn flags */
};

/*
 * genl_header_check() in net/netlink/genetlink.c as it runs for a cmd at or
 * past its family's resv_start_op: the reserved word, then the flags
 * outside REQUEST, ACK, ECHO and the dump pair.
 */
static bool header_check_passes(const struct nlmsghdr *nlh,
				const struct genlmsghdr *genl)
{
	unsigned short flags = nlh->nlmsg_flags;

	if (genl->reserved)
		return false;
	if ((flags & NLM_F_DUMP) == NLM_F_DUMP)	/* DUMP is 2 bits */
		flags &= ~NLM_F_DUMP;
	return !(flags & ~(NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO));
}

static void tally_msg(struct tally *t, const struct nlmsghdr *nlh,
		      const struct genlmsghdr *genl)
{
	t->msgs++;
	if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP)
		t->dump++;
	if (header_check_passes(nlh, genl))
		t->pass++;
	if (genl->reserved)
		t->reserved++;
	if (nlh->nlmsg_flags & ~DRAWN_FLAGS)
		return;
	t->drawn++;
	if (genl->reserved)
		t->drawn_reserved++;
	if (nlh->nlmsg_flags & MODIFIER_FLAGS)
		t->modifiers++;
}

static void tally_flags(struct tally *tallies, unsigned int nr_tallies)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_GENERIC,
	};
	unsigned int round, i;

	for (round = 0; round < ROUNDS; round++) {
		const struct nlmsghdr *nlh;
		struct genlmsghdr genl;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len >= NLMSG_HDRLEN + GENL_HDRLEN) {
			memcpy(&genl, NLMSG_DATA(nlh), sizeof(genl));
			for (i = 0; i < nr_tallies; i++) {
				if (nlh->nlmsg_type == tallies[i].id)
					tally_msg(&tallies[i], nlh, &genl);
			}
		}
		free(buf);
	}
}

/*
 * A request clears the genl core's header check unless a flag lies outside
 * REQUEST, ACK, ECHO and the dump pair, or the reserved word is not 0.  A
 * random chaos word (one message in ten) clears it about one time in 4000
 * and the modifiers, drawn for one genl message in 8, leave about 0.91 of
 * the rest clear, so 0.82 of a family's messages do.  When every message
 * drew them and one in four carried a reserved word it was 0.16 to 0.21;
 * either fault alone leaves at most 0.62, so the floor of 0.75, nine
 * sigma under 0.82, turns away both.
 *
 * The modifiers must stay, and rare: ATOMIC/CREATE or APPEND show in 0.077
 * of the messages, counted among those whose flags are all the
 * generator's own bits (a chaos word is one time in 512), and the bounds
 * 0.02 and 0.12 turn away dropping them and drawing them one time in 4.
 * The reserved word is 0 on all of those but the few chaos words among
 * them, and nonzero on 0.025 of all messages (chaos, one time in four);
 * the limit is 0.5% either way.
 */
static void check_header_check(const struct tally *t, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		double pass, mods, drawn_reserved, reserved;

		if (t[i].msgs < 1000 || t[i].drawn < 1000)
			BUG("genl ops: too few messages to judge the header check");
		pass = (double) t[i].pass / t[i].msgs;
		mods = (double) t[i].modifiers / t[i].msgs;
		drawn_reserved = (double) t[i].drawn_reserved / t[i].drawn;
		reserved = (double) t[i].reserved / t[i].msgs;

		if (pass < 0.75) {
			fprintf(stderr, "%s: %u of %u messages clear the genl header check, want at least 0.75\n",
				t[i].what, t[i].pass, t[i].msgs);
			BUG("genl ops: genl requests mostly bounce in the header check");
		}
		if (mods < 0.02 || mods > 0.12) {
			fprintf(stderr, "%s: %u of %u messages carry NLM_F_ATOMIC, CREATE or APPEND, want a fraction in [0.020, 0.120]\n",
				t[i].what, t[i].modifiers, t[i].msgs);
			BUG("genl ops: the modifier flags are not rare but present");
		}
		if (drawn_reserved > 0.005) {
			fprintf(stderr, "%s: %u of %u messages with drawn flags carry a reserved word\n",
				t[i].what, t[i].drawn_reserved, t[i].drawn);
			BUG("genl ops: a message that is not chaos carries a reserved word");
		}
		if (reserved < 0.005) {
			fprintf(stderr, "%s: %u of %u messages carry a reserved word\n",
				t[i].what, t[i].reserved, t[i].msgs);
			BUG("genl ops: no message carries a reserved word");
		}
	}
}

/*
 * One message in ten carries flags drawn at random, which the cmd's
 * shape leaves alone: both dump bits show in one such word in four.  In
 * the rest, a coin flip sets NLM_F_DUMP, and when it does not the NEW and
 * DELETE modifiers still set both bits between them 13 times in 32 for
 * the one genl message in 8 that draws them, so a cmd with no pin shows
 * both bits in 0.52 of them.  Fractions expected over the 3000 or so
 * messages each family gets:
 *
 *	dumpit only	0.925	(0.9 pinned + 0.1 * 0.25)
 *	doit only	0.025	(0.1 * 0.25)
 *	both, unknown	0.50	(0.9 * 0.52 + 0.1 * 0.25)
 */
static void check_dump_pinned(const struct tally *t, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		double frac = t[i].msgs ? (double) t[i].dump / t[i].msgs : -1.0;

		if (t[i].msgs < 1000 || frac < t[i].lo || frac > t[i].hi) {
			fprintf(stderr, "%s: %u of %u messages carry NLM_F_DUMP, want a fraction in [%.3f, %.3f]\n",
				t[i].what, t[i].dump, t[i].msgs, t[i].lo, t[i].hi);
			BUG("genl ops: the dump flag does not follow the cmd's handlers");
		}
	}
}

/*
 * Another protocol still draws the modifiers on every message, as it did.
 * Over xfrm messages ATOMIC/CREATE or APPEND show in 0.62 of them (0.9 *
 * 0.69), and both dump bits in 0.66.  A genl-style gate would give 0.08
 * and 0.50.
 */
static void check_other_protocol_flags(void)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_XFRM,
	};
	unsigned int round, msgs = 0, dump = 0, mods = 0;
	double dump_frac, mods_frac;

	for (round = 0; round < ROUNDS; round++) {
		const struct nlmsghdr *nlh;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len >= NLMSG_HDRLEN) {
			msgs++;
			if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP)
				dump++;
			if (!(nlh->nlmsg_flags & ~DRAWN_FLAGS) &&
			    (nlh->nlmsg_flags & MODIFIER_FLAGS))
				mods++;
		}
		free(buf);
	}

	dump_frac = (double) dump / msgs;
	mods_frac = (double) mods / msgs;
	if (dump_frac < 0.58 || dump_frac > 0.74 || mods_frac < 0.5 || mods_frac > 0.7) {
		fprintf(stderr, "xfrm: %u of %u messages carry both dump bits and %u the modifier flags, want fractions in [0.58, 0.74] and [0.50, 0.70]\n",
			dump, msgs, mods);
		BUG("genl ops: a protocol other than genl draws its flags differently");
	}
}

static void check_flags(void)
{
	struct tally t[] = {
		{ "doit only", ID_DO_ONLY, 0.005, 0.045 },
		{ "dumpit only", ID_DUMP_ONLY, 0.88, 0.98 },
		{ "doit and dumpit", ID_BOTH, 0.42, 0.58 },
		{ "no op list", ID_NO_OPS, 0.42, 0.58 },
	};

	tally_flags(t, ARRAY_SIZE(t));
	check_header_check(t, ARRAY_SIZE(t));
	check_dump_pinned(t, ARRAY_SIZE(t));
	check_other_protocol_flags();
}

/* ---------- Checking the attributes a cmd's policy takes ---------------- */

static struct slot *find_slot(struct slot *slots, unsigned int n_slots,
			      unsigned short id)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		if (slots[i].id == id)
			return &slots[i];
	}
	return NULL;
}

/*
 * Whether v, a host-order scalar or the count of an array's elements, is
 * inside the slot's bound.  What is inside is kept apart, with the bits it
 * sets and the ends it reaches, so that a spec which draws from less of the
 * bound than the policy allows shows up as well as one that strays outside
 * it.
 */
static void tally_bound(struct slot *slot, uint64_t v)
{
	if (slot->bound == SB_MASK ? (v & ~slot->hi) != 0 :
				     (v < slot->lo || v > slot->hi))
		return;

	if (slot->in_bound++ == 0) {
		slot->or_all = slot->and_all = slot->min_v = slot->max_v = v;
		return;
	}
	slot->or_all |= v;
	slot->and_all &= v;
	if (v < slot->min_v)
		slot->min_v = v;
	if (v > slot->max_v)
		slot->max_v = v;
}

static bool stream_conforms(const unsigned char *p, size_t len,
			    struct slot *slots, unsigned int n_slots);

/* The attributes in a stream that conformed. */
static uint32_t stream_count(const unsigned char *p, size_t len)
{
	uint32_t n = 0;
	size_t off;

	for (off = 0; off < len; n++)
		off += NLA_ALIGN(((const struct nlattr *) (p + off))->nla_len);
	return n;
}

/*
 * The elements of an NLA_POLICY_NESTED_ARRAY: any type, but each an
 * NLA_F_NESTED attribute, as userspace sends them and a handler's
 * nla_parse_nested() wants, holding a stream of its own.
 */
static bool array_conforms(const unsigned char *p, size_t len, struct slot *slot)
{
	size_t off = 0;
	uint32_t count = 0;

	for (; off < len; count++) {
		const struct nlattr *elem;

		if (len - off < NLA_HDRLEN)
			return false;
		elem = (const struct nlattr *) (p + off);
		if (elem->nla_len < NLA_HDRLEN || elem->nla_len > len - off ||
		    !(elem->nla_type & NLA_F_NESTED))
			return false;
		if (elem->nla_len > NLA_HDRLEN &&
		    !stream_conforms(p + off + NLA_HDRLEN, elem->nla_len - NLA_HDRLEN,
				     slot->nest, slot->n_nest))
			return false;
		off += NLA_ALIGN(elem->nla_len);
	}
	if (slot->bound != SB_NONE)
		tally_bound(slot, count);
	return true;
}

/*
 * What nla_validate() with NL_VALIDATE_STRICT makes of the stream: an id
 * past the policy, or in a slot it leaves untyped, is refused, as is a
 * length the slot does not take, a string with no NUL, a nest without
 * NLA_F_NESTED and that flag on an attribute that is not a nest.
 */
static bool stream_conforms(const unsigned char *p, size_t len,
			    struct slot *slots, unsigned int n_slots)
{
	uint64_t once_seen = 0;
	size_t off = 0;

	while (off < len) {
		const struct nlattr *nla;
		struct slot *slot;
		size_t plen;

		if (len - off < NLA_HDRLEN)
			return false;
		nla = (const struct nlattr *) (p + off);
		if (nla->nla_len < NLA_HDRLEN || nla->nla_len > len - off)
			return false;
		slot = find_slot(slots, n_slots, nla->nla_type & NLA_TYPE_MASK);
		if (slot == NULL)
			return false;
		if (slot->once) {
			uint64_t bit = 1ULL << (slot - slots);

			if (once_seen & bit)
				return false;
			once_seen |= bit;
		}

		plen = nla->nla_len - NLA_HDRLEN;
		if (!!(nla->nla_type & NLA_F_NESTED) !=
		    (slot->kind == SK_NEST || slot->kind == SK_ARRAY))
			return false;
		switch (slot->kind) {
		case SK_BYTES:
			if (plen < slot->min || plen > slot->max)
				return false;
			if (slot->bound != SB_NONE) {
				uint64_t v = 0;

				/* A bound is read at the payload's own width:
				 * a byte, a u16, a u32 or an NLA_UINT's 8. */
				memcpy(&v, p + off + NLA_HDRLEN,
				       plen < sizeof(v) ? plen : sizeof(v));
				tally_bound(slot, v);
			}
			break;
		case SK_SINT:
			if (plen != 4 && plen != 8)
				return false;
			break;
		case SK_STRING:
			if (plen < slot->min || (slot->max && plen > slot->max + 1u) ||
			    p[off + nla->nla_len - 1] != '\0')
				return false;
			break;
		case SK_NEST:
			if (!stream_conforms(p + off + NLA_HDRLEN, plen,
					     slot->nest, slot->n_nest))
				return false;
			if (slot->bound != SB_NONE)
				tally_bound(slot, stream_count(p + off + NLA_HDRLEN,
							       plen));
			break;
		case SK_ARRAY:
			if (!array_conforms(p + off + NLA_HDRLEN, plen, slot))
				return false;
			break;
		}
		slot->seen++;
		off += NLA_ALIGN(nla->nla_len);
	}
	return true;
}

/* The row for a request: its dump row when it is a dump and there is one. */
static struct cmd_policy *find_policy(struct policy_family *pf,
				      unsigned char cmd, bool dump)
{
	struct cmd_policy *found = NULL;
	unsigned int i;

	for (i = 0; i < pf->n_cmds; i++) {
		if (pf->cmds[i].cmd != cmd)
			continue;
		if (pf->cmds[i].dump == dump)
			return &pf->cmds[i];
		if (!pf->cmds[i].dump)
			found = &pf->cmds[i];
	}
	return found;
}

static struct policy_family *family_by_id(unsigned short id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		if (policy_families[i].id == id)
			return &policy_families[i];
	}
	return NULL;
}

static void hexdump(const unsigned char *p, size_t len)
{
	size_t i;

	for (i = 0; i < len && i < 256; i++)
		fprintf(stderr, "%02x%c", p[i], (i % 16 == 15) ? '\n' : ' ');
	fputc('\n', stderr);
}

static void expect_slots_seen(const struct slot *slots, unsigned int n_slots,
			      const char *what)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		if (slots[i].seen == 0) {
			fprintf(stderr, "%s: attribute %u was never emitted\n",
				what, slots[i].id);
			BUG("genl ops: a policy's attribute is out of the generator's reach");
		}
		expect_slots_seen(slots[i].nest, slots[i].n_nest, what);
	}
}

#define BOUND_SAMPLES	1000

/*
 * A bounded slot is filled inside its bound seven draws in eight; the
 * eighth is random bytes, which land inside as often as the bound's share
 * of the values its width takes (2^8 for a byte, 2^16 for a u16, 2^32
 * for a u32, 2^64 for an NLA_UINT's 8-byte form), so the fraction inside
 * is 0.875 plus that share of 0.125.  Over the 1000 draws or more asked
 * for it has a standard deviation of about 0.01, so 0.06 either way turns
 * away a spec that never strays outside the bound and one that never
 * settles inside it.  The eighth draw of an array or a nest goes past
 * its cap, so never lands inside.  The draws inside must also span the
 * bound, which a spec with a narrower one than the policy's does not: a
 * mask sets and clears each of its bits, and a range reaches to within a
 * tenth of its width of both ends.
 */
static void expect_slots_bounded(const struct slot *slots, unsigned int n_slots,
				 const char *what)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		const struct slot *slot = &slots[i];
		double share, want, frac;
		bool spans;

		expect_slots_bounded(slot->nest, slot->n_nest, what);
		if (slot->bound == SB_NONE)
			continue;

		if (slot->seen < BOUND_SAMPLES) {
			fprintf(stderr, "%s: attribute %u drawn %u times, want %u\n",
				what, slot->id, slot->seen, BOUND_SAMPLES);
			BUG("genl ops: too few draws to judge a bounded attribute");
		}

		/* The share of random bytes that land inside the bound:
		 * the bound's share of the values one width takes, 2^64
		 * for an NLA_UINT's 8-byte form, which no shift reaches.
		 * An NLA_UINT draws 4 or 8 bytes equally often, so its
		 * share is the mean of the two widths'. */
		if (slot->kind == SK_ARRAY || slot->kind == SK_NEST) {
			share = 0;
		} else {
			unsigned int w;

			share = 0;
			for (w = slot->min; ; w = slot->max) {
				double values = w >= 8 ? 18446744073709551616.0 :
						 (double) (1ULL << (8 * w));

				if (slot->bound == SB_MASK)
					share += (double) (1ULL <<
							  __builtin_popcountll(slot->hi)) /
					       values;
				else
					share += ((double) slot->hi -
						  slot->lo + 1) / values;
				if (w == slot->max)
					break;
			}
			if (slot->min < slot->max)
				share /= 2;
		}
		want = 0.875 + 0.125 * share;
		frac = (double) slot->in_bound / slot->seen;
		if (frac < want - 0.06 || frac > want + 0.06) {
			fprintf(stderr, "%s: %u of %u draws of attribute %u inside the bound, want a fraction near %.3f\n",
				what, slot->in_bound, slot->seen, slot->id, want);
			BUG("genl ops: a bounded attribute is not drawn from its bound");
		}

		if (slot->bound == SB_MASK) {
			spans = slot->or_all == slot->hi && slot->and_all == 0;
		} else {
			uint64_t slack = (slot->hi - slot->lo) / 10;

			spans = slot->min_v - slot->lo <= slack &&
				slot->hi - slot->max_v <= slack;
		}
		if (!spans) {
			fprintf(stderr, "%s: draws of attribute %u inside the bound set %#llx and keep %#llx, from %llu to %llu\n",
				what, slot->id, (unsigned long long) slot->or_all,
				(unsigned long long) slot->and_all,
				(unsigned long long) slot->min_v,
				(unsigned long long) slot->max_v);
			BUG("genl ops: a bounded attribute does not cover its bound");
		}
	}
}

static void tally_required(const unsigned char *p, size_t len,
			   struct slot *slots, unsigned int n_slots);

/* The elements of an array, each a stream of the policy the slot names. */
static void tally_elements(const unsigned char *p, size_t len,
			   const struct slot *slot)
{
	size_t off = 0;

	while (off + NLA_HDRLEN <= len) {
		const struct nlattr *elem = (const struct nlattr *) (p + off);

		tally_required(p + off + NLA_HDRLEN, elem->nla_len - NLA_HDRLEN,
			       slot->nest, slot->n_nest);
		off += NLA_ALIGN(elem->nla_len);
	}
}

/*
 * A stream that is known to conform, against its policy of up to 64 slots:
 * every slot marked required counts the stream, and counts it again if the
 * stream holds the attribute.  A nest and each element of an array is a
 * stream of the policy its slot names, and counts the same way.
 */
static void tally_required(const unsigned char *p, size_t len,
			   struct slot *slots, unsigned int n_slots)
{
	unsigned long long got = 0;
	size_t off = 0;
	unsigned int i;

	while (off + NLA_HDRLEN <= len) {
		const struct nlattr *nla = (const struct nlattr *) (p + off);
		struct slot *slot = find_slot(slots, n_slots,
					      nla->nla_type & NLA_TYPE_MASK);

		if (slot != NULL) {
			size_t plen = nla->nla_len - NLA_HDRLEN;

			got |= 1ULL << (slot - slots);
			if (slot->kind == SK_NEST)
				tally_required(p + off + NLA_HDRLEN, plen,
					       slot->nest, slot->n_nest);
			else if (slot->kind == SK_ARRAY)
				tally_elements(p + off + NLA_HDRLEN, plen, slot);
		}
		off += NLA_ALIGN(nla->nla_len);
	}

	for (i = 0; i < n_slots; i++) {
		if (!slots[i].required)
			continue;
		slots[i].streams++;
		if (got & (1ULL << i))
			slots[i].present++;
	}
}

#define REQUIRED_STREAMS	600

/*
 * A required slot is left out of some streams and is in most of them.  The
 * emitter skips it one time in eight, and the draws that follow bring some
 * of those back, so it is in 0.875 of them or more, fewer where a nest deep
 * in the message has no room left for it.  Unmarked it would be in 0.2 to
 * 0.75 of the streams of the tables here.  Over 600 streams the fraction has
 * a standard deviation under 0.02, so 0.70 is five of them under a rate of
 * 0.80 and turns the unmarked case away for any table of more than two
 * attributes.  A slot that is never left out leaves the handler's
 * missing-attribute arm without traffic.
 */
static void expect_slots_required(const struct slot *slots, unsigned int n_slots,
				  const char *what)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		const struct slot *slot = &slots[i];

		expect_slots_required(slot->nest, slot->n_nest, what);
		if (!slot->required)
			continue;

		if (slot->streams < REQUIRED_STREAMS) {
			fprintf(stderr, "%s: attribute %u has %u streams, want %u\n",
				what, slot->id, slot->streams, REQUIRED_STREAMS);
			BUG("genl ops: too few streams to judge a required attribute");
		}
		if (slot->present < slot->streams * 7 / 10) {
			fprintf(stderr, "%s: attribute %u is in %u of %u streams, want at least 0.70\n",
				what, slot->id, slot->present, slot->streams);
			BUG("genl ops: a required attribute is left out too often");
		}
		if (slot->present == slot->streams) {
			fprintf(stderr, "%s: attribute %u is in all %u streams\n",
				what, slot->id, slot->streams);
			BUG("genl ops: a required attribute is never left out");
		}
	}
}

/* The fewest streams any required slot in the mirror, nests included, has
 * been counted in; UINT_MAX when it has none. */
static unsigned int min_required_streams(const struct slot *slots,
					 unsigned int n_slots)
{
	unsigned int least = UINT_MAX;
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		unsigned int streams = min_required_streams(slots[i].nest,
							    slots[i].n_nest);

		if (slots[i].required && slots[i].streams < streams)
			streams = slots[i].streams;
		if (streams < least)
			least = streams;
	}
	return least;
}

/* The same over the mirrors of every cmd of the families the test checks. */
static unsigned int min_policy_streams(void)
{
	unsigned int least = UINT_MAX;
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		const struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->n_cmds; j++) {
			unsigned int streams = min_required_streams(pf->cmds[j].slots,
								    pf->cmds[j].n_slots);

			if (streams < least)
				least = streams;
		}
	}
	return least;
}

/*
 * Only a lone message whose nlmsg_len is intact says where its attributes
 * end, so a batch is left out, and so is a message the generator gave a
 * corrupt length.  The corruption that doubles the length passes for an
 * intact one on a batch whose later messages are as long as the first,
 * which doubled_batch() tells apart.  An attribute that does not fit its
 * buffer is also cut short to fill it, which no policy takes, so a message
 * as long as the smallest buffer is left out too.
 */
#define SMALLEST_BUFFER	(NLMSG_HDRLEN + 1280)
#define ATTR_ROUNDS	150000
#define MIN_MSGS	30

/* Every family in the reply takes a share of the rounds, so the streams of a
 * nest deep in one family's cmd thin out as families are added: the rounds
 * go on, to this many, until each required slot has its REQUIRED_STREAMS. */
#define ATTR_ROUNDS_MAX	3000000

/*
 * Whether the len bytes at msg are a batch whose first message claims
 * twice its length, which then covers the rest.  Its length is a multiple
 * of 8, and the first message's attributes end halfway, where the next
 * message's header reads as an attribute of type 0, or of a random type
 * when that header's length is corrupt too.  An attribute of a lone message
 * that starts halfway has a type its policy takes, unless the table it came
 * from is wrong, which then shows at other offsets.
 */
static bool doubled_batch(const unsigned char *msg, size_t len, size_t hdrs,
			  struct slot *slots, unsigned int n_slots)
{
	const struct nlattr *nla;
	size_t off = hdrs;

	if (len % 8 != 0)
		return false;
	while (off < len / 2) {
		nla = (const struct nlattr *) (msg + off);
		if (nla->nla_len < NLA_HDRLEN)
			return false;
		off += NLA_ALIGN(nla->nla_len);
	}
	if (off != len / 2)
		return false;
	nla = (const struct nlattr *) (msg + off);
	return find_slot(slots, n_slots, nla->nla_type & NLA_TYPE_MASK) == NULL;
}

/*
 * Every attribute of every request to a family above is one its cmd's
 * policy takes, shaped to pass it, and every slot of every policy turns
 * up: a table that lost one, or took an id of another cmd's, fails.
 */
static void check_attrs_in_policy(void)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_GENERIC,
	};
	unsigned int round, i, j;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->fam->n_cmds; j++) {
			if (find_policy(pf, pf->fam->cmds[j].cmd, false) == NULL) {
				fprintf(stderr, "%s: cmd %u has no policy mirror\n",
					pf->fam->name, pf->fam->cmds[j].cmd);
				BUG("genl ops: a cmd of a checked family is not mirrored");
			}
		}
	}

	for (round = 0; round < ATTR_ROUNDS ||
	     (round < ATTR_ROUNDS_MAX && min_policy_streams() < REQUIRED_STREAMS);
	     round++) {
		const struct genlmsghdr *genl;
		const struct nlmsghdr *nlh;
		struct policy_family *pf;
		struct cmd_policy *cp;
		const unsigned char *attrs;
		size_t attrs_len, hdrs;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len < NLMSG_HDRLEN + GENL_HDRLEN || len >= SMALLEST_BUFFER ||
		    NLMSG_ALIGN(nlh->nlmsg_len) != len)
			goto next;
		pf = family_by_id(nlh->nlmsg_type);
		if (pf == NULL)
			goto next;

		/* A family with a fixed header of its own, openvswitch's, has
		 * its attributes after that. */
		hdrs = NLMSG_HDRLEN + GENL_HDRLEN + pf->fam->hdrsize;
		if (nlh->nlmsg_len < hdrs)
			goto next;

		genl = NLMSG_DATA(nlh);
		cp = find_policy(pf, genl->cmd,
				 (nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP);
		if (cp == NULL ||
		    doubled_batch(buf, len, hdrs, cp->slots, cp->n_slots))
			goto next;
		cp->msgs++;

		attrs = (const unsigned char *) nlh + hdrs;
		attrs_len = nlh->nlmsg_len - hdrs;
		if (!stream_conforms(attrs, attrs_len, cp->slots, cp->n_slots)) {
			fprintf(stderr, "%s cmd %u%s: attributes its policy does not take:\n",
				pf->fam->name, genl->cmd, cp->dump ? " dump" : "");
			hexdump(attrs, attrs_len);
			BUG("genl ops: a request carries what its cmd's policy refuses");
		}
		tally_required(attrs, attrs_len, cp->slots, cp->n_slots);
next:
		free(buf);
	}

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		const struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->n_cmds; j++) {
			const struct cmd_policy *cp = &pf->cmds[j];
			char what[64];

			if (cp->msgs < MIN_MSGS) {
				fprintf(stderr, "%s cmd %u%s: only %u messages\n",
					pf->fam->name, cp->cmd, cp->dump ? " dump" : "",
					cp->msgs);
				BUG("genl ops: too few messages to judge a cmd's attributes");
			}
			snprintf(what, sizeof(what), "%s cmd %u%s", pf->fam->name,
				 cp->cmd, cp->dump ? " dump" : "");
			expect_slots_seen(cp->slots, cp->n_slots, what);
		}
	}
}

/* ---------- Checking the controller's requests --------------------------- */

/*
 * net/netlink/genetlink.c: ctrl_policy_family, which GETFAMILY takes, and
 * ctrl_policy_policy, GETPOLICY's, which adds OP.  GETPOLICY and the dump
 * of GETFAMILY parse strictly, so an id that is not here, or one of another
 * length, refuses the request.
 */
static struct slot ctrl_family[] = {
	S_U16(CTRL_ATTR_FAMILY_ID),
	S_STR(CTRL_ATTR_FAMILY_NAME, GENL_NAMSIZ - 1),
};
static struct slot ctrl_policy[] = {
	S_U16(CTRL_ATTR_FAMILY_ID),
	S_STR(CTRL_ATTR_FAMILY_NAME, GENL_NAMSIZ - 1),
	S_U32(CTRL_ATTR_OP),
};

#define CTRL_ROUNDS	40000

/* The families the canned reply resolved, and how many requests named each. */
static struct {
	const struct genl_family_grammar *fam;
	unsigned int named;
} resolved[64];
static unsigned int n_resolved;

/*
 * What the requests of one cmd name.  A family is named by a FAMILY_ID or a
 * FAMILY_NAME that is a resolved family's; the last of each in a request is
 * the one the kernel reads.
 */
struct ctrl_names {
	unsigned int msgs;		/* requests parsed */
	unsigned int named;		/* ... that name a resolved family */
	unsigned int ids, ids_ok;	/* FAMILY_ID attributes, those that do */
	unsigned int names, names_ok;	/* the same of FAMILY_NAME */
	unsigned int both, agree;	/* with both, those naming one family */
	unsigned int ops, ops_ok;	/* OP beside a family, those it has */
};

static void count_named(const struct genl_family_grammar *fam)
{
	unsigned int i;

	for (i = 0; i < n_resolved; i++) {
		if (resolved[i].fam == fam)
			resolved[i].named++;
	}
}

/* The ids and names in the stream, which has conformed, and what they name. */
static void tally_ctrl_names(struct ctrl_names *t, const unsigned char *attrs,
			     size_t len)
{
	const struct genl_family_grammar *by_id = NULL, *by_name = NULL, *fam;
	bool have_id = false, have_name = false, have_op = false;
	uint32_t op = 0;
	size_t off = 0;
	unsigned int i, j;

	while (off < len) {
		const struct nlattr *nla = (const struct nlattr *) (attrs + off);
		const unsigned char *payload = attrs + off + NLA_HDRLEN;
		uint16_t id;

		switch (nla->nla_type & NLA_TYPE_MASK) {
		case CTRL_ATTR_FAMILY_ID:
			memcpy(&id, payload, sizeof(id));
			by_id = genl_lookup_by_id(id);
			have_id = true;
			break;
		case CTRL_ATTR_FAMILY_NAME:
			by_name = NULL;
			for (i = 0; i < n_resolved; i++) {
				if (strcmp(resolved[i].fam->name, (const char *) payload) == 0)
					by_name = resolved[i].fam;
			}
			have_name = true;
			break;
		case CTRL_ATTR_OP:
			memcpy(&op, payload, sizeof(op));
			have_op = true;
			break;
		}
		off += NLA_ALIGN(nla->nla_len);
	}

	t->msgs++;
	t->ids += have_id;
	t->ids_ok += by_id != NULL;
	t->names += have_name;
	t->names_ok += by_name != NULL;
	if (by_id != NULL || by_name != NULL)
		t->named++;
	if (have_id && have_name) {
		t->both++;
		t->agree += by_id != NULL && by_id == by_name;
	}
	count_named(by_id);
	count_named(by_name);

	/* The kernel reads the family from the id when there is one. */
	fam = have_id ? by_id : by_name;
	if (have_op && fam != NULL) {
		t->ops++;
		for (j = 0; j < fam->n_cmds; j++) {
			if (fam->cmds[j].cmd == op) {
				t->ops_ok++;
				break;
			}
		}
	}
}

static void expect_fraction(unsigned int part, unsigned int whole, double lo,
			    double hi, const char *what, const char *bug)
{
	if (whole < 300 || part < whole * lo || part > whole * hi) {
		fprintf(stderr, "%s: %u of %u, want a fraction in [%.2f, %.2f]\n",
			what, part, whole, lo, hi);
		BUG(bug);
	}
}

/*
 * A request names a resolved family, by id, by name or by both, and a
 * GETPOLICY request with an OP asks for a cmd of that family.  The
 * generator draws each attribute from the family it picked for the request
 * seven times in eight and leaves the eighth random bytes, so the ids and
 * names are a resolved family's 0.875 of the time and no more, and the two
 * name one family 0.766 of the time they are both there.  A request has
 * one to seven attributes about seven times in eight, each a third of the
 * three ids (a half of the two), so it names a family 0.762 of the time
 * for GETPOLICY and 0.834 for GETFAMILY, and the OP beside a family is one
 * of its cmds 0.875 of the time.  Each fraction is held to a band that is
 * five standard deviations or more from its value over the 1000 requests or
 * so each cmd has; a request that never names a family, as the random bytes
 * of the old table did, has none.
 */
static void expect_ctrl_names(const struct ctrl_names *t, double named_floor,
			      bool has_op, const char *what)
{
	expect_fraction(t->named, t->msgs, named_floor, 1.0, what,
			"genl ops: the controller is not asked about a resolved family");
	expect_fraction(t->ids_ok, t->ids, 0.80, 0.95, what,
			"genl ops: a FAMILY_ID is not a resolved family's seven times in eight");
	expect_fraction(t->names_ok, t->names, 0.80, 0.95, what,
			"genl ops: a FAMILY_NAME is not a resolved family's seven times in eight");
	expect_fraction(t->agree, t->both, 0.65, 1.0, what,
			"genl ops: the id and the name of a request name two families");
	if (has_op)
		expect_fraction(t->ops_ok, t->ops, 0.80, 0.95, what,
				"genl ops: an OP is not a cmd of the family it is asked of");
}

/*
 * What a request to the controller carries.  Only GETFAMILY and GETPOLICY
 * have handlers; genl_family_rcv_msg() answers any other cmd before it
 * reads an attribute.  The generator sends one of the two seven times in
 * eight, so each is 0.449 of the requests and the cmds with no handler
 * 0.10, which a cmd drawn from all eleven would make 0.82.  A cmd with no
 * handler carries no attribute and the others only those their policy takes.
 * GETPOLICY has a dumpit alone and carries both dump bits as a dumpit-only
 * family's cmd does, 0.925 of the time (the message in ten with random
 * flags aside); GETFAMILY has both handlers and carries them 0.49 of the
 * time, as a cmd of either does.  Over the 2000 requests or so of each the
 * fractions have standard deviations under 0.012, and the bounds are six of
 * them out or more.
 */
static void check_ctrl_requests(void)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_GENERIC,
	};
	unsigned int msgs = 0, unserved = 0;
	unsigned int family_msgs = 0, family_dump = 0;
	unsigned int policy_msgs = 0, policy_dump = 0;
	struct ctrl_names family_names = { 0 }, policy_names = { 0 };
	unsigned int round, id, i;

	for (id = 1; id < 1024; id++) {
		const struct genl_family_grammar *fam = genl_lookup_by_id(id);

		if (fam == NULL)
			continue;
		if (n_resolved == ARRAY_SIZE(resolved))
			BUG("genl ops: more resolved families than the controller check holds");
		resolved[n_resolved++].fam = fam;
	}

	for (round = 0; round < CTRL_ROUNDS; round++) {
		const unsigned char *attrs;
		const struct genlmsghdr *genl;
		const struct nlmsghdr *nlh;
		struct slot *slots = NULL;
		unsigned int n_slots = 0;
		size_t hdrs = NLMSG_HDRLEN + GENL_HDRLEN;
		bool dump;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len < hdrs || nlh->nlmsg_type != GENL_ID_CTRL)
			goto next;
		genl = NLMSG_DATA(nlh);
		dump = (nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;

		msgs++;
		if (genl->cmd == CTRL_CMD_GETFAMILY) {
			family_msgs++;
			family_dump += dump;
			slots = ctrl_family;
			n_slots = ARRAY_SIZE(ctrl_family);
		} else if (genl->cmd == CTRL_CMD_GETPOLICY) {
			policy_msgs++;
			policy_dump += dump;
			slots = ctrl_policy;
			n_slots = ARRAY_SIZE(ctrl_policy);
		} else {
			unserved++;
		}

		if (len >= SMALLEST_BUFFER || NLMSG_ALIGN(nlh->nlmsg_len) != len ||
		    doubled_batch(buf, len, hdrs, slots, n_slots))
			goto next;
		attrs = (const unsigned char *) nlh + hdrs;
		if (slots == NULL ? nlh->nlmsg_len != hdrs :
		    !stream_conforms(attrs, nlh->nlmsg_len - hdrs, slots, n_slots)) {
			fprintf(stderr, "controller cmd %u: attributes its policy does not take:\n",
				genl->cmd);
			hexdump(attrs, nlh->nlmsg_len - hdrs);
			BUG("genl ops: a request to the controller carries what its policy refuses");
		}
		if (slots != NULL)
			tally_ctrl_names(slots == ctrl_family ? &family_names :
					 &policy_names, attrs, nlh->nlmsg_len - hdrs);
next:
		free(buf);
	}

	if (msgs < 2000 || family_msgs < msgs * 0.40 || policy_msgs < msgs * 0.40 ||
	    unserved < msgs * 0.05 || unserved > msgs * 0.16) {
		fprintf(stderr, "controller: %u requests, %u GETFAMILY, %u GETPOLICY, %u of other cmds\n",
			msgs, family_msgs, policy_msgs, unserved);
		BUG("genl ops: the controller is not sent mostly the cmds it has handlers for");
	}
	if (policy_dump < policy_msgs * 0.88 || policy_dump > policy_msgs * 0.98) {
		fprintf(stderr, "controller: %u of %u GETPOLICY requests carry NLM_F_DUMP, want a fraction in [0.88, 0.98]\n",
			policy_dump, policy_msgs);
		BUG("genl ops: GETPOLICY is not sent as a dump");
	}
	if (family_dump < family_msgs * 0.42 || family_dump > family_msgs * 0.58) {
		fprintf(stderr, "controller: %u of %u GETFAMILY requests carry NLM_F_DUMP, want a fraction in [0.42, 0.58]\n",
			family_dump, family_msgs);
		BUG("genl ops: GETFAMILY is pinned to one of its handlers");
	}
	expect_slots_seen(ctrl_family, ARRAY_SIZE(ctrl_family), "controller GETFAMILY");
	expect_slots_seen(ctrl_policy, ARRAY_SIZE(ctrl_policy), "controller GETPOLICY");

	expect_ctrl_names(&family_names, 0.75, false, "controller GETFAMILY");
	expect_ctrl_names(&policy_names, 0.70, true, "controller GETPOLICY");
	for (i = 0; i < n_resolved; i++) {
		if (resolved[i].named == 0) {
			fprintf(stderr, "controller: no request names %s\n",
				resolved[i].fam->name);
			BUG("genl ops: the controller is never asked about a resolved family");
		}
	}
}

/* ---------- Checking how a nest is filled -------------------------------- */

size_t append_specced_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs,
			     uint64_t *used);

#define NEST_ROUNDS	20000

/*
 * Nests of the generator's own tables and mirrors of what each must hold.
 * A nest with a table of its own gets its children from it, a fixed-size
 * one at its size however long, an array gets flagged elements that hold a
 * stream apiece, and the nests of a table without any hold what the table
 * holds, a NESTED child among them a placeholder of 16 bytes.
 */
static void check_nest_tables(void)
{
	static const struct nla_attr_spec leaf[] = {
		{ 1, NLA_KIND_U16, 2 },
		{ 2, NLA_KIND_BINARY_FIXED2, 6, 6 },
		{ 3, NLA_KIND_BINARY_FIXED2, 80, 80 },
	};
	static const struct nla_attr_spec elem[] = {
		{ 1, NLA_KIND_U32, 4 },
		{ 2, NLA_KIND_NESTED_ARRAY, 0, 0, leaf, ARRAY_SIZE(leaf) },
		{ 3, NLA_KIND_NESTED, 0, 0, leaf, ARRAY_SIZE(leaf) },
	};
	static const struct nla_attr_spec top[] = {
		{ 4, NLA_KIND_NESTED_ARRAY, 0, 0, elem, ARRAY_SIZE(elem) },
		{ 5, NLA_KIND_NESTED, 0, 0, elem, ARRAY_SIZE(elem) },
		{ 6, NLA_KIND_U8, 1 },
	};
	static const struct nla_attr_spec flat[] = {
		{ 7, NLA_KIND_NESTED, 0 },
		{ 8, NLA_KIND_U16, 2 },
	};
	static struct slot leaf_mirror[] = {
		S_U16(1), S_BLOB(2, 6, 6), S_BLOB(3, 80, 80),
	};
	static struct slot elem_mirror[] = {
		S_U32(1), S_ARRAY(2, leaf_mirror), S_NEST(3, leaf_mirror),
	};
	static struct slot top_mirror[] = {
		S_ARRAY(4, elem_mirror), S_NEST(5, elem_mirror), S_U8(6),
	};
	static struct slot flat_inside[] = { S_BLOB(7, 16, 16), S_U16(8) };
	static struct slot flat_mirror[] = { S_NEST(7, flat_inside), S_U16(8) };
	static const struct {
		const struct nla_attr_spec *specs;
		unsigned int n_specs;
		struct slot *mirror;
		unsigned int n_mirror;
	} cases[] = {
		{ top, ARRAY_SIZE(top), top_mirror, ARRAY_SIZE(top_mirror) },
		{ flat, ARRAY_SIZE(flat), flat_mirror, ARRAY_SIZE(flat_mirror) },
	};
	unsigned char buf[2048];
	unsigned int i, round;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		char what[32];

		for (round = 0; round < NEST_ROUNDS; round++) {
			size_t end;

			memset(buf, 0, sizeof(buf));
			end = append_specced_nlattr(buf, 0, sizeof(buf),
						    cases[i].specs, cases[i].n_specs,
						    NULL);
			if (stream_conforms(buf, end, cases[i].mirror, cases[i].n_mirror))
				continue;
			fprintf(stderr, "nest table %u:\n", i);
			hexdump(buf, end);
			BUG("genl ops: a nest is not filled from the table it names");
		}
		snprintf(what, sizeof(what), "nest table %u", i);
		expect_slots_seen(cases[i].mirror, cases[i].n_mirror, what);
	}
}

/* ---------- Checking the values of the bounded scalars ------------------- */

/* The fewest draws of any bounded slot in the mirror, nests included;
 * UINT_MAX when it has none. */
static unsigned int min_bounded_seen(const struct slot *slots, unsigned int n_slots)
{
	unsigned int least = UINT_MAX;
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		unsigned int seen = min_bounded_seen(slots[i].nest, slots[i].n_nest);

		if (slots[i].bound != SB_NONE && slots[i].seen < seen)
			seen = slots[i].seen;
		if (seen < least)
			least = seen;
	}
	return least;
}

/* A slot deep in a nest is drawn rarely, so the rounds run until every
 * bounded slot has its BOUND_SAMPLES, or to this many. */
#define BOUND_ROUNDS	400000

/*
 * Attributes drawn from table, each held to the mirror of the policy the
 * table stands for, until the bounded slots have their draws, and then
 * those slots held to their bounds.  The 2048 bytes leave an attribute
 * room, so none is cut short.
 */
static void check_bounded_draws(const struct nla_attr_spec *table, size_t n_table,
				struct slot *mirror, unsigned int n_mirror,
				const char *what)
{
	unsigned char buf[2048];
	unsigned int round;

	for (round = 0; round < BOUND_ROUNDS; round++) {
		size_t end;

		if (round % 256 == 0 &&
		    min_bounded_seen(mirror, n_mirror) >= BOUND_SAMPLES)
			break;
		memset(buf, 0, sizeof(buf));
		end = append_specced_nlattr(buf, 0, sizeof(buf), table, n_table,
					    NULL);
		if (stream_conforms(buf, end, mirror, n_mirror))
			continue;
		fprintf(stderr, "%s:\n", what);
		hexdump(buf, end);
		BUG("genl ops: a draw carries what its policy refuses");
	}
	expect_slots_bounded(mirror, n_mirror, what);
}

/*
 * Each bounded kind through the emitter: a mask of one bit and one of
 * eighteen, as wide as nfsd's export flags; a range from 1 and one from 0,
 * which is NLA_POLICY_MAX; one that runs to the top of the type, as
 * NLA_POLICY_MIN does; the same three of a u16, which is two bytes and
 * host order; a byte's range, one of them pinned to one number; an
 * NLA_UINT's range and two of its masks, at 4 or 8 bytes; an array of
 * two elements at most; and a nest of two children at most.
 */
static void check_bounded_tables(void)
{
	static const struct nla_attr_spec leaf[] = {
		{ 1, NLA_KIND_U32, 4 },
	};
	static const struct nla_attr_spec specs[] = {
		{ 1, NLA_KIND_U32_MASK, 0x1 },
		{ 2, NLA_KIND_U32_MASK, 0x3ffff },
		{ 3, NLA_KIND_U32_RANGE, 6, 1 },
		{ 4, NLA_KIND_U32_RANGE, 4095 },
		{ 5, NLA_KIND_U32_RANGE, UINT32_MAX, 68 },
		{ 6, NLA_KIND_NESTED_ARRAY, 2, 0, leaf, ARRAY_SIZE(leaf) },
		{ 7, NLA_KIND_NESTED, 2, 0, leaf, ARRAY_SIZE(leaf) },
		{ 8, NLA_KIND_U16_RANGE, 1000, 10 },
		{ 9, NLA_KIND_U16_RANGE, 255 },
		{ 10, NLA_KIND_U16_RANGE, UINT16_MAX, 1 },
		{ 11, NLA_KIND_U8_RANGE, 127 },
		{ 12, NLA_KIND_U8_RANGE, 5, 5 },
		{ 13, NLA_KIND_UINT_RANGE, UINT32_MAX, 1 },
		{ 14, NLA_KIND_UINT_MASK, 0x1 },
		{ 15, NLA_KIND_UINT_MASK, 0x3ffff },
	};
	static struct slot leaf_mirror[] = { S_U32(1) };
	static struct slot mirror[] = {
		S_U32_MASK(1, 0x1),
		S_U32_MASK(2, 0x3ffff),
		S_U32_RANGE(3, 1, 6),
		S_U32_RANGE(4, 0, 4095),
		S_U32_RANGE(5, 68, UINT32_MAX),
		S_ARRAY_MAX(6, leaf_mirror, 2),
		S_NEST_MAX(7, leaf_mirror, 2),
		S_U16_RANGE(8, 10, 1000),
		S_U16_RANGE(9, 0, 255),
		S_U16_RANGE(10, 1, UINT16_MAX),
		S_U8_RANGE(11, 0, 127),
		S_U8_RANGE(12, 5, 5),
		S_UINT_RANGE(13, 1, UINT32_MAX),
		S_UINT_MASK(14, 0x1),
		S_UINT_MASK(15, 0x3ffff),
	};

	check_bounded_draws(specs, ARRAY_SIZE(specs), mirror, ARRAY_SIZE(mirror),
			    "bounded tables");
}

/*
 * NLA_KIND_SOCKADDR through the emitter: seven draws in eight a
 * sockaddr_in or sockaddr_in6 at its own length, both families about as
 * often, on the loopback address seven times in eight and with a port
 * above the privileged ones; the eighth random bytes.  Over 4000 draws the
 * fraction well formed has a standard deviation of about 0.005.
 */
#define SOCKADDR_DRAWS	4000

static void check_sockaddr_kind(void)
{
	static const struct nla_attr_spec spec[] = {
		{ 1, NLA_KIND_SOCKADDR },
	};
	unsigned int i, good = 0, v4 = 0, loopback = 0;
	unsigned char buf[256];

	for (i = 0; i < SOCKADDR_DRAWS; i++) {
		const unsigned char *p = buf + NLA_HDRLEN;
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
		struct nlattr nla;
		sa_family_t family;

		memset(buf, 0, sizeof(buf));
		if (append_specced_nlattr(buf, 0, sizeof(buf), spec,
					  ARRAY_SIZE(spec), NULL) == 0)
			BUG("genl ops: a sockaddr spec emitted nothing");
		memcpy(&nla, buf, sizeof(nla));
		memcpy(&family, p, sizeof(family));
		if (nla.nla_len == NLA_HDRLEN + sizeof(sin) && family == AF_INET) {
			memcpy(&sin, p, sizeof(sin));
			if (ntohs(sin.sin_port) < 1024)
				continue;
			v4++;
			loopback += sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
		} else if (nla.nla_len == NLA_HDRLEN + sizeof(sin6) &&
			   family == AF_INET6) {
			memcpy(&sin6, p, sizeof(sin6));
			if (ntohs(sin6.sin6_port) < 1024)
				continue;
			loopback += IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr);
		} else {
			continue;
		}
		good++;
	}
	if (good < SOCKADDR_DRAWS * 0.84 || good > SOCKADDR_DRAWS * 0.91 ||
	    v4 < good * 0.4 || v4 > good * 0.6 ||
	    loopback < good * 0.84 || loopback > good * 0.91) {
		fprintf(stderr, "sockaddr kind: %u of %u well formed, %u IPv4, %u on loopback\n",
			good, SOCKADDR_DRAWS, v4, loopback);
		BUG("genl ops: a sockaddr is not drawn as its family's");
	}
}

/*
 * Whether spec declares slot's bound: a mask or range kind at the slot's
 * width, with the bound's ends, or a nest or array capped where its
 * handler caps it.  A byte's range is NLA_KIND_U8_RANGE, a u16's
 * NLA_KIND_U16_RANGE, a u32's NLA_KIND_U32_MASK or NLA_KIND_U32_RANGE,
 * and an NLA_UINT's, at 4 or 8 bytes, NLA_KIND_UINT_MASK or
 * NLA_KIND_UINT_RANGE.
 */
static bool spec_declares_bound(const struct nla_attr_spec *spec,
				const struct slot *slot)
{
	if (slot->kind == SK_ARRAY)
		return spec->kind == NLA_KIND_NESTED_ARRAY &&
		       spec->max_len == slot->hi;
	if (slot->kind == SK_NEST)
		return spec->kind == NLA_KIND_NESTED &&
		       spec->max_len == slot->hi;
	if (slot->bound == SB_NONE)
		return false;
	if (slot->bound == SB_MASK) {
		if (slot->min == 4 && slot->max == 8)
			return spec->kind == NLA_KIND_UINT_MASK &&
			       spec->max_len == slot->hi;
		return spec->kind == NLA_KIND_U32_MASK &&
		       spec->max_len == slot->hi;
	}
	if (slot->min == 1 && slot->max == 1)
		return spec->kind == NLA_KIND_U8_RANGE &&
		       spec->max_len == slot->hi &&
		       spec->min_len == slot->lo;
	if (slot->min == 2 && slot->max == 2)
		return spec->kind == NLA_KIND_U16_RANGE &&
		       spec->max_len == slot->hi &&
		       spec->min_len == slot->lo;
	if (slot->min == 4 && slot->max == 8)
		return spec->kind == NLA_KIND_UINT_RANGE &&
		       spec->max_len == slot->hi &&
		       spec->min_len == slot->lo;
	return spec->kind == NLA_KIND_U32_RANGE &&
	       spec->max_len == slot->hi &&
	       spec->min_len == slot->lo;
}

/*
 * What each spec declares, its bound and whether it is marked required, is
 * what its policy and its handler give: none declares a bound that both
 * lack or a mark the handler does not need, and an array is capped where
 * its handler caps it.  The draws show a bound that is
 * off by a tenth of its width or more, and none that is off by one, as a cap
 * of MAX_ERRNO could be; and a mark lost from a table of two attributes
 * leaves a rate of presence that they cannot tell from the marked one.
 */
static void expect_specs_declared(const struct nla_attr_spec *specs, size_t n_specs,
				  const struct slot *slots, unsigned int n_slots,
				  const char *what)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		const struct slot *slot = &slots[i];
		const struct nla_attr_spec *spec = NULL;
		size_t j;
		bool bounded;

		for (j = 0; j < n_specs; j++) {
			if (specs[j].type == slot->id)
				spec = &specs[j];
		}
		if (spec == NULL) {
			fprintf(stderr, "%s: attribute %u has no spec\n", what, slot->id);
			BUG("genl ops: a policy's attribute has no spec");
		}
		if (spec->nest != NULL)
			expect_specs_declared(spec->nest, spec->n_nest,
					      slot->nest, slot->n_nest, what);

		if (spec->required != slot->required) {
			fprintf(stderr, "%s: attribute %u is %smarked required, and its handler %s it\n",
				what, slot->id, spec->required ? "" : "not ",
				slot->required ? "needs" : "does not need");
			BUG("genl ops: a spec does not mark what its handler requires");
		}
		if (spec->once != slot->once) {
			fprintf(stderr, "%s: attribute %u is %smarked once, and its handler %s it twice\n",
				what, slot->id, spec->once ? "" : "not ",
				slot->once ? "refuses" : "takes");
			BUG("genl ops: a spec does not mark what its handler refuses twice");
		}

		bounded = spec->kind == NLA_KIND_U32_MASK ||
			  spec->kind == NLA_KIND_U32_RANGE ||
			  spec->kind == NLA_KIND_U16_RANGE ||
			  spec->kind == NLA_KIND_U8_RANGE ||
			  spec->kind == NLA_KIND_UINT_MASK ||
			  spec->kind == NLA_KIND_UINT_RANGE ||
			  ((spec->kind == NLA_KIND_NESTED_ARRAY ||
			    spec->kind == NLA_KIND_NESTED) && spec->max_len != 0);
		if (slot->bound == SB_NONE && !bounded)
			continue;
		if (spec_declares_bound(spec, slot))
			continue;
		fprintf(stderr, "%s: attribute %u is declared kind %u from %u to %u, its policy has bound %u from %llu to %llu\n",
			what, slot->id, spec->kind, spec->min_len, spec->max_len,
			slot->bound, (unsigned long long) slot->lo,
			(unsigned long long) slot->hi);
		BUG("genl ops: a spec does not declare its policy's bound");
	}
}

/*
 * The bounded scalars of the families above, drawn through the table their
 * cmd takes.  This runs after the messages are checked, so that the draws
 * made here do not count towards a slot that no message reaches.
 */
static void check_policy_values(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		const struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->n_cmds; j++) {
			struct cmd_policy *cp = &pf->cmds[j];
			const struct nla_attr_spec *table;
			size_t n_table = 0;
			char what[64];

			if (min_bounded_seen(cp->slots, cp->n_slots) == UINT_MAX)
				continue;
			snprintf(what, sizeof(what), "%s cmd %u%s", pf->fam->name,
				 cp->cmd, cp->dump ? " dump" : "");
			table = genl_cmd_attrs(pf->fam, cp->cmd, cp->dump, &n_table);
			if (table == NULL)
				BUG("genl ops: a cmd with bounded values draws from no table");
			check_bounded_draws(table, n_table, cp->slots, cp->n_slots, what);
		}
	}
}

/*
 * Every cmd of the families above, for what the specs of the table it draws
 * from declare.
 */
static void check_policy_specs(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		const struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->n_cmds; j++) {
			const struct cmd_policy *cp = &pf->cmds[j];
			const struct nla_attr_spec *table;
			size_t n_table = 0;
			char what[64];

			snprintf(what, sizeof(what), "%s cmd %u%s", pf->fam->name,
				 cp->cmd, cp->dump ? " dump" : "");
			table = genl_cmd_attrs(pf->fam, cp->cmd, cp->dump, &n_table);
			if (table == NULL && cp->n_slots != 0)
				BUG("genl ops: a cmd with a policy draws from no table");
			if (table != NULL)
				expect_specs_declared(table, n_table, cp->slots,
						      cp->n_slots, what);
		}
	}
}

/* ---------- Checking the attributes a handler requires ------------------- */

/*
 * The attributes that the handlers of the families above need, as the
 * messages carried them: the tallies are the ones check_attrs_in_policy()
 * made, so a table the messages build carries its marks only if
 * build_one_nlmsg() emits them.
 */
static void check_policy_required(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(policy_families); i++) {
		const struct policy_family *pf = &policy_families[i];

		for (j = 0; j < pf->n_cmds; j++) {
			const struct cmd_policy *cp = &pf->cmds[j];
			char what[64];

			snprintf(what, sizeof(what), "%s cmd %u%s", pf->fam->name,
				 cp->cmd, cp->dump ? " dump" : "");
			expect_slots_required(cp->slots, cp->n_slots, what);
		}
	}
}

size_t append_required_attrs(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs,
			     uint64_t *used);

#define REQUIRED_ROUNDS	20000

/*
 * Tables of the test's own, with marks, drawn through the emitter and held
 * to mirrors of what they stand for.  append_required_attrs() draws nothing
 * but the one-in-eight skip, so it puts each marked attribute of a table in
 * seven calls in eight.  Over the rounds here that fraction, 0.875, has a
 * standard deviation of 0.0023, so the bounds of 0.84 and 0.91 are 15 of
 * them out.  It puts in no unmarked one, and the marked children of a nest
 * with a table of its own are in most of its elements.  A table with no
 * marks takes nothing from the RNG, which is why the bytes generated for the
 * grammars that mark nothing are as they were.
 */
static void check_required_tables(void)
{
	static const struct nla_attr_spec leaf[] = {
		{ 1, NLA_KIND_U16, 2, .required = true },
		{ 2, NLA_KIND_BINARY_FIXED2, 6, 6 },
		{ 3, NLA_KIND_U32, 4 },
	};
	static const struct nla_attr_spec top[] = {
		{ 1, NLA_KIND_U8, 1, .required = true },
		{ 2, NLA_KIND_U32, 4 },
		{ 3, NLA_KIND_STRING, 15, 1 },
		{ 4, NLA_KIND_NESTED_ARRAY, 0, 0, leaf, ARRAY_SIZE(leaf),
		  .required = true },
		{ 5, NLA_KIND_NESTED, 0, 0, leaf, ARRAY_SIZE(leaf) },
	};
	static const struct nla_attr_spec plain[] = {
		{ 1, NLA_KIND_U8, 1 },
		{ 2, NLA_KIND_U32, 4 },
	};
	static struct slot leaf_mirror[] = {
		S_U16(1, .required = true), S_BLOB(2, 6, 6), S_U32(3),
	};
	static struct slot top_mirror[] = {
		S_U8(1, .required = true), S_U32(2), S_STR(3, 15),
		S_ARRAY(4, leaf_mirror, .required = true),
		S_NEST(5, leaf_mirror),
	};
	unsigned char buf[2048];
	unsigned int round, i;
	uint64_t state;

	for (round = 0; round < REQUIRED_ROUNDS; round++) {
		size_t end;

		memset(buf, 0, sizeof(buf));
		end = append_required_attrs(buf, 0, sizeof(buf), top,
					    ARRAY_SIZE(top), NULL);
		if (!stream_conforms(buf, end, top_mirror, ARRAY_SIZE(top_mirror))) {
			fprintf(stderr, "required tables:\n");
			hexdump(buf, end);
			BUG("genl ops: a required attribute is built out of shape");
		}
		tally_required(buf, end, top_mirror, ARRAY_SIZE(top_mirror));
	}

	for (i = 0; i < ARRAY_SIZE(top_mirror); i++) {
		const struct slot *slot = &top_mirror[i];
		double frac = (double) slot->present / REQUIRED_ROUNDS;

		if (!slot->required) {
			if (slot->seen != 0)
				BUG("genl ops: an attribute no mark names was emitted");
			continue;
		}
		if (frac < 0.84 || frac > 0.91) {
			fprintf(stderr, "required tables: attribute %u in %u of %u calls, want a fraction in [0.84, 0.91]\n",
				slot->id, slot->present, REQUIRED_ROUNDS);
			BUG("genl ops: a marked attribute is not left out one time in eight");
		}
	}
	expect_slots_required(top_mirror, ARRAY_SIZE(top_mirror), "required tables");

	state = rnd_state;
	if (append_required_attrs(buf, 0, sizeof(buf), plain, ARRAY_SIZE(plain),
				  NULL) != 0 ||
	    rnd_state != state)
		BUG("genl ops: a table with no marks emitted or drew something");
}

/*
 * A nest without a table of its own is filled from the table it is in,
 * whose ids belong to the outer policy and whose marks are the outer
 * handler's, so it takes the random draws alone: a child of a three-spec
 * table is in 0.53 of the nests of one to three children.  Marked it would
 * be in 0.94.
 */
static void check_required_not_inherited(void)
{
	static const struct nla_attr_spec flat[] = {
		{ 7, NLA_KIND_U8, 1, .required = true },
		{ 8, NLA_KIND_NESTED, 0 },
		{ 9, NLA_KIND_U16, 2 },
	};
	static struct slot flat_inside[] = {
		S_U8(7, .required = true), S_BLOB(8, 16, 16), S_U16(9),
	};
	static struct slot flat_mirror[] = {
		S_U8(7), S_NEST(8, flat_inside), S_U16(9),
	};
	unsigned char buf[2048];
	unsigned int round;

	for (round = 0; round < REQUIRED_ROUNDS; round++) {
		size_t end;

		memset(buf, 0, sizeof(buf));
		end = append_specced_nlattr(buf, 0, sizeof(buf), flat,
					    ARRAY_SIZE(flat), NULL);
		if (!stream_conforms(buf, end, flat_mirror, ARRAY_SIZE(flat_mirror))) {
			fprintf(stderr, "required, not inherited:\n");
			hexdump(buf, end);
			BUG("genl ops: a nest without a table is built out of shape");
		}
		tally_required(buf, end, flat_mirror, ARRAY_SIZE(flat_mirror));
	}

	if (flat_inside[0].streams < 1000 ||
	    flat_inside[0].present * 4 >= flat_inside[0].streams * 3) {
		fprintf(stderr, "required, not inherited: %u of %u nests hold the outer table's marked attribute, want under 0.75\n",
			flat_inside[0].present, flat_inside[0].streams);
		BUG("genl ops: a nest takes the marks of a table that is not its own");
	}
}

/* Each required slot of a mirror, nests included, in seven of its streams
 * in eight: a fraction in [0.84, 0.91], as check_required_tables() wants. */
static void expect_seven_in_eight(const struct slot *slots,
				  unsigned int n_slots, const char *what)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		const struct slot *slot = &slots[i];

		expect_seven_in_eight(slot->nest, slot->n_nest, what);
		if (!slot->required)
			continue;
		if (slot->streams == 0 ||
		    slot->present < slot->streams * 0.84 ||
		    slot->present > slot->streams * 0.91) {
			fprintf(stderr, "%s: attribute %u in %u of %u streams, want a fraction in [0.84, 0.91]\n",
				what, slot->id, slot->present, slot->streams);
			BUG("genl ops: a marked attribute is not left out one time in eight");
		}
	}
}

/*
 * Specs marked once, drawn as build_one_nlmsg() draws them: the required
 * pass and then the random draws, which share a used mask, at the top level
 * and in a nest with a table of its own.  None goes in twice, and one marked
 * required as well is in seven streams in eight, since the draws cannot
 * bring it back after the required pass left it out; they would put it in
 * 0.997 of them.  The draws in the nest find its third child alone.
 */
static void check_once_tables(void)
{
	static const struct nla_attr_spec pair[] = {
		{ 1, NLA_KIND_U32, 4, .required = true, .once = true },
		{ 2, NLA_KIND_U16, 2, .required = true, .once = true },
		{ 3, NLA_KIND_U8, 1, .once = true },
	};
	static const struct nla_attr_spec top[] = {
		{ 1, NLA_KIND_U32, 4, .required = true, .once = true },
		{ 2, NLA_KIND_NESTED, 0, 0, pair, ARRAY_SIZE(pair),
		  .required = true, .once = true },
	};
	static struct slot pair_mirror[] = {
		S_U32(1, .required = true, .once = true),
		S_U16(2, .required = true, .once = true),
		S_U8(3, .once = true),
	};
	static struct slot top_mirror[] = {
		S_U32(1, .required = true, .once = true),
		S_NEST(2, pair_mirror, .required = true, .once = true),
	};
	unsigned char buf[2048];
	unsigned int round, draw;

	for (round = 0; round < REQUIRED_ROUNDS; round++) {
		uint64_t used = 0;
		size_t end;

		memset(buf, 0, sizeof(buf));
		end = append_required_attrs(buf, 0, sizeof(buf), top,
					    ARRAY_SIZE(top), &used);
		for (draw = 0; draw < 3; draw++)
			end = append_specced_nlattr(buf, end, sizeof(buf), top,
						    ARRAY_SIZE(top), &used);
		if (!stream_conforms(buf, end, top_mirror, ARRAY_SIZE(top_mirror))) {
			fprintf(stderr, "once tables:\n");
			hexdump(buf, end);
			BUG("genl ops: an attribute marked once went in twice");
		}
		tally_required(buf, end, top_mirror, ARRAY_SIZE(top_mirror));
	}
	expect_seven_in_eight(top_mirror, ARRAY_SIZE(top_mirror), "once tables");
}

/* ---------- Checking which attribute table a cmd draws from ------------ */

struct table_case {
	unsigned char cmd;
	bool dump;
	const struct nla_attr_spec *want;
	size_t want_nr;
};

static void expect_tables(const struct genl_family_grammar *fam,
			  const struct table_case *cases, unsigned int nr_cases,
			  const char *what)
{
	unsigned int i;

	for (i = 0; i < nr_cases; i++) {
		size_t nr = 0;
		const struct nla_attr_spec *got;

		got = genl_cmd_attrs(fam, cases[i].cmd, cases[i].dump, &nr);
		if (got == cases[i].want && (got == NULL || nr == cases[i].want_nr))
			continue;
		fprintf(stderr, "%s: cmd %u%s drew from %p (%zu), want %p (%zu)\n",
			what, cases[i].cmd, cases[i].dump ? " dump" : "",
			(const void *) got, nr, (const void *) cases[i].want,
			cases[i].want_nr);
		BUG("genl ops: a cmd drew from the wrong attribute table");
	}
}

/*
 * A cmd's own table beats the family's, its dump table beats its own for a
 * dump request, and a cmd that names none takes the family's.  A cmd with
 * genl_no_attrs gets an empty table, which differs from none at all: that
 * sends the caller to the random-attribute path.
 */
static void check_cmd_attr_tables(void)
{
	static const struct nla_attr_spec family[] = { { 1, NLA_KIND_U32, 4 } };
	static const struct nla_attr_spec own[] = {
		{ 2, NLA_KIND_U8, 1 }, { 3, NLA_KIND_U16, 2 },
	};
	static const struct nla_attr_spec dump[] = { { 4, NLA_KIND_U64, 8 } };
	static const struct genl_cmd_grammar cmds[] = {
		{ 1, "plain" },
		{ 2, "own", own, ARRAY_SIZE(own) },
		{ 3, "none", genl_no_attrs },
		{ 4, "own, dump", own, ARRAY_SIZE(own), dump, ARRAY_SIZE(dump) },
		{ 5, "own, dump none", own, ARRAY_SIZE(own), genl_no_attrs },
		{ 6, "dump only", NULL, 0, dump, ARRAY_SIZE(dump) },
	};
	static const struct table_case with_family[] = {
		{ 1, false, family, ARRAY_SIZE(family) },
		{ 1, true, family, ARRAY_SIZE(family) },
		{ 2, false, own, ARRAY_SIZE(own) },
		{ 2, true, own, ARRAY_SIZE(own) },
		{ 3, false, genl_no_attrs, 0 },
		{ 3, true, genl_no_attrs, 0 },
		{ 4, false, own, ARRAY_SIZE(own) },
		{ 4, true, dump, ARRAY_SIZE(dump) },
		{ 5, false, own, ARRAY_SIZE(own) },
		{ 5, true, genl_no_attrs, 0 },
		{ 6, false, family, ARRAY_SIZE(family) },
		{ 6, true, dump, ARRAY_SIZE(dump) },
		{ 99, false, family, ARRAY_SIZE(family) },
		{ 99, true, family, ARRAY_SIZE(family) },
	};
	static const struct table_case without_family[] = {
		{ 1, false, NULL, 0 },
		{ 2, false, own, ARRAY_SIZE(own) },
		{ 3, true, genl_no_attrs, 0 },
		{ 6, false, NULL, 0 },
		{ 99, true, NULL, 0 },
	};
	struct genl_family_grammar fam = {
		.name = "table test",
		.cmds = cmds,
		.n_cmds = ARRAY_SIZE(cmds),
		.attrs = family,
		.n_attrs = ARRAY_SIZE(family),
	};

	expect_tables(&fam, with_family, ARRAY_SIZE(with_family), "family table");

	fam.attrs = NULL;
	fam.n_attrs = 0;
	expect_tables(&fam, without_family, ARRAY_SIZE(without_family), "no family table");
}

void genl_ops_self_check(void);
void genl_ops_self_check(void)
{
	build_reply(&canned);
	serve = &canned;
	genl_resolve_families();
	if (serve != NULL)
		BUG("genl ops: the resolver never opened its socket");

	check_reply_parsed();
	check_flags();
	check_cmd_attr_tables();
	check_nest_tables();
	check_bounded_tables();
	check_sockaddr_kind();
	check_required_tables();
	check_required_not_inherited();
	check_once_tables();
	check_attrs_in_policy();
	check_ctrl_requests();
	check_policy_specs();
	check_policy_required();
	check_policy_values();
	close(peer_fd);
}
