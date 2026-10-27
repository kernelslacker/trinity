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
 * its children meet.  A u32 that the policy bounds with a mask or a range
 * says so, and the generator draws inside the bound most of the time, so a
 * draw outside it is tallied rather than refused: the policy's reject arm
 * wants some.  Other values are not the generator's to shape and are not
 * modelled.  A slot that the handler needs says so, and the generator puts
 * it in most streams of its policy and leaves it out of some.  seen counts
 * what the generator emitted, so a slot it never reaches shows up.
 */
enum slot_kind { SK_BYTES, SK_SINT, SK_STRING, SK_NEST, SK_ARRAY };

/* NLA_POLICY_MASK: hi holds the bits a value may set.  NLA_POLICY_RANGE:
 * lo to hi, both inclusive; MAX and MIN are ranges that start at 0 and end
 * at the top of the type. */
enum slot_bound { SB_NONE, SB_MASK, SB_RANGE };

struct slot {
	unsigned short id;
	unsigned char kind;
	unsigned short min, max;	/* payload length; a string's max 0 is any */
	struct slot *nest;		/* SK_NEST, SK_ARRAY: the children's policy */
	unsigned int n_nest;
	unsigned int seen;
	unsigned char bound;		/* a u32's bound, host order */
	unsigned int lo, hi;
	unsigned int in_bound;		/* draws inside it, and what they span: */
	unsigned int or_all, and_all, min_v, max_v;
	bool required;			/* its handler needs it */
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
#define S_U32_MASK(id, bits, ...) \
	{ id, SK_BYTES, 4, 4, .bound = SB_MASK, .hi = bits, ##__VA_ARGS__ }
#define S_U32_RANGE(id, from, to, ...) \
	{ id, SK_BYTES, 4, 4, .bound = SB_RANGE, .lo = from, .hi = to, ##__VA_ARGS__ }

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
	S_U16(VDPA_ATTR_DEV_NET_CFG_MTU),
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
	S_U16(VDPA_ATTR_DEV_NET_CFG_MTU),
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
	S_U32(NFSD_A_SERVER_GRACETIME),
	S_U32(NFSD_A_SERVER_LEASETIME),
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
static struct slot dpll_device_id_get[] = {
	S_STR(DPLL_A_MODULE_NAME, 0),
	S_U64(DPLL_A_CLOCK_ID),
	S_U32_RANGE(DPLL_A_TYPE, 1, 3),
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
	S_STR(DPLL_A_PIN_MODULE_NAME, 0),
	S_U64(DPLL_A_PIN_CLOCK_ID),
	S_STR(DPLL_A_PIN_BOARD_LABEL, 0),
	S_STR(DPLL_A_PIN_PANEL_LABEL, 0),
	S_STR(DPLL_A_PIN_PACKAGE_LABEL, 0),
	S_U32_RANGE(DPLL_A_PIN_TYPE, 1, 6),
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
	S_U32(WGPEER_A_PROTOCOL_VERSION),
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

/* fs/lockd/netlink.c: lockd_server_set_nl_policy */
static struct slot lockd_server_set[] = {
	S_U32(LOCKD_A_SERVER_GRACETIME),
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

/* net/sunrpc/netlink.c: the sunrpc_*_nl_policy tables */
static struct slot sunrpc_ip_map[] = {
	S_U64(SUNRPC_A_IP_MAP_SEQNO),
	S_STR(SUNRPC_A_IP_MAP_CLASS, 0),
	S_STR(SUNRPC_A_IP_MAP_ADDR, 0),
	S_STR(SUNRPC_A_IP_MAP_DOMAIN, 0),
	S_FLAG(SUNRPC_A_IP_MAP_NEGATIVE),
	S_U64(SUNRPC_A_IP_MAP_EXPIRY),
};
static struct slot sunrpc_unix_gid[] = {
	S_U64(SUNRPC_A_UNIX_GID_SEQNO),
	S_U32(SUNRPC_A_UNIX_GID_UID),
	S_U32(SUNRPC_A_UNIX_GID_GIDS),
	S_FLAG(SUNRPC_A_UNIX_GID_NEGATIVE),
	S_U64(SUNRPC_A_UNIX_GID_EXPIRY),
};
static struct slot sunrpc_ip_map_set_reqs[] = {
	S_NEST(SUNRPC_A_IP_MAP_REQS_REQUESTS, sunrpc_ip_map),
};
static struct slot sunrpc_unix_gid_set_reqs[] = {
	S_NEST(SUNRPC_A_UNIX_GID_REQS_REQUESTS, sunrpc_unix_gid),
};
static struct slot sunrpc_cache_flush[] = {
	S_U32(SUNRPC_A_CACHE_FLUSH_MASK),
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

/* net/psp/psp-nl-gen.c: the psp_*_nl_policy tables */
static struct slot psp_keys[] = {
	S_BLOB(PSP_A_KEYS_KEY, 0, 0xffff),
	S_U32(PSP_A_KEYS_SPI),
};
static struct slot psp_dev_get[] = {
	S_U32(PSP_A_DEV_ID),
};
static struct slot psp_dev_set[] = {
	S_U32(PSP_A_DEV_ID),
	S_U32(PSP_A_DEV_PSP_VERSIONS_ENA),
};
static struct slot psp_key_rotate[] = {
	S_U32(PSP_A_DEV_ID),
};
static struct slot psp_rx_assoc[] = {
	S_U32(PSP_A_ASSOC_DEV_ID),
	S_U32(PSP_A_ASSOC_VERSION),
	S_U32(PSP_A_ASSOC_SOCK_FD),
};
static struct slot psp_tx_assoc[] = {
	S_U32(PSP_A_ASSOC_DEV_ID),
	S_U32(PSP_A_ASSOC_VERSION),
	S_NEST(PSP_A_ASSOC_TX_KEY, psp_keys),
	S_U32(PSP_A_ASSOC_SOCK_FD),
};
static struct slot psp_get_stats[] = {
	S_U32(PSP_A_STATS_DEV_ID),
};
static struct slot psp_dev_assoc[] = {
	S_U32(PSP_A_DEV_ID),
	S_U32(PSP_A_DEV_IFINDEX),
	S_U32(PSP_A_DEV_NSID),
};
static struct slot psp_dev_disassoc[] = {
	S_U32(PSP_A_DEV_ID),
	S_U32(PSP_A_DEV_IFINDEX),
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
 * takes 4 or 8 bytes, as an NLA_SINT does.
 */
static struct slot netdev_queue_id[] = {
	S_U32(NETDEV_A_QUEUE_ID),
	S_U32(NETDEV_A_QUEUE_TYPE),
};
static struct slot netdev_page_pool_info[] = {
	S_SINT(NETDEV_A_PAGE_POOL_ID),
	S_U32(NETDEV_A_PAGE_POOL_IFINDEX),
};
static struct slot netdev_lease[] = {
	S_U32(NETDEV_A_LEASE_IFINDEX),
	S_NEST(NETDEV_A_LEASE_QUEUE, netdev_queue_id),
	S_U32(NETDEV_A_LEASE_NETNS_ID),
};
static struct slot netdev_dev_get[] = {
	S_U32(NETDEV_A_DEV_IFINDEX),
};
static struct slot netdev_page_pool_get_do[] = {
	S_SINT(NETDEV_A_PAGE_POOL_ID),
};
static struct slot netdev_page_pool_get_dump[] = {
	S_U32(NETDEV_A_PAGE_POOL_IFINDEX),
};
static struct slot netdev_page_pool_stats_get[] = {
	S_NEST(NETDEV_A_PAGE_POOL_STATS_INFO, netdev_page_pool_info),
};
static struct slot netdev_queue_get_do[] = {
	S_U32(NETDEV_A_QUEUE_IFINDEX),
	S_U32(NETDEV_A_QUEUE_TYPE),
	S_U32(NETDEV_A_QUEUE_ID),
};
static struct slot netdev_queue_get_dump[] = {
	S_U32(NETDEV_A_QUEUE_IFINDEX),
};
static struct slot netdev_napi_get_do[] = {
	S_U32(NETDEV_A_NAPI_ID),
};
static struct slot netdev_napi_get_dump[] = {
	S_U32(NETDEV_A_NAPI_IFINDEX),
};
static struct slot netdev_qstats_get[] = {
	S_U32(NETDEV_A_QSTATS_IFINDEX),
	S_SINT(NETDEV_A_QSTATS_SCOPE),
};
static struct slot netdev_bind_rx[] = {
	S_U32(NETDEV_A_DMABUF_IFINDEX),
	S_U32(NETDEV_A_DMABUF_FD),
	S_NEST(NETDEV_A_DMABUF_QUEUES, netdev_queue_id),
	S_U32(NETDEV_A_DMABUF_RX_PAGE_SIZE),
};
static struct slot netdev_napi_set[] = {
	S_U32(NETDEV_A_NAPI_ID),
	S_U32(NETDEV_A_NAPI_DEFER_HARD_IRQS),
	S_SINT(NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT),
	S_SINT(NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT),
	S_U32(NETDEV_A_NAPI_THREADED),
};
static struct slot netdev_bind_tx[] = {
	S_U32(NETDEV_A_DMABUF_IFINDEX),
	S_U32(NETDEV_A_DMABUF_FD),
};
static struct slot netdev_queue_create[] = {
	S_U32(NETDEV_A_QUEUE_IFINDEX),
	S_U32(NETDEV_A_QUEUE_TYPE),
	S_NEST(NETDEV_A_QUEUE_LEASE, netdev_lease),
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
#include "kernel/ethtool_netlink_generated.h"

extern struct genl_family_grammar fam_ethtool;

/*
 * net/ethtool: the header policies the read-side cmds nest, ethnl_header_policy
 * and ethnl_header_policy_phy, which the stats variants match but for the
 * flags mask, and the ethnl_*_get_policy tables.  Most cmds' policy is the
 * HEADER alone, so those rows share a table.
 */
static struct slot ethtool_header[] = {
	S_U32(ETHTOOL_A_HEADER_DEV_INDEX),
	S_STR(ETHTOOL_A_HEADER_DEV_NAME, 127),
	S_U32(ETHTOOL_A_HEADER_FLAGS),
};
static struct slot ethtool_header_phy[] = {
	S_U32(ETHTOOL_A_HEADER_DEV_INDEX),
	S_STR(ETHTOOL_A_HEADER_DEV_NAME, 127),
	S_U32(ETHTOOL_A_HEADER_FLAGS),
	S_U32(ETHTOOL_A_HEADER_PHY_INDEX),
};
static struct slot ethtool_stringset[] = {
	S_U32(ETHTOOL_A_STRINGSET_ID),
};
static struct slot ethtool_stringsets[] = {
	S_NEST(ETHTOOL_A_STRINGSETS_STRINGSET, ethtool_stringset),
};
static struct slot ethtool_ts_provider[] = {
	S_U32(ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX),
	S_U32(ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER),
};
static struct slot ethtool_get[] = {
	S_NEST(ETHTOOL_A_LINKINFO_HEADER, ethtool_header),
};
static struct slot ethtool_get_phy[] = {
	S_NEST(ETHTOOL_A_PSE_HEADER, ethtool_header_phy),
};
static struct slot ethtool_strset_get[] = {
	S_NEST(ETHTOOL_A_STRSET_HEADER, ethtool_header_phy),
	S_NEST(ETHTOOL_A_STRSET_STRINGSETS, ethtool_stringsets),
	S_FLAG(ETHTOOL_A_STRSET_COUNTS_ONLY),
};
static struct slot ethtool_pause_get[] = {
	S_NEST(ETHTOOL_A_PAUSE_HEADER, ethtool_header),
	S_U32(ETHTOOL_A_PAUSE_STATS_SRC),
};
static struct slot ethtool_tsinfo_get[] = {
	S_NEST(ETHTOOL_A_TSINFO_HEADER, ethtool_header),
	S_NEST(ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER, ethtool_ts_provider),
};
static struct slot ethtool_module_eeprom_get[] = {
	S_NEST(ETHTOOL_A_MODULE_EEPROM_HEADER, ethtool_header),
	S_U32(ETHTOOL_A_MODULE_EEPROM_OFFSET),
	S_U32(ETHTOOL_A_MODULE_EEPROM_LENGTH),
	S_U8(ETHTOOL_A_MODULE_EEPROM_PAGE),
	S_U8(ETHTOOL_A_MODULE_EEPROM_BANK),
	S_U8(ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS),
};
static struct slot ethtool_stats_get[] = {
	S_NEST(ETHTOOL_A_STATS_HEADER, ethtool_header),
	S_U32(ETHTOOL_A_STATS_SRC),
};
static struct slot ethtool_rss_get[] = {
	S_NEST(ETHTOOL_A_RSS_HEADER, ethtool_header),
	S_U32(ETHTOOL_A_RSS_CONTEXT),
	S_U32(ETHTOOL_A_RSS_START_CONTEXT),
};
static struct cmd_policy ethtool_cmds[] = {
	P_CMD(ETHTOOL_MSG_STRSET_GET, ethtool_strset_get),
	P_CMD(ETHTOOL_MSG_LINKINFO_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_LINKMODES_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_LINKSTATE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_DEBUG_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_WOL_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_FEATURES_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PRIVFLAGS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_RINGS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_CHANNELS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_COALESCE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PAUSE_GET, ethtool_pause_get),
	P_CMD(ETHTOOL_MSG_EEE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_TSINFO_GET, ethtool_tsinfo_get),
	P_CMD(ETHTOOL_MSG_TUNNEL_INFO_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_FEC_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_MODULE_EEPROM_GET, ethtool_module_eeprom_get),
	P_CMD(ETHTOOL_MSG_STATS_GET, ethtool_stats_get),
	P_CMD(ETHTOOL_MSG_PHC_VCLOCKS_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_MODULE_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PSE_GET, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_RSS_GET, ethtool_rss_get),
	P_CMD(ETHTOOL_MSG_PLCA_GET_CFG, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_PLCA_GET_STATUS, ethtool_get_phy),
	P_CMD(ETHTOOL_MSG_MM_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_PHY_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_TSCONFIG_GET, ethtool_get),
	P_CMD(ETHTOOL_MSG_MSE_GET, ethtool_get_phy),
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
	S_U32(OVS_DP_ATTR_MASKS_CACHE_SIZE),
	S_BLOB(OVS_DP_ATTR_PER_CPU_PIDS, 0, 0xffff),
	S_U32(OVS_DP_ATTR_IFINDEX),
};
static struct cmd_policy ovs_datapath_cmds[] = {
	P_CMD(OVS_DP_CMD_NEW, ovs_datapath),
	P_CMD(OVS_DP_CMD_DEL, ovs_datapath),
	P_CMD(OVS_DP_CMD_GET, ovs_datapath),
	P_CMD(OVS_DP_CMD_SET, ovs_datapath),
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
 * Whether the host-order u32 at p is inside the slot's bound.  What is
 * inside is kept apart, with the bits it sets and the ends it reaches, so
 * that a spec which draws from less of the bound than the policy allows
 * shows up as well as one that strays outside it.
 */
static void tally_bound(struct slot *slot, const unsigned char *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
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

/*
 * The elements of an NLA_POLICY_NESTED_ARRAY: any type, but each an
 * NLA_F_NESTED attribute, as userspace sends them and a handler's
 * nla_parse_nested() wants, holding a stream of its own.
 */
static bool array_conforms(const unsigned char *p, size_t len, struct slot *slot)
{
	size_t off = 0;

	while (off < len) {
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

		plen = nla->nla_len - NLA_HDRLEN;
		if (!!(nla->nla_type & NLA_F_NESTED) !=
		    (slot->kind == SK_NEST || slot->kind == SK_ARRAY))
			return false;
		switch (slot->kind) {
		case SK_BYTES:
			if (plen < slot->min || plen > slot->max)
				return false;
			if (slot->bound != SB_NONE)
				tally_bound(slot, p + off + NLA_HDRLEN);
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
 * of the 2^32 values, so the fraction inside is 0.875 plus that share of
 * 0.125.  Over the 1000 draws or more asked for it has a standard deviation
 * of about 0.01, so 0.06 either way turns away a spec that never strays
 * outside the bound and one that never settles inside it.  The draws inside
 * must also span the bound, which a spec with a narrower one than the
 * policy's does not: a mask sets and clears each of its bits, and a range
 * reaches to within a tenth of its width of both ends.
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

		if (slot->bound == SB_MASK)
			share = (double) (1ULL << __builtin_popcount(slot->hi)) / 4294967296.0;
		else
			share = ((double) slot->hi - slot->lo + 1) / 4294967296.0;
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
			uint32_t slack = (slot->hi - slot->lo) / 10;

			spans = slot->min_v - slot->lo <= slack &&
				slot->hi - slot->max_v <= slack;
		}
		if (!spans) {
			fprintf(stderr, "%s: draws of attribute %u inside the bound set %#x and keep %#x, from %u to %u\n",
				what, slot->id, slot->or_all, slot->and_all,
				slot->min_v, slot->max_v);
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
 * intact one on a batch of two equal halves, whose length is a multiple of
 * 8; a lone message is 4 modulo 8 half the time and cannot be mistaken.
 * An attribute that does not fit its buffer is also cut short to fill it,
 * which no policy takes, so a message as long as the smallest buffer is
 * left out too.
 */
#define SMALLEST_BUFFER	(NLMSG_HDRLEN + 1280)
#define ATTR_ROUNDS	150000
#define MIN_MSGS	30

/* Every family in the reply takes a share of the rounds, so the streams of a
 * nest deep in one family's cmd thin out as families are added: the rounds
 * go on, to this many, until each required slot has its REQUIRED_STREAMS. */
#define ATTR_ROUNDS_MAX	1500000

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
		    len % 8 != 4 || NLMSG_ALIGN(nlh->nlmsg_len) != len)
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
		if (cp == NULL)
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

/* ---------- Checking how a nest is filled -------------------------------- */

size_t append_specced_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs);

#define NEST_ROUNDS	20000

/*
 * Nests of the generator's own tables and mirrors of what each must hold.
 * A nest with a table of its own gets its children from it, an array gets
 * flagged elements that hold a stream apiece, and the nests of a table
 * without any hold what the table holds, a NESTED child among them a
 * placeholder of 16 bytes.
 */
static void check_nest_tables(void)
{
	static const struct nla_attr_spec leaf[] = {
		{ 1, NLA_KIND_U16, 2 },
		{ 2, NLA_KIND_BINARY_FIXED2, 6, 6 },
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
	static struct slot leaf_mirror[] = { S_U16(1), S_BLOB(2, 6, 6) };
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
						    cases[i].specs, cases[i].n_specs);
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
		end = append_specced_nlattr(buf, 0, sizeof(buf), table, n_table);
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
 * which is NLA_POLICY_MAX; and one that runs to the top of the type, as
 * NLA_POLICY_MIN does.
 */
static void check_bounded_tables(void)
{
	static const struct nla_attr_spec specs[] = {
		{ 1, NLA_KIND_U32_MASK, 0x1 },
		{ 2, NLA_KIND_U32_MASK, 0x3ffff },
		{ 3, NLA_KIND_U32_RANGE, 6, 1 },
		{ 4, NLA_KIND_U32_RANGE, 4095 },
		{ 5, NLA_KIND_U32_RANGE, UINT32_MAX, 68 },
	};
	static struct slot mirror[] = {
		S_U32_MASK(1, 0x1),
		S_U32_MASK(2, 0x3ffff),
		S_U32_RANGE(3, 1, 6),
		S_U32_RANGE(4, 0, 4095),
		S_U32_RANGE(5, 68, UINT32_MAX),
	};

	check_bounded_draws(specs, ARRAY_SIZE(specs), mirror, ARRAY_SIZE(mirror),
			    "bounded tables");
}

/*
 * What each spec declares, its bound and whether it is marked required, is
 * what its policy and its handler give: none declares a bound the policy
 * lacks or a mark the handler does not need.  The draws show a bound that is
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

		bounded = spec->kind == NLA_KIND_U32_MASK ||
			  spec->kind == NLA_KIND_U32_RANGE;
		if (slot->bound == SB_NONE && !bounded)
			continue;
		if (slot->bound == SB_MASK ? spec->kind == NLA_KIND_U32_MASK &&
					     spec->max_len == slot->hi :
					     spec->kind == NLA_KIND_U32_RANGE &&
					     spec->max_len == slot->hi &&
					     spec->min_len == slot->lo)
			continue;
		fprintf(stderr, "%s: attribute %u is declared kind %u from %u to %u, its policy has bound %u from %u to %u\n",
			what, slot->id, spec->kind, spec->min_len, spec->max_len,
			slot->bound, slot->lo, slot->hi);
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
			     const struct nla_attr_spec *table, size_t nr_specs);

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
					    ARRAY_SIZE(top));
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
	if (append_required_attrs(buf, 0, sizeof(buf), plain, ARRAY_SIZE(plain)) != 0 ||
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
					    ARRAY_SIZE(flat));
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
	check_required_tables();
	check_required_not_inherited();
	check_attrs_in_policy();
	check_policy_specs();
	check_policy_required();
	check_policy_values();
	close(peer_fd);
}
