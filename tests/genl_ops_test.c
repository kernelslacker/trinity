/*
 * Self-check for the genl op shapes.  The op list in the controller's
 * GETFAMILY reply lands in each registered family's cmd_caps, and
 * netlink_gen_msg() sets NLM_F_DUMP to suit the cmd it picks.  The reply
 * is canned and arrives over a unix socketpair standing in for the
 * NETLINK_GENERIC socket; no netlink socket is opened.
 */

#include <errno.h>
#include <stddef.h>
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
extern struct genl_family_grammar fam_psp;
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
#define ID_UNREGISTERED	900

#define ROUNDS		30000

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

/* Only the rtnetlink link builder asks, and this test builds no rtnetlink. */
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values)
{
	(void) num;
	(void) values;
	return 0;
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
	put_truncated_family(r, &fam_psp, ID_TRUNCATED);
	put_ops_first_family(r, &fam_binder, ID_OPS_FIRST);

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
	expect_caps(&fam_psp, ID_TRUNCATED, want, "op list past the message");

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
};

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
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		for (i = 0; i < nr_tallies; i++) {
			if (len < NLMSG_HDRLEN || nlh->nlmsg_type != tallies[i].id)
				continue;
			tallies[i].msgs++;
			if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP)
				tallies[i].dump++;
		}
		free(buf);
	}
}

/*
 * One message in ten carries flags drawn at random, which the cmd's
 * shape leaves alone: both dump bits show in one such word in four.  In
 * the rest, a coin flip sets NLM_F_DUMP, and when it does not the NEW and
 * DELETE modifiers still set both bits between them 13 times in 32, so a
 * cmd with no pin shows both bits in 0.70 of them.  Fractions expected
 * over the 3000 or so messages each family gets:
 *
 *	dumpit only	0.925	(0.9 pinned + 0.1 * 0.25)
 *	doit only	0.025	(0.1 * 0.25)
 *	both, unknown	0.66	(0.9 * 0.70 + 0.1 * 0.25)
 */
static void check_flags_pinned(void)
{
	struct tally t[] = {
		{ "doit only", ID_DO_ONLY, 0.005, 0.06 },
		{ "dumpit only", ID_DUMP_ONLY, 0.88, 0.98 },
		{ "doit and dumpit", ID_BOTH, 0.58, 0.74 },
		{ "no op list", ID_NO_OPS, 0.58, 0.74 },
	};
	unsigned int i;

	tally_flags(t, ARRAY_SIZE(t));

	for (i = 0; i < ARRAY_SIZE(t); i++) {
		double frac = t[i].msgs ? (double) t[i].dump / t[i].msgs : -1.0;

		if (t[i].msgs < 1000 || frac < t[i].lo || frac > t[i].hi) {
			fprintf(stderr, "%s: %u of %u messages carry NLM_F_DUMP, want a fraction in [%.3f, %.3f]\n",
				t[i].what, t[i].dump, t[i].msgs, t[i].lo, t[i].hi);
			BUG("genl ops: the dump flag does not follow the cmd's handlers");
		}
	}
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
	check_flags_pinned();
	close(peer_fd);
}
