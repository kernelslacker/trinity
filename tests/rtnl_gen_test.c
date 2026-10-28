/*
 * Self-check for the rtnetlink message builders.  netlink_gen_msg() runs for
 * NETLINK_ROUTE, and the messages of each type a check names are held to a
 * model of what the kernel's handler for that type takes, written from the
 * kernel.  The RNG helpers it reaches are the fakes in genl_ops_test.c; no
 * netlink socket is opened.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "debug.h"		/* BUG */
#include "kernel/if_addr.h"	/* struct ifaddrmsg, IFA_TARGET_NETNSID */
#include "socketinfo.h"		/* struct socket_triplet */

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

#define ROUNDS		200000

/*
 * Only a lone message whose nlmsg_len is intact says where its attributes
 * end, so a batch is left out, and so is a message the generator gave a
 * corrupt length.  An attribute that does not fit its buffer is cut short to
 * fill it, which no policy takes, so a message as long as the smallest
 * buffer is left out too.
 */
#define SMALLEST_BUFFER	(NLMSG_HDRLEN + 1280)

/* lo, which every netns has. */
#define LOOPBACK_IFINDEX	1

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

/* ---------- RTM_GETMULTICAST and RTM_GETANYCAST -------------------------- */

struct addr_dump {
	unsigned int msgs;
	unsigned int whole;		/* an ifaddrmsg in full */
	unsigned int packet, inet, inet6, other;	/* by ifa_family */
	unsigned int zero;		/* prefixlen, flags and scope all 0 */
	unsigned int index_all, index_lo;	/* ifa_index 0, and lo's */
	unsigned int attrs_ok;		/* IFA_TARGET_NETNSID alone, or nothing */
	unsigned int with_attr;		/* ... and at least one */
	unsigned int nsids, unassigned, small;	/* the ids, -1, and 0 to 3 */
	unsigned int packet_msgs, takes;	/* AF_PACKET, and those taken */
};

/*
 * The attributes of a request to one of the address dumps, whose attribute
 * policy is IFA_TARGET_NETNSID alone, an NLA_S32, parsed strictly: how many
 * it carries, or -1 when one is another id, is not four bytes or is flagged
 * a nest, or when the stream ends in bytes that are no attribute, which the
 * strict parse refuses as trailing garbage.
 */
static int target_netnsid_attrs(const unsigned char *p, size_t len)
{
	int n = 0;

	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *) p;
		size_t total;

		if (nla->nla_len < NLA_HDRLEN || nla->nla_len > len ||
		    (nla->nla_type & NLA_TYPE_MASK) != IFA_TARGET_NETNSID ||
		    (nla->nla_type & NLA_F_NESTED) ||
		    nla->nla_len != NLA_HDRLEN + sizeof(int32_t))
			return -1;
		total = NLA_ALIGN(nla->nla_len);
		if (total > len)
			return -1;
		p += total;
		len -= total;
		n++;
	}
	return len ? -1 : n;
}

static void tally_nsids(struct addr_dump *t, const unsigned char *p, size_t len)
{
	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *) p;
		int32_t id;

		memcpy(&id, p + NLA_HDRLEN, sizeof(id));
		t->nsids++;
		t->unassigned += id == -1;
		t->small += id >= 0 && id < 4;
		p += NLA_ALIGN(nla->nla_len);
		len -= NLA_ALIGN(nla->nla_len);
	}
}

/*
 * dev_mc_valid_dump_req() in net/core/dev_addr_lists.c, which takes the
 * AF_PACKET dump of RTM_GETMULTICAST: a whole ifaddrmsg with prefixlen,
 * flags and scope 0, and no attribute but IFA_TARGET_NETNSID.  The
 * address dumps of IPv4 and IPv6 hold their requests to the same, when the
 * socket asks for strict checking.
 */
static void tally_addr_dump(struct addr_dump *t, const struct nlmsghdr *nlh)
{
	const struct ifaddrmsg *ifm;
	const unsigned char *attrs;
	size_t attrs_len;
	bool zero;
	int n;

	t->msgs++;
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifm)))
		return;
	t->whole++;

	ifm = NLMSG_DATA(nlh);
	switch (ifm->ifa_family) {
	case AF_PACKET:	t->packet++; break;
	case AF_INET:	t->inet++; break;
	case AF_INET6:	t->inet6++; break;
	default:	t->other++;
	}
	zero = !ifm->ifa_prefixlen && !ifm->ifa_flags && !ifm->ifa_scope;
	t->zero += zero;
	t->index_all += ifm->ifa_index == 0;
	t->index_lo += ifm->ifa_index == LOOPBACK_IFINDEX;

	attrs = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(*ifm));
	attrs_len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(*ifm));
	n = target_netnsid_attrs(attrs, attrs_len);
	t->attrs_ok += n >= 0;
	t->with_attr += n > 0;
	if (n > 0)
		tally_nsids(t, attrs, attrs_len);

	if (ifm->ifa_family == AF_PACKET) {
		t->packet_msgs++;
		t->takes += zero && n >= 0;
	}
}

/*
 * RTM_GETMULTICAST is registered for PF_INET, PF_INET6 and, since
 * ebff14be20c3, PF_PACKET, and RTM_GETANYCAST for PF_INET6 alone; both have
 * a dumpit and no doit.  The builder sends AF_PACKET three times in four for
 * the first, and the other two a quarter of the time between them, and
 * AF_INET6 for the second, the families it is registered for, but for the
 * one request in sixteen with a family at random; so AF_PACKET is 0.71 of
 * the first's requests and AF_INET and AF_INET6 0.13 each, and AF_INET6 0.95
 * of the second's.  The header's prefixlen, flags and scope are 0 seven
 * times in eight and random the eighth, and the index is 0 half the time and
 * lo's a quarter.  Each of up to seven attributes is an IFA_TARGET_NETNSID
 * of four bytes seven times in eight, but one draw in seven is a nest of
 * them, so about 0.48 of the requests are clear of anything the strict
 * parse refuses and 0.35 of them hold one; the ids are -1 one time in eight
 * and 0 to 3 the rest.  Over the 1900 requests or so each type has the
 * fractions have standard deviations under 0.012, and the bounds are five of
 * them out or more.
 */
static void expect_addr_dump(const struct addr_dump *t, bool multicast,
			     const char *what)
{
	expect_fraction(t->whole, t->msgs, 0.99, 1.0, what,
			"rtnl: a dump request is shorter than an ifaddrmsg");
	if (multicast) {
		expect_fraction(t->packet, t->whole, 0.60, 1.0, what,
				"rtnl: RTM_GETMULTICAST is not mostly AF_PACKET");
		expect_fraction(t->inet, t->whole, 0.05, 1.0, what,
				"rtnl: RTM_GETMULTICAST is never AF_INET");
		expect_fraction(t->inet6, t->whole, 0.05, 1.0, what,
				"rtnl: RTM_GETMULTICAST is never AF_INET6");
		expect_fraction(t->other, t->whole, 0.01, 0.15, what,
				"rtnl: RTM_GETMULTICAST is not sometimes a family it has no dumpit for");
		expect_fraction(t->takes, t->packet_msgs, 0.30, 0.50, what,
				"rtnl: AF_PACKET dump requests are not taken by dev_mc_valid_dump_req()");
	} else {
		expect_fraction(t->inet6, t->whole, 0.85, 1.0, what,
				"rtnl: RTM_GETANYCAST is not mostly AF_INET6");
		expect_fraction(t->packet, t->whole, 0.0, 0.10, what,
				"rtnl: RTM_GETANYCAST is sent as AF_PACKET, which it is not registered for");
	}
	expect_fraction(t->zero, t->whole, 0.80, 0.95, what,
			"rtnl: a dump request's prefixlen, flags and scope are not 0 seven times in eight");
	expect_fraction(t->index_all, t->whole, 0.40, 0.60, what,
			"rtnl: a dump request does not ask for every device half the time");
	expect_fraction(t->index_lo, t->whole, 0.18, 0.32, what,
			"rtnl: a dump request does not ask for lo a quarter of the time");
	expect_fraction(t->attrs_ok, t->whole, 0.38, 0.60, what,
			"rtnl: a dump request does not carry only IFA_TARGET_NETNSID");
	expect_fraction(t->with_attr, t->whole, 0.25, 0.45, what,
			"rtnl: a dump request does not carry an IFA_TARGET_NETNSID");
	expect_fraction(t->unassigned, t->nsids, 0.06, 0.20, what,
			"rtnl: an IFA_TARGET_NETNSID is not unassigned one time in eight");
	expect_fraction(t->small, t->nsids, 0.80, 0.94, what,
			"rtnl: an IFA_TARGET_NETNSID is not a small id");
}

/* ---------- The rounds --------------------------------------------------- */

struct tallies {
	struct addr_dump multicast, anycast;
};

static void run_rounds(struct tallies *t)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_ROUTE,
	};
	unsigned int round;

	for (round = 0; round < ROUNDS; round++) {
		const struct nlmsghdr *nlh;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		nlh = buf;
		if (len < NLMSG_HDRLEN || len >= SMALLEST_BUFFER ||
		    NLMSG_ALIGN(nlh->nlmsg_len) != len)
			goto next;

		switch (nlh->nlmsg_type) {
		case RTM_GETMULTICAST:
			tally_addr_dump(&t->multicast, nlh);
			break;
		case RTM_GETANYCAST:
			tally_addr_dump(&t->anycast, nlh);
			break;
		}
next:
		free(buf);
	}
}

void rtnl_gen_self_check(void);
void rtnl_gen_self_check(void)
{
	static struct tallies t;

	run_rounds(&t);
	expect_addr_dump(&t.multicast, true, "RTM_GETMULTICAST");
	expect_addr_dump(&t.anycast, false, "RTM_GETANYCAST");
}
