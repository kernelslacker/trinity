/*
 * Self-check for the rtnetlink message builders.  netlink_gen_msg() runs for
 * NETLINK_ROUTE, and the messages of each type a check names are held to a
 * model of what the kernel's handler for that type takes, written from the
 * kernel.  The RNG helpers it reaches are the fakes in genl_ops_test.c, and
 * the pick of a BPF program by type is fake_fds.c's, hooked to answer an fd
 * per type; no netlink socket is opened.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/bpf.h>
#include <linux/if_bridge.h>
#include <linux/lwtunnel.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_gact.h>

#include "debug.h"		/* BUG */
#include "kernel/if_addr.h"	/* struct ifaddrmsg, IFA_TARGET_NETNSID */
#include "kernel/if_link.h"	/* the IFLA_* limits and IFLA_PACING_OFFLOAD */
#include "kernel/nexthop.h"	/* NHA_DST_PORT */
#include "kernel/rtnetlink.h"	/* RTA_FLOWLABEL */
#include "socketinfo.h"		/* struct socket_triplet */
#include "utils-macros.h"	/* ARRAY_SIZE */

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);
extern int (*fake_get_rand_bpf_prog_fd_of_type)(unsigned int prog_type);	/* fake_fds.c */
size_t gen_rta_tunnel_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);
size_t gen_rta_route_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type, unsigned char family);
void mask_route_dst(struct nlmsghdr *nlh, size_t len);

#define ROUNDS		800000

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

/* The attribute at p of the len bytes left, or NULL when it does not fit. */
static const struct nlattr *fit_attr(const unsigned char *p, size_t len)
{
	const struct nlattr *nla = (const struct nlattr *) p;

	if (len < NLA_HDRLEN || nla->nla_len < NLA_HDRLEN || nla->nla_len > len)
		return NULL;
	return nla;
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
 * and 0 to 3 the rest.  Over the 7800 requests or so each type has the
 * fractions have standard deviations under 0.006, and the bounds are five of
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

/* ---------- The ifinfomsg of the link and linkprop types ---------------- */

struct link_header {
	unsigned int msgs;
	unsigned int zero;	/* ifi_type, ifi_flags and ifi_change all 0 */
	unsigned int index_all, index_lo;
};

static void tally_link_header(struct link_header *t, const struct nlmsghdr *nlh)
{
	const struct ifinfomsg *ifi = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return;
	t->msgs++;
	t->zero += !ifi->ifi_type && !ifi->ifi_flags && !ifi->ifi_change;
	t->index_all += ifi->ifi_index == 0;
	t->index_lo += ifi->ifi_index == LOOPBACK_IFINDEX;
}

/*
 * rtnl_getlink() and rtnl_linkprop() answer an index that names no device
 * -ENODEV, and a lane child's netns holds lo alone, so the builder names lo
 * half the time for RTM_GETLINK and the linkprop types.  On a socket that
 * asks for strict checking, rtnl_valid_getlink_req() refuses a GET with a
 * nonzero ifi_type, ifi_flags or ifi_change, and the dump's check any index
 * but 0 as well: a GET has the three 0 seven times in eight and asks for
 * every device a quarter of the time.  RTM_NEWLINK and RTM_SETLINK hand
 * their flags to whatever device the index names, so the other link types
 * keep a random small index, lo's one time in 64, and random flags.
 */
static void expect_link_header(const struct link_header *get,
			       const struct link_header *prop,
			       const struct link_header *other)
{
	expect_fraction(get->index_lo, get->msgs, 0.45, 0.56, "RTM_GETLINK",
			"rtnl: RTM_GETLINK does not name lo half the time");
	expect_fraction(get->index_all, get->msgs, 0.20, 0.31, "RTM_GETLINK",
			"rtnl: RTM_GETLINK does not ask for every device a quarter of the time");
	expect_fraction(get->zero, get->msgs, 0.84, 0.91, "RTM_GETLINK",
			"rtnl: RTM_GETLINK's type, flags and change are not 0 seven times in eight");
	expect_fraction(prop->index_lo, prop->msgs, 0.45, 0.56, "the linkprop types",
			"rtnl: the linkprop types do not name lo half the time");
	expect_fraction(other->index_lo, other->msgs, 0.0, 0.03,
			"RTM_NEWLINK, RTM_DELLINK and RTM_SETLINK",
			"rtnl: RTM_NEWLINK, RTM_DELLINK or RTM_SETLINK names lo more often than a random small index does");
	expect_fraction(other->zero, other->msgs, 0.0, 0.001,
			"RTM_NEWLINK, RTM_DELLINK and RTM_SETLINK",
			"rtnl: RTM_NEWLINK, RTM_DELLINK and RTM_SETLINK lose their random type, flags and change");
}

/* ---------- The ifaddrmsg of RTM_NEWADDR, RTM_DELADDR and RTM_GETADDR ---- */

struct addr_header {
	unsigned int msgs;
	unsigned int zero;	/* prefixlen, flags and scope all 0 */
	unsigned int index_all, index_lo;
	unsigned int inet;	/* AF_INET or AF_INET6 */
	unsigned int v4, v4_prefix;	/* AF_INET, with a prefix of 32 bits at most */
};

static void tally_addr_header(struct addr_header *t, const struct nlmsghdr *nlh)
{
	const struct ifaddrmsg *ifm = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifm)))
		return;
	t->msgs++;
	t->zero += !ifm->ifa_prefixlen && !ifm->ifa_flags && !ifm->ifa_scope;
	t->index_all += ifm->ifa_index == 0;
	t->index_lo += ifm->ifa_index == LOOPBACK_IFINDEX;
	t->inet += ifm->ifa_family == AF_INET || ifm->ifa_family == AF_INET6;
	if (ifm->ifa_family == AF_INET) {
		t->v4++;
		t->v4_prefix += ifm->ifa_prefixlen <= 32;
	}
}

/*
 * inet_valid_dump_ifaddr_req() and inet6_valid_dump_ifaddr_req(), the IPv4
 * and IPv6 address dumps, and inet6_rtm_valid_getaddr_req(), the IPv6 doit,
 * refuse a GET with a nonzero prefixlen, flags or scope on a socket that
 * asks for strict checking, and the dumps an index that names no device.
 * The builder leaves the three 0 seven times in eight for a GET, and its
 * index is 0 half the time and lo's a quarter.  NEW and DEL have handlers
 * under AF_INET and AF_INET6, and phonet's and MCTP's, which answer an
 * index that names no device -ENODEV, and inet_validate_rtm() refuses an
 * IPv4 add with a prefix past 32 bits; the builder names AF_INET or
 * AF_INET6 seven times in eight, with an IPv4 prefix of 32 bits at most and
 * lo's index half of those, and draws the prefixlen, flags and scope at
 * random, which leaves them all 0 about once in a few million.
 */
static void expect_addr_header(const struct addr_header *get,
			       const struct addr_header *newdel)
{
	expect_fraction(get->zero, get->msgs, 0.84, 0.91, "RTM_GETADDR",
			"rtnl: RTM_GETADDR's prefixlen, flags and scope are not 0 seven times in eight");
	expect_fraction(get->index_all, get->msgs, 0.44, 0.57, "RTM_GETADDR",
			"rtnl: RTM_GETADDR does not ask for every device half the time");
	expect_fraction(get->index_lo, get->msgs, 0.20, 0.31, "RTM_GETADDR",
			"rtnl: RTM_GETADDR does not ask for lo a quarter of the time");
	expect_fraction(newdel->zero, newdel->msgs, 0.0, 0.001,
			"RTM_NEWADDR and RTM_DELADDR",
			"rtnl: RTM_NEWADDR and RTM_DELADDR lose their random prefixlen, flags and scope");
	expect_fraction(newdel->inet, newdel->msgs, 0.88, 0.94,
			"RTM_NEWADDR and RTM_DELADDR",
			"rtnl: RTM_NEWADDR and RTM_DELADDR do not name AF_INET or AF_INET6 seven times in eight");
	expect_fraction(newdel->v4_prefix, newdel->v4, 0.94, 1.0,
			"IPv4 RTM_NEWADDR and RTM_DELADDR",
			"rtnl: an IPv4 RTM_NEWADDR or RTM_DELADDR has a prefix past 32 bits more than one time in sixteen");
	expect_fraction(newdel->index_lo, newdel->msgs, 0.39, 0.50,
			"RTM_NEWADDR and RTM_DELADDR",
			"rtnl: RTM_NEWADDR and RTM_DELADDR do not name lo about half the time");
	expect_fraction(newdel->index_all, newdel->msgs, 0.0, 0.02,
			"RTM_NEWADDR and RTM_DELADDR",
			"rtnl: RTM_NEWADDR and RTM_DELADDR name index 0, which no device has, more than one time in fifty");
}

/* ---------- The ndmsg of RTM_NEWNEIGH, RTM_DELNEIGH and RTM_GETNEIGH ---- */

struct neigh_header {
	unsigned int msgs;
	unsigned int tabled;	/* AF_INET, AF_INET6 or AF_BRIDGE */
	unsigned int taken;	/* pads, state and type 0, and a flag a GET takes */
	unsigned int index_all, index_lo;
};

static void tally_neigh_header(struct neigh_header *t, const struct nlmsghdr *nlh)
{
	const struct ndmsg *ndm = NLMSG_DATA(nlh);
	uint8_t get_flags;

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ndm)))
		return;
	t->msgs++;
	t->tabled += ndm->ndm_family == AF_INET || ndm->ndm_family == AF_INET6 ||
		     ndm->ndm_family == AF_BRIDGE;
	get_flags = ndm->ndm_family == AF_BRIDGE ? NTF_MASTER | NTF_SELF : NTF_PROXY;
	t->taken += !ndm->ndm_pad1 && !ndm->ndm_pad2 && !ndm->ndm_state &&
		    !ndm->ndm_type && !(ndm->ndm_flags & ~get_flags);
	t->index_all += ndm->ndm_ifindex == 0;
	t->index_lo += ndm->ndm_ifindex == LOOPBACK_IFINDEX;
}

/*
 * neigh_add(), neigh_delete() and neigh_get() answer -EAFNOSUPPORT to a
 * family with no neighbour table, all but AF_INET and AF_INET6, AF_BRIDGE
 * going to the fdb handlers instead, -ENODEV to an index that names no
 * device and, but for a proxy entry, -EINVAL to an index of 0, which a
 * strict dump wants.  neigh_get() and rtnl_fdb_get() refuse a nonzero pad,
 * state or type, and a flag but NTF_PROXY, or NTF_MASTER and NTF_SELF for
 * the fdb, on every socket, and the dumps the same on a socket that asks
 * for strict checking.  The builder names one of the three families seven
 * times in eight and holds a GET's header to that seven times in eight;
 * its index is 0 half the time and lo's a quarter, and NEW and DEL keep
 * their state, flags and type random.
 */
static void expect_neigh_header(const struct neigh_header *get,
				const struct neigh_header *newdel)
{
	unsigned int msgs = get->msgs + newdel->msgs;

	expect_fraction(get->tabled + newdel->tabled, msgs, 0.90, 0.96,
			"RTM_*NEIGH",
			"rtnl: RTM_*NEIGH does not name AF_INET, AF_INET6 or AF_BRIDGE seven times in eight");
	expect_fraction(get->taken, get->msgs, 0.84, 0.91, "RTM_GETNEIGH",
			"rtnl: RTM_GETNEIGH's state, type and flags are not a GET's seven times in eight");
	expect_fraction(get->index_all + newdel->index_all, msgs, 0.44, 0.57,
			"RTM_*NEIGH",
			"rtnl: RTM_*NEIGH does not name index 0 half the time");
	expect_fraction(get->index_lo + newdel->index_lo, msgs, 0.20, 0.31,
			"RTM_*NEIGH",
			"rtnl: RTM_*NEIGH does not name lo a quarter of the time");
	expect_fraction(newdel->taken, newdel->msgs, 0.0, 0.001,
			"RTM_NEWNEIGH and RTM_DELNEIGH",
			"rtnl: RTM_NEWNEIGH and RTM_DELNEIGH lose their random state, flags and type");
}

/* ---------- The attributes of RTM_GETNEIGH ------------------------------ */

struct getneigh_attrs {
	unsigned int doits, doits_taken;	/* AF_INET, AF_INET6 or AF_BRIDGE */
	unsigned int dumps, dumps_taken;
};

/* A GET whose attributes are all flat ones of a type its handler takes, and
 * for a doit at least one, an NDA_DST of the family's key length where the
 * doit is neigh_get(). */
static void tally_getneigh_attrs(struct getneigh_attrs *t,
				 const struct nlmsghdr *nlh)
{
	const struct ndmsg *ndm = NLMSG_DATA(nlh);
	bool dump = nlh->nlmsg_flags & NLM_F_DUMP;
	unsigned int attrs = 0, taken = 0;
	const unsigned char *p;
	const struct nlattr *nla;
	unsigned int key_len;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(*ndm)))
		return;
	key_len = ndm->ndm_family == AF_INET6 ? 16 : 4;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(*ndm));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(*ndm));
	while ((nla = fit_attr(p, len)) != NULL) {
		unsigned short type = nla->nla_type & NLA_TYPE_MASK;
		size_t total = NLA_ALIGN(nla->nla_len);

		attrs++;
		if (nla->nla_type & NLA_F_NESTED)
			;
		else if (dump)
			taken += type == NDA_IFINDEX || type == NDA_MASTER;
		else if (ndm->ndm_family == AF_BRIDGE)
			taken += type == NDA_LLADDR || type == NDA_MASTER ||
				 type == NDA_VLAN || type == NDA_VNI;
		else
			taken += type == NDA_DST &&
				 nla->nla_len == NLA_HDRLEN + key_len;
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	if (dump) {
		t->dumps++;
		t->dumps_taken += taken == attrs;
	} else if (ndm->ndm_family == AF_INET || ndm->ndm_family == AF_INET6 ||
		   ndm->ndm_family == AF_BRIDGE) {
		t->doits++;
		t->doits_taken += attrs && taken == attrs;
	}
}

/*
 * neigh_valid_get_req() parses neigh_get()'s attributes strictly on every
 * socket and refuses any but NDA_DST, which it needs, and neigh_get() one
 * that is not the family's key length; the bridge's rtnl_fdb_get() takes
 * NDA_LLADDR, which it needs, NDA_MASTER, NDA_VLAN and NDA_VNI, and the
 * strict neighbour and fdb dumps NDA_IFINDEX and NDA_MASTER.  The builder
 * draws a GETNEIGH's types from those seven times in eight, and the rest
 * of the attribute path still makes one in eight a random type and one in
 * seven a nested container, so about 0.24 of the doits and 0.36 of the
 * dumps carry nothing else; drawing from every NDA_* type left 0.01 and
 * 0.14.
 */
static void expect_getneigh_attrs(const struct getneigh_attrs *t)
{
	expect_fraction(t->doits_taken, t->doits, 0.17, 0.30,
			"RTM_GETNEIGH doits",
			"rtnl: a GETNEIGH doit rarely carries only what neigh_get() or rtnl_fdb_get() takes");
	expect_fraction(t->dumps_taken, t->dumps, 0.30, 0.42,
			"RTM_GETNEIGH dumps",
			"rtnl: a GETNEIGH dump rarely carries only the NDA_IFINDEX and NDA_MASTER the strict dump takes");
}

/* ---------- The nhmsg of RTM_*NEXTHOP and RTM_GETNEXTHOPBUCKET ---------- */

struct nexthop_header {
	unsigned int msgs;
	unsigned int taken;	/* a header the request's handler takes */
	unsigned int onlink;	/* flags RTNH_F_ONLINK */
};

static void tally_nexthop_header(struct nexthop_header *t,
				 const struct nlmsghdr *nlh, bool add)
{
	const struct nhmsg *nhm = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*nhm)))
		return;
	t->msgs++;
	t->onlink += nhm->nh_flags == RTNH_F_ONLINK;
	if (nhm->resvd || nhm->nh_scope)
		return;
	if (add)
		t->taken += !(nhm->nh_flags & ~RTNH_F_ONLINK) &&
			    (nhm->nh_family == AF_INET ||
			     nhm->nh_family == AF_INET6 ||
			     nhm->nh_family == AF_UNSPEC);
	else
		t->taken += !nhm->nh_protocol && !nhm->nh_flags;
}

/*
 * rtm_to_nh_config() refuses a nexthop add whose scope or reserved byte is
 * nonzero, whose flags hold any but RTNH_F_ONLINK or whose family is not
 * AF_INET, AF_INET6 or, for a group, AF_UNSPEC, and nh_valid_get_del_req()
 * and the dumps refuse a delete or a GET whose protocol, scope, reserved
 * byte or flags are nonzero, on every socket.  The builder keeps both to
 * that seven times in eight, and an add carries RTNH_F_ONLINK half of
 * those.
 */
static void expect_nexthop_header(const struct nexthop_header *add,
				  const struct nexthop_header *other)
{
	expect_fraction(add->taken, add->msgs, 0.84, 0.91, "RTM_NEWNEXTHOP",
			"rtnl: RTM_NEWNEXTHOP's header is not one rtm_to_nh_config() takes seven times in eight");
	expect_fraction(add->onlink, add->msgs, 0.38, 0.50, "RTM_NEWNEXTHOP",
			"rtnl: RTM_NEWNEXTHOP does not carry RTNH_F_ONLINK about half the time");
	expect_fraction(other->taken, other->msgs, 0.84, 0.91,
			"RTM_DELNEXTHOP, RTM_GETNEXTHOP and RTM_GETNEXTHOPBUCKET",
			"rtnl: a nexthop delete or GET does not have a zero protocol, scope and flags seven times in eight");
}

/* ---------- The NLA_FLAG attributes of RTM_*NEXTHOP --------------------- */

struct nexthop_flags {
	unsigned int flags;	/* NHA_BLACKHOLE, NHA_FDB or NHA_GROUPS */
	unsigned int empty;	/* ... with no payload and no NLA_F_NESTED */
};

static void tally_nexthop_flags(struct nexthop_flags *t,
				const struct nlmsghdr *nlh)
{
	const unsigned char *p;
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct nhmsg)))
		return;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct nhmsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct nhmsg));
	while ((nla = fit_attr(p, len)) != NULL) {
		unsigned short type = nla->nla_type & NLA_TYPE_MASK;
		size_t total = NLA_ALIGN(nla->nla_len);

		if (type == NHA_BLACKHOLE || type == NHA_FDB || type == NHA_GROUPS) {
			t->flags++;
			t->empty += nla->nla_len == NLA_HDRLEN &&
				    !(nla->nla_type & NLA_F_NESTED);
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * NHA_BLACKHOLE, NHA_FDB and NHA_GROUPS are NLA_FLAGs, which validate_nla()
 * refuses with any payload (-ERANGE), and the nexthop parses are strict, so
 * they refuse one flagged NLA_F_NESTED as well.  The builder sends them
 * empty all but one time in eight where the attribute path does not make
 * one a nested container's outer attribute, about 0.73 of them; random
 * bytes left about one in a hundred empty.
 */
static void expect_nexthop_flags(const struct nexthop_flags *t)
{
	expect_fraction(t->empty, t->flags, 0.66, 0.80, "nexthop flags",
			"rtnl: NHA_BLACKHOLE, NHA_FDB and NHA_GROUPS mostly carry the payload an NLA_FLAG refuses");
}

/* ---------- NHA_GATEWAY ------------------------------------------------- */

struct nexthop_gateway {
	unsigned int gateways;	/* in AF_INET and AF_INET6 adds */
	unsigned int sized;	/* ... flat and the family's address width */
};

static void tally_nexthop_gateway(struct nexthop_gateway *t,
				  const struct nlmsghdr *nlh)
{
	const struct nhmsg *nhm = NLMSG_DATA(nlh);
	const unsigned char *p;
	const struct nlattr *nla;
	unsigned int width;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(*nhm)) ||
	    (nhm->nh_family != AF_INET && nhm->nh_family != AF_INET6))
		return;
	width = nhm->nh_family == AF_INET6 ? 16 : 4;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(*nhm));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(*nhm));
	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == NHA_GATEWAY) {
			t->gateways++;
			t->sized += nla->nla_len == NLA_HDRLEN + width &&
				    !(nla->nla_type & NLA_F_NESTED);
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * rtm_to_nh_config() refuses an NHA_GATEWAY that is not the nhmsg family's
 * address, 4 bytes for AF_INET and 16 for AF_INET6.  The builder sizes it
 * to the family where the attribute path does not make it a nested
 * container's outer attribute, about 0.84 of them; random bytes were the
 * right width about one time in a hundred.
 */
static void expect_nexthop_gateway(const struct nexthop_gateway *t)
{
	expect_fraction(t->sized, t->gateways, 0.78, 0.90, "NHA_GATEWAY",
			"rtnl: a nexthop's NHA_GATEWAY is mostly not its family's address width");
}

/* ---------- The attribute types of the nexthop ops ---------------------- */

enum { NH_NEW, NH_DEL, NH_GET, NH_DUMP, NH_GET_BUCKET, NH_DUMP_BUCKET, NH_OPS };

/* The NHA_* types of each op's policy in net/ipv4/nexthop.c. */
static const unsigned short nh_new_policy[] = {
	NHA_ID, NHA_GROUP, NHA_GROUP_TYPE, NHA_BLACKHOLE, NHA_OIF,
	NHA_GATEWAY, NHA_ENCAP_TYPE, NHA_ENCAP, NHA_FDB, NHA_DST_PORT,
	NHA_RES_GROUP, NHA_HW_STATS_ENABLE,
};
static const unsigned short nh_del_policy[] = { NHA_ID };
static const unsigned short nh_get_policy[] = { NHA_ID, NHA_OP_FLAGS };
static const unsigned short nh_dump_policy[] = {
	NHA_OIF, NHA_GROUPS, NHA_MASTER, NHA_FDB, NHA_OP_FLAGS,
};
static const unsigned short nh_get_bucket_policy[] = { NHA_ID, NHA_RES_BUCKET };
static const unsigned short nh_dump_bucket_policy[] = {
	NHA_ID, NHA_OIF, NHA_MASTER, NHA_RES_BUCKET,
};

static const struct {
	const unsigned short *types;
	size_t n;
	bool needs_id;		/* -EINVAL without NHA_ID */
	const char *name;
} nh_policies[NH_OPS] = {
	[NH_NEW]	= { nh_new_policy, ARRAY_SIZE(nh_new_policy), false,
			    "RTM_NEWNEXTHOP" },
	[NH_DEL]	= { nh_del_policy, ARRAY_SIZE(nh_del_policy), true,
			    "RTM_DELNEXTHOP" },
	[NH_GET]	= { nh_get_policy, ARRAY_SIZE(nh_get_policy), true,
			    "RTM_GETNEXTHOP doits" },
	[NH_DUMP]	= { nh_dump_policy, ARRAY_SIZE(nh_dump_policy), false,
			    "RTM_GETNEXTHOP dumps" },
	[NH_GET_BUCKET]	= { nh_get_bucket_policy, ARRAY_SIZE(nh_get_bucket_policy),
			    true, "RTM_GETNEXTHOPBUCKET doits" },
	[NH_DUMP_BUCKET] = { nh_dump_bucket_policy,
			     ARRAY_SIZE(nh_dump_bucket_policy), false,
			     "RTM_GETNEXTHOPBUCKET dumps" },
};

struct nexthop_attrs {
	unsigned int msgs;
	unsigned int taken;	/* types all the op's, with an NHA_ID it needs */
};

static void tally_nexthop_attrs(struct nexthop_attrs *t, const struct nlmsghdr *nlh)
{
	bool dump = nlh->nlmsg_flags & NLM_F_DUMP;
	unsigned int attrs = 0, in = 0, ids = 0;
	const unsigned char *p;
	const struct nlattr *nla;
	size_t len, i;
	int op;

	switch (nlh->nlmsg_type) {
	case RTM_NEWNEXTHOP:	op = NH_NEW; break;
	case RTM_DELNEXTHOP:	op = NH_DEL; break;
	case RTM_GETNEXTHOP:	op = dump ? NH_DUMP : NH_GET; break;
	default:		op = dump ? NH_DUMP_BUCKET : NH_GET_BUCKET; break;
	}
	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct nhmsg)))
		return;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct nhmsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct nhmsg));
	while ((nla = fit_attr(p, len)) != NULL) {
		unsigned short type = nla->nla_type & NLA_TYPE_MASK;
		size_t total = NLA_ALIGN(nla->nla_len);

		attrs++;
		for (i = 0; i < nh_policies[op].n; i++)
			in += type == nh_policies[op].types[i];
		ids += type == NHA_ID;
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	t[op].msgs++;
	t[op].taken += in == attrs && (!nh_policies[op].needs_id || ids);
}

/*
 * Every nexthop op parses strictly against a policy of its own, and an
 * attribute outside it refuses the request; a delete, a GET doit and a
 * bucket GET doit answer -EINVAL without NHA_ID too.  The builder draws
 * each op's types from its policy seven times in eight, and the attribute
 * path still makes one in eight of them random, so about 0.62 of the adds,
 * 0.38 of the deletes, 0.30 of the doits and 0.53 of the dumps carry only
 * types their op takes; drawing from one table without NHA_ID left 0.29,
 * none, none and 0.17 or less.
 */
static void expect_nexthop_attrs(const struct nexthop_attrs *t)
{
	static const double lo[NH_OPS] = { 0.55, 0.30, 0.24, 0.46, 0.24, 0.46 };
	static const double hi[NH_OPS] = { 0.68, 0.45, 0.37, 0.61, 0.37, 0.61 };
	int op;

	for (op = 0; op < NH_OPS; op++)
		expect_fraction(t[op].taken, t[op].msgs, lo[op], hi[op],
				nh_policies[op].name,
				"rtnl: a nexthop op's attributes are mostly not the types its policy holds");
}

/* ---------- The fib_rule_hdr of RTM_NEWRULE, RTM_DELRULE and RTM_GETRULE - */

struct rule_header {
	unsigned int msgs;
	unsigned int taken;	/* a header the request's handler takes */
	unsigned int unspec;	/* AF_UNSPEC, every family's rules */
};

static void tally_rule_header(struct rule_header *t, const struct nlmsghdr *nlh,
			      bool get)
{
	const struct fib_rule_hdr *frh = NLMSG_DATA(nlh);
	bool ruled;

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*frh)))
		return;
	t->msgs++;
	t->unspec += frh->family == AF_UNSPEC;
	if (frh->src_len || frh->dst_len || frh->res1 || frh->res2)
		return;
	ruled = frh->family == AF_INET || frh->family == AF_INET6 ||
		frh->family == RTNL_FAMILY_IPMR || frh->family == RTNL_FAMILY_IP6MR;
	if (get)
		t->taken += (ruled || frh->family == AF_UNSPEC) && !frh->tos &&
			    !frh->table && !frh->action && !frh->flags;
	else
		t->taken += ruled && !(frh->tos & IPTOS_ECN_MASK) &&
			    (frh->family != AF_INET || !(frh->tos & ~IPTOS_TOS_MASK));
}

/*
 * fib_newrule() and fib_delrule() answer -EAFNOSUPPORT to a family with no
 * rules ops, all but AF_INET, AF_INET6, RTNL_FAMILY_IPMR and
 * RTNL_FAMILY_IP6MR, and fib_nl2rule() refuses a nonzero src_len or dst_len
 * without the FRA_SRC or FRA_DST it needs; the IPv4 and IPv6 rules refuse a
 * tos with an ECN bit, and IPv4 a bit outside IPTOS_TOS_MASK.  The dump
 * takes those families and AF_UNSPEC, and on a socket that asks for strict
 * checking refuses anything else in the header that is not 0.  The builder
 * keeps both to that seven times in eight, a dump asking for every family
 * one time in five.
 */
static void expect_rule_header(const struct rule_header *get,
			       const struct rule_header *newdel)
{
	expect_fraction(get->taken, get->msgs, 0.84, 0.91, "RTM_GETRULE",
			"rtnl: RTM_GETRULE's header is not one the rule dump takes seven times in eight");
	expect_fraction(get->unspec, get->msgs, 0.15, 0.24, "RTM_GETRULE",
			"rtnl: RTM_GETRULE does not ask for every family's rules one time in five");
	expect_fraction(newdel->taken, newdel->msgs, 0.84, 0.91,
			"RTM_NEWRULE and RTM_DELRULE",
			"rtnl: a rule add or delete's header is not one fib_nl2rule() and its family take seven times in eight");
}

/* ---------- The ifaddrlblmsg of RTM_*ADDRLABEL --------------------------- */

struct addrlabel_header {
	unsigned int msgs;
	unsigned int inet6;	/* AF_INET6 */
	unsigned int index_all, index_lo, index_small;	/* 0, lo's, under 64 */
	unsigned int taken;	/* no flags, seq or reserved, a prefix of 0 or 128 */
};

static void tally_addrlabel_header(struct addrlabel_header *t,
				   const struct nlmsghdr *nlh)
{
	const struct ifaddrlblmsg *ifal = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifal)))
		return;
	t->msgs++;
	t->inet6 += ifal->ifal_family == AF_INET6;
	t->index_all += ifal->ifal_index == 0;
	t->index_lo += ifal->ifal_index == LOOPBACK_IFINDEX;
	t->index_small += ifal->ifal_index < 64;
	t->taken += !ifal->__ifal_reserved && !ifal->ifal_flags &&
		    !ifal->ifal_seq &&
		    (ifal->ifal_prefixlen == 0 || ifal->ifal_prefixlen == 128);
}

/*
 * net/ipv6/addrlabel.c registers the three types for PF_INET6 alone, and
 * an add and the GET doit refuse an index that names no device.  The GET
 * doit wants a prefix of 128 and, on a socket that asks for strict
 * checking, no flags or seq, and the dump a header of zeros.  The builder
 * names AF_INET6 and an index of 0, lo's or one under 64 seven times in
 * eight, 0 half of those and lo's a quarter, and a GET a prefix of 128 or
 * 0 with no flags or seq; an add or delete keeps its random flags and seq,
 * which neither reads.
 */
static void expect_addrlabel_header(const struct addrlabel_header *get,
				    const struct addrlabel_header *newdel)
{
	unsigned int msgs = get->msgs + newdel->msgs;

	expect_fraction(get->inet6 + newdel->inet6, msgs, 0.86, 0.93,
			"RTM_*ADDRLABEL",
			"rtnl: RTM_*ADDRLABEL does not name AF_INET6 seven times in eight");
	expect_fraction(get->index_small + newdel->index_small, msgs, 0.84, 0.91,
			"RTM_*ADDRLABEL",
			"rtnl: RTM_*ADDRLABEL's index is not 0, lo's or a small one seven times in eight");
	expect_fraction(get->index_all + newdel->index_all, msgs, 0.38, 0.50,
			"RTM_*ADDRLABEL",
			"rtnl: RTM_*ADDRLABEL does not name index 0 about half the time");
	expect_fraction(get->index_lo + newdel->index_lo, msgs, 0.17, 0.28,
			"RTM_*ADDRLABEL",
			"rtnl: RTM_*ADDRLABEL does not name lo about a quarter of the time");
	expect_fraction(get->taken, get->msgs, 0.84, 0.91, "RTM_GETADDRLABEL",
			"rtnl: RTM_GETADDRLABEL's header is not one the GET takes seven times in eight");
	expect_fraction(newdel->taken, newdel->msgs, 0.0, 0.001,
			"RTM_NEWADDRLABEL and RTM_DELADDRLABEL",
			"rtnl: RTM_NEWADDRLABEL and RTM_DELADDRLABEL lose their random flags and seq");
}

/* ---------- The if_stats_msg of RTM_GETSTATS and RTM_SETSTATS ------------ */

struct stats_header {
	unsigned int msgs;
	unsigned int taken;	/* a header the request's handler takes */
	unsigned int index_lo;
};

static void tally_stats_header(struct stats_header *t,
			       const struct nlmsghdr *nlh, bool set)
{
	const struct if_stats_msg *ifsm = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifsm)))
		return;
	t->msgs++;
	t->index_lo += ifsm->ifindex == LOOPBACK_IFINDEX;
	if (ifsm->pad1 || ifsm->pad2 || ifsm->ifindex >= 64)
		return;
	if (set)
		t->taken += ifsm->family == AF_UNSPEC && ifsm->ifindex &&
			    !ifsm->filter_mask;
	else
		t->taken += ifsm->filter_mask &&
			    ifsm->filter_mask < IFLA_STATS_FILTER_BIT(IFLA_STATS_MAX + 1);
}

/*
 * rtnl_stats_get() and rtnl_stats_set() answer an index that names no
 * device -ENODEV, or -EINVAL for 0; the GET and the dump refuse a filter
 * mask of 0, and on a socket that asks for strict checking one past the
 * IFLA_STATS_* bits; the SET refuses any filter mask and a family but
 * AF_UNSPEC.  The builder keeps both to that seven times in eight, a GET
 * naming lo a quarter of the time, as RTM_GETADDR does, and a SET half.
 */
static void expect_stats_header(const struct stats_header *get,
				const struct stats_header *set)
{
	expect_fraction(get->taken, get->msgs, 0.84, 0.91, "RTM_GETSTATS",
			"rtnl: RTM_GETSTATS's filter mask is not a few IFLA_STATS_* bits seven times in eight");
	expect_fraction(get->index_lo, get->msgs, 0.17, 0.28, "RTM_GETSTATS",
			"rtnl: RTM_GETSTATS does not name lo about a quarter of the time");
	expect_fraction(set->taken, set->msgs, 0.83, 0.91, "RTM_SETSTATS",
			"rtnl: RTM_SETSTATS's header is not one rtnl_stats_set() takes seven times in eight");
	expect_fraction(set->index_lo, set->msgs, 0.39, 0.50, "RTM_SETSTATS",
			"rtnl: RTM_SETSTATS does not name lo about half the time");
}

/* ---------- The br_port_msg of RTM_*MDB and br_vlan_msg of RTM_*VLAN ----- */

struct bridge_header {
	unsigned int msgs;
	unsigned int bridge;	/* AF_BRIDGE */
	unsigned int index_all;	/* index 0 */
};

static void tally_bridge_header(struct bridge_header *t,
				const struct nlmsghdr *nlh, bool mdb)
{
	const struct br_port_msg *bpm = NLMSG_DATA(nlh);
	const struct br_vlan_msg *bvm = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(mdb ? sizeof(*bpm) : sizeof(*bvm)))
		return;
	t->msgs++;
	t->bridge += (mdb ? bpm->family : bvm->family) == AF_BRIDGE;
	t->index_all += (mdb ? bpm->ifindex : bvm->ifindex) == 0;
}

/*
 * rtnetlink.c registers the MDB types for PF_BRIDGE alone, and br_vlan.c
 * the VLAN ones, so rtnetlink_rcv_msg() answers any other family
 * -EOPNOTSUPP.  The MDB dump refuses an index but 0 on a socket that asks
 * for strict checking, and the VLAN dump one that names no device, where
 * 0 dumps every device; an add or a delete needs a bridge, or a vxlan for
 * the MDB, which 0 and lo never are.  The builder names AF_BRIDGE but one
 * time in sixteen, and gives a GET index 0 half the time and an add or a
 * delete a small index.
 */
static void expect_bridge_header(const struct bridge_header *get,
				 const struct bridge_header *newdel)
{
	expect_fraction(get->bridge + newdel->bridge, get->msgs + newdel->msgs,
			0.92, 0.97, "RTM_*MDB and RTM_*VLAN",
			"rtnl: RTM_*MDB and RTM_*VLAN do not name AF_BRIDGE fifteen times in sixteen");
	expect_fraction(get->index_all, get->msgs, 0.44, 0.57,
			"RTM_GETMDB and RTM_GETVLAN",
			"rtnl: RTM_GETMDB and RTM_GETVLAN do not ask for every device half the time");
	expect_fraction(newdel->index_all, newdel->msgs, 0.0, 0.04,
			"RTM_NEWMDB, RTM_DELMDB, RTM_NEWVLAN and RTM_DELVLAN",
			"rtnl: a bridge add or delete names index 0, which its handler refuses, more than one time in 25");
}

/* ---------- The headers that carry a family alone ----------------------- */

struct family_header {
	unsigned int msgs;
	unsigned int taken;	/* a family with a handler for the request */
};

/* The family byte that opens the header, against the n a handler takes. */
static void tally_family(struct family_header *t, const struct nlmsghdr *nlh,
			 const unsigned char *families, size_t n)
{
	const unsigned char *family = NLMSG_DATA(nlh);
	size_t i;

	if (nlh->nlmsg_len < NLMSG_LENGTH(1))
		return;
	t->msgs++;
	for (i = 0; i < n; i++)
		t->taken += *family == families[i];
}

/* RTM_GETNETCONF's doit is registered for these alone, and
 * rtnetlink_rcv_msg() answers a doit under any other family -EOPNOTSUPP. */
static const unsigned char netconf_families[] = { AF_INET, AF_INET6, AF_MPLS };

/* Only AF_INET and AF_INET6 have neighbour tables, and neightbl_set() and
 * the dump skip one whose family is not the header's unless it names none. */
static const unsigned char neightbl_families[] = { AF_UNSPEC, AF_INET, AF_INET6 };

/*
 * The builder names a family with a handler but one time in eight, when
 * rand_family() still lands on one about half the time.
 */
static void expect_family_headers(const struct family_header *netconf,
				  const struct family_header *neightbl)
{
	expect_fraction(netconf->taken, netconf->msgs, 0.90, 0.96, "RTM_GETNETCONF",
			"rtnl: RTM_GETNETCONF does not name AF_INET, AF_INET6 or AF_MPLS seven times in eight");
	expect_fraction(neightbl->taken, neightbl->msgs, 0.90, 0.96,
			"RTM_GETNEIGHTBL and RTM_SETNEIGHTBL",
			"rtnl: a neighbour table request does not name AF_UNSPEC, AF_INET or AF_INET6 seven times in eight");
}

/* ---------- The VNI filter entries of RTM_*TUNNEL ------------------------ */

struct tunnel_attrs {
	unsigned int msgs;
	unsigned int bridge;	/* tunnel_msg.family AF_BRIDGE */
	unsigned int flags_ok;	/* no flag but TUNNEL_MSG_FLAG_STATS */
	unsigned int index_all;	/* ifindex 0 */
	unsigned int attrs;
	unsigned int entries;	/* of type VXLAN_VNIFILTER_ENTRY */
	unsigned int flagged;	/* ... flagged NLA_F_NESTED */
};

static void tally_tunnel_attrs(struct tunnel_attrs *t, const struct nlmsghdr *nlh)
{
	const struct tunnel_msg *tm = NLMSG_DATA(nlh);
	const unsigned char *p;
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct tunnel_msg)))
		return;
	t->msgs++;
	t->bridge += tm->family == AF_BRIDGE;
	t->flags_ok += !(tm->flags & ~TUNNEL_MSG_FLAG_STATS);
	t->index_all += tm->ifindex == 0;

	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct tunnel_msg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct tunnel_msg));
	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		t->attrs++;
		if ((nla->nla_type & NLA_TYPE_MASK) == VXLAN_VNIFILTER_ENTRY) {
			t->entries++;
			t->flagged += !!(nla->nla_type & NLA_F_NESTED);
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * vxlan_vnifilter.c registers the three types for PF_BRIDGE alone, and
 * rtnetlink_rcv_msg() answers any other family -EOPNOTSUPP;
 * vxlan_vnifilter_dump() refuses a flag but TUNNEL_MSG_FLAG_STATS and walks
 * every device for ifindex 0.  The builder names AF_BRIDGE but one request
 * in sixteen, which takes one of six families seven times in eight, holds
 * valid flags seven times in eight and asks for every device half the time.
 * vxlan_vnifilter_process() parses RTM_NEWTUNNEL and RTM_DELTUNNEL strictly
 * against vni_filter_policy, whose one attribute is VXLAN_VNIFILTER_ENTRY,
 * so a request of any other type is refused whole, and the dump reads only
 * that type.  An attribute takes its group's type seven times in eight,
 * whether it is a nest of the builder's or built by the type's own payload
 * generator, so about seven in eight of them are entries.  The strict parse
 * refuses an entry without NLA_F_NESTED, which the builder's nests always
 * carry and the payload generator's seven times in eight: about 0.89 of the
 * entries.
 */
static void expect_tunnel_attrs(const struct tunnel_attrs *t)
{
	expect_fraction(t->bridge, t->msgs, 0.91, 0.98, "RTM_*TUNNEL",
			"rtnl: a tunnel request does not name AF_BRIDGE but one time in sixteen");
	expect_fraction(t->flags_ok, t->msgs, 0.84, 0.91, "RTM_*TUNNEL",
			"rtnl: a tunnel request's flags are not valid seven times in eight");
	expect_fraction(t->index_all, t->msgs, 0.44, 0.57, "RTM_*TUNNEL",
			"rtnl: a tunnel request does not ask for every device half the time");
	expect_fraction(t->entries, t->attrs, 0.80, 0.95, "RTM_*TUNNEL",
			"rtnl: a tunnel request's attributes are not mostly VXLAN_VNIFILTER_ENTRY");
	expect_fraction(t->flagged, t->entries, 0.82, 0.95, "RTM_*TUNNEL",
			"rtnl: a VNI filter entry mostly lacks NLA_F_NESTED, which the strict parse wants");
}

#define ENTRIES		40000

/*
 * Whether the VXLAN_VNIFILTER_ENTRY payload of len bytes at p holds a GROUP
 * or GROUP6 of a length other than an address's, which the exact-length
 * policy refuses.
 */
static bool short_group(const unsigned char *p, size_t len)
{
	const struct nlattr *nla;

	while ((nla = fit_attr(p, len)) != NULL) {
		unsigned short type = nla->nla_type & NLA_TYPE_MASK;
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((type == VXLAN_VNIFILTER_ENTRY_GROUP &&
		     nla->nla_len != NLA_HDRLEN + sizeof(struct in_addr)) ||
		    (type == VXLAN_VNIFILTER_ENTRY_GROUP6 &&
		     nla->nla_len != NLA_HDRLEN + sizeof(struct in6_addr)))
			return true;
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	return false;
}

/*
 * vni_filter_policy validates every entry against vni_filter_entry_policy,
 * whose GROUP and GROUP6 are NLA_POLICY_EXACT_LEN, so one short entry
 * refuses the whole message.  An entry has up to three siblings after
 * START, each a GROUP or GROUP6 two times in three and short one time in
 * 32, so about 0.03 of the entries are short.
 */
static void builds_vni_entries_the_policy_takes(void)
{
	static unsigned char buf[256];
	unsigned int i, bad = 0;

	for (i = 0; i < ENTRIES; i++) {
		size_t len = gen_rta_tunnel_payload(buf, sizeof(buf),
						    VXLAN_VNIFILTER_ENTRY);

		if (len == 0)
			BUG("rtnl: no VXLAN_VNIFILTER_ENTRY payload fits 256 bytes");
		bad += short_group(buf, len);
	}
	expect_fraction(bad, ENTRIES, 0.015, 0.05, "VXLAN_VNIFILTER_ENTRY",
			"rtnl: a VNI filter entry is not short about one time in 32");
}

/* ---------- The link size limits and IFLA_PACING_OFFLOAD ----------------- */

/*
 * What the kernel takes of them, from ifla_policy and validate_linkmsg() in
 * net/core/rtnetlink.c.  IFLA_GSO_MAX_SIZE and IFLA_GSO_IPV4_MAX_SIZE are
 * NLA_POLICY_MIN(NLA_U32, MAX_TCP_HEADER + 1), and MAX_TCP_HEADER is
 * L1_CACHE_ALIGN(128 + MAX_HEADER): 512 at most, with the 176 bytes of header
 * room that tunnels and wireless give it and a 256 byte cache line, so 513
 * clears the floor on any config.  validate_linkmsg() then refuses either
 * above the device's tso_max_size, which is TSO_LEGACY_MAX_SIZE until a
 * driver raises it, as lo and veth do to GSO_MAX_SIZE, and refuses
 * IFLA_GRO_MAX_SIZE and IFLA_GRO_IPV4_MAX_SIZE above GRO_MAX_SIZE.
 * IFLA_PACING_OFFLOAD is NLA_POLICY_MAX(NLA_U32, 1), and ifla_policy parses
 * the types from IFLA_DPLL_PIN up strictly, so it takes four bytes exactly.
 */
#define FLOOR_CLEARED		513u
#define TSO_LEGACY_MAX_SIZE	65536u
#define GSO_MAX_SIZE		(8 * 65535u)
#define GRO_MAX_SIZE		(8 * 65535u)

/* A few segments of a 1500 byte MTU: what a limit has to be under to bite. */
#define FEW_SEGMENTS		4096u

enum limit_kind { GSO_LIMIT, GRO_LIMIT, PACING };

static const struct {
	unsigned short type;
	enum limit_kind kind;
	const char *name;
} limit_types[] = {
	{ IFLA_GSO_MAX_SIZE,      GSO_LIMIT, "IFLA_GSO_MAX_SIZE" },
	{ IFLA_GSO_IPV4_MAX_SIZE, GSO_LIMIT, "IFLA_GSO_IPV4_MAX_SIZE" },
	{ IFLA_GRO_MAX_SIZE,      GRO_LIMIT, "IFLA_GRO_MAX_SIZE" },
	{ IFLA_GRO_IPV4_MAX_SIZE, GRO_LIMIT, "IFLA_GRO_IPV4_MAX_SIZE" },
	{ IFLA_PACING_OFFLOAD,    PACING,    "IFLA_PACING_OFFLOAD" },
};

struct limit {
	unsigned int seen;
	unsigned int exact;		/* four bytes, without the nest flag */
	unsigned int below;		/* under FLOOR_CLEARED */
	unsigned int few;		/* up to FEW_SEGMENTS */
	unsigned int legacy;		/* up to TSO_LEGACY_MAX_SIZE */
	unsigned int big;		/* up to GSO_MAX_SIZE, as a raised limit takes */
	unsigned int over;		/* past it, which no device takes */
	unsigned int zero, one;
};

/*
 * The limit attributes among the top-level ones of an RTM_*LINK request, by
 * the size of the number each carries.
 */
static void tally_link_limits(struct limit *t, const struct nlmsghdr *nlh)
{
	const unsigned char *p = (const unsigned char *) nlh +
				 NLMSG_SPACE(sizeof(struct ifinfomsg));
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct ifinfomsg)))
		return;
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct ifinfomsg));

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(limit_types); i++) {
			struct limit *l = &t[i];
			uint32_t v;

			if ((nla->nla_type & NLA_TYPE_MASK) != limit_types[i].type)
				continue;
			l->seen++;
			if ((nla->nla_type & NLA_F_NESTED) ||
			    nla->nla_len != NLA_HDRLEN + sizeof(v))
				break;
			l->exact++;
			memcpy(&v, p + NLA_HDRLEN, sizeof(v));
			l->below += v < FLOOR_CLEARED;
			l->few += v <= FEW_SEGMENTS;
			l->legacy += v <= TSO_LEGACY_MAX_SIZE;
			l->big += v > TSO_LEGACY_MAX_SIZE && v <= GSO_MAX_SIZE;
			l->over += v > GSO_MAX_SIZE;
			l->zero += v == 0;
			l->one += v == 1;
			break;
		}
		if (total > len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * A draw has to clear the policy and validate_linkmsg() of a device that has
 * the legacy limit to reach do_setlink() on every device, and a limit bites
 * only when it is under what the flow sends, which since 32bfd220cd6f is when
 * a device re-segments an oversized skb instead of dropping its GSO features.
 * So the GSO limits are mostly between the floor and TSO_LEGACY_MAX_SIZE, a
 * quarter of them within a few segments, and some take the BIG TCP sizes that
 * lo and veth do, where the legacy limit refuses them.  The GRO limits are as
 * often above 64 KiB as under it, and the pacing switch is 0 or 1.  One draw
 * in seven of the shared attribute loop is a nest of the type instead of a
 * number, so about six in seven of each are the four bytes.
 */
static void expect_link_limits(const struct limit *t)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(limit_types); i++) {
		const struct limit *l = &t[i];
		const char *name = limit_types[i].name;

		expect_fraction(l->exact, l->seen, 0.75, 0.95, name,
				"rtnl: a link limit is not mostly a four byte number");
		switch (limit_types[i].kind) {
		case GSO_LIMIT:
			expect_fraction(l->legacy - l->below, l->exact, 0.75, 1.0, name,
					"rtnl: a gso limit is not mostly in the policy's range");
			expect_fraction(l->below, l->exact, 0.0, 0.05, name,
					"rtnl: a gso limit is under the policy's floor");
			expect_fraction(l->few - l->below, l->exact, 0.15, 0.45, name,
					"rtnl: a gso limit is not often within a few segments");
			expect_fraction(l->big, l->exact, 0.03, 0.25, name,
					"rtnl: a gso limit is never a BIG TCP size");
			expect_fraction(l->over, l->exact, 0.0, 0.01, name,
					"rtnl: a gso limit is past what any device takes");
			break;
		case GRO_LIMIT:
			expect_fraction(l->over, l->exact, 0.0, 0.01, name,
					"rtnl: a gro limit is past GRO_MAX_SIZE");
			expect_fraction(l->big, l->exact, 0.35, 0.65, name,
					"rtnl: a gro limit is not often a BIG TCP size");
			expect_fraction(l->legacy, l->exact, 0.35, 0.65, name,
					"rtnl: a gro limit is not often a legacy size");
			break;
		case PACING:
			expect_fraction(l->zero, l->exact, 0.35, 0.65, name,
					"rtnl: pacing offload is not often 0");
			expect_fraction(l->one, l->exact, 0.35, 0.65, name,
					"rtnl: pacing offload is not often 1");
			break;
		}
	}
}

/* ---------- NDTPA_INTERVAL_PROBE_TIME_MS --------------------------------- */

/*
 * neightbl_set() in net/core/neighbour.c parses the NDTPA_* attributes of
 * NDTA_PARMS against nl_ntbl_parm_policy, which holds
 * NDTPA_INTERVAL_PROBE_TIME_MS, an NLA_U64, to nl_ntbl_parm_ms_range: 1000
 * through 86400000 since 7a71343ba1a6, and answers any other value -ERANGE.
 */
#define NTBL_PARM_MS_MIN	1000u
#define NTBL_PARM_MS_MAX	86400000u

/* The interval at which neigh_managed_work() runs often. */
#define SHORT_INTERVAL_MS	10000u

struct probe_interval {
	unsigned int seen;		/* the attribute, inside an NDTA_PARMS */
	unsigned int exact;		/* of eight bytes */
	unsigned int below, above;	/* under nl_ntbl_parm_ms_range, and over it */
	unsigned int short_ms;		/* in it, and up to SHORT_INTERVAL_MS */
};

/* The children of one NDTA_PARMS, the policy's NDTPA_* attributes. */
static void tally_parms(struct probe_interval *t, const unsigned char *p,
			size_t len)
{
	const struct nlattr *nla;

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);
		uint64_t v;

		if ((nla->nla_type & NLA_TYPE_MASK) == NDTPA_INTERVAL_PROBE_TIME_MS) {
			t->seen++;
			if (!(nla->nla_type & NLA_F_NESTED) &&
			    nla->nla_len == NLA_HDRLEN + sizeof(v)) {
				memcpy(&v, p + NLA_HDRLEN, sizeof(v));
				t->exact++;
				t->below += v < NTBL_PARM_MS_MIN;
				t->above += v > NTBL_PARM_MS_MAX;
				t->short_ms += v >= NTBL_PARM_MS_MIN &&
					       v <= SHORT_INTERVAL_MS;
			}
		}
		if (total > len)
			break;
		p += total;
		len -= total;
	}
}

/* The probe interval among the NDTPA_* attributes of an RTM_*NEIGHTBL request. */
static void tally_probe_interval(struct probe_interval *t,
				 const struct nlmsghdr *nlh)
{
	const unsigned char *p = (const unsigned char *) nlh +
				 NLMSG_SPACE(sizeof(struct ndtmsg));
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct ndtmsg)))
		return;
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct ndtmsg));

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == NDTA_PARMS)
			tally_parms(t, p + NLA_HDRLEN, nla->nla_len - NLA_HDRLEN);
		if (total > len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * The builder draws the interval from nl_ntbl_parm_ms_range seven times in
 * eight, and random bytes the eighth, which land in it about once in 2^38 and
 * over it the rest of the time.  Half of the draws in range are up to ten
 * seconds, where neigh_managed_work() reruns often.  None is under the floor,
 * which a draw from the range the policy had before 7a71343ba1a6 would be.
 */
static void expect_probe_interval(const struct probe_interval *t)
{
	const char *name = "NDTPA_INTERVAL_PROBE_TIME_MS";

	expect_fraction(t->exact, t->seen, 0.99, 1.0, name,
			"rtnl: the probe interval is not eight bytes");
	expect_fraction(t->exact - t->below - t->above, t->exact, 0.75, 0.95, name,
			"rtnl: the probe interval is not mostly in the policy's range");
	expect_fraction(t->below, t->exact, 0.0, 0.001, name,
			"rtnl: the probe interval is under the policy's floor");
	expect_fraction(t->short_ms, t->exact, 0.30, 0.55, name,
			"rtnl: the probe interval is not often a short one");
}

/* ---------- The types no kernel handler takes ---------------------------- */

#ifndef RTM_GETLINKPROP
#define RTM_GETLINKPROP		110
#endif

/*
 * The types the kernel only sends, as replies or notifications, and the two
 * it has never registered: rtnetlink_rcv_msg() finds no handler for them
 * and answers -EOPNOTSUPP whatever they carry.  Only the random type in 20
 * names one, about once in 160000 messages.
 */
static bool unhandled(unsigned short type)
{
	switch (type) {
	case RTM_NEWPREFIX:
	case RTM_NEWNDUSEROPT:
	case RTM_NEWNEIGHTBL:
	case RTM_NEWNETCONF:
	case RTM_NEWSTATS:
	case RTM_NEWNEXTHOPBUCKET:
	case RTM_DELNEXTHOPBUCKET:
	case RTM_GETLINKPROP:
		return true;
	default:
		return false;
	}
}

static void expect_handled_types(unsigned int unhandled_msgs, unsigned int msgs)
{
	expect_fraction(unhandled_msgs, msgs, 0.0, 0.001, "rtnl types",
			"rtnl: a type no kernel handler takes is drawn from the table");
}

/* ---------- The dump bits of a GET -------------------------------------- */

/*
 * rtnetlink_rcv_msg() routes a GET to its dumpit on either dump bit and
 * answers -EOPNOTSUPP to one routed to a handler the type does not have,
 * under the request's family or PF_UNSPEC.  These GETs have only a dumpit
 * under every family; RTM_GETDCB has only a doit.
 */
static bool dumpit_only(unsigned short type)
{
	switch (type) {
	case RTM_GETNEIGHTBL:
	case RTM_GETRULE:
	case RTM_GETMULTICAST:
	case RTM_GETANYCAST:
	case RTM_GETVLAN:
	case RTM_GETTUNNEL:
		return true;
	default:
		return false;
	}
}

struct dump_bits {
	unsigned int msgs;
	unsigned int dumps;	/* routed to the dumpit */
};

static void tally_dump_bits(struct dump_bits *t, const struct nlmsghdr *nlh)
{
	t->msgs++;
	t->dumps += (nlh->nlmsg_flags & NLM_F_DUMP) != 0;
}

/*
 * Only the chaos message in ten keeps a random flags word, which holds
 * neither dump bit a quarter of the time and one or both the rest, so
 * 0.025 of the dumpit-only GETs' requests and 0.075 of RTM_GETDCB's are
 * routed to the handler the type lacks.  The other GETs have both handlers,
 * under some family at least, and are left to the draw: NLM_F_DUMP half the
 * time, and the NEW and DELETE modifiers, which no GET's doit reads and
 * which set one dump bit or both 27 times in 32, one time in eight, so 0.57
 * of their requests go to the dumpit.  Over thousands of requests the
 * bounds are many standard deviations out.
 */
static void expect_dump_bits(const struct dump_bits *dumps,
			     const struct dump_bits *dcb,
			     const struct dump_bits *both)
{
	expect_fraction(dumps->dumps, dumps->msgs, 0.96, 1.0,
			"the dumpit-only GETs",
			"rtnl: a GET with only a dumpit is sent without NLM_F_DUMP");
	expect_fraction(dcb->dumps, dcb->msgs, 0.0, 0.12, "RTM_GETDCB",
			"rtnl: RTM_GETDCB, which has only a doit, is sent a dump bit");
	expect_fraction(both->dumps, both->msgs, 0.50, 0.65, "the other GETs",
			"rtnl: a GET with both handlers seldom reaches its doit");
}

/* ---------- The rtmsg of RTM_NEWROUTE and RTM_DELROUTE ------------------ */

struct route_header {
	unsigned int v4, v4_tos, v4_len;	/* AF_INET; ECN bits clear; prefix <= 32 */
	unsigned int v4_scope;			/* ... a type and a scope the fib takes */
	unsigned int v4_flags;			/* ... neither DEAD nor LINKDOWN */
	unsigned int v6, v6_tos;		/* AF_INET6; tos 0 */
	unsigned int v6_type, v6_flags;		/* ... type <= RTN_MAX; not CLONED */
	unsigned int v6_src;			/* ... no source prefix */
};

/* fib_props[]'s scopes: the narrowest a route of each type may have. */
static const unsigned char fib_type_scope[RTN_MAX + 1] = {
	[RTN_UNSPEC]		= RT_SCOPE_NOWHERE,
	[RTN_UNICAST]		= RT_SCOPE_UNIVERSE,
	[RTN_LOCAL]		= RT_SCOPE_HOST,
	[RTN_BROADCAST]		= RT_SCOPE_LINK,
	[RTN_ANYCAST]		= RT_SCOPE_LINK,
	[RTN_MULTICAST]		= RT_SCOPE_UNIVERSE,
	[RTN_BLACKHOLE]		= RT_SCOPE_UNIVERSE,
	[RTN_UNREACHABLE]	= RT_SCOPE_UNIVERSE,
	[RTN_PROHIBIT]		= RT_SCOPE_UNIVERSE,
	[RTN_THROW]		= RT_SCOPE_UNIVERSE,
	[RTN_NAT]		= RT_SCOPE_NOWHERE,
	[RTN_XRESOLVE]		= RT_SCOPE_NOWHERE,
};

static void tally_route_header(struct route_header *t, const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = NLMSG_DATA(nlh);

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*rtm)))
		return;
	if (rtm->rtm_family == AF_INET) {
		t->v4++;
		t->v4_tos += !(rtm->rtm_tos & 0x03);
		t->v4_len += rtm->rtm_dst_len <= 32;
		t->v4_scope += rtm->rtm_type <= RTN_MAX &&
			       rtm->rtm_scope >= fib_type_scope[rtm->rtm_type] &&
			       rtm->rtm_scope <= RT_SCOPE_HOST;
		t->v4_flags += !(rtm->rtm_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN));
	} else if (rtm->rtm_family == AF_INET6) {
		t->v6++;
		t->v6_tos += rtm->rtm_tos == 0;
		t->v6_type += rtm->rtm_type <= RTN_MAX;
		t->v6_flags += !(rtm->rtm_flags & RTM_F_CLONED);
		t->v6_src += rtm->rtm_src_len == 0;
	}
}

/*
 * rtm_to_fib_config() refuses an IPv4 route whose tos has an ECN bit set or
 * whose prefix is longer than 32 bits, and rtm_to_fib6_config() an IPv6 one
 * with any tos, before either reads an attribute.  The builder keeps a
 * random rtmsg one time in eight and holds the rest to that, so about 0.91
 * of the IPv4 routes clear each check and 0.88 of the IPv6 ones the tos;
 * random fields cleared them a quarter of the time and one time in 256.
 * fib_create_info() refuses an IPv4 route whose type is past RTN_MAX, whose
 * scope is narrower than its type's fib_props[] one or wider than host, or
 * whose flags hold DEAD or LINKDOWN, and fib6_config_validate() an IPv6 one
 * whose type is past RTN_MAX or whose flags hold RTM_F_CLONED, which sets
 * RTF_CACHE.  About 0.91 of the IPv4 routes clear the first two, and 0.94
 * of the IPv6 ones each of theirs; random fields cleared them a quarter,
 * a quarter, a half and a half of the time.  Without CONFIG_IPV6_SUBTREES,
 * fib6_config_validate() also refuses an IPv6 route with a source prefix,
 * which about 0.44 of them leave out, so a kernel with subtrees still sees
 * source-specific routes; a random length left it out one time in 129.
 */
static void expect_route_header(const struct route_header *t)
{
	expect_fraction(t->v4_tos, t->v4, 0.82, 0.97, "IPv4 route tos",
			"rtnl: an IPv4 route's tos mostly carries the ECN bits rtm_to_fib_config() refuses");
	expect_fraction(t->v4_len, t->v4, 0.82, 0.97, "IPv4 route prefix",
			"rtnl: an IPv4 route's prefix is mostly longer than 32 bits");
	expect_fraction(t->v6_tos, t->v6, 0.80, 0.95, "IPv6 route tos",
			"rtnl: an IPv6 route mostly carries the tos rtm_to_fib6_config() refuses");
	expect_fraction(t->v4_scope, t->v4, 0.84, 0.97, "IPv4 route type and scope",
			"rtnl: an IPv4 route's type and scope are mostly ones fib_create_info() refuses");
	expect_fraction(t->v4_flags, t->v4, 0.84, 0.97, "IPv4 route flags",
			"rtnl: an IPv4 route's flags mostly hold the DEAD or LINKDOWN fib_create_info() refuses");
	expect_fraction(t->v6_type, t->v6, 0.88, 0.99, "IPv6 route type",
			"rtnl: an IPv6 route's type is mostly past the RTN_MAX fib6_config_validate() refuses");
	expect_fraction(t->v6_flags, t->v6, 0.88, 0.99, "IPv6 route flags",
			"rtnl: an IPv6 route's flags mostly hold the RTM_F_CLONED fib6_config_validate() refuses");
	expect_fraction(t->v6_src, t->v6, 0.38, 0.50, "IPv6 route source prefix",
			"rtnl: an IPv6 route does not leave out the source prefix a kernel without subtrees refuses about half the time");
}

/* ---------- An IPv4 route's RTA_DST under its rtm_dst_len -------------- */

struct route_dst {
	unsigned int prefixed;	/* IPv4, a prefix under 32 bits, an RTA_DST */
	unsigned int held;	/* ... every RTA_DST inside the prefix */
};

static void tally_route_dst(struct route_dst *t, const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = NLMSG_DATA(nlh);
	const struct rtattr *rta;
	unsigned int dsts = 0, inside = 0;
	int len;

	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*rtm)) ||
	    rtm->rtm_family != AF_INET || rtm->rtm_dst_len >= 32)
		return;
	len = (int) (nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm)));
	for (rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		uint32_t dst;

		if ((rta->rta_type & NLA_TYPE_MASK) != RTA_DST ||
		    RTA_PAYLOAD(rta) < sizeof(dst))
			continue;
		memcpy(&dst, RTA_DATA(rta), sizeof(dst));
		dsts++;
		inside += (uint32_t) (ntohl(dst) << rtm->rtm_dst_len) == 0;
	}
	if (dsts == 0)
		return;
	t->prefixed++;
	t->held += inside == dsts;
}

/*
 * rtm_to_fib_config() refuses an IPv4 route add or delete whose RTA_DST has
 * a bit set past rtm_dst_len, which a random address under a short prefix
 * nearly always has.  Once the attributes are in, the builder cuts each
 * RTA_DST of such a route to its prefix seven times in eight
 * (cuts_route_dsts_to_their_prefix() holds it to the rate); the rounds draw
 * a few hundred of them, enough to show the cut is made.
 */
static void expect_route_dst(const struct route_dst *t)
{
	if (t->prefixed < 100 || t->held * 2 < t->prefixed) {
		fprintf(stderr, "IPv4 route RTA_DST: %u of %u inside the prefix\n",
			t->held, t->prefixed);
		BUG("rtnl: a built IPv4 route's RTA_DST is mostly outside its prefix");
	}
}

/* Two RTA_DSTs of all ones in a route message of @type, @family and
 * @dst_len, through mask_route_dst(): 1 when both come back cut to the
 * prefix with its bits kept, 0 when both come back whole, -1 otherwise. */
static int cut_route(unsigned short type, unsigned char family,
		     unsigned int dst_len)
{
	static unsigned char buf[NLMSG_SPACE(sizeof(struct rtmsg)) + 2 * RTA_SPACE(4)];
	struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	const uint32_t ones = 0xffffffffU;
	uint32_t prefix, dst;
	unsigned int cut = 0, whole = 0, i;
	struct rtattr *rta;
	int len;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = sizeof(buf);
	rtm->rtm_family = family;
	rtm->rtm_dst_len = dst_len;
	for (i = 0; i < 2; i++) {
		rta = (struct rtattr *) ((char *) RTM_RTA(rtm) + i * RTA_SPACE(sizeof(ones)));
		rta->rta_type = RTA_DST;
		rta->rta_len = RTA_LENGTH(sizeof(ones));
		memcpy(RTA_DATA(rta), &ones, sizeof(ones));
	}
	mask_route_dst(nlh, sizeof(buf));

	prefix = dst_len < 32 ? htonl(~(0xffffffffU >> dst_len)) : ones;
	len = (int) (sizeof(buf) - NLMSG_LENGTH(sizeof(*rtm)));
	for (rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		memcpy(&dst, RTA_DATA(rta), sizeof(dst));
		whole += dst == ones;
		cut += dst != ones && dst == prefix;
	}
	return cut == 2 ? 1 : whole == 2 ? 0 : -1;
}

/* mask_route_dst() cuts both RTA_DSTs of an IPv4 add or delete with a
 * prefix under 32 bits seven times in eight, and no RTA_DST of a route the
 * kernel takes whole: a GET, an IPv6 one, one with a 32-bit prefix. */
static void cuts_route_dsts_to_their_prefix(void)
{
	unsigned int i, cut = 0;
	int r;

	for (i = 0; i < ENTRIES; i++) {
		r = cut_route(i % 2 ? RTM_NEWROUTE : RTM_DELROUTE, AF_INET, i % 32);
		if (r < 0)
			BUG("rtnl: an IPv4 route's RTA_DSTs were cut apart, or past the prefix");
		cut += r;
		if (cut_route(RTM_GETROUTE, AF_INET, i % 32) != 0 ||
		    cut_route(RTM_NEWROUTE, AF_INET6, i % 32) != 0 ||
		    cut_route(RTM_NEWROUTE, AF_INET, 32) != 0)
			BUG("rtnl: an RTA_DST was cut where the kernel takes it whole");
	}
	expect_fraction(cut, ENTRIES, 0.84, 0.91, "IPv4 route RTA_DST cuts",
			"rtnl: an IPv4 route's RTA_DSTs are not cut to its prefix seven times in eight");
}

/* ---------- RTA_FLOWLABEL ---------------------------------------------- */

struct route_flowlabel {
	unsigned int changes;	/* RTM_NEWROUTE and RTM_DELROUTE requests */
	unsigned int labelled;	/* ... carrying an RTA_FLOWLABEL */
};

static void tally_route_flowlabel(struct route_flowlabel *t,
				  const struct nlmsghdr *nlh)
{
	const unsigned char *p;
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct rtmsg)))
		return;
	t->changes++;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct rtmsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct rtmsg));
	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == RTA_FLOWLABEL) {
			t->labelled++;
			return;
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * rtm_to_fib6_config() refuses an IPv6 route add or delete that carries an
 * RTA_FLOWLABEL at all, and rtm_to_fib_config() ignores one, so only a
 * GETROUTE reads it.  The builder draws the type again when an add or a
 * delete drew it, all but one time in eight, so about 0.02 of them carry
 * one, where 0.12 did.
 */
static void expect_route_flowlabel(const struct route_flowlabel *t)
{
	expect_fraction(t->labelled, t->changes, 0.0, 0.05,
			"route add or delete with RTA_FLOWLABEL",
			"rtnl: a route add or delete carries the RTA_FLOWLABEL rtm_to_fib6_config() refuses");
}

/*
 * A strict IPv6 GETROUTE refuses a flow label with a bit set outside
 * IPV6_FLOWLABEL_MASK, the low 20 bits of the big-endian word, so about
 * 0.88 of the labels are inside it, where one in 4096 was.
 */
static void draws_flowlabels_inside_the_mask(void)
{
	static unsigned char buf[16];
	unsigned int i, inside = 0;

	for (i = 0; i < ENTRIES; i++) {
		uint32_t label;

		if (gen_rta_route_payload(buf, sizeof(buf), RTA_FLOWLABEL,
					  AF_INET6) != sizeof(label))
			BUG("rtnl: an RTA_FLOWLABEL payload is not four bytes");
		memcpy(&label, buf, sizeof(label));
		inside += !(ntohl(label) & ~0x000fffffu);
	}
	expect_fraction(inside, ENTRIES, 0.82, 0.93, "RTA_FLOWLABEL",
			"rtnl: a flow label is mostly outside IPV6_FLOWLABEL_MASK");
}

/* ---------- The RTA_ENCAP_TYPE of RTM_NEWROUTE, DELROUTE and GETROUTE --- */

struct route_encap {
	unsigned int types;	/* RTA_ENCAP_TYPEs of two bytes */
	unsigned int kinds;	/* ... naming LWTUNNEL_ENCAP_MPLS to _MAX */
	unsigned int protos;	/* an IPv4 or IPv6 route's one-byte RTA_IP_PROTOs */
	unsigned int protos_taken;	/* ... rtm_getroute_parse_ip_proto() takes */
};

/* rtm_getroute_parse_ip_proto(): TCP, UDP and the family's ICMP. */
static bool getroute_takes_proto(uint8_t proto, uint8_t family)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return true;
	case IPPROTO_ICMP:
		return family == AF_INET;
	case IPPROTO_ICMPV6:
		return family == AF_INET6;
	}
	return false;
}

static void tally_route_encap(struct route_encap *t, const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = NLMSG_DATA(nlh);
	const unsigned char *p;
	const struct nlattr *nla;
	bool inet;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct rtmsg)))
		return;
	inet = rtm->rtm_family == AF_INET || rtm->rtm_family == AF_INET6;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct rtmsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct rtmsg));
	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == RTA_ENCAP_TYPE &&
		    nla->nla_len == NLA_HDRLEN + sizeof(uint16_t)) {
			uint16_t type;

			memcpy(&type, p + NLA_HDRLEN, sizeof(type));
			t->types++;
			t->kinds += type > LWTUNNEL_ENCAP_NONE &&
				    type <= LWTUNNEL_ENCAP_MAX;
		}
		if (inet && (nla->nla_type & NLA_TYPE_MASK) == RTA_IP_PROTO &&
		    nla->nla_len == NLA_HDRLEN + sizeof(uint8_t)) {
			uint8_t proto = p[NLA_HDRLEN];

			t->protos++;
			t->protos_taken += getroute_takes_proto(proto,
								rtm->rtm_family);
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * rtm_to_fib_config() and rtm_to_fib6_config() hand RTA_ENCAP_TYPE to
 * lwtunnel_valid_encap_type(), which refuses LWTUNNEL_ENCAP_NONE and
 * anything past LWTUNNEL_ENCAP_MAX, and the request with it.  The builder
 * draws the type from NONE to MAX, as it does NHA_ENCAP_TYPE, so all but
 * the one draw in LWTUNNEL_ENCAP_MAX + 1 that is NONE name an encap kind;
 * a random 16-bit type named one ten times in 65536.  Over the thousands
 * of types the bounds are many standard deviations out.
 *
 * inet_rtm_getroute() and inet6_rtm_getroute() refuse the request for an
 * RTA_IP_PROTO but TCP, UDP and the family's ICMP.  The builder draws TCP or
 * UDP five times in eight and the family's ICMP two, and a random byte the
 * eighth, so about 0.88 of an IPv4 or IPv6 route's protocols are ones a
 * GETROUTE would have taken (the other two types ignore the attribute, and
 * share the draw so the rounds see enough of them); a random byte was
 * three times in 256.
 */
static void expect_route_encap(const struct route_encap *t)
{
	expect_fraction(t->kinds, t->types, 0.80, 0.97, "RTA_ENCAP_TYPE",
			"rtnl: a route's RTA_ENCAP_TYPE names no encap kind lwtunnel_valid_encap_type() takes");
	expect_fraction(t->protos_taken, t->protos, 0.80, 0.95, "RTA_IP_PROTO",
			"rtnl: a route's RTA_IP_PROTO is mostly one rtm_getroute_parse_ip_proto() refuses");
}

/* ---------- The RTA_ENCAP of RTM_NEWROUTE, DELROUTE and GETROUTE -------- */

/* The fd the stand-in typed pick answers for a program of each type. */
static int lwt_prog_fd(unsigned int prog_type)
{
	return 100 + prog_type;
}

/* The last attribute of type in the chain at p, the one a parse keeps. */
static const struct nlattr *last_attr(const unsigned char *p, size_t len,
				      unsigned short type)
{
	const struct nlattr *nla, *last = NULL;

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			last = nla;
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	return last;
}

/*
 * bpf_parse_prog(): an LWT_BPF_PROG_FD naming a program of the hook's type
 * and an LWT_BPF_PROG_NAME, an NLA_NUL_STRING of up to MAX_PROG_NAME (256)
 * bytes.
 */
static bool lwt_prog_taken(const struct nlattr *hook, unsigned int prog_type)
{
	const unsigned char *p = (const unsigned char *) hook + NLA_HDRLEN;
	size_t len = hook->nla_len - NLA_HDRLEN;
	const struct nlattr *fd = last_attr(p, len, LWT_BPF_PROG_FD);
	const struct nlattr *name = last_attr(p, len, LWT_BPF_PROG_NAME);
	const char *str;
	size_t slen;
	uint32_t val;

	if (fd == NULL || name == NULL || fd->nla_len < NLA_HDRLEN + sizeof(val))
		return false;
	str = (const char *) name + NLA_HDRLEN;
	slen = name->nla_len - NLA_HDRLEN;
	if (slen == 0 || memchr(str, '\0', slen < 257 ? slen : 257) == NULL ||
	    slen - (str[slen - 1] == '\0') > 256)
		return false;
	memcpy(&val, (const char *) fd + NLA_HDRLEN, sizeof(val));
	return val == (uint32_t) lwt_prog_fd(prog_type);
}

/*
 * bpf_build_state(): one or more of LWT_BPF_IN, OUT and XMIT, each taken by
 * bpf_parse_prog() for a program of BPF_PROG_TYPE_LWT_IN, _OUT or _XMIT,
 * and an XMIT_HEADROOM of at most LWT_BPF_MAX_HEADROOM.
 */
static bool lwt_bpf_encap_taken(const struct nlattr *encap)
{
	static const struct {
		unsigned short attr;
		unsigned int prog_type;
	} hooks[] = {
		{ LWT_BPF_IN, BPF_PROG_TYPE_LWT_IN },
		{ LWT_BPF_OUT, BPF_PROG_TYPE_LWT_OUT },
		{ LWT_BPF_XMIT, BPF_PROG_TYPE_LWT_XMIT },
	};
	const unsigned char *p = (const unsigned char *) encap + NLA_HDRLEN;
	size_t len = encap->nla_len - NLA_HDRLEN;
	const struct nlattr *headroom;
	unsigned int i, hooked = 0;
	uint32_t room;

	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		const struct nlattr *hook = last_attr(p, len, hooks[i].attr);

		if (hook == NULL)
			continue;
		if (!lwt_prog_taken(hook, hooks[i].prog_type))
			return false;
		hooked++;
	}
	headroom = last_attr(p, len, LWT_BPF_XMIT_HEADROOM);
	if (headroom != NULL) {
		if (headroom->nla_len < NLA_HDRLEN + sizeof(room))
			return false;
		memcpy(&room, (const char *) headroom + NLA_HDRLEN, sizeof(room));
		if (room > LWT_BPF_MAX_HEADROOM)
			return false;
	}
	return hooked > 0;
}

struct lwt_encap {
	unsigned int encaps;	/* routes with an RTA_ENCAP */
	unsigned int bpf;	/* ... and LWTUNNEL_ENCAP_BPF the type in force */
	unsigned int taken;	/* ... whose nest bpf_build_state() takes */
};

static void tally_lwt_encap(struct lwt_encap *t, const struct nlmsghdr *nlh)
{
	const struct nlattr *encap, *type;
	const unsigned char *p;
	uint16_t kind;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct rtmsg)))
		return;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct rtmsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct rtmsg));
	encap = last_attr(p, len, RTA_ENCAP);
	if (encap == NULL)
		return;
	t->encaps++;
	type = last_attr(p, len, RTA_ENCAP_TYPE);
	if (type == NULL || type->nla_len < NLA_HDRLEN + sizeof(kind))
		return;
	memcpy(&kind, (const char *) type + NLA_HDRLEN, sizeof(kind));
	if (kind != LWTUNNEL_ENCAP_BPF)
		return;
	t->bpf++;
	t->taken += lwt_bpf_encap_taken(encap);
}

/*
 * lwtunnel_build_state() hands a route's RTA_ENCAP to the build_state() of
 * the kind RTA_ENCAP_TYPE names, a parse keeping the last of each, so the
 * builder sends the two together, the kind LWTUNNEL_ENCAP_BPF seven times
 * in eight.  A lone RTA_ENCAP_TYPE drawn later in the request now and then
 * names another kind, so about 0.86 of the routes with an encap have BPF in
 * force.  bpf_build_state() wants one or more of the three hooks, each
 * naming a program of its own type, which the builder does seven times in
 * eight with the fd the stand-in typed pick answers, and any program the
 * eighth (none here); it adds an XMIT_HEADROOM half the time, past
 * LWT_BPF_MAX_HEADROOM one time in eight, so about 0.75 of the BPF nests
 * are taken.  Random bytes in RTA_ENCAP never were.
 */
static void expect_lwt_encap(const struct lwt_encap *t)
{
	expect_fraction(t->bpf, t->encaps, 0.75, 0.95, "RTA_ENCAP",
			"rtnl: a route's RTA_ENCAP is seldom beside an LWTUNNEL_ENCAP_BPF type");
	expect_fraction(t->taken, t->bpf, 0.65, 0.85, "LWTUNNEL_ENCAP_BPF nests",
			"rtnl: a route's BPF encap is seldom one bpf_build_state() takes");
}

/* ---------- The attributes of RTM_NEWACTION, DELACTION and GETACTION ---- */

struct action_attrs {
	unsigned int attrs;
	unsigned int tabs;	/* of type TCA_ROOT_TAB */
	unsigned int gacts;	/* actions in them of kind "gact" */
	unsigned int parms;	/* ... with a TCA_GACT_PARMS tcf_gact_init() takes */
	unsigned int indexed;	/* ... of those, naming index 1 to 8 */
	unsigned int probs;	/* ... and with a TCA_GACT_PROB it takes */
};

/* tcf_action_valid() and tcf_action_check_ctrlact(), with no filter for a
 * goto chain to name. */
static bool ctrlact_takes(int action)
{
	int opcode = TC_ACT_EXT_OPCODE(action);

	if (TC_ACT_EXT_CMP(action, TC_ACT_GOTO_CHAIN))
		return false;
	if (!opcode)
		return action <= TC_ACT_VALUE_MAX;
	return opcode <= TC_ACT_EXT_OPCODE_MAX || action == TC_ACT_UNSPEC;
}

/* The TCA_ACT_OPTIONS of one gact action, as tcf_gact_init() reads them. */
static void tally_gact_options(struct action_attrs *t, const unsigned char *p,
			       size_t len)
{
	const struct nlattr *nla;
	bool parms = false, prob = false;

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);
		const unsigned char *data = p + NLA_HDRLEN;

		switch (nla->nla_type & NLA_TYPE_MASK) {
		case TCA_GACT_PARMS:
			if (nla->nla_len >= NLA_HDRLEN + sizeof(struct tc_gact)) {
				struct tc_gact parm;

				memcpy(&parm, data, sizeof(parm));
				parms = ctrlact_takes(parm.action);
				t->indexed += parms && parm.index >= 1 &&
					      parm.index <= 8;
			}
			break;
		case TCA_GACT_PROB:
			if (nla->nla_len >= NLA_HDRLEN + sizeof(struct tc_gact_p)) {
				struct tc_gact_p pp;

				memcpy(&pp, data, sizeof(pp));
				prob = pp.ptype < MAX_RAND &&
				       ctrlact_takes(pp.paction);
			}
			break;
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	t->parms += parms;
	t->probs += parms && prob;
}

/* One action of a TCA_ROOT_TAB: its kind, and a gact's options. */
static void tally_tab_action(struct action_attrs *t, const unsigned char *p,
			     size_t len)
{
	const unsigned char *options = NULL;
	size_t options_len = 0;
	const struct nlattr *nla;
	bool gact = false;

	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);
		size_t plen = nla->nla_len - NLA_HDRLEN;

		switch (nla->nla_type & NLA_TYPE_MASK) {
		case TCA_ACT_KIND:
			gact = plen == sizeof("gact") &&
			       !memcmp(p + NLA_HDRLEN, "gact", sizeof("gact"));
			break;
		case TCA_ACT_OPTIONS:
			options = p + NLA_HDRLEN;
			options_len = plen;
			break;
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
	if (!gact)
		return;
	t->gacts++;
	if (options != NULL)
		tally_gact_options(t, options, options_len);
}

static void tally_tab(struct action_attrs *t, const unsigned char *p,
		      size_t len)
{
	const struct nlattr *act;

	while ((act = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(act->nla_len);

		tally_tab_action(t, p + NLA_HDRLEN, act->nla_len - NLA_HDRLEN);
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

static void tally_action_attrs(struct action_attrs *t, const struct nlmsghdr *nlh)
{
	const unsigned char *p;
	const struct nlattr *nla;
	size_t len;

	if (nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct tcamsg)))
		return;
	p = (const unsigned char *) nlh + NLMSG_SPACE(sizeof(struct tcamsg));
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct tcamsg));
	while ((nla = fit_attr(p, len)) != NULL) {
		size_t total = NLA_ALIGN(nla->nla_len);

		t->attrs++;
		if ((nla->nla_type & NLA_TYPE_MASK) == TCA_ROOT_TAB) {
			t->tabs++;
			tally_tab(t, p + NLA_HDRLEN, nla->nla_len - NLA_HDRLEN);
		}
		if (total >= len)
			break;
		p += total;
		len -= total;
	}
}

/*
 * tc_ctl_action() refuses a request without TCA_ACT_TAB, which is
 * TCA_ROOT_TAB, before it reads anything else, and tc_dump_action() finds
 * the kind to list in it.  An attribute takes the group's hint seven times
 * in eight, and the hint is one of the five TCA_ROOT_* types, so about
 * 0.18 of the attributes are TCA_ROOT_TAB; a random 16-bit type is that one
 * time in 65536.  Over the ninety thousand attributes the bounds are many
 * standard deviations out.
 *
 * tcf_gact_init() refuses a gact action without TCA_ACT_OPTIONS or without
 * a TCA_GACT_PARMS in them, and a TCA_GACT_PROB whose ptype is past
 * PGACT_DETERM or whose fallback verdict is no verdict or a goto chain;
 * the PARMS verdict goes to tcf_action_check_ctrlact(), which refuses a
 * goto chain on an action with no filter.  The builder gives every gact
 * action PARMS the kernel takes, unless the action outgrows its room,
 * naming index 1 to 8 three times in four, so a NLM_F_REPLACE can meet an
 * action an earlier call made, and adds a PROB it takes half the time.
 * Over the thousand or more gact actions the bounds are several standard
 * deviations out.
 */
static void expect_action_attrs(const struct action_attrs *t)
{
	expect_fraction(t->tabs, t->attrs, 0.12, 0.25, "RTM_*ACTION attributes",
			"rtnl: an action request almost never carries a TCA_ROOT_TAB");
	expect_fraction(t->parms, t->gacts, 0.90, 1.0, "gact actions",
			"rtnl: a gact action carries no TCA_GACT_PARMS tcf_gact_init() takes");
	expect_fraction(t->indexed, t->parms, 0.65, 0.85, "gact PARMS",
			"rtnl: a gact action does not name a small index three times in four");
	expect_fraction(t->probs, t->parms, 0.40, 0.60, "gact PROBs",
			"rtnl: a gact action does not carry a TCA_GACT_PROB half the time");
}

/* ---------- The rounds --------------------------------------------------- */

struct tallies {
	unsigned int msgs, unhandled;
	struct dump_bits dumps, dcb, both;
	struct link_header getlink, linkprop, link;
	struct addr_header getaddr, newdeladdr;
	struct neigh_header getneigh, newdelneigh;
	struct getneigh_attrs getneigh_attrs;
	struct nexthop_header newnexthop, nexthop;
	struct nexthop_flags nexthop_flags;
	struct nexthop_attrs nexthop_attrs[NH_OPS];
	struct nexthop_gateway nexthop_gateway;
	struct rule_header getrule, newdelrule;
	struct addrlabel_header getaddrlabel, newdeladdrlabel;
	struct stats_header getstats, setstats;
	struct bridge_header bridgeget, bridgenewdel;
	struct family_header netconf, neightbl;
	struct tunnel_attrs tunnel;
	struct addr_dump multicast, anycast;
	struct limit limits[ARRAY_SIZE(limit_types)];
	struct probe_interval probe_interval;
	struct route_header route_header;
	struct route_dst route_dst;
	struct route_encap route_encap;
	struct lwt_encap lwt_encap;
	struct route_flowlabel route_flowlabel;
	struct action_attrs action;
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

		t->msgs++;
		t->unhandled += unhandled(nlh->nlmsg_type);
		if (dumpit_only(nlh->nlmsg_type))
			tally_dump_bits(&t->dumps, nlh);
		else if (nlh->nlmsg_type == RTM_GETDCB)
			tally_dump_bits(&t->dcb, nlh);
		else if (nlh->nlmsg_type >= RTM_BASE &&
			 nlh->nlmsg_type < RTM_MAX &&
			 (nlh->nlmsg_type - RTM_BASE) % 4 == 2)	/* a GET */
			tally_dump_bits(&t->both, nlh);

		switch (nlh->nlmsg_type) {
		case RTM_GETADDR:
			tally_addr_header(&t->getaddr, nlh);
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
			tally_addr_header(&t->newdeladdr, nlh);
			break;
		case RTM_GETNEIGH:
			tally_neigh_header(&t->getneigh, nlh);
			tally_getneigh_attrs(&t->getneigh_attrs, nlh);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			tally_neigh_header(&t->newdelneigh, nlh);
			break;
		case RTM_GETRULE:
			tally_rule_header(&t->getrule, nlh, true);
			break;
		case RTM_GETADDRLABEL:
			tally_addrlabel_header(&t->getaddrlabel, nlh);
			break;
		case RTM_GETSTATS:
			tally_stats_header(&t->getstats, nlh, false);
			break;
		case RTM_GETNETCONF:
			tally_family(&t->netconf, nlh, netconf_families,
				     ARRAY_SIZE(netconf_families));
			break;
		case RTM_GETMDB:
			tally_bridge_header(&t->bridgeget, nlh, true);
			break;
		case RTM_GETVLAN:
			tally_bridge_header(&t->bridgeget, nlh, false);
			break;
		case RTM_NEWMDB:
		case RTM_DELMDB:
			tally_bridge_header(&t->bridgenewdel, nlh, true);
			break;
		case RTM_NEWVLAN:
		case RTM_DELVLAN:
			tally_bridge_header(&t->bridgenewdel, nlh, false);
			break;
		case RTM_SETSTATS:
			tally_stats_header(&t->setstats, nlh, true);
			break;
		case RTM_NEWADDRLABEL:
		case RTM_DELADDRLABEL:
			tally_addrlabel_header(&t->newdeladdrlabel, nlh);
			break;
		case RTM_NEWRULE:
		case RTM_DELRULE:
			tally_rule_header(&t->newdelrule, nlh, false);
			break;
		case RTM_NEWNEXTHOP:
			tally_nexthop_header(&t->newnexthop, nlh, true);
			tally_nexthop_flags(&t->nexthop_flags, nlh);
			tally_nexthop_attrs(t->nexthop_attrs, nlh);
			tally_nexthop_gateway(&t->nexthop_gateway, nlh);
			break;
		case RTM_DELNEXTHOP:
		case RTM_GETNEXTHOP:
		case RTM_GETNEXTHOPBUCKET:
			tally_nexthop_header(&t->nexthop, nlh, false);
			tally_nexthop_flags(&t->nexthop_flags, nlh);
			tally_nexthop_attrs(t->nexthop_attrs, nlh);
			break;
		case RTM_NEWTUNNEL:
		case RTM_DELTUNNEL:
		case RTM_GETTUNNEL:
			tally_tunnel_attrs(&t->tunnel, nlh);
			break;
		case RTM_GETMULTICAST:
			tally_addr_dump(&t->multicast, nlh);
			break;
		case RTM_GETANYCAST:
			tally_addr_dump(&t->anycast, nlh);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
		case RTM_GETLINK:
		case RTM_SETLINK:
			tally_link_header(nlh->nlmsg_type == RTM_GETLINK ?
					  &t->getlink : &t->link, nlh);
			tally_link_limits(t->limits, nlh);
			break;
		case RTM_NEWLINKPROP:
		case RTM_DELLINKPROP:
			tally_link_header(&t->linkprop, nlh);
			break;
		case RTM_GETNEIGHTBL:
		case RTM_SETNEIGHTBL:
			tally_probe_interval(&t->probe_interval, nlh);
			tally_family(&t->neightbl, nlh, neightbl_families,
				     ARRAY_SIZE(neightbl_families));
			break;
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			tally_route_header(&t->route_header, nlh);
			tally_route_dst(&t->route_dst, nlh);
			tally_route_encap(&t->route_encap, nlh);
			tally_lwt_encap(&t->lwt_encap, nlh);
			tally_route_flowlabel(&t->route_flowlabel, nlh);
			break;
		case RTM_GETROUTE:
			tally_route_encap(&t->route_encap, nlh);
			tally_lwt_encap(&t->lwt_encap, nlh);
			break;
		case RTM_NEWACTION:
		case RTM_DELACTION:
		case RTM_GETACTION:
			tally_action_attrs(&t->action, nlh);
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

	fake_get_rand_bpf_prog_fd_of_type = lwt_prog_fd;
	run_rounds(&t);
	fake_get_rand_bpf_prog_fd_of_type = NULL;
	expect_handled_types(t.unhandled, t.msgs);
	expect_dump_bits(&t.dumps, &t.dcb, &t.both);
	expect_link_header(&t.getlink, &t.linkprop, &t.link);
	expect_addr_header(&t.getaddr, &t.newdeladdr);
	expect_neigh_header(&t.getneigh, &t.newdelneigh);
	expect_getneigh_attrs(&t.getneigh_attrs);
	expect_nexthop_header(&t.newnexthop, &t.nexthop);
	expect_nexthop_flags(&t.nexthop_flags);
	expect_nexthop_attrs(t.nexthop_attrs);
	expect_nexthop_gateway(&t.nexthop_gateway);
	expect_rule_header(&t.getrule, &t.newdelrule);
	expect_addrlabel_header(&t.getaddrlabel, &t.newdeladdrlabel);
	expect_stats_header(&t.getstats, &t.setstats);
	expect_bridge_header(&t.bridgeget, &t.bridgenewdel);
	expect_family_headers(&t.netconf, &t.neightbl);
	expect_tunnel_attrs(&t.tunnel);
	builds_vni_entries_the_policy_takes();
	expect_addr_dump(&t.multicast, true, "RTM_GETMULTICAST");
	expect_addr_dump(&t.anycast, false, "RTM_GETANYCAST");
	expect_link_limits(t.limits);
	expect_probe_interval(&t.probe_interval);
	expect_route_header(&t.route_header);
	expect_route_dst(&t.route_dst);
	cuts_route_dsts_to_their_prefix();
	expect_route_encap(&t.route_encap);
	expect_lwt_encap(&t.lwt_encap);
	expect_route_flowlabel(&t.route_flowlabel);
	draws_flowlabels_inside_the_mask();
	expect_action_attrs(&t.action);
}
