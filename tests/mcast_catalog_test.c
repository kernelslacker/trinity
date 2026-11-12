/*
 * Self-check for the multicast membership rows of the setsockopt catalog: a
 * filled ip_mreqn, ip_mreq_source, ipv6_mreq, group_req or group_source_req
 * names a multicast group on a device every network namespace has, ifindex 0
 * (the group's route) or 1 (lo), or an unset or loopback address, so
 * ip_mc_find_dev() and ip6_mc_find_dev() find one; and a group_req or
 * group_source_req carries the family its level reads.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include "args-internal.h"	/* struct_fill_passes */
#include "debug.h"		/* BUG */
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

#define MCAST_ROUNDS	64

extern bool fake_catalog_lookup;	/* fake_stubs.c */

/* An ifindex of 0 or 1, seen both ways over the rounds. */
static void note_ifindex(bool seen[2], unsigned int ifindex, const char *what)
{
	if (ifindex > 1)
		BUG(what);
	seen[ifindex] = true;
}

/* An interface address that is unset or lo's, seen both ways. */
static void note_iface(bool seen[2], in_addr_t addr, const char *what)
{
	if (addr == htonl(INADDR_ANY))
		seen[0] = true;
	else if (addr == htonl(INADDR_LOOPBACK))
		seen[1] = true;
	else
		BUG(what);
}

/* A group sockaddr: @family, and a multicast address of it. */
static void check_group(const struct sockaddr_storage *ss, int family,
			const char *what)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *) ss;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) ss;

	if (ss->ss_family != family)
		BUG(what);
	if (family == AF_INET ? !IN_MULTICAST(ntohl(sin->sin_addr.s_addr)) :
				!IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
		BUG(what);
}

/*
 * The MCAST_* rows of each level, whose sockaddrs the catalog fills through
 * the embedded rows fake_stubs.c holds: every one of them of the family that
 * level reads, which the other level refuses.
 */
static void check_group_rows(void)
{
	static const struct {
		int family;
		const struct struct_field *gr, *gsr;
	} levels[] = {
		{ AF_INET, group_req_ip_fields, group_source_req_ip_fields },
		{ AF_INET6, group_req_ipv6_fields, group_source_req_ipv6_fields },
	};
	bool seen[ARRAY_SIZE(levels)][2] = { { false } };
	unsigned int i, l;

	fake_catalog_lookup = true;
	for (i = 0; i < MCAST_ROUNDS; i++) {
		for (l = 0; l < ARRAY_SIZE(levels); l++) {
			struct group_req gr;
			struct group_source_req gsr;

			memset(&gr, 0, sizeof(gr));
			struct_fill_passes((unsigned char *) &gr, sizeof(gr),
					   levels[l].gr, GROUP_REQ_FIELDS_N,
					   NULL);
			note_ifindex(seen[l], gr.gr_interface,
				     "group_req: the ifindex names no device every netns has");
			check_group(&gr.gr_group, levels[l].family,
				    "group_req: the group is not a multicast address of the level's family");

			memset(&gsr, 0, sizeof(gsr));
			struct_fill_passes((unsigned char *) &gsr, sizeof(gsr),
					   levels[l].gsr,
					   GROUP_SOURCE_REQ_FIELDS_N, NULL);
			note_ifindex(seen[l], gsr.gsr_interface,
				     "group_source_req: the ifindex names no device every netns has");
			check_group(&gsr.gsr_group, levels[l].family,
				    "group_source_req: the group is not a multicast address of the level's family");
			if (gsr.gsr_source.ss_family != levels[l].family)
				BUG("group_source_req: the source is not of the level's family");
		}
	}
	fake_catalog_lookup = false;

	for (l = 0; l < ARRAY_SIZE(levels); l++) {
		if (!seen[l][0] || !seen[l][1])
			BUG("group rows: an ifindex never names the route's device or lo");
	}
}

void mcast_catalog_self_check(void);
void mcast_catalog_self_check(void)
{
	bool seen4[2] = { false, false }, seen6[2] = { false, false };
	bool addr4[2] = { false, false }, src_iface[2] = { false, false };
	unsigned int i;

	for (i = 0; i < MCAST_ROUNDS; i++) {
		struct ip_mreqn mr;
		struct ip_mreq_source ms;
		struct ipv6_mreq m6;

		memset(&mr, 0, sizeof(mr));
		struct_fill_passes((unsigned char *) &mr, sizeof(mr),
				   ip_mreqn_fields, IP_MREQN_FIELDS_N, NULL);
		if (!IN_MULTICAST(ntohl(mr.imr_multiaddr.s_addr)))
			BUG("ip_mreqn: the group is not multicast");
		note_ifindex(seen4, (unsigned int) mr.imr_ifindex,
			     "ip_mreqn: the ifindex names no device every netns has");
		/* With no ifindex, the address picks the device: lo's or none. */
		note_iface(addr4, mr.imr_address.s_addr,
			   "ip_mreqn: the address is neither unset nor lo's");

		/* The source ops have no ifindex: imr_interface picks alone. */
		memset(&ms, 0, sizeof(ms));
		struct_fill_passes((unsigned char *) &ms, sizeof(ms),
				   ip_mreq_source_fields,
				   IP_MREQ_SOURCE_FIELDS_N, NULL);
		if (!IN_MULTICAST(ntohl(ms.imr_multiaddr.s_addr)))
			BUG("ip_mreq_source: the group is not multicast");
		note_iface(src_iface, ms.imr_interface.s_addr,
			   "ip_mreq_source: the interface is neither unset nor lo's");

		memset(&m6, 0, sizeof(m6));
		struct_fill_passes((unsigned char *) &m6, sizeof(m6),
				   ipv6_mreq_fields, IPV6_MREQ_FIELDS_N, NULL);
		if (!IN6_IS_ADDR_MULTICAST(&m6.ipv6mr_multiaddr))
			BUG("ipv6_mreq: the group is not multicast");
		note_ifindex(seen6, m6.ipv6mr_interface,
			     "ipv6_mreq: the ifindex names no device every netns has");
	}

	if (!seen4[0] || !seen4[1] || !seen6[0] || !seen6[1])
		BUG("mcast rows: an ifindex never names the route's device or lo");
	if (!addr4[0] || !addr4[1] || !src_iface[0] || !src_iface[1])
		BUG("mcast rows: an address is never unset or never lo's");

	check_group_rows();
}
