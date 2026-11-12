/*
 * Self-check for the multicast membership rows of the setsockopt catalog: a
 * filled ip_mreqn or ipv6_mreq names a multicast group on a device every
 * network namespace has, ifindex 0 (the group's route) or 1 (lo), so
 * ip_mc_find_dev() and ip6_mc_find_dev() find one.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "args-internal.h"	/* struct_fill_passes */
#include "debug.h"		/* BUG */
#include "struct_catalog.h"
#include "struct_catalog-internal.h"

#define MCAST_ROUNDS	64

/* An ifindex of 0 or 1, seen both ways over the rounds. */
static void note_ifindex(bool seen[2], unsigned int ifindex, const char *what)
{
	if (ifindex > 1)
		BUG(what);
	seen[ifindex] = true;
}

void mcast_catalog_self_check(void);
void mcast_catalog_self_check(void)
{
	bool seen4[2] = { false, false }, seen6[2] = { false, false };
	bool lo_addr = false;
	unsigned int i;

	for (i = 0; i < MCAST_ROUNDS; i++) {
		struct ip_mreqn mr;
		struct ipv6_mreq m6;

		memset(&mr, 0, sizeof(mr));
		struct_fill_passes((unsigned char *) &mr, sizeof(mr),
				   ip_mreqn_fields, IP_MREQN_FIELDS_N, NULL);
		if (!IN_MULTICAST(ntohl(mr.imr_multiaddr.s_addr)))
			BUG("ip_mreqn: the group is not multicast");
		note_ifindex(seen4, (unsigned int) mr.imr_ifindex,
			     "ip_mreqn: the ifindex names no device every netns has");
		/* With no ifindex, the address picks the device: lo's or none. */
		if (mr.imr_address.s_addr == htonl(INADDR_LOOPBACK))
			lo_addr = true;
		else if (mr.imr_address.s_addr != htonl(INADDR_ANY))
			BUG("ip_mreqn: the address is neither unset nor lo's");

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
	if (!lo_addr)
		BUG("ip_mreqn: the address never names lo");
}
