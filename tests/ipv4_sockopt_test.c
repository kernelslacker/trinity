/*
 * Self-check for the IPv4 option builder's int options: do_ip_setsockopt()
 * (net/ipv4/ip_sockglue.c) reads an int from an optlen of four or more and
 * an unsigned char from a shorter one, turns a flag on for any value but
 * 0, and holds the ranged options to their bounds, so the flags drawn turn
 * both on and off and most ranged draws are ones it takes.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/in.h>		/* IP_PMTUDISC_*, IP_RECVERR_RFC4884 */
#include <linux/mroute.h>	/* MRT_* */

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_ipv4, struct sockopt */
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "kernel/in.h"		/* IP_LOCAL_PORT_RANGE, ... */

#define IPV4_ROUNDS	30000
#define IPV4_OPTVAL_LEN	4096

/* The flags do_ip_setsockopt() turns on for any value but 0. */
static const unsigned int ip_flags[] = {
	IP_HDRINCL, IP_ROUTER_ALERT, IP_RECVOPTS, IP_RETOPTS, IP_PKTINFO,
	IP_RECVERR, IP_RECVTTL, IP_RECVTOS, IP_FREEBIND, IP_PASSSEC,
	IP_TRANSPARENT, IP_ORIGDSTADDR, IP_NODEFRAG, IP_CHECKSUM,
	IP_BIND_ADDRESS_NO_PORT, IP_RECVFRAGSIZE, IP_MULTICAST_LOOP,
};

static int optval_int(const unsigned char *optval, unsigned int optlen)
{
	int val = 0;

	if (optlen >= sizeof(int))
		memcpy(&val, optval, sizeof(val));
	else if (optlen >= sizeof(char))
		val = optval[0];
	return val;
}

/* Whether do_ip_setsockopt() takes @val for a ranged int option, or -1
 * for an option that is none. */
static int ip_int_taken(unsigned int optname, int val, unsigned int optlen)
{
	switch (optname) {
	case IP_TTL:
		return val == -1 || (val >= 1 && val <= 255);
	case IP_MULTICAST_TTL:
		return val >= -1 && val <= 255;
	case IP_MINTTL:
	case IP_TOS:
		return val >= 0 && val <= 255;
	case IP_MTU_DISCOVER:
		return val >= IP_PMTUDISC_DONT && val <= IP_PMTUDISC_OMIT;
	case IP_RECVERR_RFC4884:
	case IP_MULTICAST_ALL:
		return val == 0 || val == 1;
	case IP_UNICAST_IF:
	case MRT_INIT:
	case MRT_ASSERT:
	case MRT_PIM:
		return optlen == sizeof(int);
	case IP_LOCAL_PORT_RANGE: {
		uint16_t lo = (uint32_t) val, hi = (uint32_t) val >> 16;

		return optlen == sizeof(uint32_t) && (!lo || !hi || lo <= hi);
	}
	}
	return -1;
}

static bool is_ip_flag(unsigned int optname)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ip_flags); i++)
		if (ip_flags[i] == optname)
			return true;
	return false;
}

void ipv4_sockopt_self_check(void);
void ipv4_sockopt_self_check(void)
{
	/* A UDP socket draws IP-level options a third of the time. */
	struct socket_triplet udp = {
		.family = PF_INET, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP,
	};
	static unsigned char optval[IPV4_OPTVAL_LEN];
	unsigned int i, on = 0, off = 0, ranged = 0, taken = 0;

	for (i = 0; i < IPV4_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		int val, t;

		memset(optval, 0, sizeof(optval));
		proto_ipv4.setsockopt(&so, &udp);
		if (so.level != SOL_IP)
			continue;

		val = optval_int(optval, so.optlen);
		if (is_ip_flag(so.optname)) {
			if (val != 0)
				on++;
			else
				off++;
			continue;
		}
		t = ip_int_taken(so.optname, val, so.optlen);
		if (t < 0)
			continue;
		ranged++;
		taken += t;
	}

	if (on == 0 || off == 0)
		BUG("ipv4: the flag options never turn both on and off");
	if (ranged == 0 || taken < ranged * 3 / 4)
		BUG("ipv4: the ranged int options' values the kernel takes are rare");
}
