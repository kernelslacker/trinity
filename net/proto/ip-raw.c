#include <linux/icmp.h>
#include "net.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"

#include "kernel/in6.h"

/*
 * A raw socket's options at SOL_RAW: do_raw_setsockopt() takes only
 * ICMP_FILTER, and only from an ICMP socket, and do_rawv6_setsockopt()
 * only IPV6_CHECKSUM and IPV6_HDRINCL.
 */
static const unsigned int raw_opts[] = { ICMP_FILTER };
static const unsigned int rawv6_opts[] = { IPV6_CHECKSUM, IPV6_HDRINCL };

void raw_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int *optval32 = (unsigned int *) so->optval;

	so->level = SOL_RAW;
	if (triplet->family == PF_INET6)
		so->optname = RAND_ARRAY(rawv6_opts);
	else
		so->optname = RAND_ARRAY(raw_opts);
	so->optlen = sizeof(unsigned int);

	switch (so->optname) {
	case ICMP_FILTER:
		/* struct icmp_filter — bitmask of ICMP types to block */
		*optval32 = rnd_u32();
		break;

	case IPV6_CHECKSUM:
		/* Offset of checksum field, or -1 to disable */
		switch (rnd_modulo_u32(4)) {
		case 0: *optval32 = (unsigned int) -1; break;	/* disable */
		case 1: *optval32 = 6; break;			/* ICMPv6 offset */
		case 2: *optval32 = rnd_modulo_u32(256); break;
		case 3: *optval32 = rnd_u32(); break;
		}
		break;

	case IPV6_HDRINCL:
		*optval32 = RAND_BOOL();
		break;
	}
}
