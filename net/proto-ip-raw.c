#include <netinet/in.h>
#include <linux/icmp.h>
#include "net.h"
#include "random.h"
#include "trinity.h"

#ifndef IPV6_CHECKSUM
#define IPV6_CHECKSUM	7
#endif

static const unsigned int raw_opts[] = {
	ICMP_FILTER, IPV6_CHECKSUM,
};

void raw_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval32;

	so->optname = RAND_ARRAY(raw_opts);

	switch (so->optname) {
	case ICMP_FILTER:
		/* struct icmp_filter — bitmask of ICMP types to block */
		optval32 = (unsigned int *) so->optval;
		*optval32 = rand();
		so->optlen = sizeof(unsigned int);
		break;

	case IPV6_CHECKSUM:
		/* Offset of checksum field, or -1 to disable */
		optval32 = (unsigned int *) so->optval;
		switch (rand() % 4) {
		case 0: *optval32 = (unsigned int) -1; break;	/* disable */
		case 1: *optval32 = 6; break;			/* ICMPv6 offset */
		case 2: *optval32 = rand() % 256; break;
		case 3: *optval32 = rand(); break;
		}
		so->optlen = sizeof(unsigned int);
		break;

	default:
		break;
	}
}
