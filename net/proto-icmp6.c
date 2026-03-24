
#ifdef USE_IPV6
#include <stdlib.h>
#include <string.h>
#include <linux/icmpv6.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static const unsigned int icmpv6_opts[] = { ICMPV6_FILTER };

void icmpv6_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct icmp6_filter *filter;

	so->optname = RAND_ARRAY(icmpv6_opts);

	switch (so->optname) {
	case ICMPV6_FILTER:
		filter = (struct icmp6_filter *) so->optval;
		switch (rand() % 4) {
		case 0:
			/* Pass all — clear all bits */
			memset(filter, 0, sizeof(struct icmp6_filter));
			break;
		case 1:
			/* Block all — set all bits */
			memset(filter, 0xff, sizeof(struct icmp6_filter));
			break;
		case 2:
			/* Random bitmask */
			generate_rand_bytes((unsigned char *) filter, sizeof(struct icmp6_filter));
			break;
		case 3: {
			/* Block a few specific types */
			unsigned int i;

			memset(filter, 0, sizeof(struct icmp6_filter));
			for (i = 0; i < (unsigned int)(rand() % 8) + 1; i++) {
				unsigned int type = rand() % 256;

				filter->data[type >> 5] |= 1U << (type & 31);
			}
			break;
		}
		}
		so->optlen = sizeof(struct icmp6_filter);
		break;
	}
}
#endif
