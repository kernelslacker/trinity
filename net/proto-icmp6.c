#include "config.h"

#ifdef USE_IPV6
#include <stdlib.h>
#include <linux/icmpv6.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

#define NR_SOL_ICMPV6_OPTS ARRAY_SIZE(icmpv6_opts)
static const unsigned int icmpv6_opts[] = { ICMPV6_FILTER };

void icmpv6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % NR_SOL_ICMPV6_OPTS;
	so->optname = icmpv6_opts[val];
}
#endif
