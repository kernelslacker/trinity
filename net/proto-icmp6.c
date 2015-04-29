#include "config.h"

#ifdef USE_IPV6
#include <stdlib.h>
#include <linux/icmpv6.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

static const unsigned int icmpv6_opts[] = { ICMPV6_FILTER };

void icmpv6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % ARRAY_SIZE(icmpv6_opts);
	so->optname = icmpv6_opts[val];
}
#endif
