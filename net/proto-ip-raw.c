#include <netinet/in.h>
#include <linux/icmp.h>
#include "net.h"
#include "trinity.h"

void raw_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->optname = ICMP_FILTER; // that's all (for now?)
}
