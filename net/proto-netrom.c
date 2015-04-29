#include "config.h"

#ifdef USE_NETROM
#include <stdlib.h>
#include <netrom/netrom.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

#define NR_SOL_NETROM_OPTS ARRAY_SIZE(netrom_opts)
static const unsigned int netrom_opts[] = {
	NETROM_T1, NETROM_T2, NETROM_N2, NETROM_T4, NETROM_IDLE };

void netrom_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % NR_SOL_NETROM_OPTS;
	so->optname = netrom_opts[val];
}
#endif
