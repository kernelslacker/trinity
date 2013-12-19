#include <stdlib.h>
#include "net.h"
#include "config.h"

#define SOL_RDS 276

#ifdef USE_RDS
#include <linux/rds.h>

#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

void rds_gen_sockaddr(unsigned long **addr, unsigned long *addrlen)
{
	struct sockaddr_in *rds;

	rds = malloc(sizeof(struct sockaddr_in));
	if (rds == NULL)
		return;
	rds->sin_family = AF_INET;
	rds->sin_addr.s_addr = random_ipv4_address();
	rds->sin_port = rand() % 65535;

	*addr = (unsigned long *) rds;
	*addrlen = sizeof(struct sockaddr_in);
}

static const unsigned int rds_opts[] = {
	RDS_CANCEL_SENT_TO, RDS_GET_MR, RDS_FREE_MR,
	4, /* deprecated RDS_BARRIER 4 */
	RDS_RECVERR, RDS_CONG_MONITOR, RDS_GET_MR_FOR_DEST };
#define NR_SOL_RDS_OPTS ARRAY_SIZE(rds_opts)

void rds_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_RDS;

	val = rand() % NR_SOL_RDS_OPTS;
	so->optname = rds_opts[val];
}

#else
/* stub if we are built on something without RDS headers */
void rds_setsockopt(struct sockopt *so)
{
	so->level = SOL_RDS;
}
#endif	/* USE_RDS */
