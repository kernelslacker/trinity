#include <stdlib.h>
#include "net.h"
#include "config.h"
#ifdef USE_RDS
#include <linux/rds.h>
#endif

#include "compat.h"
#include "trinity.h"	// ARRAY_SIZE

#define SOL_RDS 276

#ifdef USE_RDS
#define NR_SOL_RDS_OPTS ARRAY_SIZE(rds_opts)
static const unsigned int rds_opts[] = {
	RDS_CANCEL_SENT_TO, RDS_GET_MR, RDS_FREE_MR,
	4, /* deprecated RDS_BARRIER 4 */
	RDS_RECVERR, RDS_CONG_MONITOR, RDS_GET_MR_FOR_DEST };
#endif

void rds_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_RDS;
#ifdef USE_RDS
	val = rand() % NR_SOL_RDS_OPTS;
	so->optname = rds_opts[val];
#endif
}
