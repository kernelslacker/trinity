#ifdef USE_RDS
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include <linux/rds.h>

static void rds_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_in *rds;

	rds = zmalloc(sizeof(struct sockaddr_in));

	rds->sin_family = AF_INET;
	rds->sin_addr.s_addr = random_ipv4_address();
	rds->sin_port = rnd() % 65535;

	*addr = (struct sockaddr *) rds;
	*addrlen = sizeof(struct sockaddr_in);
}

static const unsigned int rds_opts[] = {
	RDS_CANCEL_SENT_TO, RDS_GET_MR, RDS_FREE_MR,
	4, /* deprecated RDS_BARRIER 4 */
	RDS_RECVERR, RDS_CONG_MONITOR, RDS_GET_MR_FOR_DEST,
};

#define SOL_RDS 276

static void rds_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_RDS;
	so->optname = RAND_ARRAY(rds_opts);
}

static struct socket_triplet rds_triplet[] = {
	{ .family = PF_RDS, .protocol = 0, .type = SOCK_SEQPACKET },
};

const struct netproto proto_rds = {
	.name = "rds",
	.setsockopt = rds_setsockopt,
	.gen_sockaddr = rds_gen_sockaddr,
	.valid_triplets = rds_triplet,
	.nr_triplets = ARRAY_SIZE(rds_triplet),
};
#endif	/* USE_RDS */
