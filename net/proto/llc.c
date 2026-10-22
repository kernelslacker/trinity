#include <sys/socket.h>
#include <sys/un.h>
#include <net/if_arp.h>
#include <linux/llc.h>
#include "net.h"
#include "trinity.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/socket.h"
static void llc_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = zmalloc_tracked(sizeof(struct sockaddr_llc));

	llc->sllc_family = AF_LLC;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rnd_u32();
	llc->sllc_xid = rnd_u32();
	llc->sllc_ua = rnd_u32();
	llc->sllc_sap = rnd_u32();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rnd_u32();
	*addr = (struct sockaddr *) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

#ifndef USE_LLC_OPT_PKTINFO
#define LLC_OPT_PKTINFO LLC_OPT_UNKNOWN
#endif

static const unsigned int llc_opts[] = {
	LLC_OPT_RETRY, LLC_OPT_SIZE, LLC_OPT_ACK_TMR_EXP, LLC_OPT_P_TMR_EXP,
	LLC_OPT_REJ_TMR_EXP, LLC_OPT_BUSY_TMR_EXP, LLC_OPT_TX_WIN, LLC_OPT_RX_WIN,
	LLC_OPT_PKTINFO,
};

#define SOL_NETBEUI 267
#define SOL_LLC 268

static void llc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_LLC;
	so->optname = RAND_ARRAY(llc_opts);
	so->optlen = sizeof(unsigned int);
}

static void netbeui_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NETBEUI;
	so->optname = RAND_ARRAY(llc_opts);
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet llc_triplets[] = {
	{ .family = PF_LLC, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_LLC, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_llc = {
	.name = "llc",
	.setsockopt = llc_setsockopt,
	.gen_sockaddr = llc_gen_sockaddr,
	.valid_triplets = llc_triplets,
	.nr_triplets = ARRAY_SIZE(llc_triplets),
};

static void netbeui_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = zmalloc_tracked(sizeof(struct sockaddr_llc));

	llc->sllc_family = PF_NETBEUI;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rnd_u32();
	llc->sllc_xid = rnd_u32();
	llc->sllc_ua = rnd_u32();
	llc->sllc_sap = rnd_u32();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rnd_u32();
	*addr = (struct sockaddr *) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

static struct socket_triplet netbeui_triplets[] = {
	{ .family = PF_NETBEUI, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_NETBEUI, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_netbeui = {
	.name = "netbeui",
	.setsockopt = netbeui_setsockopt,
	.gen_sockaddr = netbeui_gen_sockaddr,
	.valid_triplets = netbeui_triplets,
	.nr_triplets = ARRAY_SIZE(netbeui_triplets),
};
