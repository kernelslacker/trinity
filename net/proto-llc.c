#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/llc.h>
#include <stdlib.h>
#include "config.h"
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void llc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = zmalloc(sizeof(struct sockaddr_llc));

	llc->sllc_family = AF_LLC;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rnd();
	llc->sllc_xid = rnd();
	llc->sllc_ua = rnd();
	llc->sllc_sap = rnd();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rnd();
	*addr = (struct sockaddr *) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

static void llc_rand_socket(struct socket_triplet *st)
{
	st->protocol = rnd() % PROTO_MAX;
	if (RAND_BOOL())
		st->type = SOCK_STREAM;
	else
		st->type = SOCK_DGRAM;
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
}

static void netbeui_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NETBEUI;
}

const struct netproto proto_llc = {
	.name = "llc",
	.socket = llc_rand_socket,
	.setsockopt = llc_setsockopt,
	.gen_sockaddr = llc_gen_sockaddr,
};

const struct netproto proto_netbeui = {
	.name = "netbeui",
	.setsockopt = netbeui_setsockopt,
	.gen_sockaddr = llc_gen_sockaddr,
};
