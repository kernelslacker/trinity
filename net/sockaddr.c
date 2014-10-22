#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "arch.h"
#include "config.h"
#include "maps.h"
#include "net.h"
#include "params.h"	// do_specific_domain
#include "random.h"
#include "sanitise.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

struct sa_func_entry {
	unsigned int pf;
	void (*func)(struct sockaddr **addr, socklen_t *addrlen);
};

static const struct sa_func_entry sa_funcs[] = {
//TODO	{ .pf = PF_UNSPEC, .func = &unspec_gen_sockaddr },
	{ .pf = PF_UNIX, .func = &unix_gen_sockaddr },
	{ .pf = PF_INET, .func = &ipv4_gen_sockaddr },
	{ .pf = PF_AX25, .func = &ax25_gen_sockaddr },
	{ .pf = PF_IPX, .func = &ipx_gen_sockaddr },
#ifdef USE_APPLETALK
	{ .pf = PF_APPLETALK, .func = &atalk_gen_sockaddr },
#endif
//TODO	{ .pf = PF_NETROM, .func = &netrom_gen_sockaddr },
//TODO	{ .pf = PF_BRIDGE, .func = &bridge_gen_sockaddr },
	{ .pf = PF_ATMPVC, .func = &atmpvc_gen_sockaddr },
	{ .pf = PF_X25, .func = &x25_gen_sockaddr },
#ifdef USE_IPV6
	{ .pf = PF_INET6, .func = &ipv6_gen_sockaddr },
#endif
#ifdef USE_ROSE
	{ .pf = PF_ROSE, .func = &rose_gen_sockaddr },
#endif
	{ .pf = PF_DECnet, .func = &decnet_gen_sockaddr },
	{ .pf = PF_NETBEUI, .func = &llc_gen_sockaddr },
//TODO	{ .pf = PF_SECURITY, .func = &security_gen_sockaddr },
//TODO	{ .pf = PF_KEY, .func = &key_gen_sockaddr },
	{ .pf = PF_NETLINK, .func = &netlink_gen_sockaddr },
	{ .pf = PF_PACKET, .func = &packet_gen_sockaddr },
//TODO	{ .pf = PF_ASH, .func = &ash_gen_sockaddr },
	{ .pf = PF_ECONET, .func = &econet_gen_sockaddr },
	{ .pf = PF_ATMSVC, .func = &atmsvc_gen_sockaddr },
	{ .pf = PF_RDS, .func = &rds_gen_sockaddr },
//TODO	{ .pf = PF_SNA, .func = &sna_gen_sockaddr },
	{ .pf = PF_IRDA, .func = &irda_gen_sockaddr },
	{ .pf = PF_PPPOX, .func = &pppox_gen_sockaddr },
//TODO	{ .pf = PF_WANPIPE, .func = &wanpipe_gen_sockaddr },
	{ .pf = PF_LLC, .func = &llc_gen_sockaddr },
	{ .pf = PF_CAN, .func = &can_gen_sockaddr },
	{ .pf = PF_TIPC, .func = &tipc_gen_sockaddr },
//TODO	{ .pf = PF_BLUETOOTH, .func = &bluetooth_gen_sockaddr },
//TODO	{ .pf = PF_IUCV, .func = &iucv_gen_sockaddr },
//TODO	{ .pf = PF_RXRPC, .func = &rxrpc_gen_sockaddr },
//TODO	{ .pf = PF_ISDN, .func = &isdn_gen_sockaddr },
	{ .pf = PF_PHONET, .func = &phonet_gen_sockaddr },
//TODO	{ .pf = PF_IEEE802154, .func = &ieee802154_gen_sockaddr },
#ifdef USE_CAIF
	{ .pf = PF_CAIF, .func = &caif_gen_sockaddr },
#endif
#ifdef USE_IF_ALG
	{ .pf = PF_ALG, .func = &alg_gen_sockaddr },
#endif
	{ .pf = PF_NFC, .func = &nfc_gen_sockaddr },
//TODO	{ .pf = PF_VSOCK, .func = &vsock_gen_sockaddr },
};

void generate_sockaddr(struct sockaddr **addr, socklen_t *addrlen, int pf)
{
	unsigned int i;

	/* If we want sockets of a specific type, we'll want sockaddrs that match. */
	if (do_specific_domain == TRUE)
		pf = specific_domain;

	/* If we got no hint passed down, pick a random proto. */
	if (pf == -1)
		pf = rand() % TRINITY_PF_MAX;

	for (i = 0; i < ARRAY_SIZE(sa_funcs); i++) {
		if (sa_funcs[i].pf == (unsigned int) pf) {
			sa_funcs[i].func(addr, addrlen);
			return;
		}
	}

	/* Make something up for unknown protocols. */
	*addr = (struct sockaddr *) zmalloc(page_size);
	*addrlen = rand() % page_size;
}
