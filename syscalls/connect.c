/*
 * SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen
 *
 * If the connection or binding succeeds, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/x25.h>
#include <linux/ax25.h>
#include <linux/ipx.h>
#include <linux/atalk.h>
#include <linux/atm.h>
#include <linux/rose.h>
#include <linux/dn.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/llc.h>
#include <linux/if_packet.h>
#include <neteconet/ec.h>
#include <linux/irda.h>
#include <linux/if_pppox.h>
#include <linux/can.h>
#include <linux/tipc.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_connect(int childno)
{
	struct sockaddr_un *unixsock;
	struct sockaddr_in *ipv4;
	struct sockaddr_x25 *x25;
	struct sockaddr_in6 *ipv6;
	struct sockaddr_ax25 *ax25;
	struct sockaddr_ipx *ipx;
	struct sockaddr_at *atalk;
	struct sockaddr_atmpvc *atmpvc;
	struct sockaddr_atmsvc *atmsvc;
	struct sockaddr_rose *rose;
	struct sockaddr_dn *dn;
	struct sockaddr_llc *llc;
	struct sockaddr_pkt *pkt;
	struct sockaddr_ec *ec;
	struct sockaddr_irda *irda;
	struct sockaddr_pppox *pppox;
	struct sockaddr_can *can;
	struct sockaddr_tipc *tipc;
	struct sockaddr_nl *nl;
	struct sockaddr_nfc *nfc;
	unsigned int len;
	unsigned int pf;
	unsigned int i;

	pf = rand() % PF_MAX;

	switch (pf) {

	case PF_UNSPEC:
		//TODO
		break;

	case PF_UNIX:
		unixsock = malloc(sizeof(struct sockaddr_un));
		if (unixsock == NULL)
			return;

		unixsock->sun_family = PF_UNIX;
		len = rand() % 20;
		memset(&page_rand[len], 0, 1);
		strncpy(unixsock->sun_path, page_rand, len);
		shm->a2[childno] = (unsigned long) unixsock;
		shm->a3[childno] = sizeof(struct sockaddr_un);
		break;

	case PF_INET:
		ipv4 = malloc(sizeof(struct sockaddr_in));
		if (ipv4 == NULL)
			return;

		ipv4->sin_family = PF_INET;
		ipv4->sin_addr.s_addr = htonl(0x7f000001);
		ipv4->sin_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv4;
		shm->a3[childno] = sizeof(struct sockaddr_in);
		break;

	case PF_AX25:
		ax25 = malloc(sizeof(struct sockaddr_ax25));
		if (ax25 == NULL)
			return;

		ax25->sax25_family = PF_AX25;
		strncpy(ax25->sax25_call.ax25_call, page_rand, 7);
		ax25->sax25_ndigis = rand();
		shm->a2[childno] = (unsigned long) ax25;
		shm->a3[childno] = sizeof(struct sockaddr_ax25);
		break;

	case PF_IPX:
		ipx = malloc(sizeof(struct sockaddr_ipx));
		if (ipx == NULL)
			return;

		ipx->sipx_family = PF_AX25;
		ipx->sipx_port = rand();
		ipx->sipx_network = rand();
		for (i = 0; i < 6; i++)
			ipx->sipx_node[i] = rand();
		ipx->sipx_type = rand();
		ipx->sipx_zero = rand() % 2;
		shm->a2[childno] = (unsigned long) ipx;
		shm->a3[childno] = sizeof(struct sockaddr_ipx);
		break;

	case PF_APPLETALK:
		atalk = malloc(sizeof(struct sockaddr_at));
		if (atalk == NULL)
			return;

		atalk->sat_family = PF_APPLETALK;
		atalk->sat_port = rand();
		atalk->sat_addr.s_net = rand();
		atalk->sat_addr.s_node = rand();
		shm->a2[childno] = (unsigned long) atalk;
		shm->a3[childno] = sizeof(struct sockaddr_at);
		break;

	case PF_NETROM:
		//TODO
		break;

	case PF_BRIDGE:
		//TODO
		break;

	case PF_ATMPVC:
		atmpvc = malloc(sizeof(struct sockaddr_atmpvc));
		if (atmpvc == NULL)
			return;

		atmpvc->sap_family = PF_ATMPVC;
		atmpvc->sap_addr.itf = rand();
		atmpvc->sap_addr.vpi = rand();
		atmpvc->sap_addr.vci = rand();
		shm->a2[childno] = (unsigned long) atmpvc;
		shm->a3[childno] = sizeof(struct sockaddr_atmpvc);
		break;

	case PF_X25:
		x25 = malloc(sizeof(struct sockaddr_x25));
		if (x25 == NULL)
			return;

		x25->sx25_family = PF_X25;
		len = rand() % 15;
		memset(&page_rand[len], 0, 1);
		strncpy(x25->sx25_addr.x25_addr, page_rand, len);
		shm->a2[childno] = (unsigned long) x25;
		shm->a3[childno] = sizeof(struct sockaddr_x25);
		break;

	case PF_INET6:
		ipv6 = malloc(sizeof(struct sockaddr_in6));
		if (ipv6 == NULL)
			return;

		ipv6->sin6_family = PF_INET6;
		ipv6->sin6_addr.s6_addr32[0] = 0;
		ipv6->sin6_addr.s6_addr32[1] = 0;
		ipv6->sin6_addr.s6_addr32[2] = 0;
		ipv6->sin6_addr.s6_addr32[3] = htonl(1);
		ipv6->sin6_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv6;
		shm->a3[childno] = sizeof(struct sockaddr_in6);
		break;

	case PF_ROSE:
		rose = malloc(sizeof(struct sockaddr_rose));
		if (rose == NULL)
			return;

		rose->srose_family = PF_ROSE;
		rose->srose_addr.rose_addr[0] = rand();
		rose->srose_addr.rose_addr[1] = rand();
		rose->srose_addr.rose_addr[2] = rand();
		rose->srose_addr.rose_addr[3] = rand();
		rose->srose_addr.rose_addr[4] = rand();

		strncpy(rose->srose_call.ax25_call, page_rand, 7);

		rose->srose_ndigis = rand();
		strncpy(rose->srose_digi.ax25_call, page_rand+7, 7);

		shm->a2[childno] = (unsigned long) rose;
		shm->a3[childno] = sizeof(struct sockaddr_rose);
		break;

		//TODO
		break;

	case PF_DECnet:
		dn = malloc(sizeof(struct sockaddr_dn));
		if (dn == NULL)
			return;

		dn->sdn_family = PF_DECnet;
		dn->sdn_flags = rand();
		dn->sdn_objnum = rand();
		dn->sdn_objnamel = rand() % 16;
		for (i = 0; i < dn->sdn_objnamel; i++)
			dn->sdn_objname[i] = rand();
		dn->sdn_add.a_len = rand() % 2;
		dn->sdn_add.a_addr[0] = rand();
		dn->sdn_add.a_addr[1] = rand();
		shm->a2[childno] = (unsigned long) dn;
		shm->a3[childno] = sizeof(struct sockaddr_dn);
		break;

	case PF_NETBEUI:
		llc = malloc(sizeof(struct sockaddr_llc));
		if (llc == NULL)
			return;
		llc->sllc_family = AF_LLC;
		llc->sllc_arphrd = ARPHRD_ETHER;
		llc->sllc_test = rand();
		llc->sllc_xid = rand();
		llc->sllc_ua = rand();
		llc->sllc_sap = rand();
		for (i = 0; i < IFHWADDRLEN; i++)
			llc->sllc_mac[i] = rand();
		shm->a2[childno] = (unsigned long) llc;
		shm->a3[childno] = sizeof(struct sockaddr_llc);
		break;

	case PF_SECURITY:
		//TODO
		break;

	case PF_KEY:
		break;

	case PF_NETLINK:
		nl = malloc(sizeof(struct sockaddr_nl));
		if (nl == NULL)
			return;

		nl->nl_family = PF_NETLINK;
		nl->nl_pid = rand();
		nl->nl_groups = rand();
		shm->a2[childno] = (unsigned long) nl;
		shm->a3[childno] = sizeof(struct sockaddr_nl);
		break;

	case PF_PACKET:
		//TODO: See also sockaddr_ll
		pkt = malloc(sizeof(struct sockaddr_pkt));
		if (pkt == NULL)
			return;

		pkt->spkt_family = PF_PACKET;
		for (i = 0; i < 14; i++)
			pkt->spkt_device[i] = rand();
		shm->a2[childno] = (unsigned long) pkt;
		shm->a3[childno] = sizeof(struct sockaddr_pkt);
		break;

	case PF_ASH:
		//TODO
		break;

	case PF_ECONET:
		ec = malloc(sizeof(struct sockaddr_ec));
		if (ec == NULL)
			return;

		ec->sec_family = PF_ECONET;
		ec->port = rand();
		ec->cb = rand();
		ec->type = rand();
		ec->addr.station = rand();
		ec->addr.net = rand();
		ec->cookie = rand();
		shm->a2[childno] = (unsigned long) ec;
		shm->a3[childno] = sizeof(struct sockaddr_ec);
		break;

	case PF_ATMSVC:
		atmsvc = malloc(sizeof(struct sockaddr_atmsvc));
		if (atmsvc == NULL)
			return;

		atmsvc->sas_family = PF_ATMSVC;
		for (i = 0; i < ATM_ESA_LEN; i++)
			atmsvc->sas_addr.prv[i] = rand();
		for (i = 0; i < ATM_E164_LEN; i++)
			atmsvc->sas_addr.pub[i] = rand();
		atmsvc->sas_addr.lij_type = rand();
		atmsvc->sas_addr.lij_id = rand();
		shm->a2[childno] = (unsigned long) atmsvc;
		shm->a3[childno] = sizeof(struct sockaddr_atmsvc);
		break;

	case PF_RDS:
		//TODO
		break;

	case PF_SNA:
		//TODO
		break;

	case PF_IRDA:
		irda = malloc(sizeof(struct sockaddr_irda));
		if (irda == NULL)
			return;

		irda->sir_family = PF_IRDA;
		irda->sir_lsap_sel = rand();
		irda->sir_addr = rand();
		for (i = 0; i < 25; i++)
			irda->sir_name[i] = rand();
		shm->a2[childno] = (unsigned long) irda;
		shm->a3[childno] = sizeof(struct sockaddr_irda);
		break;

	case PF_PPPOX:
		pppox = malloc(sizeof(struct sockaddr_pppox));
		if (pppox == NULL)
			return;

		pppox->sa_family = PF_PPPOX;
		pppox->sa_addr.pppoe.sid = rand();
		for (i = 0; i < ETH_ALEN; i++)
			pppox->sa_addr.pppoe.remote[i] = rand();
		for (i = 0; i < IFNAMSIZ; i++)
			pppox->sa_addr.pppoe.dev[i] = rand();

		pppox->sa_addr.pptp.call_id = rand();
		pppox->sa_addr.pptp.sin_addr.s_addr = htonl(0x7f000001);

		shm->a2[childno] = (unsigned long) pppox;
		shm->a3[childno] = sizeof(struct sockaddr_pppox);
		break;


	case PF_WANPIPE:
		//TODO
		break;

	case PF_LLC:
		llc = malloc(sizeof(struct sockaddr_llc));
		if (llc == NULL)
			return;
		llc->sllc_family = AF_LLC;
		llc->sllc_arphrd = ARPHRD_ETHER;
		llc->sllc_test = rand();
		llc->sllc_xid = rand();
		llc->sllc_ua = rand();
		llc->sllc_sap = rand();
		for (i = 0; i < IFHWADDRLEN; i++)
			llc->sllc_mac[i] = rand();
		shm->a2[childno] = (unsigned long) llc;
		shm->a3[childno] = sizeof(struct sockaddr_llc);
		break;

	case PF_CAN:
		can = malloc(sizeof(struct sockaddr_can));
		if (can == NULL)
			return;
		can->can_family = AF_CAN;
		can->can_ifindex = rand();
		can->can_addr.tp.rx_id = rand();
		can->can_addr.tp.tx_id = rand();
		shm->a2[childno] = (unsigned long) can;
		shm->a3[childno] = sizeof(struct sockaddr_can);
		break;

	case PF_TIPC:
		tipc = malloc(sizeof(struct sockaddr_tipc));
		if (tipc == NULL)
			return;
		tipc->family = AF_TIPC;
		tipc->addrtype = rand();
		tipc->scope = rand();
		tipc->addr.id.ref = rand();
		tipc->addr.id.node = rand();
		tipc->addr.nameseq.type = rand();
		tipc->addr.nameseq.lower = rand();
		tipc->addr.nameseq.upper = rand();
		tipc->addr.name.name.type = rand();
		tipc->addr.name.name.instance = rand();
		tipc->addr.name.domain = rand();
		shm->a2[childno] = (unsigned long) tipc;
		shm->a3[childno] = sizeof(struct sockaddr_tipc);
		break;

	case PF_BLUETOOTH:
		//TODO
		break;

	case PF_IUCV:
		//TODO
		break;

	case PF_RXRPC:
		//TODO
		break;

	case PF_ISDN:
		//TODO
		break;

	case PF_PHONET:
		//TODO
		break;

	case PF_IEEE802154:
		//TODO
		break;

	case PF_CAIF:
		//TODO
		break;

	case PF_ALG:
		//TODO
		break;

	case PF_NFC:
		// TODO: See also sockaddr_nfc_llcp
		nfc = malloc(sizeof(struct sockaddr_nfc));
		if (nfc == NULL)
			return;

		nfc->sa_family = PF_NFC;
		nfc->dev_idx = rand();
		nfc->target_idx = rand();
		nfc->nfc_protocol = rand() % 5;
		shm->a2[childno] = (unsigned long) nfc;
		shm->a3[childno] = sizeof(struct sockaddr_nfc);
		break;

	default:
		break;
	}
}

struct syscall syscall_connect = {
	.name = "connect",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "uservaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "addrlen",
	.arg3type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_connect,
};
