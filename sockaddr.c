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
#include <linux/caif/caif_socket.h>
#include <linux/if_alg.h>
#include <linux/phonet.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "compat.h"
#include "config.h"

static in_addr_t random_ipv4_address(void)
{
	int addr = 0;
	int class = 0;

	switch (rand() % 9) {
	case 0:	addr = 0;		/* 0.0.0.0 */
		break;
	case 1:	addr = 0x0a000000;	/* 10.0.0.0/8 */
		class = 8;
		break;
	case 2:	addr = 0x7f000001;	/* 127.0.0.0/8 */
		class = 8;
		break;
	case 3:	addr = 0xa9fe0000;	/* 169.254.0.0/16 (link-local) */
		class = 16;
		break;
	case 4:	addr = 0xac100000;	/* 172.16.0.0/12 */
		class = 12;
		break;
	case 5:	addr = 0xc0586300;	/* 192.88.99.0/24 (6to4 anycast) */
		class = 24;
		break;
	case 6:	addr = 0xc0a80000;	/* 192.168.0.0/16 */
		class = 16;
		break;
	case 7:	addr = 0xe0000000;	/* 224.0.0.0/4 (multicast)*/
		class = 4;
		break;
	case 8:	addr = 0xffffffff;	/* 255.255.255.255 */
		break;
	default:
		break;
	}

	if (rand() % 100 < 50) {
		switch (class) {
		case 4:	addr |= rand() % 0xfffffff;
			break;
		case 8:	addr |= rand() % 0xffffff;
			break;
		case 12: addr |= rand() % 0xfffff;
			break;
		case 16: addr |= rand() % 0xffff;
			break;
		case 24: addr |= rand() % 0xff;
			break;
		default: break;
		}
	}
	return htonl(addr);
}

static void gen_unixsock(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = malloc(sizeof(struct sockaddr_un));
	if (unixsock == NULL)
		return;

	unixsock->sun_family = PF_UNIX;
	len = rand() % 20;
	memset(&page_rand[len], 0, 1);
	strncpy(unixsock->sun_path, page_rand, len);
	*addr = (unsigned long) unixsock;
	*addrlen = sizeof(struct sockaddr_un);
}

static void gen_ipv4(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_in *ipv4;

	ipv4 = malloc(sizeof(struct sockaddr_in));
	if (ipv4 == NULL)
		return;

	ipv4->sin_family = PF_INET;
	ipv4->sin_addr.s_addr = random_ipv4_address();
	ipv4->sin_port = rand() % 65535;
	*addr = (unsigned long) ipv4;
	*addrlen = sizeof(struct sockaddr_in);
}

static void gen_ax25(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = malloc(sizeof(struct sockaddr_ax25));
	if (ax25 == NULL)
		return;

	ax25->sax25_family = PF_AX25;
	strncpy(ax25->sax25_call.ax25_call, page_rand, 7);
	ax25->sax25_ndigis = rand();
	*addr = (unsigned long) ax25;
	*addrlen = sizeof(struct sockaddr_ax25);
}

static void gen_ipx(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_ipx *ipx;
	unsigned int i;

	ipx = malloc(sizeof(struct sockaddr_ipx));
	if (ipx == NULL)
		return;

	ipx->sipx_family = PF_IPX;
	ipx->sipx_port = rand();
	ipx->sipx_network = rand();
	for (i = 0; i < 6; i++)
		ipx->sipx_node[i] = rand();
	ipx->sipx_type = rand();
	ipx->sipx_zero = rand() % 2;
	*addr = (unsigned long) ipx;
	*addrlen = sizeof(struct sockaddr_ipx);
}

static void gen_ipv6(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_in6 *ipv6;

	ipv6 = malloc(sizeof(struct sockaddr_in6));
	if (ipv6 == NULL)
		return;

	ipv6->sin6_family = PF_INET6;
	ipv6->sin6_addr.s6_addr32[0] = 0;
	ipv6->sin6_addr.s6_addr32[1] = 0;
	ipv6->sin6_addr.s6_addr32[2] = 0;
	ipv6->sin6_addr.s6_addr32[3] = htonl(1);
	ipv6->sin6_port = rand() % 65535;
	*addr = (unsigned long) ipv6;
	*addrlen = sizeof(struct sockaddr_in6);
}

static void gen_appletalk(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_at *atalk;

	atalk = malloc(sizeof(struct sockaddr_at));
	if (atalk == NULL)
		return;

	atalk->sat_family = PF_APPLETALK;
	atalk->sat_port = rand();
	atalk->sat_addr.s_net = rand();
	atalk->sat_addr.s_node = rand();
	*addr = (unsigned long) atalk;
	*addrlen = sizeof(struct sockaddr_at);
}

static void gen_atmpvc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = malloc(sizeof(struct sockaddr_atmpvc));
	if (atmpvc == NULL)
		return;

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rand();
	atmpvc->sap_addr.vpi = rand();
	atmpvc->sap_addr.vci = rand();
	*addr = (unsigned long) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}

static void gen_x25(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_x25 *x25;
	unsigned int len;

	x25 = malloc(sizeof(struct sockaddr_x25));
	if (x25 == NULL)
		return;

	x25->sx25_family = PF_X25;
	len = rand() % 15;
	memset(&page_rand[len], 0, 1);
	strncpy(x25->sx25_addr.x25_addr, page_rand, len);
	*addr = (unsigned long) x25;
	*addrlen = sizeof(struct sockaddr_x25);
}

static void gen_rose(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_rose *rose;

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

	*addr = (unsigned long) rose;
	*addrlen = sizeof(struct sockaddr_rose);
}

static void gen_decnet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_dn *dn;
	unsigned int i;

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
	*addr = (unsigned long) dn;
	*addrlen = sizeof(struct sockaddr_dn);
}

static void gen_llc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

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
	*addr = (unsigned long) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

static void gen_netlink(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_nl *nl;

	nl = malloc(sizeof(struct sockaddr_nl));
	if (nl == NULL)
		return;

	nl->nl_family = PF_NETLINK;
	nl->nl_pid = rand();
	nl->nl_groups = rand();
	*addr = (unsigned long) nl;
	*addrlen = sizeof(struct sockaddr_nl);
}

static void gen_packet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_pkt *pkt;
	unsigned int i;

	//TODO: See also sockaddr_ll
	pkt = malloc(sizeof(struct sockaddr_pkt));
	if (pkt == NULL)
		return;

	pkt->spkt_family = PF_PACKET;
	for (i = 0; i < 14; i++)
		pkt->spkt_device[i] = rand();
	*addr = (unsigned long) pkt;
	*addrlen = sizeof(struct sockaddr_pkt);
}

static void gen_econet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_ec *ec;

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
	*addr = (unsigned long) ec;
	*addrlen = sizeof(struct sockaddr_ec);
}

static void gen_atmsvc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_atmsvc *atmsvc;
	unsigned int i;

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
	*addr = (unsigned long) atmsvc;
	*addrlen = sizeof(struct sockaddr_atmsvc);
}

static void gen_irda(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_irda *irda;
	unsigned int i;

	irda = malloc(sizeof(struct sockaddr_irda));
	if (irda == NULL)
		return;

	irda->sir_family = PF_IRDA;
	irda->sir_lsap_sel = rand();
	irda->sir_addr = rand();
	for (i = 0; i < 25; i++)
		irda->sir_name[i] = rand();
	*addr = (unsigned long) irda;
	*addrlen = sizeof(struct sockaddr_irda);
}

static void gen_pppox(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_pppox *pppox;
	struct sockaddr_pppol2tp *pppol2tp;
	struct sockaddr_pppol2tpv3 *pppol2tpv3;
	unsigned int proto;
	unsigned int i;

	proto = rand() % 3;

	switch (proto) {

	case PX_PROTO_OE:
		pppox = malloc(sizeof(struct sockaddr_pppox));
		if (pppox == NULL)
			return;

		pppox->sa_family = PF_PPPOX;
		pppox->sa_protocol = proto;

		pppox->sa_addr.pppoe.sid = rand();
		for (i = 0; i < ETH_ALEN; i++)
			pppox->sa_addr.pppoe.remote[i] = rand();
		for (i = 0; i < IFNAMSIZ; i++)
			pppox->sa_addr.pppoe.dev[i] = rand();

		pppox->sa_addr.pptp.call_id = rand();
		pppox->sa_addr.pptp.sin_addr.s_addr = random_ipv4_address();

		*addr = (unsigned long) pppox;
		*addrlen = sizeof(struct sockaddr_pppox);
		break;

	case PX_PROTO_OL2TP:
		switch (rand() % 4) {

		case 0:	/* PPPoL2TP */
			pppol2tp = malloc(sizeof(struct sockaddr_pppol2tp));
			if (pppol2tp == NULL)
				return;

			pppol2tp->sa_family = PF_PPPOX;
			pppol2tp->sa_protocol = proto;
			pppol2tp->pppol2tp.pid = get_pid();
			pppol2tp->pppol2tp.fd = get_random_fd();
			pppol2tp->pppol2tp.addr.sin_addr.s_addr = random_ipv4_address();
			pppol2tp->pppol2tp.s_tunnel = rand();
			pppol2tp->pppol2tp.s_session = rand();
			pppol2tp->pppol2tp.d_tunnel = rand();
			pppol2tp->pppol2tp.d_session = rand();
			*addr = (unsigned long) pppol2tp;
			*addrlen = sizeof(struct sockaddr_pppol2tp);
			break;

		case 1:	/* PPPoL2TPin6*/
#ifdef USE_PPPOL2TPIN6
			{
			struct sockaddr_pppol2tpin6 *pppol2tpin6;

			pppol2tpin6 = malloc(sizeof(struct sockaddr_pppol2tpin6));
			if (pppol2tpin6 == NULL)
				return;

			pppol2tpin6->sa_family = PF_PPPOX;
			pppol2tpin6->sa_protocol = proto;
			pppol2tpin6->pppol2tp.pid = get_pid();
			pppol2tpin6->pppol2tp.fd = get_random_fd();
			pppol2tpin6->pppol2tp.s_tunnel = rand();
			pppol2tpin6->pppol2tp.s_session = rand();
			pppol2tpin6->pppol2tp.d_tunnel = rand();
			pppol2tpin6->pppol2tp.d_session = rand();
			pppol2tpin6->pppol2tp.addr.sin6_family = AF_INET6;
			pppol2tpin6->pppol2tp.addr.sin6_port = rand();
			pppol2tpin6->pppol2tp.addr.sin6_flowinfo = rand();
			pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[0] = 0;
			pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[1] = 0;
			pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[2] = 0;
			pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[3] = htonl(1);
			pppol2tpin6->pppol2tp.addr.sin6_scope_id = rand();
			*addr = (unsigned long) pppol2tpin6;
			*addrlen = sizeof(struct sockaddr_pppol2tpin6);
			}
#endif
			break;

		case 2:	/* PPPoL2TPv3*/
			pppol2tpv3 = malloc(sizeof(struct sockaddr_pppol2tpv3));
			if (pppol2tpv3 == NULL)
				return;

			pppol2tpv3->sa_family = PF_PPPOX;
			pppol2tpv3->sa_protocol = proto;
			pppol2tpv3->pppol2tp.pid = get_pid();
			pppol2tpv3->pppol2tp.fd = get_random_fd();
			pppol2tpv3->pppol2tp.addr.sin_addr.s_addr = random_ipv4_address();
			pppol2tpv3->pppol2tp.s_tunnel = rand();
			pppol2tpv3->pppol2tp.s_session = rand();
			pppol2tpv3->pppol2tp.d_tunnel = rand();
			pppol2tpv3->pppol2tp.d_session = rand();
			*addr = (unsigned long) pppol2tpv3;
			*addrlen = sizeof(struct sockaddr_pppol2tpv3);
			break;

		case 3:	/* PPPoL2TPv3in6 */
#ifdef USE_PPPOL2TPIN6
			{
			struct sockaddr_pppol2tpv3in6 *pppol2tpv3in6;

			pppol2tpv3in6 = malloc(sizeof(struct sockaddr_pppol2tpv3in6));
			if (pppol2tpv3in6 == NULL)
				return;

			pppol2tpv3in6->sa_family = PF_PPPOX;
			pppol2tpv3in6->sa_protocol = proto;
			pppol2tpv3in6->pppol2tp.pid = get_pid();
			pppol2tpv3in6->pppol2tp.fd = get_random_fd();
			pppol2tpv3in6->pppol2tp.s_tunnel = rand();
			pppol2tpv3in6->pppol2tp.s_session = rand();
			pppol2tpv3in6->pppol2tp.d_tunnel = rand();
			pppol2tpv3in6->pppol2tp.d_session = rand();
			pppol2tpv3in6->pppol2tp.addr.sin6_family = AF_INET6;
			pppol2tpv3in6->pppol2tp.addr.sin6_port = rand();
			pppol2tpv3in6->pppol2tp.addr.sin6_flowinfo = rand();
			pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[0] = 0;
			pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[1] = 0;
			pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[2] = 0;
			pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[3] = random_ipv4_address();
			pppol2tpv3in6->pppol2tp.addr.sin6_scope_id = rand();
			*addr = (unsigned long) pppol2tpv3in6;
			*addrlen = sizeof(struct sockaddr_pppol2tpv3in6);
			}
#endif
			break;

		default:
			break;
		}


	case PX_PROTO_PPTP:
		//FIXME: What do we do here?
		break;

	default:
		break;
	}
}

static void gen_can(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_can *can;

	can = malloc(sizeof(struct sockaddr_can));
	if (can == NULL)
		return;
	can->can_family = AF_CAN;
	can->can_ifindex = rand();
	can->can_addr.tp.rx_id = rand();
	can->can_addr.tp.tx_id = rand();
	*addr = (unsigned long) can;
	*addrlen = sizeof(struct sockaddr_can);
}

static void gen_tipc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_tipc *tipc;

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
	*addr = (unsigned long) tipc;
	*addrlen = sizeof(struct sockaddr_tipc);
}

static void gen_phonet(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_pn *pn;

	pn = malloc(sizeof(struct sockaddr_pn));
	if (pn == NULL)
		return;

	pn->spn_family = PF_PHONET;
	pn->spn_obj = rand();
	pn->spn_dev = rand();
	pn->spn_resource = rand();
	*addr = (unsigned long) pn;
	*addrlen = sizeof(struct sockaddr_pn);
}

static void gen_caif(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_caif *caif;
	unsigned int i;

	caif = malloc(sizeof(struct sockaddr_caif));
	if (caif == NULL)
		return;

	caif->family = PF_CAIF;
	caif->u.at.type = rand();
	for (i = 0; i < 16; i++)
		caif->u.util.service[i] = rand();
	caif->u.dgm.connection_id = rand();
	caif->u.dgm.nsapi = rand();
	caif->u.rfm.connection_id = rand();
	for (i = 0; i < 16; i++)
		caif->u.rfm.volume[i] = rand();
	caif->u.dbg.type = rand();
	caif->u.dbg.service = rand();
	*addr = (unsigned long) caif;
	*addrlen = sizeof(struct sockaddr_caif);
}

static void gen_alg(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_alg *alg;
	unsigned int i;

	alg = malloc(sizeof(struct sockaddr_alg));
	if (alg == NULL)
		return;

	alg->salg_family = PF_ALG;
	for (i = 0; i < 14; i++)
		alg->salg_type[i] = rand();
	alg->salg_feat = rand();
	alg->salg_mask = rand();
	for (i = 0; i < 64; i++)
		alg->salg_name[i] = rand();
	*addr = (unsigned long) alg;
	*addrlen = sizeof(struct sockaddr_alg);
}

static void gen_nfc(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_nfc *nfc;

	// TODO: See also sockaddr_nfc_llcp
	nfc = malloc(sizeof(struct sockaddr_nfc));
	if (nfc == NULL)
		return;

	nfc->sa_family = PF_NFC;
	nfc->dev_idx = rand();
	nfc->target_idx = rand();
	nfc->nfc_protocol = rand() % 5;
	*addr = (unsigned long) nfc;
	*addrlen = sizeof(struct sockaddr_nfc);
}

void generate_sockaddr(unsigned long *addr, unsigned long *addrlen, int pf)
{
	/* If we want sockets of a specific type, we'll want sockaddrs that match. */
	if (do_specific_proto == TRUE)
		pf = specific_proto;

	/* If we got no hint passed down, pick a random proto. */
	if (pf == -1)
		pf = rand() % PF_MAX;

	switch (pf) {

	case PF_UNSPEC:
		//TODO
		break;

	case PF_UNIX:
		gen_unixsock(addr, addrlen);
		break;

	case PF_INET:
		gen_ipv4(addr, addrlen);
		break;

	case PF_AX25:
		gen_ax25(addr, addrlen);
		break;

	case PF_IPX:
		gen_ipx(addr, addrlen);
		break;

	case PF_APPLETALK:
		gen_appletalk(addr, addrlen);
		break;

	case PF_NETROM:
		//TODO
		break;

	case PF_BRIDGE:
		//TODO
		break;

	case PF_ATMPVC:
		gen_atmpvc(addr, addrlen);
		break;

	case PF_X25:
		gen_x25(addr, addrlen);
		break;

	case PF_INET6:
		gen_ipv6(addr, addrlen);
		break;

	case PF_ROSE:
		gen_rose(addr, addrlen);
		break;

	case PF_DECnet:
		gen_decnet(addr, addrlen);
		break;

	case PF_NETBEUI:
		gen_llc(addr, addrlen);
		break;

	case PF_SECURITY:
		//TODO
		break;

	case PF_KEY:
		break;

	case PF_NETLINK:
		gen_netlink(addr, addrlen);
		break;

	case PF_PACKET:
		gen_packet(addr, addrlen);
		break;

	case PF_ASH:
		//TODO
		break;

	case PF_ECONET:
		gen_econet(addr, addrlen);
		break;

	case PF_ATMSVC:
		gen_atmsvc(addr, addrlen);
		break;

	case PF_RDS:
		//TODO
		break;

	case PF_SNA:
		//TODO
		break;

	case PF_IRDA:
		gen_irda(addr, addrlen);
		break;

	case PF_PPPOX:
		gen_pppox(addr, addrlen);
		break;

	case PF_WANPIPE:
		//TODO
		break;

	case PF_LLC:
		gen_llc(addr, addrlen);
		break;

	case PF_CAN:
		gen_can(addr, addrlen);
		break;

	case PF_TIPC:
		gen_tipc(addr, addrlen);
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
		gen_phonet(addr, addrlen);
		break;

	case PF_IEEE802154:
		//TODO
		break;

	case PF_CAIF:
		gen_caif(addr, addrlen);
		break;

	case PF_ALG:
		gen_alg(addr, addrlen);
		break;

	case PF_NFC:
		gen_nfc(addr, addrlen);
		break;

	default:
		break;
	}
}
