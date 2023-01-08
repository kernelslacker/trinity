#include <sys/socket.h>
#include "net.h"
#include "compat.h"

const struct protoptr net_protocols[TRINITY_PF_MAX] = {
	[PF_UNIX] = { .proto = &proto_unix },
	[PF_INET] = { .proto = &proto_ipv4 },
#ifdef USE_NETAX25
	[PF_AX25] = { .proto = &proto_ax25 },
#endif
#ifdef USE_IPX
	[PF_IPX] = { .proto = &proto_ipx },
#endif
#ifdef USE_APPLETALK
	[PF_APPLETALK] = { .proto = &proto_appletalk },
#endif
	[PF_X25] = { .proto = &proto_x25 },
#ifdef USE_IPV6
	[PF_INET6] = { .proto = &proto_inet6 },
#endif
	[PF_PACKET] = { .proto = &proto_packet },
#ifdef USE_NETECONET
	[PF_ECONET] = { .proto = &proto_econet },
#endif
#ifdef USE_RDS
	[PF_RDS] = { .proto = &proto_rds },
#endif
#ifdef USE_IRDA
	[PF_IRDA] = { .proto = &proto_irda },
#endif
	[PF_LLC] = { .proto = &proto_llc },
	[PF_CAN] = { .proto = &proto_can },
	[PF_TIPC] = { .proto = &proto_tipc },
	[PF_BLUETOOTH] = { .proto = &proto_bluetooth },
	[PF_PHONET] = { .proto = &proto_phonet },
#ifdef USE_CAIF
	[PF_CAIF] = { .proto = &proto_caif },
#endif
	[PF_NFC] = { .proto = &proto_nfc },
#ifdef USE_NETROM
	[PF_NETROM] = { .proto = &proto_netrom },
#endif
	[PF_NETLINK] = { .proto = &proto_netlink },
#ifdef USE_ROSE
	[PF_ROSE] = { .proto = &proto_rose },
#endif
	[PF_ATMPVC] = { .proto = &proto_atmpvc },
	[PF_ATMSVC] = { .proto = &proto_atmsvc },
	[PF_NETBEUI] = { .proto = &proto_netbeui },
	[PF_PPPOX] = { .proto = &proto_pppol2tp },
	[PF_IUCV] = { .proto = &proto_iucv },
	[PF_RXRPC] = { .proto = &proto_rxrpc },
#ifdef USE_IF_ALG
	[PF_ALG] = { .proto = &proto_alg },
#endif
	[PF_KCM] = { .proto = &proto_kcm },
	[PF_QIPCRTR] = { .proto = &proto_qipcrtr },
	[PF_SMC] = { .proto = &proto_smc },
	[PF_XDP] = { .proto = &proto_xdp },
};
