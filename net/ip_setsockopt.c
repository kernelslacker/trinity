#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/mroute.h>
#include "sanitise.h"
#include "compat.h"
#include "maps.h"
#include "shm.h"
#include "net.h"
#include "config.h"
#include "random.h"
#include "trinity.h"	// ARRAY_SIZE

#define NR_SOL_IP_OPTS ARRAY_SIZE(ip_opts)
static int ip_opts[] = { IP_TOS, IP_TTL, IP_HDRINCL, IP_OPTIONS,
	IP_ROUTER_ALERT, IP_RECVOPTS, IP_RETOPTS, IP_PKTINFO,
	IP_PKTOPTIONS, IP_MTU_DISCOVER, IP_RECVERR, IP_RECVTTL,
	IP_RECVTOS, IP_MTU, IP_FREEBIND, IP_IPSEC_POLICY,
	IP_XFRM_POLICY, IP_PASSSEC, IP_TRANSPARENT,
	IP_ORIGDSTADDR, IP_MINTTL, IP_NODEFRAG,
	IP_MULTICAST_IF, IP_MULTICAST_TTL, IP_MULTICAST_LOOP,
	IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP,
	IP_UNBLOCK_SOURCE, IP_BLOCK_SOURCE,
	IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP,
	IP_MSFILTER,
	MCAST_JOIN_GROUP, MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE, MCAST_LEAVE_GROUP, MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP, MCAST_MSFILTER,
	IP_MULTICAST_ALL, IP_UNICAST_IF,
	MRT_INIT, MRT_DONE, MRT_ADD_VIF, MRT_DEL_VIF,
	MRT_ADD_MFC, MRT_DEL_MFC, MRT_VERSION, MRT_ASSERT,
	MRT_PIM, MRT_TABLE, MRT_ADD_MFC_PROXY, MRT_DEL_MFC_PROXY,
};

void ip_setsockopt(int childno)
{
	unsigned char val;

	val = rand() % NR_SOL_IP_OPTS;
	shm->a3[childno] = ip_opts[val];

	switch (ip_opts[val]) {
	case IP_PKTINFO:
	case IP_RECVTTL:
	case IP_RECVOPTS:
	case IP_RECVTOS:
	case IP_RETOPTS:
	case IP_TOS:
	case IP_TTL:
	case IP_HDRINCL:
	case IP_MTU_DISCOVER:
	case IP_RECVERR:
	case IP_ROUTER_ALERT:
	case IP_FREEBIND:
	case IP_PASSSEC:
	case IP_TRANSPARENT:
	case IP_MINTTL:
	case IP_NODEFRAG:
	case IP_UNICAST_IF:
	case IP_MULTICAST_TTL:
	case IP_MULTICAST_ALL:
	case IP_MULTICAST_LOOP:
	case IP_RECVORIGDSTADDR:
		if (rand_bool())
			shm->a5[childno] = sizeof(int);
		else
			shm->a5[childno] = sizeof(char);
		break;

	case IP_OPTIONS:
		shm->a5[childno] = rand() % 40;
		break;

	case IP_MULTICAST_IF:
	case IP_ADD_MEMBERSHIP:
	case IP_DROP_MEMBERSHIP:
		if (rand_bool())
			shm->a4[childno] = (unsigned long) page_allocs;

		if (rand_bool())
			shm->a5[childno] = sizeof(struct in_addr);
		else
			shm->a5[childno] = sizeof(struct ip_mreqn);
		break;

	case MRT_ADD_VIF:
	case MRT_DEL_VIF:
		shm->a5[childno] = sizeof(struct vifctl);
		break;

	case MRT_ADD_MFC:
	case MRT_ADD_MFC_PROXY:
	case MRT_DEL_MFC:
	case MRT_DEL_MFC_PROXY:
		shm->a5[childno] = sizeof(struct mfcctl);
		break;

	case MRT_TABLE:
		shm->a5[childno] = sizeof(__u32);
		break;

	case IP_MSFILTER:
		//FIXME: Read size from sysctl /proc/sys/net/core/optmem_max
		shm->a5[childno] = rand() % sizeof(unsigned long)*(2*UIO_MAXIOV+512);
		shm->a5[childno] |= IP_MSFILTER_SIZE(0);
		break;
	default:
		break;
	}
}
