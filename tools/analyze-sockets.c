#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/l2tp.h>
#include <linux/netlink.h>
#include <net/if_packet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "../include/utils.h"

struct family {
	const char *name;
	const unsigned int family;
};

struct protocol {
	const char *name;
	const unsigned int proto;
};

static const struct family families[] = {
	{ "PF_UNSPEC",       0 },
	{ "PF_LOCAL",        1 },
	{ "PF_UNIX",         PF_LOCAL },
	{ "PF_FILE",         PF_LOCAL },
	{ "PF_INET",         2 },
	{ "PF_AX25",         3 },
	{ "PF_IPX",          4 },
	{ "PF_APPLETALK",    5 },
	{ "PF_NETROM",       6 },
	{ "PF_BRIDGE",       7 },
	{ "PF_ATMPVC",       8 },
	{ "PF_X25",          9 },
	{ "PF_INET6",        10 },
	{ "PF_ROSE",         11 },
	{ "PF_DECnet",       12 },
	{ "PF_NETBEUI",      13 },
	{ "PF_SECURITY",     14 },
	{ "PF_KEY",          15 },
	{ "PF_NETLINK",      16 },
	{ "PF_ROUTE",        PF_NETLINK },
	{ "PF_PACKET",       17 },
	{ "PF_ASH",          18 },
	{ "PF_ECONET",       19 },
	{ "PF_ATMSVC",       20 },
	{ "PF_RDS",          21 },
	{ "PF_SNA",          22 },
	{ "PF_IRDA",         23 },
	{ "PF_PPPOX",        24 },
	{ "PF_WANPIPE",      25 },
	{ "PF_LLC",          26 },
	{ "PF_CAN",          29 },
	{ "PF_TIPC",         30 },
	{ "PF_BLUETOOTH",    31 },
	{ "PF_IUCV",         32 },
	{ "PF_RXRPC",        33 },
	{ "PF_ISDN",         34 },
	{ "PF_PHONET",       35 },
	{ "PF_IEEE802154",   36 },
	{ "PF_CAIF",         37 },
	{ "PF_ALG",          38 },
	{ "PF_NFC",          39 },
	{ "PF_VSOCK",        40 },
};

static const char * get_family_name(unsigned int family)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(families); i++)
		if (families[i].family == family)
			return families[i].name;
	return NULL;
}

static const char * get_proto_name(unsigned int family, unsigned int proto)
{
	char *str;
	unsigned int i;

	const struct protocol ip_protocols[] = {
		{ "IPPROTO_IP", IPPROTO_IP },
		{ "IPPROTO_ICMP", IPPROTO_ICMP },
		{ "IPPROTO_IGMP", IPPROTO_IGMP },
		{ "IPPROTO_IPIP", IPPROTO_IPIP },
		{ "IPPROTO_TCP", IPPROTO_TCP },
		{ "IPPROTO_EGP", IPPROTO_EGP },
		{ "IPPROTO_PUP", IPPROTO_PUP },
		{ "IPPROTO_UDP", IPPROTO_UDP },
		{ "IPPROTO_IDP", IPPROTO_IDP },
		{ "IPPROTO_TP", IPPROTO_TP },
		{ "IPPROTO_DCCP", IPPROTO_DCCP },
		{ "IPPROTO_IPV6", IPPROTO_IPV6 },
		{ "IPPROTO_RSVP", IPPROTO_RSVP },
		{ "IPPROTO_GRE", IPPROTO_GRE },
		{ "IPPROTO_ESP", IPPROTO_ESP },
		{ "IPPROTO_AH", IPPROTO_AH },
		{ "IPPROTO_MTP", IPPROTO_MTP },
		{ "IPPROTO_BEETPH", IPPROTO_BEETPH },
		{ "IPPROTO_ENCAP", IPPROTO_ENCAP },
		{ "IPPROTO_PIM", IPPROTO_PIM },
		{ "IPPROTO_COMP", IPPROTO_COMP },
		{ "IPPROTO_SCTP", IPPROTO_SCTP },
		{ "IPPROTO_UDPLITE", IPPROTO_UDPLITE },
		{ "IPPROTO_RAW", IPPROTO_RAW },
		{ "IPPROTO_L2TP", IPPROTO_L2TP },
	};

	const struct protocol netlink_proto[] = {
		{ "NETLINK_ROUTE", NETLINK_ROUTE },
		{ "NETLINK_UNUSED", NETLINK_UNUSED },
		{ "NETLINK_USERSOCK", NETLINK_USERSOCK },
		{ "NETLINK_FIREWALL", NETLINK_FIREWALL },
		{ "NETLINK_SOCK_DIAG", NETLINK_SOCK_DIAG },
		{ "NETLINK_NFLOG", NETLINK_NFLOG },
		{ "NETLINK_XFRM", NETLINK_XFRM },
		{ "NETLINK_SELINUX", NETLINK_SELINUX },
		{ "NETLINK_ISCSI", NETLINK_ISCSI },
		{ "NETLINK_AUDIT", NETLINK_AUDIT },
		{ "NETLINK_FIB_LOOKUP", NETLINK_FIB_LOOKUP },
		{ "NETLINK_CONNECTOR", NETLINK_CONNECTOR },
		{ "NETLINK_NETFILTER", NETLINK_NETFILTER },
		{ "NETLINK_IP6_FW", NETLINK_IP6_FW },
		{ "NETLINK_DNRTMSG", NETLINK_DNRTMSG },
		{ "NETLINK_KOBJECT_UEVENT", NETLINK_KOBJECT_UEVENT },
		{ "NETLINK_GENERIC", NETLINK_GENERIC },
		{ "NETLINK_SCSITRANSPORT", NETLINK_SCSITRANSPORT },
		{ "NETLINK_ECRYPTFS", NETLINK_ECRYPTFS },
		{ "NETLINK_RDMA", NETLINK_RDMA },
		{ "NETLINK_CRYPTO", NETLINK_CRYPTO },
		{ "NETLINK_SMC", NETLINK_SMC },
	};

	switch (family) {
	case AF_INET6:
	case AF_INET:
		for (i = 0; i < ARRAY_SIZE(ip_protocols); i++)
			if (ip_protocols[i].proto == proto)
				return ip_protocols[i].name;
		break;
	case AF_NETLINK:
		for (i = 0; i < ARRAY_SIZE(netlink_proto); i++) {
			if (netlink_proto[i].proto == proto)
				return netlink_proto[i].name;
		}
		break;
	}

	str = calloc(1, 80);
	sprintf(str, "Unknown(%u)", proto);
	return str;
}

static const char *decode_type(unsigned int type)
{
	char *str;

	switch (type) {
	case SOCK_STREAM:
		return "SOCK_STREAM";
	case SOCK_DGRAM:
		return "SOCK_DGRAM";
	case SOCK_RAW:
		return "SOCK_RAW";
	case SOCK_RDM:
		return "SOCK_RDM";
	case SOCK_SEQPACKET:
		return "SOCK_SEQPACKET";
	case SOCK_DCCP:
		return "SOCK_DCCP";
	case SOCK_PACKET:
		return "SOCK_PACKET";
	}
	str = calloc(1, 80);
	sprintf(str, "Unknown(%u)", type);
	return str;
}


static void open_sockets(char *cachefilename)
{
	int cachefile;
	unsigned int buffer[3];
	int bytesread = -1;
	unsigned int nr_sockets = 0;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0)
		return;

	while (bytesread != 0) {
		unsigned int family, type, protocol;

		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0)
			break;

		family = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		printf("family:%s type:%s protocol:%s\n",
			get_family_name(family),
			decode_type(type),
			get_proto_name(family, protocol));
		nr_sockets++;

	}

	printf("%u entries in socket cachefile.\n", nr_sockets);

	close(cachefile);
}

int main(int argc, char* argv[])
{
	if (argc < 1) {
		printf("Pass filename of socket file as argument.\n");
		exit(EXIT_FAILURE);
	}

	open_sockets(argv[1]);

	exit(EXIT_SUCCESS);
}
