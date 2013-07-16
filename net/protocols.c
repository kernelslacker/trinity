#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trinity.h"
#include "constants.h"
#include "net.h"

struct protocol {
	const char *name;
	const unsigned int proto;
};

static const struct protocol protocols[] = {
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

const char * get_proto_name(unsigned int proto)
{
	unsigned int i;

	for (i = 0; i < TRINITY_PF_MAX; i++)
		if (protocols[i].proto == proto)
			return protocols[i].name;
	return NULL;
}

void find_specific_proto(const char *protoarg)
{
	unsigned int i;

	if (specific_proto == 0) {
		/* we were passed a string */
		for (i = 0; i < ARRAY_SIZE(protocols); i++) {
			if (strcmp(protoarg, protocols[i].name) == 0) {
				specific_proto = protocols[i].proto;
				printf("Proto %s = %d\n", protoarg, specific_proto);
				break;
			}
		}
	} else {
		/* we were passed a numeric arg. */
		for (i = 0; i < TRINITY_PF_MAX; i++) {
			if (specific_proto == protocols[i].proto)
				break;
		}
	}

	if (i > TRINITY_PF_MAX) {
		printf("Protocol unknown. Pass a numeric value [0-%d] or one of ", TRINITY_PF_MAX);
		for (i = 0; i < ARRAY_SIZE(protocols); i++)
			printf("%s ", protocols[i].name);
		printf("\n");

		exit(EXIT_FAILURE);
	}

	printf("Using protocol %s (%u) for all sockets\n", protocols[i].name, protocols[i].proto);
}
