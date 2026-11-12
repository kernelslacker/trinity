/*
 * Self-check for the AF_NETLINK option builder: netlink_setsockopt()
 * (net/netlink/af_netlink.c) refuses a membership of group 0, or of one
 * past the protocol's groups, which __netlink_kernel_create() makes 32 at
 * the least, and turns a flag on for any value but 0, so most memberships
 * drawn name a group from 1 to 32, and flags are drawn both ways.
 */

#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_netlink, struct sockopt */

#define NETLINK_ROUNDS		4000
#define NETLINK_OPTVAL_LEN	4096

void netlink_sockopt_self_check(void);
void netlink_sockopt_self_check(void)
{
	struct socket_triplet route = {
		.family = PF_NETLINK, .type = SOCK_RAW,
		.protocol = NETLINK_ROUTE,
	};
	static unsigned char optval[NETLINK_OPTVAL_LEN];
	unsigned int i, groups = 0, joinable = 0, flags = 0, on = 0;

	for (i = 0; i < NETLINK_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		proto_netlink.setsockopt(&so, &route);
		memcpy(&val, optval, sizeof(val));

		switch (so.optname) {
		case NETLINK_ADD_MEMBERSHIP:
		case NETLINK_DROP_MEMBERSHIP:
			groups++;
			if (val >= 1 && val <= 32)
				joinable++;
			break;
		case NETLINK_PKTINFO:
		case NETLINK_BROADCAST_ERROR:
		case NETLINK_NO_ENOBUFS:
		case NETLINK_LISTEN_ALL_NSID:
		case NETLINK_CAP_ACK:
		case NETLINK_EXT_ACK:
		case NETLINK_GET_STRICT_CHK:
			flags++;
			if (val != 0)
				on++;
			break;
		}
	}

	if (groups == 0 || joinable < groups * 3 / 4)
		BUG("netlink: a membership of a group the socket can join is rare");
	if (flags == 0 || on == 0 || on == flags)
		BUG("netlink: a flag is never turned on, or never off");
}
