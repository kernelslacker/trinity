/*
 * Self-check for the CAN option builders: isotp_setsockopt_locked()
 * (net/can/isotp.c) takes CAN_ISOTP_LL_OPTS only with the MTU of CAN or
 * CAN FD and a data length padlen() keeps, 8, 12, 16, 20, 24, 32, 48 or
 * 64, and with the classic MTU only 8 and no tx_flags, so the link-layer
 * options drawn are ones it takes.
 */

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/isotp.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_can, struct sockopt */

#define CAN_ROUNDS	4000
#define CAN_OPTVAL_LEN	4096

static bool isotp_ll_taken(const struct can_isotp_ll_options *ll)
{
	switch (ll->tx_dl) {
	case 8: case 12: case 16: case 20: case 24: case 32: case 48: case 64:
		break;
	default:
		return false;
	}
	if (ll->mtu == CAN_MTU)
		return ll->tx_dl <= CAN_MAX_DLEN && ll->tx_flags == 0;
	return ll->mtu == CANFD_MTU;
}

void can_sockopt_self_check(void);
void can_sockopt_self_check(void)
{
	struct socket_triplet isotp = {
		.family = PF_CAN, .type = SOCK_DGRAM, .protocol = CAN_ISOTP,
	};
	static unsigned char optval[CAN_OPTVAL_LEN];
	unsigned int i, ll = 0, taken = 0;

	for (i = 0; i < CAN_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };

		memset(optval, 0, sizeof(optval));
		proto_can.setsockopt(&so, &isotp);
		if (so.level != SOL_CAN_ISOTP || so.optname != CAN_ISOTP_LL_OPTS)
			continue;

		ll++;
		if (isotp_ll_taken((const struct can_isotp_ll_options *) optval))
			taken++;
	}

	if (ll == 0)
		BUG("can: no ISO-TP link-layer option drawn");
	if (taken < ll * 3 / 4)
		BUG("can: the ISO-TP link-layer options the kernel takes are rare");
}
