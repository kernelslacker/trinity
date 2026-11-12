/*
 * Self-check for the AF_CAN sockaddr's ifindex: raw_bind() and
 * bcm_connect() (net/can/raw.c, bcm.c) take 0 for every CAN device and
 * refuse any other index with -ENODEV unless it names a CAN one, so most
 * draws are 0; the rest are small indices, which name real devices, or
 * random ones, which name none.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <linux/can.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_can */

#define CAN_ROUNDS	4000

void can_sockaddr_self_check(void);
void can_sockaddr_self_check(void)
{
	unsigned int i, any = 0, other = 0;

	for (i = 0; i < CAN_ROUNDS; i++) {
		struct sockaddr *addr = NULL;
		socklen_t len = 0;
		const struct sockaddr_can *sa;

		proto_can.gen_sockaddr(NULL, &addr, &len);
		sa = (const struct sockaddr_can *) addr;
		if (sa == NULL || len != sizeof(*sa) || sa->can_family != AF_CAN)
			BUG("can: a sockaddr that is no sockaddr_can");
		if (sa->can_ifindex == 0)
			any++;
		else
			other++;
		free(addr);
	}
	if (any < CAN_ROUNDS / 4 || other == 0)
		BUG("can: the ifindex raw_bind() and bcm_connect() take for any device is rare, or the only one");
}
