/*
 * Self-check for the PACKET_FANOUT argument: fanout_add()
 * (net/packet/af_packet.c) reads the int as struct fanout_args' first
 * word, the group id in the low 16 bits and the type with its flags in
 * the high 16, so the type drawn lands there, and more than one.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "net.h"		/* struct sockopt, proto_packet */

#define PACKET_ROUNDS		4000
/* include/uapi/linux/if_packet.h: the PACKET_FANOUT_FLAG_* bits */
#define PACKET_FANOUT_FLAGS	0xf000

void packet_sockopt_self_check(void);
void packet_sockopt_self_check(void)
{
	unsigned int i, fanouts = 0, hashes = 0;
	unsigned int *optval;

	optval = calloc(1, page_size);
	if (optval == NULL)
		BUG("packet: no buffer for the option payload");

	for (i = 0; i < PACKET_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int type_flags;

		proto_packet.setsockopt(&so, NULL);
		if (so.optname != PACKET_FANOUT)
			continue;

		fanouts++;
		type_flags = *optval >> 16;
		if (type_flags & ~(0xff | PACKET_FANOUT_FLAGS))
			BUG("packet: a fanout carries type_flags bits fanout_add() knows nothing of");
		if ((type_flags & 0xff) > PACKET_FANOUT_EBPF)
			BUG("packet: a fanout type past the last one");
		if ((type_flags & 0xff) == PACKET_FANOUT_HASH)
			hashes++;
	}
	free(optval);

	if (fanouts == 0)
		BUG("packet: no PACKET_FANOUT drawn");
	if (hashes == fanouts)
		BUG("packet: every fanout group is a hash one");
}
