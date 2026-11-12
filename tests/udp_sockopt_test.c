/*
 * Self-check for the UDP option builders: udp_lib_setsockopt()
 * (net/ipv4/udp.c), which takes UDP's options on a UDP-Lite socket too,
 * reads an int for every option, refusing a shorter optlen, turns a flag
 * on for any value but 0, and takes UDP_ENCAP's ESP-in-UDP, L2TP or 0,
 * so the flags drawn turn both on and off, and most UDP_ENCAP and
 * UDP_SEGMENT draws are ones it takes.
 */

#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/udp.h>

#include "debug.h"		/* BUG */
#include "kernel/udp.h"		/* UDP_SEGMENT, UDP_GRO */
#include "net.h"		/* udp_setsockopt, udplite_setsockopt */

#define UDP_ROUNDS	6000
#define UDP_OPTVAL_LEN	4096

/* What of the kernel's rules the builder's draws break, or NULL. */
static const char *udp_options_refused(void (*build)(struct sockopt *,
						     struct socket_triplet *))
{
	static unsigned char optval[UDP_OPTVAL_LEN];
	unsigned int i, on = 0, off = 0;
	unsigned int encaps = 0, encaps_taken = 0, segments = 0, segments_taken = 0;

	for (i = 0; i < UDP_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		build(&so, NULL);
		memcpy(&val, optval, sizeof(val));

		switch (so.optname) {
		case UDP_CORK:
		case UDP_NO_CHECK6_TX:
		case UDP_NO_CHECK6_RX:
		case UDP_GRO:
			if (val != 0)
				on++;
			else
				off++;
			break;
		case UDP_ENCAP:
			encaps++;
			if (val == 0 || val == UDP_ENCAP_ESPINUDP ||
			    val == UDP_ENCAP_L2TPINUDP)
				encaps_taken++;
			break;
		case UDP_SEGMENT:
			segments++;
			if (so.optlen >= sizeof(int) && val <= USHRT_MAX)
				segments_taken++;
			break;
		}
	}

	if (on == 0 || off == 0)
		return "udp: the flag options never turn both on and off";
	if (encaps == 0 || encaps_taken < encaps * 3 / 4)
		return "udp: the UDP_ENCAP types the kernel takes are rare";
	if (segments == 0 || segments_taken < segments * 3 / 4)
		return "udp: the UDP_SEGMENT sizes the kernel takes are rare";
	return NULL;
}

void udp_sockopt_self_check(void);
void udp_sockopt_self_check(void)
{
	const char *refused;

	refused = udp_options_refused(udp_setsockopt);
	if (refused != NULL)
		BUG(refused);
	refused = udp_options_refused(udplite_setsockopt);
	if (refused != NULL)
		BUG(refused);
}
