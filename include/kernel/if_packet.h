#pragma once

#include <linux/if_packet.h>

/* UAPI fallbacks for stripped sysroots without <linux/if_packet.h>.
 * Older headers may predate these PACKET_FANOUT_* names; define the
 * bits locally so the fuzzer can name them even when building against
 * an old UAPI header. */
#ifndef PACKET_FANOUT_FLAG_IGNORE_OUTGOING
#define PACKET_FANOUT_FLAG_IGNORE_OUTGOING	0x4000
#endif
#ifndef PACKET_FANOUT_HASH
#define PACKET_FANOUT_HASH		0
#endif
