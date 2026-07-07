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

#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS		20
#endif
#ifndef PACKET_ROLLOVER_STATS
#define PACKET_ROLLOVER_STATS		21
#endif
#ifndef PACKET_FANOUT_CBPF
#define PACKET_FANOUT_CBPF		6
#endif
#ifndef PACKET_FANOUT_EBPF
#define PACKET_FANOUT_EBPF		7
#endif
#define PACKET_VNET_HDR		15
#define PACKET_TX_TIMESTAMP	16
#define PACKET_TIMESTAMP	17
#define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#define PACKET_FANOUT_FLAG_UNIQUEID	0x2000
#define PACKET_FANOUT_FLAG_DEFRAG	0x8000
