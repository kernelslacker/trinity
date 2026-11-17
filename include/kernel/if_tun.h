#pragma once

#include <linux/if_tun.h>

#ifndef TUN_F_CSUM
#define TUN_F_CSUM	0x01
#endif
#ifndef TUN_F_TSO4
#define TUN_F_TSO4	0x02
#endif
#ifndef TUN_F_TSO6
#define TUN_F_TSO6	0x04
#endif
#ifndef TUN_F_TSO_ECN
#define TUN_F_TSO_ECN	0x08
#endif
#ifndef TUN_F_UFO
#define TUN_F_UFO	0x10
#endif
#ifndef TUN_F_USO4
#define TUN_F_USO4	0x20
#endif
#ifndef TUN_F_USO6
#define TUN_F_USO6	0x40
#endif
#ifndef TUN_F_UDP_TUNNEL_GSO
#define TUN_F_UDP_TUNNEL_GSO	0x80
#endif
#ifndef TUN_F_UDP_TUNNEL_GSO_CSUM
#define TUN_F_UDP_TUNNEL_GSO_CSUM	0x100
#endif
