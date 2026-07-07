#pragma once

/*
 * Wrapper around <linux/if_ether.h> that ships #ifndef-guarded fallbacks
 * for the ETH_P_* protocol IDs a few consumers were carrying inline.
 * Values are the stable kernel UAPI values; stripped sysroots may be
 * missing one or more of these symbols on older build hosts.
 */
#include <linux/if_ether.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL		0x0003
#endif
#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC		0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC		0x8848
#endif

#ifndef ETH_P_CANFD
#define ETH_P_CANFD	0x000D
#endif
#ifndef ETH_P_CAIF
#define ETH_P_CAIF	0x00F7
#endif
#ifndef ETH_P_802_3_MIN
#define ETH_P_802_3_MIN	0x0600
#endif

