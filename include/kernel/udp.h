#pragma once

/*
 * UDP setsockopt / encap fallbacks for stripped sysroots without
 * <linux/udp.h>.  <linux/udp.h> is not included here because it
 * conflicts with <netinet/udp.h> (both define struct udphdr); the
 * consumer already pulls in <netinet/udp.h>, and these fallbacks
 * fill in any UDP_* setsockopt levels or encap ids missing from it.
 */

#ifndef UDP_NO_CHECK6_TX
#define UDP_NO_CHECK6_TX	101
#endif
#ifndef UDP_NO_CHECK6_RX
#define UDP_NO_CHECK6_RX	102
#endif
#ifndef UDP_GRO
#define UDP_GRO			104
#endif

#ifndef UDP_ENCAP_GTP0
#define UDP_ENCAP_GTP0		4
#endif
#ifndef UDP_ENCAP_GTP1U
#define UDP_ENCAP_GTP1U		5
#endif
#ifndef UDP_ENCAP_RXRPC
#define UDP_ENCAP_RXRPC		6
#endif

#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif
