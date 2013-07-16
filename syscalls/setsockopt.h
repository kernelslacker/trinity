/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <bits/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <netinet/udp.h>
#include <netipx/ipx.h>
#include <netatalk/at.h>
#include <netax25/ax25.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include "compat.h"
#include "config.h"
#include "trinity.h"

#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>
#endif

#define SOL_IUCV        277
#define SOL_CAIF        278
#define SOL_ALG         279
#define SOL_NFC		280

#define NR_SOL_IUCV_OPTS ARRAY_SIZE(iucv_opts)
static int iucv_opts[] = {
	SO_IPRMDATA_MSG, SO_MSGLIMIT, SO_MSGSIZE };

#ifdef USE_CAIF
#define NR_SOL_CAIF_OPTS ARRAY_SIZE(caif_opts)
static int caif_opts[] = {
	CAIFSO_LINK_SELECT, CAIFSO_REQ_PARAM };
#endif
