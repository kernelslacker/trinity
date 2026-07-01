#pragma once

#include <linux/mctp.h>
#include <linux/sockios.h>

#ifndef SIOCMCTPALLOCTAG
#define SIOCMCTPALLOCTAG	(SIOCPROTOPRIVATE + 0)
#define SIOCMCTPDROPTAG		(SIOCPROTOPRIVATE + 1)
struct mctp_ioc_tag_ctl {
	mctp_eid_t	peer_addr;
	__u8		tag;
	__u16		flags;
};
#endif

#ifndef MCTP_NET_ANY
#define MCTP_NET_ANY		0x0
#endif
#ifndef MCTP_ADDR_NULL
#define MCTP_ADDR_NULL		0x00
#endif
#ifndef MCTP_ADDR_ANY
#define MCTP_ADDR_ANY		0xff
#endif
#ifndef MCTP_TAG_MASK
#define MCTP_TAG_MASK		0x07
#endif
#ifndef MCTP_TAG_OWNER
#define MCTP_TAG_OWNER		0x08
#endif
#ifndef MCTP_OPT_ADDR_EXT
#define MCTP_OPT_ADDR_EXT	1
#endif
