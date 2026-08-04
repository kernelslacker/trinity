#pragma once

#include <linux/rds.h>
#include <linux/sockios.h>	/* SIOCPROTOPRIVATE for SIOCRDSSETTOS/SIOCRDSGETTOS */

#ifndef SO_RDS_TRANSPORT
#define SO_RDS_TRANSPORT	8
#endif
#ifndef SOL_RDS
#define SOL_RDS			276
#endif
#ifndef RDS_CMSG_ZCOPY_COOKIE
#define RDS_CMSG_ZCOPY_COOKIE	12
#endif

#ifndef RDS_CMSG_RDMA_ARGS
#define RDS_CMSG_RDMA_ARGS		1
struct rds_rdma_args {
	rds_rdma_cookie_t cookie;
	struct rds_iovec  remote_vec;
	__u64             local_vec_addr;
	__u64             nr_local;
	__u64             flags;
	__u64             user_token;
};
#endif

#ifndef RDS_CMSG_ATOMIC_FADD
#define RDS_CMSG_ATOMIC_FADD		6
#define RDS_CMSG_ATOMIC_CSWP		7
#define RDS_CMSG_MASKED_ATOMIC_FADD	8
#define RDS_CMSG_MASKED_ATOMIC_CSWP	9
struct rds_atomic_args {
	rds_rdma_cookie_t cookie;
	__u64             local_addr;
	__u64             remote_addr;
	union {
		struct { __u64 compare; __u64 swap; }                   cswp;
		struct { __u64 add; }                                   fadd;
		struct { __u64 compare; __u64 swap;
		         __u64 compare_mask; __u64 swap_mask; }         m_cswp;
		struct { __u64 add; __u64 nocarry_mask; }               m_fadd;
	};
	__u64             flags;
	__u64             user_token;
};
#endif

#ifndef RDS_CANCEL_SENT_TO
#define RDS_CANCEL_SENT_TO              1
#define RDS_GET_MR                      2
#define RDS_FREE_MR                     3
#define RDS_RECVERR                     5
#define RDS_CONG_MONITOR                6
#define RDS_GET_MR_FOR_DEST             7
#endif

#ifndef SO_RDS_MSG_RXPATH_LATENCY
#define SO_RDS_MSG_RXPATH_LATENCY	10
#endif

#ifndef RDS_INFO_FIRST
#define RDS_INFO_FIRST			10000
#define RDS_INFO_COUNTERS		10000
#define RDS_INFO_CONNECTIONS		10001
/* 10002 aka RDS_INFO_FLOWS is deprecated */
#define RDS_INFO_SEND_MESSAGES		10003
#define RDS_INFO_RETRANS_MESSAGES	10004
#define RDS_INFO_RECV_MESSAGES		10005
#define RDS_INFO_SOCKETS		10006
#define RDS_INFO_TCP_SOCKETS		10007
#define RDS_INFO_IB_CONNECTIONS		10008
#define RDS_INFO_CONNECTION_STATS	10009
#define RDS_INFO_IWARP_CONNECTIONS	10010
#define RDS6_INFO_CONNECTIONS		10011
#define RDS6_INFO_SEND_MESSAGES		10012
#define RDS6_INFO_RETRANS_MESSAGES	10013
#define RDS6_INFO_RECV_MESSAGES		10014
#define RDS6_INFO_SOCKETS		10015
#define RDS6_INFO_TCP_SOCKETS		10016
#define RDS6_INFO_IB_CONNECTIONS	10017
#define RDS_INFO_LAST			10017
#endif


#ifndef SIOCRDSSETTOS
/*
 * RDS Type-of-Service ioctls.  Both live at SIOCPROTOPRIVATE + {0,1}.
 * The argument is a rds_tos_t (u8); SET writes the per-socket TOS
 * field, GET reads it back.  Defined upstream in include/uapi/linux/rds.h
 * since v4.17 but absent from stripped sysroots.
 */
#define SIOCRDSSETTOS		SIOCPROTOPRIVATE
#define SIOCRDSGETTOS		(SIOCPROTOPRIVATE + 1)
#endif
