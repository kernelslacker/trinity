#pragma once

#include <linux/rds.h>

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

