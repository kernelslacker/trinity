#ifndef _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H
#define _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H

struct rds_zcopy_crafted_send_stats {
	/* rds_zcopy_crafted_send childop counters */
	unsigned long runs;			/* total rds_zcopy_crafted_send invocations */
	unsigned long setup_failed;		/* socket(AF_RDS) / bind / SO_ZEROCOPY / mmap / unsupported latch fired */
	unsigned long bind_ok;			/* bind(AF_RDS, 127.0.0.1:0) accepted */
	unsigned long zc_enable_ok;		/* setsockopt(SO_ZEROCOPY, 1) accepted on the AF_RDS sock */
	unsigned long hole_ok;			/* munmap punched a hole in the backing region (pin walk will fault) */
	unsigned long sends_ok;			/* sendmsg(MSG_ZEROCOPY) returned >=0 (full pin walk completed) */
	unsigned long sends_efault;		/* sendmsg(MSG_ZEROCOPY) returned EFAULT (partial-pin unwind reached) */
	unsigned long sends_failed;		/* sendmsg(MSG_ZEROCOPY) returned a non-EFAULT error (any errno) */
	unsigned long errqueue_drained;		/* recvmsg(MSG_ERRQUEUE) drained at least one zcopy completion cookie */
};

#endif /* _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H */
