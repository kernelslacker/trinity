#ifndef _TRINITY_STATS_SUBSYS_IOURING_SEND_ZC_CHURN_H
#define _TRINITY_STATS_SUBSYS_IOURING_SEND_ZC_CHURN_H

struct iouring_send_zc_churn_stats {
	/* iouring_send_zc_churn childop counters */
	unsigned long runs;			/* total iouring_send_zc_churn invocations */
	unsigned long setup_failed;		/* io_uring_setup / mmap / loopback / SO_ZEROCOPY / unsupported latch fired */
	unsigned long register_bufs_ok;		/* io_uring_register(IORING_REGISTER_BUFFERS) accepted */
	unsigned long send_zc_ok;			/* IORING_OP_SEND_ZC SQE submitted (io_uring_enter returned >=0) */
	unsigned long sendmsg_zc_ok;		/* IORING_OP_SENDMSG_ZC SQE submitted (io_uring_enter returned >=0) */
	unsigned long unregister_race_ok;		/* IORING_UNREGISTER_BUFFERS accepted mid-flight (rsrc-node race window opened) */
	unsigned long update_race_ok;		/* IORING_REGISTER_BUFFERS_UPDATE replaced slot 0 mid-flight (imu_index race window opened) */
	unsigned long cqe_drained;		/* CQE reaped from the completion ring (ZC notif or send completion) */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_SEND_ZC_CHURN_H */
