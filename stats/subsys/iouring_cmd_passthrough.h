#ifndef _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H
#define _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H

struct iouring_cmd_passthrough_stats {
	/*
	 * Outcome counter for IORING_OP_URING_CMD with
	 * IORING_URING_CMD_MULTISHOT submitted to /dev/null.
	 *
	 * /dev/null's uring_cmd_null() returns 0 for every cmd_op but
	 * never calls io_cmd_poll_multishot() to set REQ_F_APOLL_MULTISHOT.
	 * The kernel then issues IOU_ISSUE_SKIP_COMPLETE, so no CQE is
	 * ever posted.  A non-zero count here means the bug-probe path
	 * was reached; absence of a CQE is the failure signature.
	 */
	unsigned long mshot_cmd_no_cqe;	/* multishot URING_CMD to /dev/null: no CQE arrived */
	/*
	 * Prep-time rejection counter.  Incremented by variant_socket() and
	 * variant_blockdev() when cqe->res is negative — the SQE was
	 * accepted by ring_enter() but the kernel rejected it during
	 * io_uring_cmd_prep() or the uring_cmd dispatch (e.g. -EINVAL from
	 * an unsupported flag combination).  A non-zero count reveals that
	 * the path was probed but not actually entered.
	 */
	unsigned long cqe_rejected;	/* socket/blockdev CQE returned errno (prep-time reject) */
	/*
	 * Nulldev URING_CMD rejection counter.  Incremented by
	 * variant_nulldev() when the URING_CMD CQE arrives with a
	 * negative result — the submission was rejected at prep time
	 * (-EINVAL: unsupported flag combination; -EOPNOTSUPP: cmd_op not
	 * handled) before reaching uring_cmd_null().  A non-zero count
	 * here means the flag-rotation picker selected a combination that
	 * did not survive io_uring_cmd_prep().
	 */
	unsigned long nulldev_cmd_rejected;	/* nulldev URING_CMD CQE returned errno */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H */
