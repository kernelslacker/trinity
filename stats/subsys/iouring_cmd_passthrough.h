#ifndef _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H
#define _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H

struct iouring_cmd_passthrough_stats {
	/*
	 * Denominator for the nulldev multishot oracle.  Incremented once
	 * per variant_nulldev() invocation, after every precondition
	 * (open, PROVIDE_BUFFERS, ring_submit_sqe) has succeeded and
	 * immediately before the second ring_enter() call — i.e. only
	 * when we are about to ask the kernel to schedule the multishot
	 * URING_CMD.  Counts only plain IORING_URING_CMD_MULTISHOT draws;
	 * IORING_URING_CMD_FIXED|MULTISHOT draws (which the kernel rejects
	 * at prep before reaching uring_cmd_null) are excluded so the
	 * ratio is unambiguous.
	 *
	 * The bug is confirmed when:
	 *   mshot_cmd_no_cqe > 0 &&
	 *   mshot_cmd_no_cqe == nulldev_mshot_attempts
	 * (every oracle attempt failed — deterministic, not statistical).
	 * A zero for both means the arm was never selected or an earlier
	 * precondition failed; a zero for mshot_cmd_no_cqe alone with a
	 * non-zero attempts means the kernel is behaving correctly.
	 */
	unsigned long nulldev_mshot_attempts;	/* plain-MULTISHOT draws that reached ring_enter */
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
	 * negative result and the draw used plain IORING_URING_CMD_MULTISHOT
	 * — the submission was rejected at prep time (-EOPNOTSUPP: cmd_op
	 * not handled) before reaching uring_cmd_null().
	 */
	unsigned long nulldev_cmd_rejected;	/* nulldev plain-MULTISHOT CQE returned errno */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_CMD_PASSTHROUGH_H */
