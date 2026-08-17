/*
 * iouring_cmd_passthrough - IORING_OP_URING_CMD per-fd cmd_op dispatch.
 *
 * IORING_OP_URING_CMD is io_uring's escape hatch into
 * file_operations.uring_cmd; each subsystem defines its own cmd_op
 * enum and payload.  The existing iouring-recipes catalog uses only
 * standard opcodes and never reaches these per-fd cmd_op switches,
 * and random SQE fuzzing almost never assembles a structurally-valid
 * uring_cmd dispatch.  Target functions: io_uring_cmd_sock,
 * nvme_dev_uring_cmd, blkdev_uring_cmd (fuse/btrfs handlers are TODO
 * -- see arm notes below).
 *
 * Brick-safety (host kernel, not a VM):
 *   socket   - always safe; in-kernel state on a loopback AF_INET
 *              socket per invocation.
 *   blockdev - only /dev/loopN whose backing_file is absent
 *              (unbound); bound loops are skipped regardless of what
 *              they back.  Unbound loops error early in
 *              blkdev_uring_cmd_discard's validation before touching
 *              storage, but the dispatch switch has already run.
 *   nvme     - loop-transport controllers only; restricted to read-
 *              only ADMIN ops (IDENTIFY / GET_FEATURES /
 *              GET_LOG_PAGE).  Currently detected-but-skipped -- the
 *              72-byte nvme_uring_cmd struct only fits in an SQE128
 *              ring and this op uses the standard 64-byte SQE form.
 *   fuse     - TODO, needs a trinity-owned fuse session fd (touching
 *              host mounts like edenfs/gdrive would corrupt data).
 *   btrfs    - TODO, needs a trinity-owned btrfs mount for the
 *              ENCODED_READ/WRITE handlers.
 *
 * SQE form: standard 64-byte SQE; cmd_op rides in the off union and
 * inline payload goes through addr/level/optname/optval/addr3.
 * SQE128 not used here.  Variants probed once per invocation (few
 * sysfs opens, cached in a per-process static).
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "syscall-gate.h"
#include "childops-iouring.h"
#include "childops/io_uring/ring.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/io_uring.h"
#include "kernel/blkdev.h"
#include "kernel/socket.h"
#include "kernel/unistd.h"
/* Per-process variant availability cache.  Populated lazily by
 * probe_variants() on the first invocation in this child; subsequent
 * invocations hit the cached result.  Each child re-probes once
 * because the per-process state is fork-local — that's intentional:
 * the probe is cheap and it keeps the cache out of shm where a
 * sibling teardown of the source state (an unbound loop binding mid
 * run, a loop-backed nvme target going away) would otherwise leak
 * into our pick. */
struct variant_cache {
	bool	probed;
	bool	socket_ok;
	bool	blockdev_ok;
	int	loop_minor;	/* /dev/loopN to use when blockdev_ok */
};

static struct variant_cache vcache;

/*
 * Walk /sys/block/loop* and pick the lowest-numbered loop that has no
 * binding.  Two checks:
 *
 *   1. /sys/block/loopN/loop/backing_file does not exist — the
 *      "loop/" subdir is only created once a backing file has been
 *      attached, so its absence means the loop is unbound.
 *   2. /sys/block/loopN/loop/backing_file exists but reads as the
 *      empty string (after the trailing newline is stripped) — the
 *      kernel writes a zero-length file when no backing file is
 *      currently attached after a previous detach.
 *
 * Either condition makes /dev/loopN safe to open for the
 * BLOCK_URING_CMD_DISCARD path: blkdev_uring_cmd's discard handler
 * will error out before any backing storage is touched.
 *
 * Returns the chosen loop minor number, or -1 if no unbound loop is
 * reachable.
 */
static int find_unbound_loop(void)
{
	DIR *d;
	struct dirent *e;
	int best = -1;

	d = opendir("/sys/block");
	if (!d)
		return -1;

	while ((e = readdir(d)) != NULL) {
		int minor;
		char path[PATH_MAX];
		struct stat st;
		int fd;
		ssize_t n;
		char buf[64];

		if (sscanf(e->d_name, "loop%d", &minor) != 1)
			continue;
		if (minor < 0)
			continue;

		snprintf(path, sizeof(path),
			 "/sys/block/%s/loop/backing_file", e->d_name);

		if (stat(path, &st) < 0) {
			/* loop/ subdir absent — loop is unbound. */
			if (best < 0 || minor < best)
				best = minor;
			continue;
		}

		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0) {
			/* Empty backing_file — the loop's backing was
			 * detached.  Equivalent to unbound for our
			 * purposes. */
			if (best < 0 || minor < best)
				best = minor;
			continue;
		}
		buf[n] = '\0';
		/* Strip a single trailing newline; if anything else
		 * remains the loop is bound to a backing path we don't
		 * own and must not touch. */
		if (buf[n - 1] == '\n')
			buf[n - 1] = '\0';
		if (buf[0] == '\0') {
			if (best < 0 || minor < best)
				best = minor;
		}
	}

	closedir(d);
	return best;
}

/*
 * Walk /sys/class/nvme and check whether any controller has
 * transport == "loop".  That's the nvme_loop driver (CONFIG_NVME_TARGET_LOOP),
 * which exposes a fully in-kernel target — safe to drive ADMIN
 * IDENTIFY / GET_FEATURES / GET_LOG_PAGE against without touching
 * any persistent storage.
 *
 * Returns true if at least one loop-backed nvme controller is
 * present.  The caller does not currently use the controller
 * identifier — the nvme variant is currently stub-only (see
 * file header) — but the probe still runs so the surface presence
 * is logged for the eventual SQE128-enabled implementation.
 */
static bool probe_loop_nvme(void)
{
	DIR *d;
	struct dirent *e;
	bool found = false;

	d = opendir("/sys/class/nvme");
	if (!d)
		return false;

	while ((e = readdir(d)) != NULL) {
		char path[PATH_MAX];
		int fd;
		ssize_t n;
		char buf[32];

		if (e->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path),
			 "/sys/class/nvme/%s/transport", e->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		if (buf[n - 1] == '\n')
			buf[n - 1] = '\0';

		if (strcmp(buf, "loop") == 0) {
			found = true;
			break;
		}
	}

	closedir(d);
	return found;
}

static void probe_variants(void)
{
	if (vcache.probed)
		return;

	vcache.socket_ok = true;
	vcache.loop_minor = find_unbound_loop();
	vcache.blockdev_ok = (vcache.loop_minor >= 0);
	(void)probe_loop_nvme();	/* surface presence; nvme variant stubbed */

	vcache.probed = true;
}

/* ------------------------------------------------------------------ *
 * Ring lifecycle.  Trimmed mirror of childops/io_uring/recipes.c —
 * this childop only needs single-SQE submit/drain so the per-iter
 * teardown is straightforward.
 * ------------------------------------------------------------------ */

static bool ring_submit_sqe(struct iour_ring *ctx, struct io_uring_sqe *sqe)
{
	unsigned int mask = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	unsigned int head = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	unsigned int tail = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int slot;

	if (ctx->sq_entries - (tail - head) < 1)
		return false;

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);
	slot = tail & mask;
	sqes[slot] = *sqe;
	sq_array[slot] = slot;

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + 1);
	return true;
}

static int ring_enter(struct iour_ring *ctx, unsigned int n,
		      unsigned int min_complete)
{
	return (int)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, n, min_complete,
			    IORING_ENTER_GETEVENTS, NULL, 0);
}

/*
 * Drain all available CQEs and return the ->res of the first one (the
 * one just submitted).  Returns 0 when no CQE arrived — should not
 * happen after a min_complete=1 ring_enter, but is safe to handle.
 */
static int ring_drain_cqes_first_res(struct iour_ring *ctx)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	int res = 0;

	if (head != tail) {
		unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
		volatile struct io_uring_cqe *cqes =
			(volatile struct io_uring_cqe *)((char *)ctx->cq_ring +
							 ctx->cq_off_cqes);
		res = cqes[head & mask].res;
	}

	while (head != tail) {
		head++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
	return res;
}

/*
 * Drain all available CQEs without blocking and return the number
 * consumed.  Used by variant_nulldev to detect the absence of a CQE
 * after a multishot URING_CMD submission.
 */

static void sqe_clear(struct io_uring_sqe *s)
{
	memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------ *
 * uring_cmd_flags rotation.
 *
 * Two pickers exist because io_uring_cmd_prep() rejects
 * IORING_URING_CMD_MULTISHOT unless the SQE also carries
 * IOSQE_BUFFER_SELECT.  variant_socket and variant_blockdev build from
 * sqe_clear() and never set IOSQE_BUFFER_SELECT, so supplying MULTISHOT
 * there causes prep to fail with -EINVAL before reaching ->uring_cmd().
 * That is coverage-negative: the rotation wastes half its slots on
 * guaranteed prep rejects.
 *
 * pick_uring_cmd_flags_no_mshot() — for socket / blockdev:
 *   0                            - baseline; no flags
 *   IORING_URING_CMD_FIXED       - reaches io_uring_cmd_import_fixed()
 *                                  (fails -EINVAL here: no buffer table
 *                                  registered, but the validation path
 *                                  is still exercised)
 *
 * pick_uring_cmd_flags() — for nulldev, which sets IOSQE_BUFFER_SELECT
 *                          unconditionally.  io_uring_cmd_prep() enforces
 *                          a biconditional: prep passes if and only if
 *                          MULTISHOT is set when BUFFER_SELECT is present.
 *   IORING_URING_CMD_MULTISHOT   - passes the biconditional; reaches
 *                                  ->uring_cmd() (uring_cmd_null).
 *   FIXED|MULTISHOT              - rejected by the mutual-exclusion check
 *                                  in io_uring_cmd_prep() before the
 *                                  biconditional (-EINVAL), so it never
 *                                  reaches ->uring_cmd().  Kept as a
 *                                  deliberate negative probe providing a
 *                                  standing assertion that the mutual-
 *                                  exclusion check still exists.  Counted
 *                                  separately as fixed_multishot_prep_rejected
 *                                  so these draws do not dilute the oracle
 *                                  denominator (nulldev_mshot_attempts counts
 *                                  only plain-MULTISHOT draws).
 * ------------------------------------------------------------------ */

static const __u32 uring_cmd_flag_variants_no_mshot[] = {
	0,
	IORING_URING_CMD_FIXED,
};

static __u32 pick_uring_cmd_flags_no_mshot(void)
{
	return uring_cmd_flag_variants_no_mshot[
		rnd_modulo_u32(ARRAY_SIZE(uring_cmd_flag_variants_no_mshot))];
}

static const __u32 uring_cmd_flag_variants[] = {
	IORING_URING_CMD_MULTISHOT,
	IORING_URING_CMD_FIXED | IORING_URING_CMD_MULTISHOT,
};

static __u32 pick_uring_cmd_flags(void)
{
	return uring_cmd_flag_variants[
		rnd_modulo_u32(ARRAY_SIZE(uring_cmd_flag_variants))];
}

/* ------------------------------------------------------------------ *
 * Variant: socket
 *
 * io_uring_cmd_sock dispatches SOCKET_URING_OP_{SIOCINQ, SIOCOUTQ,
 * GETSOCKOPT, SETSOCKOPT}.  SIOCINQ / SIOCOUTQ read socket queue
 * length state with no payload; the SETSOCKOPT / GETSOCKOPT paths
 * read level / optname / optval / optlen from the SQE union fields
 * (no inline cmd[] needed).  All four are issued against a freshly
 * created loopback AF_INET socket so the dispatch can succeed without
 * any external state.
 *
 * Pick one cmd_op per invocation rather than burst-submitting all
 * four — gives the kernel-side dispatch a clean teardown between
 * ops, and matches the "one logical concern per submission" cadence
 * the rest of the iouring-recipes catalog uses.
 * ------------------------------------------------------------------ */

#ifndef TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP
static const __u32 sock_cmd_ops[] = {
	SOCKET_URING_OP_SIOCINQ,
	SOCKET_URING_OP_SIOCOUTQ,
	SOCKET_URING_OP_GETSOCKOPT,
	SOCKET_URING_OP_SETSOCKOPT,
};

static bool variant_socket(struct iour_ring *ctx, unsigned long *direct_calls,
			   const bool valid_op)
{
	struct io_uring_sqe sqe;
	int sock_fd = -1;
	int reuseval = 1;
	__u32 cmd_op;
	bool ok = false;
	int r;

	sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock_fd < 0)
		return false;

	cmd_op = sock_cmd_ops[rnd_modulo_u32(ARRAY_SIZE(sock_cmd_ops))];

	sqe_clear(&sqe);
	sqe.opcode          = IORING_OP_URING_CMD;
	sqe.fd              = sock_fd;
	sqe.cmd_op          = cmd_op;
	sqe.uring_cmd_flags = pick_uring_cmd_flags_no_mshot();
	sqe.user_data       = 0xc0d0;

	if (cmd_op == SOCKET_URING_OP_SETSOCKOPT) {
		/* level / optname overlay the addr union; optval / optlen
		 * overlay the optval / optlen union at the SQE tail. */
		sqe.level   = SOL_SOCKET;
		sqe.optname = SO_REUSEADDR;
		sqe.optval  = (__u64)(uintptr_t)&reuseval;
		sqe.optlen  = (__u32)sizeof(reuseval);
	} else if (cmd_op == SOCKET_URING_OP_GETSOCKOPT) {
		sqe.level   = SOL_SOCKET;
		sqe.optname = SO_TYPE;
		sqe.optval  = (__u64)(uintptr_t)&reuseval;
		sqe.optlen  = (__u32)sizeof(reuseval);
	}

	if (!ring_submit_sqe(ctx, &sqe))
		goto out;

	(*direct_calls)++;
	r = ring_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	{
		int cqe_res = ring_drain_cqes_first_res(ctx);

		ok = (cqe_res >= 0);
		if (cqe_res < 0 && valid_op)
			__atomic_add_fetch(
				&shm->stats.iouring_cmd_passthrough.cqe_rejected,
				1, __ATOMIC_RELAXED);
	}
out:
	if (sock_fd >= 0)
		close(sock_fd);
	return ok;
}
#endif /* TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP */

/* ------------------------------------------------------------------ *
 * Variant: blockdev
 *
 * blkdev_uring_cmd dispatches BLOCK_URING_CMD_DISCARD on a block
 * device fd.  The DISCARD payload is two u64s — start offset and
 * length — read from sqe->addr and sqe->addr3 respectively.  Both
 * fit in the standard 64-byte SQE.
 *
 * Open the unbound loop minor identified by find_unbound_loop().
 * blkdev_uring_cmd_discard validates the byte range and the device's
 * discard capability before submitting any bio; on an unbound loop
 * the validation fails with -ENXIO (or -EOPNOTSUPP) before any
 * backing storage is touched.  The kernel still walks the per-fd
 * dispatch into blkdev_uring_cmd's switch and into the
 * BLOCK_URING_CMD_DISCARD arm, which is the surface this variant
 * exists to exercise.
 *
 * Re-validate the loop is still unbound right before opening — a
 * sibling could have bound it between the cached probe and now.
 * If it became bound, fall through and skip this invocation; the
 * cache will be re-checked next time.
 * ------------------------------------------------------------------ */

static bool loop_still_unbound(int minor)
{
	char path[PATH_MAX];
	struct stat st;
	int fd;
	ssize_t n;
	char buf[64];

	snprintf(path, sizeof(path),
		 "/sys/block/loop%d/loop/backing_file", minor);
	if (stat(path, &st) < 0)
		return true;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return true;
	buf[n] = '\0';
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	return buf[0] == '\0';
}

static bool variant_blockdev(struct iour_ring *ctx, unsigned long *direct_calls,
			     const bool valid_op)
{
	struct io_uring_sqe sqe;
	char devpath[PATH_MAX];
	int dev_fd = -1;
	bool ok = false;
	int r;

	if (vcache.loop_minor < 0)
		return false;

	if (!loop_still_unbound(vcache.loop_minor)) {
		/* Lost the unbound state since the cache was populated.
		 * Force a re-probe on the next invocation; for this one,
		 * skip rather than open a now-bound loop. */
		vcache.probed = false;
		return false;
	}

	snprintf(devpath, sizeof(devpath), "/dev/loop%d", vcache.loop_minor);
	dev_fd = open(devpath, O_RDWR | O_CLOEXEC);
	if (dev_fd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode          = IORING_OP_URING_CMD;
	sqe.fd              = dev_fd;
	sqe.cmd_op          = BLOCK_URING_CMD_DISCARD;
	sqe.addr            = 0;		/* start offset */
	sqe.addr3           = 4096;		/* length — one page */
	sqe.uring_cmd_flags = pick_uring_cmd_flags_no_mshot();
	sqe.user_data       = 0xc0d1;

	if (!ring_submit_sqe(ctx, &sqe))
		goto out;

	(*direct_calls)++;
	r = ring_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	{
		int cqe_res = ring_drain_cqes_first_res(ctx);

		ok = (cqe_res >= 0);
		if (cqe_res < 0 && valid_op)
			__atomic_add_fetch(
				&shm->stats.iouring_cmd_passthrough.cqe_rejected,
				1, __ATOMIC_RELAXED);
	}
out:
	if (dev_fd >= 0)
		close(dev_fd);
	return ok;
}

/* ------------------------------------------------------------------ *
 * Variant: nulldev
 *
 * Probes the IORING_URING_CMD_MULTISHOT flag path against /dev/null.
 * /dev/null's uring_cmd handler returns 0 for every cmd_op without
 * calling io_cmd_poll_multishot() to set REQ_F_APOLL_MULTISHOT, so the
 * kernel issues IOU_ISSUE_SKIP_COMPLETE and no CQE is ever posted.
 * This is the "unprivileged hang" bug surface this variant exists to
 * exercise: IOSQE_BUFFER_SELECT + IORING_URING_CMD_MULTISHOT submitted
 * against an fd whose uring_cmd handler ignores the multishot flag.
 *
 * Flow:
 *   1. PROVIDE_BUFFERS: register a small buffer group so the kernel
 *      accepts IOSQE_BUFFER_SELECT without -ENOBUFS.
 *   2. URING_CMD to /dev/null with IOSQE_BUFFER_SELECT +
 *      uring_cmd_flags = IORING_URING_CMD_MULTISHOT.
 *   3. ring_enter with min_complete=0 (no blocking wait) then drain;
 *      the CQE will not arrive because the req is pinned.
 *   4. Count the CQEs.  A zero count books the mshot_cmd_no_cqe
 *      outcome counter so the absence is visible in telemetry.
 * ------------------------------------------------------------------ */

#define NULLDEV_PBUF_GROUP_ID	7
#define NULLDEV_PBUF_COUNT	2
#define NULLDEV_PBUF_SIZE	64

/*
 * Cap on the number of times the nulldev mshot arm is allowed to confirm
 * the orphaned-request bug.  The bug is deterministic: a handful of hits
 * is conclusive proof.  Beyond this bound every iteration orphans an
 * io_kiocb + io_async_cmd that is never freed for the lifetime of the box
 * (IOU_ISSUE_SKIP_COMPLETE, no WARN, no back-pressure), so a long fuzz
 * run would silently grow unreclaimable slab.  Once the cap is reached
 * the variant returns early without touching the ring.
 */
#define NULLDEV_MSHOT_BUG_CAP	3

/*
 * Settle window for the CQE peek after ring_enter(min_complete=0).
 * A FIXED|MULTISHOT rejection CQE is posted at io_uring_cmd_prep()
 * time; under DEFER_TASKRUN, SQPOLL, or scheduling pressure the
 * head/tail update may not yet be visible at the first peek.  Retry
 * up to NULLDEV_CQE_SETTLE_ATTEMPTS × NULLDEV_CQE_SETTLE_DELAY_MS ms
 * before declaring no CQE.  A deadline-based loop (not a fixed
 * iteration count) ensures SIGALRM cannot shorten the window: SIGALRM
 * is armed without SA_RESTART in child/child.c and will interrupt
 * clock_nanosleep, but the outer loop re-probes to the wall-clock
 * deadline regardless of how many times the slice is interrupted.
 */
#define NULLDEV_CQE_SETTLE_ATTEMPTS	5
#define NULLDEV_CQE_SETTLE_DELAY_MS	20

static bool variant_nulldev(struct iour_ring *ctx, unsigned long *direct_calls,
			    const bool valid_op)
{
	/* Stop driving the arm once the bug is confirmed to the cap.  The
	 * bug is deterministic; there is no value in accumulating thousands
	 * of orphaned slab objects on a buggy kernel. */
	if (__atomic_load_n(
			&shm->stats.iouring_cmd_passthrough.mshot_cmd_no_cqe,
			__ATOMIC_RELAXED) >= NULLDEV_MSHOT_BUG_CAP)
		return false;
	struct io_uring_sqe sqe;
	void *pbuf = NULL;
	int null_fd = -1;
	int r;

	null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (null_fd < 0)
		return false;

	pbuf = malloc((size_t)NULLDEV_PBUF_COUNT * NULLDEV_PBUF_SIZE);
	if (!pbuf)
		goto out;

	/* PROVIDE_BUFFERS: hand the kernel a pool so IOSQE_BUFFER_SELECT
	 * can succeed the buffer-lookup phase. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)pbuf;
	sqe.len       = NULLDEV_PBUF_SIZE;
	sqe.fd        = NULLDEV_PBUF_COUNT;
	sqe.off       = 0;
	sqe.buf_group = NULLDEV_PBUF_GROUP_ID;
	sqe.user_data = 0xc0e0;

	if (!ring_submit_sqe(ctx, &sqe))
		goto out;

	(*direct_calls)++;
	r = ring_enter(ctx, 1, 1);
	if (r < 0)
		goto out;
	if (ring_drain_cqes_first_res(ctx) < 0)
		goto out;

	/* URING_CMD to /dev/null with MULTISHOT + BUFFER_SELECT. */
	{
	__u32 cmd_flags = pick_uring_cmd_flags();

	sqe_clear(&sqe);
	sqe.opcode          = IORING_OP_URING_CMD;
	sqe.fd              = null_fd;
	sqe.cmd_op          = 0;	/* any cmd_op; uring_cmd_null handles all */
	sqe.flags           = IOSQE_BUFFER_SELECT;
	sqe.buf_group       = NULLDEV_PBUF_GROUP_ID;
	sqe.uring_cmd_flags = cmd_flags;
	sqe.user_data       = 0xc0d2;

	if (!ring_submit_sqe(ctx, &sqe))
		goto out;

	(*direct_calls)++;

	/* Submit with min_complete=0: do not block.  A blocking wait with
	 * min_complete=1 would hang forever on the bug path because the
	 * req is pinned (IOU_ISSUE_SKIP_COMPLETE) and no CQE will arrive. */
	r = ring_enter(ctx, 1, 0);
	if (r < 0)
		goto out;

	/* Count only plain-MULTISHOT draws as oracle attempts, and only after
	 * ring_enter() succeeds.  pick_uring_cmd_flags() always returns a value
	 * with MULTISHOT set (either MULTISHOT alone or FIXED|MULTISHOT), so
	 * !(FIXED) is equivalent to plain-MULTISHOT — there is no third value
	 * with neither bit set.  FIXED|MULTISHOT draws are rejected by
	 * io_uring_cmd_prep() before reaching uring_cmd_null and must not
	 * contribute to the denominator, so the ratio
	 * mshot_cmd_no_cqe/nulldev_mshot_attempts stays unambiguous and the
	 * dead-arm check is exact.  Counting only after a successful ring_enter
	 * ensures transient failures (EINTR/EAGAIN/EBUSY) do not advance the
	 * denominator while leaving the numerator untouched. */
	if (valid_op && !(cmd_flags & IORING_URING_CMD_FIXED))
		__atomic_add_fetch(
			&shm->stats.iouring_cmd_passthrough.nulldev_mshot_attempts,
			1, __ATOMIC_RELAXED);

	{
		/* Peek head/tail before draining: ring_drain_cqes_first_res()
		 * returns 0 both when no CQE is available and when a CQE
		 * carries res=0.  Capture the presence of a CQE now so the
		 * ncqe==0 oracle survives the switch to first_res.
		 *
		 * Settle: a FIXED|MULTISHOT rejection CQE is posted at
		 * io_uring_cmd_prep() time and may not be visible at the
		 * first head/tail peek under DEFER_TASKRUN, SQPOLL, or plain
		 * scheduling pressure.  A false had_cqe=false here would
		 * advance mshot_cmd_no_cqe on a healthy kernel, potentially
		 * hitting NULLDEV_MSHOT_BUG_CAP and killing the arm for the
		 * rest of the run.  Retry for up to
		 * NULLDEV_CQE_SETTLE_ATTEMPTS × NULLDEV_CQE_SETTLE_DELAY_MS ms
		 * using a deadline-based loop; see 30d2c41af5c4 ("tc/qdisc-churn: make settle window EINTR-robust against SIGALRM bleed") for the same pattern. */
		const struct timespec gap = {
			.tv_sec  = 0,
			.tv_nsec = (long)NULLDEV_CQE_SETTLE_DELAY_MS * 1000000L,
		};
		struct timespec deadline, now;
		bool had_cqe;

		clock_gettime(CLOCK_MONOTONIC, &deadline);
		deadline.tv_nsec += (long)NULLDEV_CQE_SETTLE_DELAY_MS *
		                    NULLDEV_CQE_SETTLE_ATTEMPTS * 1000000L;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec  += deadline.tv_nsec / 1000000000L;
			deadline.tv_nsec  = deadline.tv_nsec % 1000000000L;
		}

		do {
			had_cqe = (ring_u32(ctx->cq_ring, ctx->cq_off_head) !=
			           ring_u32(ctx->cq_ring, ctx->cq_off_tail));
			if (had_cqe)
				break;
			/* SIGALRM may interrupt the slice; the deadline loop
			 * compensates — the full window always elapses. */
			(void)clock_nanosleep(CLOCK_MONOTONIC, 0, &gap, NULL);
			clock_gettime(CLOCK_MONOTONIC, &now);
		} while (now.tv_sec < deadline.tv_sec ||
		         (now.tv_sec == deadline.tv_sec &&
		          now.tv_nsec < deadline.tv_nsec));

		/* One final probe after the last settle sleep: the loop
		 * exits after sleeping without re-probing, so check
		 * head/tail once more rather than relying on the stale
		 * had_cqe from before the last sleep.  Mirrors the fix in
		 * 038587938c2f ("tc/qdisc-churn: atomic-exchange skip-sw
		 * latch, probe after settle"). */
		if (!had_cqe)
			had_cqe = (ring_u32(ctx->cq_ring, ctx->cq_off_head) !=
			           ring_u32(ctx->cq_ring, ctx->cq_off_tail));

		int cqe_res = ring_drain_cqes_first_res(ctx);

		if (!had_cqe) {
			/* No CQE: /dev/null's uring_cmd did not post a
			 * completion (IOU_ISSUE_SKIP_COMPLETE — req pinned).
			 * The absence is the bug-probe signal; count it.
			 *
			 * Guard matches the denominator: !(FIXED) selects
			 * plain-MULTISHOT draws.  pick_uring_cmd_flags()
			 * always returns MULTISHOT or FIXED|MULTISHOT — never
			 * a value with neither bit set — so !(FIXED) is
			 * exact.  A FIXED|MULTISHOT submission is rejected at
			 * prep before reaching uring_cmd_null, so its CQE may
			 * carry -EINVAL rather than being absent; counting it
			 * here would make mshot_cmd_no_cqe exceed
			 * nulldev_mshot_attempts, violating the oracle
			 * invariant. */
			if (valid_op && !(cmd_flags & IORING_URING_CMD_FIXED))
				__atomic_add_fetch(
					&shm->stats.iouring_cmd_passthrough.mshot_cmd_no_cqe,
					1, __ATOMIC_RELAXED);
		} else if (cqe_res < 0) {
			/* CQE arrived with negative result: prep rejected the
			 * submission before reaching uring_cmd_null.  Route to
			 * the appropriate counter based on the draw:
			 *
			 *  FIXED|MULTISHOT: rejected by the mutual-exclusion
			 *  check in io_uring_cmd_prep() (-EINVAL).  This is a
			 *  deliberate negative probe; count it separately so
			 *  it does not dilute the oracle denominator.
			 *
			 *  Plain MULTISHOT: rejected at prep for another reason
			 *  (-EOPNOTSUPP: cmd_op not handled).  The uring_cmd
			 *  dispatch path was reached but the op was refused.
			 */
			if (valid_op) {
				if (cmd_flags & IORING_URING_CMD_FIXED)
					__atomic_add_fetch(
						&shm->stats.iouring_cmd_passthrough.fixed_multishot_prep_rejected,
						1, __ATOMIC_RELAXED);
				else
					__atomic_add_fetch(
						&shm->stats.iouring_cmd_passthrough.nulldev_cmd_rejected,
						1, __ATOMIC_RELAXED);
			}
		}
	}
	} /* end cmd_flags scope */
out:
	free(pbuf);
	if (null_fd >= 0)
		close(null_fd);
	return true;
}

/* ------------------------------------------------------------------ *
 * Variant dispatch.  Each variant is tried only when its cache flag
 * says it's available; variant_socket additionally compiles out on
 * stale-LTS hosts whose uapi headers lack the .level/.optname/.optval/
 * .optlen SQE union members.  Pick one variant per invocation
 * uniformly across the available set.
 * ------------------------------------------------------------------ */

bool iouring_cmd_passthrough(struct childdata *child)
{
	struct iour_ring ctx;
	struct io_uring_params p;
	enum iour_setup_status st;
	enum { V_SOCKET, V_BLOCKDEV, V_NULLDEV, V_MAX };
	int avail[V_MAX];
	int navail = 0;
	/* Local direct-syscall tally.  Bumped once per ring_enter() call
	 * inside the picked variant — that is the sole
	 * trinity_raw_syscall(__NR_io_uring_enter) site in this op, and
	 * it issues exactly one raw syscall regardless of the kernel's
	 * return value.  Published once to shm at op-exit via
	 * childop_direct_syscalls_add() so the hot path pays one atomic
	 * add per invocation instead of per-syscall. */
	unsigned long direct_calls = 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (__atomic_load_n(&shm->iouring_enosys, __ATOMIC_RELAXED))
		return true;

	probe_variants();

#ifndef TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP
	if (vcache.socket_ok)
		avail[navail++] = V_SOCKET;
#endif
	if (vcache.blockdev_ok)
		avail[navail++] = V_BLOCKDEV;
	/* /dev/null is always present; V_NULLDEV probes IORING_URING_CMD_MULTISHOT. */
	avail[navail++] = V_NULLDEV;

	if (navail == 0)
		return true;

	memset(&p, 0, sizeof(p));
	st = iour_ring_setup(&p, 8, &ctx);
	if (st != IOUR_SUPPORTED) {
		/* Latch the per-process iouring_enosys gate only on a
		 * real "this kernel won't ever support io_uring"
		 * verdict.  A transient setup failure (ENOMEM / EAGAIN
		 * / EMFILE / overflow-rejected hostile return / mmap
		 * blip) skips this invocation but leaves siblings free
		 * to retry on the next dispatch. */
		if (st == IOUR_UNSUPPORTED) {
			__atomic_store_n(&shm->iouring_enosys, true,
					 __ATOMIC_RELAXED);
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return true;
	}
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	switch (avail[rnd_modulo_u32((unsigned int)navail)]) {
#ifndef TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP
	case V_SOCKET:
		variant_socket(&ctx, &direct_calls, valid_op);
		break;
#endif
	case V_BLOCKDEV:
		variant_blockdev(&ctx, &direct_calls, valid_op);
		break;
	case V_NULLDEV:
		variant_nulldev(&ctx, &direct_calls, valid_op);
		break;
	}

	iour_ring_teardown(&ctx);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
