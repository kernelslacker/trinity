/*
 * iouring_cmd_passthrough — IORING_OP_URING_CMD per-fd cmd_op dispatch.
 *
 * The IORING_OP_URING_CMD opcode is io_uring's escape hatch into the
 * per-fd file_operations.uring_cmd handler.  Each subsystem that
 * registers a uring_cmd handler defines its own cmd_op enum and
 * payload layout, and the kernel routes the SQE into the file's
 * ->uring_cmd which decodes cmd_op from the SQE tail and dispatches
 * to a subsystem-specific command path.
 *
 * Trinity's existing iouring-recipes catalog never reaches this
 * dispatch — every recipe uses standard opcodes (READ/WRITE/POLL/
 * RECV/SEND/...) with standard payloads.  IORING_OP_URING_CMD plus
 * its per-subsystem cmd_op handlers are a separate attack surface
 * that the random-syscall path also misses (random SQEs almost never
 * produce a structurally valid uring_cmd dispatch).  This childop
 * walks the per-fd dispatch deliberately, on whichever subsystems
 * are reachable on the running host without risking real data.
 *
 * Five subsystems expose ->uring_cmd in the upstream tree:
 *
 *   socket   io_uring_cmd_sock        SOCKET_URING_OP_SIOCINQ /
 *                                     SIOCOUTQ / GETSOCKOPT /
 *                                     SETSOCKOPT
 *   nvme     nvme_dev_uring_cmd       NVME_URING_CMD_ADMIN / IO and
 *                                     _VEC variants
 *   fuse     fuse_uring_cmd           FUSE_IO_URING_CMD_REGISTER /
 *                                     COMMIT_AND_FETCH
 *   btrfs    btrfs_uring_cmd          BTRFS_IOC_ENCODED_READ /
 *                                     ENCODED_WRITE (and _32)
 *   blockdev blkdev_uring_cmd         BLOCK_URING_CMD_DISCARD
 *
 * Safety model: this childop runs against the host kernel, not a VM,
 * so any IO it issues hits real devices and real filesystems.  The
 * variants are gated on runtime probes that exclude every path with a
 * data-loss risk:
 *
 *   socket   — always safe.  Exercises in-kernel socket state only;
 *              loopback AF_INET socket created per invocation.
 *
 *   nvme     — only loop-backed nvme controllers (transport == "loop"
 *              in /sys/class/nvme/nvmeN/transport).  Real PCIe / TCP /
 *              RDMA controllers are skipped — a stray write to a real
 *              storage namespace would be unrecoverable.  Even on a
 *              loop-backed target the cmd_op set is restricted to the
 *              read-only ADMIN side (IDENTIFY, GET_FEATURES,
 *              GET_LOG_PAGE).  No IO opcodes, no _VEC variants.
 *              Currently a stub: NVMe URING_CMD requires a 72-byte
 *              nvme_uring_cmd struct in the SQE's inline cmd[] tail,
 *              which only fits in an SQE128-sized ring.  This driver
 *              uses the standard 64-byte SQE form (see TODO below),
 *              so the nvme variant is detected-but-skipped pending
 *              SQE128 support.
 *
 *   blockdev — only /dev/loopN where /sys/block/loopN/loop/backing_file
 *              is absent (loop is unbound).  An unbound loop returns
 *              an error early in blkdev_uring_cmd_discard's validation
 *              before any backing storage is touched, but the kernel
 *              still walks the per-fd cmd_op dispatch into
 *              blkdev_uring_cmd's switch — which is the surface this
 *              childop is here to exercise.  Bound loops are skipped
 *              regardless of what they back; even a trinity-owned
 *              backing file would risk concurrent corruption from a
 *              sibling.
 *
 *   fuse     — currently not implemented.  fuse_uring_cmd handlers
 *              (REGISTER / COMMIT_AND_FETCH) require a fuse session
 *              fd from a mount that trinity owns and pinned in a
 *              reusable way, and the fuse-side childops infrastructure
 *              that would set that up does not yet exist.  Operating
 *              against a host fuse mount (gvfs, edenfs, gdrive, ...)
 *              would block the daemon or corrupt user data.  TODO:
 *              wire this up once a fuse-owning childop exists.
 *
 *   btrfs    — currently not implemented.  btrfs_uring_cmd handlers
 *              (ENCODED_READ / ENCODED_WRITE) require a btrfs file
 *              fd inside a mount trinity owns.  No trinity-owned
 *              btrfs mount infrastructure exists; operating against
 *              the host's btrfs root would be a data-loss path.
 *              TODO: wire this up once a btrfs-owning childop exists.
 *
 * SQE form: standard 64-byte SQE.  The cmd_op field is encoded in
 * the SQE's off union (overlaps via the cmd_op/__pad1 anonymous
 * struct), and the per-cmd_op payload that fits inline goes through
 * the addr / level / optname / optval / addr3 unions at the SQE tail.
 * The 80-byte cmd[] inline payload (SQE128) is not used here — the
 * cmd_op handlers we target on safe paths read their payload through
 * the standard SQE union fields, and the nvme path that requires the
 * 80-byte cmd[] is stubbed pending SQE128 support.
 *
 * Variants are probed once per invocation; the probe is cheap (a few
 * sysfs opens) and the result is held in a per-process static so
 * subsequent invocations from the same child skip the probe.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/io_uring.h>

#include "child.h"
#include "syscall-gate.h"
#include "childops-iouring.h"
#include "childops/iouring-ring.h"
#include "compat.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

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
		if (n > 0 && buf[n - 1] == '\n')
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
 * Ring lifecycle.  Trimmed mirror of childops/iouring-recipes.c —
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

static void ring_drain_cqes(struct iour_ring *ctx)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;

	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		head++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
}

static void sqe_clear(struct io_uring_sqe *s)
{
	memset(s, 0, sizeof(*s));
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

static bool variant_socket(struct iour_ring *ctx)
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
	sqe.opcode    = IORING_OP_URING_CMD;
	sqe.fd        = sock_fd;
	sqe.cmd_op    = cmd_op;
	sqe.user_data = 0xc0d0;

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

	r = ring_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	ring_drain_cqes(ctx);
	ok = true;
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

static bool variant_blockdev(struct iour_ring *ctx)
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
	sqe.opcode    = IORING_OP_URING_CMD;
	sqe.fd        = dev_fd;
	sqe.cmd_op    = BLOCK_URING_CMD_DISCARD;
	sqe.addr      = 0;		/* start offset */
	sqe.addr3     = 4096;		/* length — one page */
	sqe.user_data = 0xc0d1;

	if (!ring_submit_sqe(ctx, &sqe))
		goto out;

	r = ring_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	ring_drain_cqes(ctx);
	ok = true;
out:
	if (dev_fd >= 0)
		close(dev_fd);
	return ok;
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
	bool ok = false;
	enum { V_SOCKET, V_BLOCKDEV, V_MAX };
	int avail[V_MAX];
	int navail = 0;

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
				__atomic_store_n(&shm->stats.childop_latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return true;
	}
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);

		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	switch (avail[rnd_modulo_u32((unsigned int)navail)]) {
#ifndef TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP
	case V_SOCKET:
		ok = variant_socket(&ctx);
		break;
#endif
	case V_BLOCKDEV:
		ok = variant_blockdev(&ctx);
		break;
	}

	iour_ring_teardown(&ctx);

	(void)ok;
	return true;
}
