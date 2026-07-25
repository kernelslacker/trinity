/*
 * bridge_fdb_stp - STP sysfs toggles.
 *
 * Drives the bridge's STP state machine via
 * /sys/class/net/<br>/bridge/stp_state.  A write of '1' then '0' arms
 * then disarms br_stp_start / br_stp_stop and the topology-change
 * timer, giving the rx-driven fdb learning in the traffic burst a
 * live STP state machine to race against.
 *
 * A per-child latch (ns_unsupported_sysfs_stp) fires on the first
 * EROFS / EACCES / ENOENT so a kernel without sysfs writeable bridge
 * knobs (read-only bind mount, lockdown=integrity, missing
 * CONFIG_SYSFS) pays the EFAIL once and short-circuits the whole
 * helper on subsequent iterations.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "kernel/fcntl.h"
#include "shm.h"

#include "bridge-fdb-stp-internal.h"

/* Per-child latched gate.  Set on the first sysfs-write failure of
 * /sys/class/net/<br>/bridge/stp_state and never cleared -- CONFIG /
 * mount-mode presence is static for the child's lifetime, so we pay
 * the EFAIL once and skip the path on subsequent invocations. */
static bool ns_unsupported_sysfs_stp;

/*
 * Toggle STP via /sys/class/net/<br>/bridge/stp_state.  Open + write
 * + close per call.  EROFS / EACCES / ENOENT all latch
 * ns_unsupported_sysfs_stp — those are the failure modes for a
 * kernel without sysfs writeable bridge knobs (read-only bind mount,
 * lockdown=integrity, missing CONFIG_SYSFS).
 */
static bool sysfs_stp_write(const char *brname, char val)
{
	char path[64];
	int fd;
	ssize_t n;

	if (snprintf(path, sizeof(path),
		     "/sys/class/net/%s/bridge/stp_state", brname) >= (int)sizeof(path))
		return false;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EROFS || errno == EACCES || errno == ENOENT)
			ns_unsupported_sysfs_stp = true;
		return false;
	}

	n = write(fd, &val, 1);
	close(fd);
	return n == 1;
}

/*
 * Phase 5: drive the STP state machine via sysfs.  Writing "1" then
 * "0" arms then disarms br_stp_start / br_stp_stop and the
 * topology-change timer, giving the rx-driven fdb learning in
 * traffic_burst a live STP state machine to race against.  The
 * ns_unsupported_sysfs_stp latch (set by sysfs_stp_write on
 * EROFS / EACCES / ENOENT) gates the whole helper so a sysfs-locked
 * kernel pays the EFAIL once per child rather than per iteration.
 */
void bridge_fdb_stp_iter_stp_toggle(struct bridge_fdb_stp_iter_ctx *ctx)
{
	if (ns_unsupported_sysfs_stp)
		return;

	if (sysfs_stp_write(ctx->br_name, '1'))
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp.stp_toggle_ok,
				   1, __ATOMIC_RELAXED);
	if (sysfs_stp_write(ctx->br_name, '0'))
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp.stp_toggle_ok,
				   1, __ATOMIC_RELAXED);
}
