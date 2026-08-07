/*
 * rds_bind_transport_refleak - expose live module-ref leak in rds_bind().
 *
 * Bug summary.  rds_bind() (net/rds/bind.c) calls rds_set_transport()
 * which in turn calls rds_trans_get() -> try_module_get(trans->t_owner),
 * incrementing the owning module's reference count by one.  On the
 * failure path where rds_add_bound() returns an error -- either -EINVAL
 * for the RDS_FLAG_PROBE_PORT sentinel (port == 1), or -EADDRINUSE for a
 * port already held by another RDS socket -- the caller nulls
 * rs->rs_transport WITHOUT calling the matching rds_trans_put().  One
 * module reference is leaked per failed bind.
 *
 * The same-socket repetition vector.  Nulling rs->rs_transport re-opens
 * the "if (rs->rs_transport) return -EOPNOTSUPP;" guard in
 * rds_setsockopt() (net/rds/af_rds.c), so the SAME open socket fd can
 * set-transport (incrementing the ref) and fail-bind (leaking the ref)
 * indefinitely without opening a new socket.
 *
 * Two-syscall trigger per inner iteration:
 *   setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &(int){RDS_TRANS_TCP}, 4)
 *       -> rds_setsockopt -> rds_set_transport -> rds_trans_get
 *          -> try_module_get(rds_tcp->t_owner): refcount +1
 *   bind(fd, {AF_INET, 127.0.0.1, htons(1)}, sizeof(sockaddr_in))
 *       -> rds_bind -> rds_add_bound: -EINVAL (port==1 ==
 *          RDS_FLAG_PROBE_PORT); rs->rs_transport = NULL; ref NOT put.
 *
 * Oracle.  /proc/modules carries the live module refcount for each
 * loaded module ("name size refcount ...").  Reading rds_tcp's refcount
 * before and after N iterations and observing a delta of N is the
 * finding.  proc_module_refcount() (include/childops-util.h) wraps this
 * read and is reusable by future childops.
 *
 * Silent-dud checks.
 *   - socket(AF_RDS) fails EAFNOSUPPORT / EPROTONOSUPPORT / ENOPROTOOPT:
 *     CONFIG_RDS absent; latch CHILDOP_LATCH_UNSUPPORTED.
 *   - setsockopt(SO_RDS_TRANSPORT) returns -EOPNOTSUPP: transport layer
 *     absent; latch CHILDOP_LATCH_UNSUPPORTED.
 *   - proc_module_refcount("rds_tcp") < 0: module not loaded; latch
 *     CHILDOP_LATCH_UNSUPPORTED.
 *
 * EADDRINUSE secondary path.  A holder socket is bound to a per-pid
 * ephemeral port; the loop fd then attempts setsockopt+bind on the same
 * port.  The holder close path is clean (rds_release calls rds_trans_put
 * for the holder's transport), so only the loop fd's EADDRINUSE-path ref
 * leaks.
 *
 * Safety.  All fd resources are per-invocation; the holder socket is
 * closed before the post-refcount read.  No netns manipulation, no
 * module load, no privileged operations.  Wall-capped at
 * RDSBTR_WALL_CAP_NS per invocation.
 *
 * Scope.  target: CONFIG_RDS=m, CONFIG_RDS_TCP=m, CONFIG_RDS_RDMA absent.
 * Runs directly in the persistent child without a netns hop.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/rds.h"
#include "kernel/socket.h"

#include "rds-bind-transport-refleak.h"

/*
 * Per-process latches.  AF_RDS / SO_RDS_TRANSPORT / rds_tcp availability
 * is static across a child's lifetime.
 *
 * rds_bind_refleak_unsupported: set on the first probe FAILURE; every
 * subsequent invocation short-circuits immediately.
 *
 * rds_probe_ok: set on the first probe SUCCESS; every subsequent
 * invocation skips the probe entirely (re-opening a socket, calling
 * setsockopt, and re-reading /proc/modules on every invocation is
 * wasted syscalls that also adds churn to sibling oracle windows).
 *
 * Together the two latches ensure the probe runs exactly ONCE per child
 * lifetime: first call always probes; later calls skip if the probe
 * already succeeded OR already failed.
 *
 * Mirrors the rds_zcopy_crafted_send / qrtr_bind_race /
 * netns_teardown_churn latch patterns.
 */
static bool rds_bind_refleak_unsupported;
static bool rds_probe_ok;

/*
 * Set the per-process latch and the shared CHILDOP_LATCH_UNSUPPORTED
 * reason code for the given op, if the op index is in range.
 */
static void latch_unsupported(const enum child_op_type op)
{
	rds_bind_refleak_unsupported = true;
	if ((int)op >= 0 && op < NR_CHILD_OP_TYPES)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_UNSUPPORTED,
				 __ATOMIC_RELAXED);
}

/*
 * probe_rds_bind_transport - check AF_RDS + SO_RDS_TRANSPORT availability
 * on this host.  Opens an AF_RDS socket, probes SO_RDS_TRANSPORT with
 * RDS_TRANS_TCP, then closes.  The close path in rds_release() calls
 * rds_trans_put() when rs->rs_transport is set, so the probe leaves no
 * leaked ref.
 *
 * Returns true on success (transport usable); false if the feature is
 * absent (latch already set, setup_failed bumped).
 */
static bool probe_rds_bind_transport(const enum child_op_type op)
{
	int fd;
	int transport = RDS_TRANS_TCP;

	fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == ENOPROTOOPT || errno == EACCES)
			latch_unsupported(op);
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.setup_failed,
				   1, __ATOMIC_RELAXED);
		return false;
	}

	if (setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT,
		       &transport, sizeof(transport)) < 0) {
		/* EOPNOTSUPP / ENOPROTOOPT: transport layer absent */
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT)
			latch_unsupported(op);
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.setup_failed,
				   1, __ATOMIC_RELAXED);
		close(fd);
		return false;
	}

	/*
	 * Probe succeeded.  Close fd: rds_release() sees rs->rs_transport
	 * set and calls rds_trans_put(), so this probe contributes zero net
	 * change to the module refcount.
	 */
	close(fd);

	/*
	 * Confirm rds_tcp appears in /proc/modules so the oracle reads will
	 * work.  If rds_tcp is not listed the pre/post delta is meaningless.
	 */
	if (proc_module_refcount("rds_tcp") < 0) {
		latch_unsupported(op);
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.setup_failed,
				   1, __ATOMIC_RELAXED);
		return false;
	}

	/*
	 * Latch success so subsequent invocations skip the probe entirely.
	 * See rds_probe_ok declaration above.
	 */
	rds_probe_ok = true;
	return true;
}

/*
 * iter_einval - one EINVAL-path leak iteration on loop_fd.
 *
 * Calls setsockopt(SO_RDS_TRANSPORT, RDS_TRANS_TCP) to increment the
 * rds_tcp module refcount by one, then bind(127.0.0.1:1).  Port 1 is
 * the RDS_FLAG_PROBE_PORT sentinel: rds_add_bound() rejects -EINVAL
 * before inserting into the bind table, but AFTER rds_set_transport()
 * has already called try_module_get().  The error path nulls
 * rs->rs_transport without calling rds_trans_put(), leaking the ref.
 * The null write re-opens the setsockopt guard so the same fd can be
 * used on the next call.
 *
 * Returns 0 on success (bind path was reached), -1 if setsockopt itself
 * failed (guard re-opened incorrectly, or racing concurrent transport
 * change).
 */
static int iter_einval(int loop_fd)
{
	struct sockaddr_in addr;
	int transport = RDS_TRANS_TCP;
	int r;

	r = setsockopt(loop_fd, SOL_RDS, SO_RDS_TRANSPORT,
		       &transport, sizeof(transport));
	if (r < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = htons(1);	/* RDS_FLAG_PROBE_PORT == 1 */

	r = bind(loop_fd, (struct sockaddr *)&addr, sizeof(addr));
	__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.binds_tried,
			   1, __ATOMIC_RELAXED);

	if (r < 0) {
		if (errno == EINVAL)
			__atomic_add_fetch(
				&shm->stats.rds_bind_transport_refleak.binds_einval,
				1, __ATOMIC_RELAXED);
		else if (errno == EADDRINUSE)
			__atomic_add_fetch(
				&shm->stats.rds_bind_transport_refleak.binds_eaddrinuse,
				1, __ATOMIC_RELAXED);
	}
	return 0;
}

/*
 * iter_eaddrinuse - EADDRINUSE secondary leak path (best-effort, one round).
 *
 * Opens a holder socket, explicitly sets its transport to RDS_TRANS_TCP,
 * and binds it to a per-pid ephemeral port so the port is held while the
 * loop fd attempts to bind the same port.  The holder bind + close path
 * is clean: setsockopt increments rds_tcp's ref, the bind succeeds
 * (rs->rs_transport stays set), and rds_release sees rs->rs_transport set
 * on close, calling rds_trans_put -- net zero for the holder.
 *
 * The loop fd then does setsockopt(TCP) (+1 ref) followed by
 * bind(holder_port) which returns -EADDRINUSE; the kernel nulls
 * rs->rs_transport without calling rds_trans_put, leaking one ref.
 *
 * Returns 1 if the EADDRINUSE bind was reached, 0 otherwise.
 */
static int iter_eaddrinuse(int loop_fd, uint16_t holder_port,
			   unsigned long *syscall_count_out)
{
	int holder_fd;
	int transport = RDS_TRANS_TCP;
	struct sockaddr_in haddr;
	int r;
	int ret = 0;
	unsigned long sc = 0;

	holder_fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
	sc++;	/* socket(AF_RDS) */
	if (holder_fd < 0) {
		*syscall_count_out = sc;
		return 0;
	}

	memset(&haddr, 0, sizeof(haddr));
	haddr.sin_family      = AF_INET;
	haddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	haddr.sin_port        = htons(holder_port);

	/*
	 * Set transport on holder explicitly so its ref/release accounting
	 * uses the same module (rds_tcp) as the loop fd.
	 */
	if (setsockopt(holder_fd, SOL_RDS, SO_RDS_TRANSPORT,
		       &transport, sizeof(transport)) < 0) {
		/* If setsockopt fails, close and bail.  rds_release sees
		 * rs->rs_transport == NULL and skips rds_trans_put. */
		close(holder_fd);
		sc += 2;	/* setsockopt + close */
		*syscall_count_out = sc;
		return 0;
	}

	if (bind(holder_fd, (struct sockaddr *)&haddr, sizeof(haddr)) != 0) {
		/* Holder bind failed.  Distinguish pid-collision
		 * (EADDRINUSE -- two children whose pids differ by a
		 * multiple of 4096 map to the same holder_port) from
		 * other errors (EINVAL, EACCES, ENOMEM, ...).  Counting
		 * each separately prevents a permanently broken
		 * holder-bind path from silently masquerading as
		 * pid-collision traffic.  In both cases the EADDRINUSE
		 * leak arm is skipped for this invocation. */
		if (errno == EADDRINUSE)
			__atomic_add_fetch(
				&shm->stats.rds_bind_transport_refleak.port_collision_skips,
				1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(
				&shm->stats.rds_bind_transport_refleak.holder_bind_other_errno,
				1, __ATOMIC_RELAXED);
		close(holder_fd);
		sc += 3;	/* setsockopt + bind + close */
		*syscall_count_out = sc;
		return 0;
	}

	/*
	 * Holder established.  Loop fd: setsockopt(TCP) (+1 ref) then
	 * bind(holder_port) expects -EADDRINUSE, which leaks the ref.
	 */
	r = setsockopt(loop_fd, SOL_RDS, SO_RDS_TRANSPORT,
		       &transport, sizeof(transport));
	sc++;	/* setsockopt(loop_fd) */
	if (r == 0) {
		r = bind(loop_fd, (struct sockaddr *)&haddr, sizeof(haddr));
		sc++;	/* bind(loop_fd) */
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.binds_tried,
				   1, __ATOMIC_RELAXED);
		if (r < 0 && errno == EADDRINUSE) {
			__atomic_add_fetch(
				&shm->stats.rds_bind_transport_refleak.binds_eaddrinuse,
				1, __ATOMIC_RELAXED);
			ret = 1;
		}
	} else {
		/* loop-fd setsockopt failed after the holder was
		 * established.  The EADDRINUSE bind is silently not
		 * reached; count it so the skip is visible in fleet
		 * stats rather than looking like 'arm not reached'. */
		__atomic_add_fetch(
			&shm->stats.rds_bind_transport_refleak.eaddrinuse_loopfd_setsockopt_fail,
			1, __ATOMIC_RELAXED);
	}

	/*
	 * Close holder.  rds_release sees rs->rs_transport set (the bind
	 * succeeded so it was not nulled) and calls rds_trans_put, returning
	 * the holder's ref cleanly.  The loop fd's leaked ref stays.
	 */
	close(holder_fd);
	sc++;	/* close(holder_fd) */

	*syscall_count_out = sc;
	return ret;
}

bool rds_bind_transport_refleak(struct childdata *child)
{
	struct timespec t_outer;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned int outer_iters, i;
	int loop_fd;
	long pre_refcount, post_refcount;
	/* Per-invocation failed-bind counts for oracle calibration. */
	unsigned long local_failed_binds;
	int local_eaddrinuse_count;
	/*
	 * Per-pid holder port in 0xB000..0xBFFF.  Keeps cross-worker
	 * collision probability low while staying outside the privileged
	 * range and away from common ephemeral ports.
	 */
	uint16_t holder_port = (uint16_t)(RDSBTR_HOLDER_PORT_BASE |
					  ((uint16_t)getpid() & 0x0FFFU));

	__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.runs,
			   1, __ATOMIC_RELAXED);

	if (rds_bind_refleak_unsupported) {
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/*
	 * Probe AF_RDS + SO_RDS_TRANSPORT availability once per child
	 * lifetime.  The probe socket is opened, tested, and closed so it
	 * contributes no ref delta.  Latch fires if the feature is absent.
	 *
	 * rds_probe_ok is set on the FIRST successful probe; skip the probe
	 * on all subsequent invocations to avoid the wasted socket()+
	 * setsockopt()+/proc/modules overhead and the sibling oracle churn
	 * it causes.
	 */
	if (!rds_probe_ok && !probe_rds_bind_transport(op))
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * Read the baseline rds_tcp module refcount.  The probe socket was
	 * closed before this point so its ref is already returned.  No RDS
	 * socket is open at this instant, giving a clean floor reading.
	 */
	pre_refcount = proc_module_refcount("rds_tcp");

	/*
	 * Open the loop socket.  socket() alone does not increment the
	 * rds_tcp module ref (that happens in rds_set_transport(), called
	 * from either setsockopt(SO_RDS_TRANSPORT) or the first bind()).
	 */
	loop_fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
	if (loop_fd < 0) {
		__atomic_add_fetch(&shm->stats.rds_bind_transport_refleak.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * EINVAL leak loop.  Each iteration issues one setsockopt
	 * (try_module_get -> +1 ref) and one bind to port 1 (rds_add_bound
	 * returns -EINVAL, nulls rs->rs_transport without rds_trans_put ->
	 * ref leaked).  rs->rs_transport == NULL after each failed bind
	 * re-opens the setsockopt guard so the cycle repeats on the same fd.
	 */
	outer_iters = BUDGETED(CHILD_OP_RDS_BIND_TRANSPORT_REFLEAK,
			       RDSBTR_OUTER_BASE);
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > RDSBTR_OUTER_CAP)
		outer_iters = RDSBTR_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if (budget_elapsed_ns(&t_outer, (long)RDSBTR_WALL_CAP_NS))
			break;
		if (iter_einval(loop_fd) < 0)
			break;
	}

	/*
	 * EADDRINUSE secondary path.  Best-effort: bind a holder socket to
	 * a per-pid port, then attempt setsockopt+bind on loop_fd to the
	 * same port.  The holder close is properly accounted (rds_trans_put
	 * fires), so only the loop_fd's EADDRINUSE-path ref is leaked.
	 * Capture the return value: 1 if the EADDRINUSE bind was reached,
	 * 0 otherwise.  This counts toward local_failed_binds.
	 */
	local_eaddrinuse_count = 0;
	unsigned long eaddrinuse_syscalls = 0;
	if (!budget_elapsed_ns(&t_outer, (long)RDSBTR_WALL_CAP_NS)) {
		local_eaddrinuse_count = iter_eaddrinuse(loop_fd, holder_port,
						     &eaddrinuse_syscalls);
	} else {
		/* RDSBTR_WALL_CAP_NS elapsed during the EINVAL loop;
		 * the entire EADDRINUSE arm is skipped.  This is the
		 * dominant skip cause on a busy box and was previously
		 * uncounted, making the arm look permanently dead. */
		__atomic_add_fetch(
			&shm->stats.rds_bind_transport_refleak.eaddrinuse_wall_cap_skip,
			1, __ATOMIC_RELAXED);
	}

	/*
	 * local_failed_binds: number of failed binds THIS invocation.
	 * i == number of successful iter_einval() calls (each producing
	 * exactly one EINVAL-path bind).  Used to calibrate the delta
	 * assertion: only attribute a leak when the /proc/modules delta is
	 * at least this large, preventing sibling noise from inflating the
	 * tally.  Binds are also accumulated into run-total shm counters
	 * inside iter_einval / iter_eaddrinuse for long-run attribution.
	 */
	local_failed_binds = (unsigned long)i + (unsigned long)local_eaddrinuse_count;

	/*
	 * Post-loop oracle read.  loop_fd is still open but
	 * rs->rs_transport == NULL (nulled by the last failed bind), so
	 * rds_release will not call rds_trans_put when we close it below.
	 * All leaked refs are already visible in the module refcount.
	 */
	post_refcount = proc_module_refcount("rds_tcp");

	if (pre_refcount >= 0L && post_refcount >= 0L) {
		long delta = post_refcount - pre_refcount;

		if (local_failed_binds > 0UL) {
			if (delta > 0L && (unsigned long)delta >= local_failed_binds) {
				/*
				 * Calibrated delta: only record when the
				 * observed growth is at least as large as the
				 * locally-caused leak count.  Sibling opens
				 * can inflate the delta (over-count); sibling
				 * closes can shrink it (under-count, caught
				 * by ref_delta_nonpositive below).
				 */
				__atomic_add_fetch(
					&shm->stats.rds_bind_transport_refleak.leaked_refs,
					(unsigned long)delta, __ATOMIC_RELAXED);
			} else if (delta <= 0L) {
				/*
				 * post_refcount <= pre_refcount: a sibling
				 * closing sockets in the window drove the
				 * delta to zero or negative.  The genuine
				 * leak is masked.  Record so operators can
				 * see how often the per-invocation oracle is
				 * unreliable.  The HWM oracle below is immune
				 * to this failure mode.
				 */
				__atomic_add_fetch(
					&shm->stats.rds_bind_transport_refleak.ref_delta_nonpositive,
					1, __ATOMIC_RELAXED);
			} else {
				/*
				 * 0 < delta < local_failed_binds: the delta
				 * is positive but smaller than the locally-
				 * observed failed-bind count.  Sibling closes
				 * during the window partially cancelled the
				 * leaked refs, causing the calibration
				 * threshold to reject the reading.  Record so
				 * operators can quantify how often busy-box
				 * sibling activity lands in this band.
				 */
				__atomic_add_fetch(
					&shm->stats.rds_bind_transport_refleak.ref_delta_undercount,
					1, __ATOMIC_RELAXED);
			}
		}

		/*
		 * HWM oracle.  Update the shared high-water mark of the
		 * absolute rds_tcp refcount.  baseline_refcount and
		 * rds_tcp_refcount_hwm are both seeded from pre_refcount on
		 * the first invocation so that leaked_refs_hwm_growth tracks
		 * growth above the pre-existing system floor, not from zero.
		 * Without this seed the first HWM advance would book the
		 * entire absolute refcount as leaked refs.
		 *
		 * The first-sample seed can be inflated when concurrent sibling
		 * sockets happen to hold transient refs at sample time.  To
		 * correct for this, pre_refcount_floor tracks the running
		 * minimum of all pre_refcount samples via a downward CAS loop.
		 * Each time the floor is revised downward, baseline_floor_revised
		 * is incremented so a bad initial seed is visible in the stats.
		 * baseline_refcount retains the first-sample value for
		 * provenance.
		 *
		 * leaked_refs_hwm_growth is an upper-bound estimate: because
		 * the absolute refcount includes refs held by concurrently-
		 * open sibling sockets, HWM advances can reflect sibling
		 * pile-up as well as genuine leaks.
		 *
		 * Use a CAS loop so concurrent children converge on the
		 * true maximum without races.  Growth accumulated into
		 * leaked_refs_hwm_growth on each successful HWM advance.
		 */
		if (post_refcount > 0L) {
			unsigned long new_hwm = (unsigned long)post_refcount;
			unsigned long zero;

			/*
			 * Seed baseline_refcount, pre_refcount_floor, and
			 * rds_tcp_refcount_hwm from pre_refcount on first use
			 * (CAS from zero).  Whichever child wins sets the initial
			 * values; losers proceed with the winner's values already
			 * in place.
			 */
			if (pre_refcount > 0L) {
				unsigned long seed = (unsigned long)pre_refcount;

				zero = 0UL;
				(void)__atomic_compare_exchange_n(
					&shm->stats.rds_bind_transport_refleak.baseline_refcount,
					&zero, seed, false,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED);
				zero = 0UL;
				(void)__atomic_compare_exchange_n(
					&shm->stats.rds_bind_transport_refleak.pre_refcount_floor,
					&zero, seed, false,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED);
				zero = 0UL;
				(void)__atomic_compare_exchange_n(
					&shm->stats.rds_bind_transport_refleak.rds_tcp_refcount_hwm,
					&zero, seed, false,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED);

				/*
				 * Downward CAS loop: revise the floor if this
				 * sample is lower than the current minimum.
				 * Bumps baseline_floor_revised on each downward
				 * revision so a bad initial seed is observable.
				 */
				unsigned long cur_floor = __atomic_load_n(
					&shm->stats.rds_bind_transport_refleak.pre_refcount_floor,
					__ATOMIC_RELAXED);

				while (seed < cur_floor) {
					if (__atomic_compare_exchange_n(
						    &shm->stats.rds_bind_transport_refleak.pre_refcount_floor,
						    &cur_floor, seed,
						    false,
						    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
						__atomic_add_fetch(
							&shm->stats.rds_bind_transport_refleak.baseline_floor_revised,
							1, __ATOMIC_RELAXED);
						break;
					}
					/* cur_floor refreshed by CAS failure; retry */
				}
			}

			unsigned long old_hwm = __atomic_load_n(
				&shm->stats.rds_bind_transport_refleak.rds_tcp_refcount_hwm,
				__ATOMIC_RELAXED);

			while (new_hwm > old_hwm) {
				unsigned long prev = old_hwm;

				if (__atomic_compare_exchange_n(
					    &shm->stats.rds_bind_transport_refleak.rds_tcp_refcount_hwm,
					    &old_hwm, new_hwm,
					    false,
					    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
					__atomic_add_fetch(
						&shm->stats.rds_bind_transport_refleak.leaked_refs_hwm_growth,
						new_hwm - prev,
						__ATOMIC_RELAXED);
					break;
				}
				/* old_hwm refreshed by CAS failure; retry */
			}
		}
	} else {
		__atomic_add_fetch(
			&shm->stats.rds_bind_transport_refleak.ref_read_failed,
			1, __ATOMIC_RELAXED);
	}

	/*
	 * Close loop_fd.  rs->rs_transport is NULL so rds_release skips
	 * rds_trans_put -- the leaked refs remain in the module refcount
	 * and are visible in the next invocation's pre-refcount read.
	 */
	close(loop_fd);

	/*
	 * Account for direct syscalls issued this invocation:
	 *   i * 2          -- EINVAL loop: setsockopt + bind per iteration
	 *                     (i is the achieved count; loop may break early)
	 *   eaddrinuse_syscalls -- EADDRINUSE path actual cost (0 if wall-cap
	 *                     skipped the call; 1..6 depending on which
	 *                     iter_eaddrinuse sub-path was reached)
	 *   1              -- socket(AF_RDS) to open loop_fd
	 *   1              -- close(loop_fd)
	 *   6              -- 2 x proc_module_refcount() = 2 x (open+read+close
	 *                     of /proc/modules)
	 */
	if (valid_op)
		childop_direct_syscalls_add(op,
					    (unsigned long)i * 2UL +
					    eaddrinuse_syscalls + 8UL);

	return true;
}
