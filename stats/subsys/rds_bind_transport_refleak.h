#ifndef _TRINITY_STATS_SUBSYS_RDS_BIND_TRANSPORT_REFLEAK_H
#define _TRINITY_STATS_SUBSYS_RDS_BIND_TRANSPORT_REFLEAK_H

/*
 * Per-invocation counters for the rds_bind_transport_refleak childop.
 *
 * The childop exercises the module-ref leak in rds_bind():
 * rds_set_transport() -> rds_trans_get() -> try_module_get() increments
 * the rds_tcp module refcount, but rds_add_bound() failure (EINVAL for
 * the RDS_FLAG_PROBE_PORT==1 sentinel, or EADDRINUSE for a port already
 * held by another RDS socket) nulls rs->rs_transport WITHOUT calling
 * rds_trans_put(), leaking one rds_tcp ref per failed bind.
 *
 * leaked_refs is the delta between /proc/modules refcount for rds_tcp
 * before and after the inner-loop iterations, accepted only when the
 * delta is at least as large as the locally-observed failed-bind count
 * (local_failed_binds calibration) so sibling noise cannot inflate the
 * tally.  ref_delta_nonpositive counts the complementary case where
 * sibling churn masked a genuine leak entirely.
 *
 * leaked_refs_hwm_growth uses a per-run high-water mark of the absolute
 * rds_tcp refcount stored in shm.  Because the leak is monotone and
 * permanent (refs are never returned until module unload), growth in the
 * HWM is immune to per-invocation sibling churn.
 */
struct rds_bind_transport_refleak_stats {
	/* rds_bind_transport_refleak childop counters */
	unsigned long runs;		/* total rds_bind_transport_refleak() invocations */
	unsigned long setup_failed;	/* socket(AF_RDS) fail / SO_RDS_TRANSPORT EOPNOTSUPP /
					 * rds_tcp absent from /proc/modules / unsupported latch */
	unsigned long binds_tried;	/* total bind() calls issued against the loop socket */
	unsigned long binds_einval;	/* bind() returned EINVAL (RDS_FLAG_PROBE_PORT path) -- run-total */
	unsigned long binds_eaddrinuse;	/* bind() returned EADDRINUSE (already-bound-port path) -- run-total */
	unsigned long leaked_refs;	/* calibrated delta: accepted when delta >= local_failed_binds */
	unsigned long ref_read_failed;	/* proc_module_refcount("rds_tcp") returned -1 */

	/*
	 * ref_delta_nonpositive: post_refcount <= pre_refcount after an
	 * invocation -- a genuine leak may have been masked by concurrent
	 * sibling socket closes.  Makes the silent-drop path visible.
	 */
	unsigned long ref_delta_nonpositive;

	/*
	 * ref_delta_undercount: band 0 < delta < local_failed_binds --
	 * partial sibling close masked a potential leak.  The delta is
	 * positive but smaller than the locally-observed failed-bind count,
	 * so the calibration threshold rejects it from leaked_refs.  Records
	 * how often busy-box sibling activity lands in this band.
	 */
	unsigned long ref_delta_undercount;

	/*
	 * HWM oracle.  rds_tcp_refcount_hwm is the largest absolute
	 * /proc/modules refcount observed for rds_tcp across all
	 * invocations in this run.  baseline_refcount is seeded from the
	 * first pre_refcount read (provenance record); pre_refcount_floor
	 * is the running minimum of all pre_refcount samples and serves as
	 * the steady-state floor for HWM accounting.
	 *
	 * A first-sample baseline_refcount may be inflated by concurrent
	 * sibling sockets holding transient refs.  pre_refcount_floor is
	 * revised downward via a CAS loop each time a quieter sample is
	 * observed; baseline_floor_revised counts how many times the floor
	 * moved down so a bad initial seed is visible in the stats.
	 *
	 * leaked_refs_hwm_growth is an upper-bound estimate: the absolute
	 * refcount includes refs held by concurrently-open sibling sockets,
	 * so HWM advances can reflect sibling pile-up as well as genuine
	 * leaks.  The per-invocation leaked_refs delta provides a
	 * calibrated complement.
	 *
	 * All fields are unsigned long.  The proc_module_refcount()
	 * sentinel (-1) is never stored here: the post_refcount > 0L guard
	 * in the childop ensures only positive readings reach the HWM path.
	 */
	unsigned long baseline_refcount;	/* first pre_refcount seen; provenance */
	unsigned long pre_refcount_floor;	/* running minimum of pre_refcount samples */
	unsigned long baseline_floor_revised;	/* times floor was revised downward */
	unsigned long rds_tcp_refcount_hwm;	/* highest rds_tcp refcount seen this run */
	unsigned long leaked_refs_hwm_growth;	/* total HWM growth above baseline */

	/*
	 * port_collision_skips: holder bind() returned EADDRINUSE because
	 * another worker child computed the same per-pid port (pids
	 * differing by a multiple of 4096 map to the same
	 * 0xB000|(pid&0x0FFF) value).  When this fires the EADDRINUSE
	 * leak path is skipped for that invocation.  Fleet visibility
	 * here prevents the silent single-path degradation from going
	 * unnoticed.
	 */
	unsigned long port_collision_skips;	/* holder bind EADDRINUSE -- pid-collision skip */

	/*
	 * holder_bind_other_errno: holder bind() failed with an errno
	 * other than EADDRINUSE (e.g. EINVAL, EACCES, ENOMEM).  Counted
	 * separately from port_collision_skips so a permanently broken
	 * holder-bind path does not silently masquerade as pid-collision
	 * traffic.  When this fires the EADDRINUSE leak path is also
	 * skipped for that invocation.
	 */
	unsigned long holder_bind_other_errno;	/* holder bind failed -- non-EADDRINUSE errno */

	/*
	 * eaddrinuse_wall_cap_skip: the EADDRINUSE arm was skipped
	 * entirely because RDSBTR_WALL_CAP_NS elapsed during the EINVAL
	 * loop.  This is the dominant skip cause on a busy box and was
	 * previously uncounted, making the arm look permanently dead.
	 */
	unsigned long eaddrinuse_wall_cap_skip;	/* wall-cap elapsed before EADDRINUSE arm */

	/*
	 * eaddrinuse_loopfd_setsockopt_fail: inside iter_eaddrinuse(),
	 * the loop-fd setsockopt(SO_RDS_TRANSPORT) failed after the
	 * holder socket was successfully established.  The function
	 * returns 0 silently, indistinguishable from 'EADDRINUSE bind
	 * not reached'.  This counter makes the silent-fail path visible.
	 */
	unsigned long eaddrinuse_loopfd_setsockopt_fail;	/* loop-fd setsockopt fail in iter_eaddrinuse */
};

#endif /* _TRINITY_STATS_SUBSYS_RDS_BIND_TRANSPORT_REFLEAK_H */
