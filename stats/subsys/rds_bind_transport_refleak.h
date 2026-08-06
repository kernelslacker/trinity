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
	 * HWM oracle.  rds_tcp_refcount_hwm is the largest absolute
	 * /proc/modules refcount observed for rds_tcp across all
	 * invocations in this run.  Because the leak is monotone and
	 * permanent, any increase in the HWM from one invocation to the
	 * next is attributable to leaked refs and is immune to sibling
	 * churn.  leaked_refs_hwm_growth accumulates the total HWM growth
	 * seen across the run.
	 *
	 * rds_tcp_refcount_hwm is stored as a long (matching
	 * proc_module_refcount()) so negative sentinel -1 is preserved;
	 * the sign bit is safe because real module refcounts never exceed
	 * LONG_MAX.
	 */
	unsigned long rds_tcp_refcount_hwm;	/* highest rds_tcp refcount seen this run */
	unsigned long leaked_refs_hwm_growth;	/* total growth of HWM across the run */
};

#endif /* _TRINITY_STATS_SUBSYS_RDS_BIND_TRANSPORT_REFLEAK_H */
