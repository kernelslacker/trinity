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
 * before and after the inner-loop iterations.  A non-zero delta across
 * N bind attempts is the finding.
 */
struct rds_bind_transport_refleak_stats {
	/* rds_bind_transport_refleak childop counters */
	unsigned long runs;		/* total rds_bind_transport_refleak() invocations */
	unsigned long setup_failed;	/* socket(AF_RDS) fail / SO_RDS_TRANSPORT EOPNOTSUPP /
					 * rds_tcp absent from /proc/modules / unsupported latch */
	unsigned long binds_tried;	/* total bind() calls issued against the loop socket */
	unsigned long binds_einval;	/* bind() returned EINVAL (RDS_FLAG_PROBE_PORT path) */
	unsigned long binds_eaddrinuse;	/* bind() returned EADDRINUSE (already-bound-port path) */
	unsigned long leaked_refs;	/* cumulative /proc/modules rds_tcp refcount delta */
	unsigned long ref_read_failed;	/* proc_module_refcount("rds_tcp") returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_RDS_BIND_TRANSPORT_REFLEAK_H */
