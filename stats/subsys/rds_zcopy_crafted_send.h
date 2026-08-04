#ifndef _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H
#define _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H

#include <stdbool.h>

struct rds_zcopy_crafted_send_stats {
	/* rds_zcopy_crafted_send childop counters */
	unsigned long runs;			/* total rds_zcopy_crafted_send invocations */
	unsigned long setup_failed;		/* socket(AF_RDS) / bind / SO_ZEROCOPY / mmap / unsupported latch fired */
	unsigned long bind_ok;			/* bind(AF_RDS, 127.0.0.1:0) accepted */
	unsigned long zc_enable_ok;		/* setsockopt(SO_ZEROCOPY, 1) accepted on the AF_RDS sock */
	unsigned long hole_ok;			/* munmap punched a hole in the backing region (pin walk will fault) */
	unsigned long sends_ok;			/* sendmsg(MSG_ZEROCOPY) returned >=0 (full pin walk completed) */
	unsigned long sends_efault;		/* sendmsg(MSG_ZEROCOPY) returned EFAULT (partial-pin unwind reached) */
	unsigned long sends_failed;		/* sendmsg(MSG_ZEROCOPY) returned a non-EFAULT error (any errno) */
	unsigned long errqueue_drained;		/* recvmsg(MSG_ERRQUEUE) drained at least one zcopy completion cookie */
};

/*
 * Sanity check: returns false when every completed send attempt landed
 * in sends_failed (100% failure rate) with neither the sends_ok nor the
 * intended sends_efault path ever reached.  A 100% sends_failed rate
 * across a non-trivial sample indicates the kernel rejected sendmsg
 * before the zcopy page-pin walk -- e.g. EINVAL from the
 * MSG_ZEROCOPY && !zcopy_cookie guard in rds_rm_size() -- making
 * rds_message_zcopy_from_user() structurally unreachable.  Callers
 * should warn when this returns false after a minimum sample of sends
 * has accumulated, rather than silently persisting a childop that never
 * reaches its target path.
 */
static inline bool
rds_zcopy_crafted_send_sanity_ok(const struct rds_zcopy_crafted_send_stats *s)
{
	unsigned long total = s->sends_ok + s->sends_efault + s->sends_failed;

	/* No sends attempted yet -- not unhealthy, just idle. */
	if (total == 0UL)
		return true;

	/* 100% failure: neither the ok nor the intended EFAULT path was
	 * ever reached.  The zcopy target path is unreachable. */
	return (s->sends_failed < total);
}

#endif /* _TRINITY_STATS_SUBSYS_RDS_ZCOPY_CRAFTED_SEND_H */
