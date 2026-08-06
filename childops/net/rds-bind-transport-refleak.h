#ifndef _CHILDOPS_NET_RDS_BIND_TRANSPORT_REFLEAK_H
#define _CHILDOPS_NET_RDS_BIND_TRANSPORT_REFLEAK_H

/*
 * rds-bind-transport-refleak: constants and declarations.
 *
 * See rds-bind-transport-refleak.c for the full description of the
 * bug class (rds_bind() module-ref leak on rds_add_bound() failure).
 *
 * proc_module_refcount() is declared as a static inline in
 * include/childops-util.h so any future childop that needs to sample
 * /proc/modules refcounts can pull it in without duplicating the
 * implementation.
 */

#include "childops-util.h"	/* proc_module_refcount(), budget_elapsed_ns() */

/* Outer iterations: budget base and hard cap.  The inner loop issues
 * one setsockopt + one bind per iteration on the SAME socket, then
 * reads /proc/modules twice per childop invocation.  Cap chosen low
 * (8) to keep the per-invocation wall time well within the budget
 * even on a busy host; the leak accumulates across runs. */
#define RDSBTR_OUTER_BASE	4U
#define RDSBTR_OUTER_CAP	8U

/* Wall-clock ceiling per childop invocation (200 ms). */
#define RDSBTR_WALL_CAP_NS	(200ULL * 1000ULL * 1000ULL)

/* Base port for the EADDRINUSE secondary leak path.  A holder socket
 * binds (RDSBTR_HOLDER_PORT_BASE | (pid & 0x0FFF)) first; the loop fd
 * then does setsockopt+bind to the same port and gets EADDRINUSE,
 * leaking one ref.  Chosen away from well-known ports. */
#define RDSBTR_HOLDER_PORT_BASE	0xB000U

#endif /* _CHILDOPS_NET_RDS_BIND_TRANSPORT_REFLEAK_H */
