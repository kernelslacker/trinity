/*
 * struct_catalog/futex.c -- futex / rseq struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.  <linux/futex.h> brings struct robust_list_head
 * and struct futex_waitv; <linux/rseq.h> brings struct rseq and the
 * RSEQ_CS_FLAG_* mask vocabulary.
 */

#include <stddef.h>
#include <linux/futex.h>
#include <linux/rseq.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct robust_list_head (set_robust_list)                           */
/* ------------------------------------------------------------------ */

/*
 * set_robust_list(struct robust_list_head __user *head, size_t len)
 * passes the head pointer at a1 with argtype ARG_ADDRESS (not
 * ARG_STRUCT_PTR_*), so the schema-aware fill path never runs against
 * it -- the bespoke sanitise_set_robust_list() in
 * syscalls/set_robust_list.c continues to own the live (list.next,
 * futex_offset, list_op_pending) layout: it zmalloc_tracked()s a head,
 * self-points list.next, zeros futex_offset, and NULLs list_op_pending
 * before each call.
 *
 * Registration is attribution-only, mirroring pollfd / sembuf /
 * open_how / sigevent above: struct_field_for_cmp() uses the FT_RANGE
 * tag to attribute small-int CMP constants at futex_offset rather than
 * at a coincidentally-same-width slot, and FT_ADDRESS on the embedded
 * list (whose first member is a __user "next" pointer) and on
 * list_op_pending documents the kernel-dereferenced slots for any
 * downstream nested-scrub walker.  futex_offset bounds envelope the
 * page-sized window the kernel walks across the robust list node.
 *
 * get_robust_list's robust_list_head is an OUTPUT (its a2 is a double
 * pointer the kernel writes), so the syscall_struct_args[] mapping
 * below names set_robust_list a1 only.
 */
const struct struct_field robust_list_head_fields[ROBUST_LIST_HEAD_FIELDS_N] = {
	FIELDX(struct robust_list_head, list, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELDX(struct robust_list_head, futex_offset, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct robust_list_head, list_op_pending, FT_ADDRESS,
	       .mutate_weight = 100),
};

/* ------------------------------------------------------------------ */
/* struct rseq (rseq)                                                  */
/* ------------------------------------------------------------------ */

/*
 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
 * passes the rseq pointer at a1.  The bespoke sanitise_rseq() in
 * syscalls/rseq.c continues to own the live fill: it allocates a
 * 32-byte-aligned struct rseq via get_writable_address(),
 * memset()s it to zero, routes a1 through avoid_shared_buffer_inout(),
 * cycles a2 through the rseq_len validation buckets (zero / undersized
 * / current ABI / oversized), and pins a4 to a fixed signature.
 *
 * Registration is attribution-only, mirroring robust_list_head /
 * pollfd / sembuf / open_how / sigevent above: struct_field_for_cmp()
 * uses the FT_RANGE tags to attribute small-int CMP constants at the
 * cpu_id / node_id / mm_cid slots rather than at a coincidentally-
 * same-width slot; FT_FLAGS on flags carries the RSEQ_CS_FLAG_*
 * vocabulary the kernel reads at critical-section abort; FT_ADDRESS
 * on rseq_cs documents the __user pointer slot the kernel
 * dereferences to reach the active struct rseq_cs.  cpu_id_start /
 * cpu_id / node_id / mm_cid are kernel-written outputs whose userspace
 * envelope still benefits from CMP attribution; the bounds mirror the
 * page-sized walk envelopes the kernel uses to validate them.  The
 * abort signature is the syscall's a4 argument, not a struct member,
 * so it has no field here.  The trailing flexible char end[] member
 * has no fixed offset/size and is not registered.
 */
const struct struct_field rseq_fields[RSEQ_FIELDS_N] = {
	FIELDX(struct rseq, cpu_id_start, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, cpu_id, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, rseq_cs, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELDX(struct rseq, flags, FT_FLAGS,
	       .u.flags.mask = RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT |
			       RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL |
			       RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE,
	       .mutate_weight = 80),
	FIELDX(struct rseq, node_id, FT_RANGE,
	       .u.range = { 0, 1024 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, mm_cid, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct futex_waitv (futex_waitv)                                    */
/* ------------------------------------------------------------------ */

const struct struct_field futex_waitv_fields[FUTEX_WAITV_FIELDS_N] = {
	FIELD(struct futex_waitv, val),
	FIELD(struct futex_waitv, uaddr),
	FIELD(struct futex_waitv, flags),
};
