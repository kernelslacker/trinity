/*
 * struct_catalog/tcp.c -- TCP-shaped struct field tables.
 *
 * Carved out of struct_catalog.c as the next leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the TCP leaf
 * data only -- struct tcp_repair_opt (IPPROTO_TCP / TCP_REPAIR_OPTIONS
 * setsockopt optval element).  Symbols flip from static const to const
 * so the spine's .fields = tcp_repair_opt_fields reference resolves
 * via the externs in struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty when USE_TCP_REPAIR_OPT is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>

/*
 * struct tcp_repair_opt -- IPPROTO_TCP / TCP_REPAIR_OPTIONS.  The kernel
 * iterates optlen/sizeof(struct tcp_repair_opt) entries from optval and
 * switches on opt_code (TCPOPT_*) -- a small discrete opcode set.  Both
 * fields stay FT_RAW: opt_code is treated as an enum by the kernel (not
 * an unsigned contiguous window, so FT_RANGE would be wrong), and opt_val
 * is a per-opcode payload with no shared range.  Single-entry fill is
 * sufficient to exercise the path; a FT_PTR_ARRAY multi-entry follow-up
 * is the natural next step but does not block this proof.
 */
const struct struct_field tcp_repair_opt_fields[TCP_REPAIR_OPT_FIELDS_N] = {
	FIELD(struct tcp_repair_opt, opt_code),
	FIELD(struct tcp_repair_opt, opt_val),
};
#endif /* USE_TCP_REPAIR_OPT */
