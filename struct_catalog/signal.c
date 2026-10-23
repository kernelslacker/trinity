/*
 * struct_catalog/signal.c -- signal-shaped struct field tables.
 *
 * Field/variant tables are `const` (not `static const`) so the spine's
 * .fields=/.variants= references resolve via struct_catalog-internal.h.
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty when USE_<X> is off.
 */

#include <stddef.h>
#include <signal.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* sigset_t (signalfd, signalfd4)                                      */
/* ------------------------------------------------------------------ */

/*
 * signalfd(int ufd, const sigset_t __user *user_mask, size_t sizemask)
 * signalfd4(int ufd, const sigset_t __user *user_mask, size_t sizemask,
 *           int flags) hand the kernel a sigset_t bitmask at a2.
 * argtype[1] is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
 * sanitise_signalfd() / sanitise_signalfd4() keep owning the live fill:
 * each draws from a four-way bucket (empty / single RT signal / classic
 * SIGUSR1/2+SIGCHLD+SIGALRM mix / sigfillset minus SIGKILL+SIGSTOP) so
 * the kernel's mask-sanitisation path gets exercised verbatim.
 *
 * sigset_t is a flat 1024-bit bitmask wrapped in a glibc struct whose
 * sole member is an unsigned long __val[] array; there are no named
 * scalar sub-fields to enumerate.  This is a deliberately weak steering
 * target -- the win is letting struct_field_for_cmp() attribute a
 * KCOV-CMP-learned constant at the named __val slot rather than at a
 * coincidentally-same-width neighbour elsewhere in the syscallrecord.
 *
 * Registration is attribution-only, mirroring the in-tree timer_create /
 * utimbuf / flock / msgbuf entries: the bespoke sanitiser keeps owning
 * the live fill -- this only feeds the CMP-attribution path.  __val
 * stays FT_RAW so the bespoke bucketed band is preserved verbatim.
 * SC_SIGSET_T is shared infra: rt_sigsuspend (and other sigset_t-taking
 * syscalls) can reuse it without re-defining the layout.
 */
const struct struct_field sigset_t_fields[SIGSET_T_FIELDS_N] = {
	FIELD(sigset_t, __val),
};
