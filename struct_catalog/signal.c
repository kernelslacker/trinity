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
#include <stdint.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct sigaction (rt_sigaction, sigaction)                          */
/* ------------------------------------------------------------------ */

/*
 * SA_* flag vocabulary for sigaction.sa_flags.  SA_RESTORER is
 * declared by linux/signal.h / asm/signal.h but is intentionally
 * not exposed by glibc's <signal.h>; the local #ifdef arm picks up
 * the architectural value when present and contributes zero
 * otherwise.  Bits outside the kernel-supported mask are silently
 * cleared by the rt_sigaction path, so a uniform-byte splat wastes
 * the field on bits the kernel ignores.
 */
#ifdef SA_RESTORER
# define SIGACTION_FLAGS_RESTORER	SA_RESTORER
#else
# define SIGACTION_FLAGS_RESTORER	0UL
#endif

#define SIGACTION_FLAGS_MASK \
	(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_NODEFER | SA_ONSTACK | \
	 SA_RESETHAND | SA_RESTART   | SA_SIGINFO | \
	 SIGACTION_FLAGS_RESTORER)

const struct struct_field sigaction_fields[SIGACTION_FIELDS_N] = {
	FIELDX(struct sigaction, sa_flags, FT_FLAGS,
	       .u.flags.mask = SIGACTION_FLAGS_MASK,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* stack_t (sigaltstack)                                                */
/* ------------------------------------------------------------------ */

const struct struct_field stack_t_fields[STACK_T_FIELDS_N] = {
	FIELD(stack_t, ss_sp),
	FIELD(stack_t, ss_flags),
	FIELD(stack_t, ss_size),
};

/* ------------------------------------------------------------------ */
/* siginfo_t (rt_sigqueueinfo, rt_tgsigqueueinfo)                       */
/* ------------------------------------------------------------------ */

/*
 * siginfo_t is a si_code-discriminated union.  si_signo / si_errno /
 * si_code form the fixed header; the union body's active arm is
 * selected primarily by si_code (with si_signo refining the positive-
 * si_code receiver-side arms).  Trinity's rt_sigqueueinfo /
 * rt_tgsigqueueinfo sanitisers own the live fill -- both hand-build
 * the buffer and pin si_code to SI_USER / SI_QUEUE / SI_TKILL (plus
 * an "intentionally invalid" bucket on rt_sigqueueinfo for the EPERM
 * gate).  This registration is attribution-only: schema-aware fill
 * never runs at the slot (argtype[*] is not ARG_STRUCT_PTR_*), but
 * struct_field_for_cmp() now steers CMP-learned constants at the
 * named si_signo / si_code / si_pid / si_uid / si_value slots rather
 * than at coincidentally-same-width slots.
 *
 * Variants resolve via the in-buffer si_code discriminator, mirroring
 * sockaddr_storage's buffer-relative ss_family and perf_event_attr's
 * buffer-relative type.  Only the negative-si_code arms userland
 * actually supplies on the SET path are modeled here: SI_QUEUE picks
 * the _rt arm (si_pid + si_uid + si_value), SI_USER / SI_TKILL pick
 * the _kill arm (si_pid + si_uid).  Positive si_code (SI_KERNEL /
 * SEGV_MAPERR / ...) is kernel-origin and rejected on the unprivileged
 * SET path with EPERM, so no variant is registered for those values
 * -- the resolver falls through to the shared head alone.  The
 * signal-specific receiver-side arms (_sigchld on SIGCHLD,
 * _sigfault on SIGSEGV/SIGBUS/..., _sigpoll on SIGIO/SIGPOLL,
 * _sigsys on SIGSYS) need a two-axis (si_signo, si_code) discriminator
 * the catalog does not express; they are deliberately left unmodeled
 * here (the SET-path consumers never reach them).
 *
 * Width / sign note: si_code is `int` (4 bytes signed).  The width-4
 * buffer_discrim reader (read_discrim) returns zero-extended, so the
 * negative SI_* constants live as their uint32_t cast in
 * discrim_value (0xFFFFFFFFUL for SI_QUEUE etc.), not as the sign-
 * extended unsigned long form.
 *
 * Not mapped here on purpose: waitid's a3 is a kernel-written OUTPUT
 * buffer with no input fill to attribute against (same shape as the
 * gettimeofday / get_robust_list / cachestat-output skips above).
 * pidfd_send_signal's a3 IS mapped (attribution-only, same as
 * rt_sigqueueinfo / rt_tgsigqueueinfo — the bespoke sanitisers keep
 * owning the live fill).
 */
const unsigned long siginfo_t_si_code_vocab[SIGINFO_T_SI_CODE_VOCAB_N] = {
	(unsigned long)(uint32_t) SI_USER,
	(unsigned long)(uint32_t) SI_QUEUE,
	(unsigned long)(uint32_t) SI_TKILL,
	(unsigned long)(uint32_t) SI_TIMER,
	(unsigned long)(uint32_t) SI_ASYNCIO,
	(unsigned long)(uint32_t) SI_KERNEL,
};

const struct struct_field siginfo_t_fields[SIGINFO_T_FIELDS_N] = {
	FIELDX(siginfo_t, si_signo, FT_RANGE,
	       .u.range = { 1, 64 }),
	FIELD(siginfo_t, si_errno),
	FIELDX(siginfo_t, si_code, FT_ENUM,
	       .u.enum_ = { .vals = siginfo_t_si_code_vocab,
			    .n    = ARRAY_SIZE(siginfo_t_si_code_vocab) }),
};

/* SI_QUEUE -- _rt arm (sigqueue() origin: pid + uid + sigval payload). */
const struct struct_field siginfo_t_rt_variant_fields[SIGINFO_T_RT_VARIANT_FIELDS_N] = {
	FIELD(siginfo_t, si_pid),
	FIELD(siginfo_t, si_uid),
	FIELD(siginfo_t, si_value),
};

/* SI_USER / SI_TKILL -- _kill arm (kill() / tkill() origin: pid + uid). */
const struct struct_field siginfo_t_kill_variant_fields[SIGINFO_T_KILL_VARIANT_FIELDS_N] = {
	FIELD(siginfo_t, si_pid),
	FIELD(siginfo_t, si_uid),
};

const unsigned long siginfo_t_kill_discrim_values[SIGINFO_T_KILL_DISCRIM_VALUES_N] = {
	(unsigned long)(uint32_t) SI_USER,
	(unsigned long)(uint32_t) SI_TKILL,
};

const struct union_variant siginfo_t_variants[SIGINFO_T_VARIANTS_N] = {
	{
		.discrim_value	= (unsigned long)(uint32_t) SI_QUEUE,
		.name		= "SI_QUEUE",
		.fields		= siginfo_t_rt_variant_fields,
		.num_fields	= ARRAY_SIZE(siginfo_t_rt_variant_fields),
	},
	{
		.discrim_values		= siginfo_t_kill_discrim_values,
		.num_discrim_values	= ARRAY_SIZE(siginfo_t_kill_discrim_values),
		.name			= "SI_USER/SI_TKILL",
		.fields			= siginfo_t_kill_variant_fields,
		.num_fields		= ARRAY_SIZE(siginfo_t_kill_variant_fields),
	},
};

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
