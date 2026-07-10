/*
 * struct_catalog/ptrace_regs.c -- ptrace register-set struct field
 * tables.
 *
 * PTRACE_GETREGS / PTRACE_SETREGS carry a per-arch general-purpose
 * register struct at ptrace(2) arg4, and PTRACE_GETREGSET /
 * PTRACE_SETREGSET carry the same shape wrapped in a struct iovec whose
 * iov_base points at the regset payload (NT_PRSTATUS on the common
 * arches).  syscalls/ptrace.c's sanitiser arm for the four ops leaves
 * arg4's argtype as ARG_UNDEFINED and hand-rolls the iovec / raw pointer
 * itself, so these descriptors are attribution-only: they exist so the
 * schema-aware CMP path can name the specific register slot a
 * KCOV-CMP-learned constant fell out of instead of guessing off width
 * alone.  Consumers reach the descriptors via struct_catalog_lookup()
 * on the struct name.
 *
 * Register slots are flat unsigned-long / u64 words with no gate-shaped
 * vocab (FT_ENUM / FT_FLAGS / FT_VERSION_MAGIC) to steer against, so
 * every field carries the default FT_RAW tag via the FIELD() macro --
 * struct_field_for_cmp() still gains per-slot naming, and the schema-
 * aware fill (unused today because arg4 is ARG_UNDEFINED) would keep
 * the historical per-field random splat if a future arm wired
 * ARG_STRUCT_PTR through.
 *
 * Per-arch: x86_64 exposes struct pt_regs via <asm/ptrace.h> and struct
 * user_regs_struct via <sys/user.h>; aarch64 exposes struct user_pt_regs
 * via <asm/ptrace.h> as the NT_PRSTATUS regset payload (kernel-side
 * struct pt_regs is not uapi on arm64) and struct user_regs_struct via
 * <sys/user.h> with the same 4-slot layout.  Other arches gain no
 * entries this cycle -- the spine's SC_PT_REGS / SC_USER_REGS_STRUCT
 * enum slots and the central-array entries are gated by the same
 * arch-macro pair so a build for an uncovered arch stays byte-identical.
 *
 * Tables are `const` (not `static const`) so the spine's designated-
 * init `.fields =` references resolve via the externs in
 * struct_catalog-internal.h.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"

#if defined(__x86_64__) || defined(__aarch64__)
#include <asm/ptrace.h>
#include <sys/user.h>
#endif

#if defined(__x86_64__)

/* ------------------------------------------------------------------ */
/* struct pt_regs -- x86_64 (asm/ptrace.h)                             */
/* ------------------------------------------------------------------ */
/*
 * The 21-slot general-purpose register frame the kernel exposes as
 * struct pt_regs to userspace on x86_64.  All fields are unsigned long
 * (8 bytes); CS/SS carry 16-bit selector values in a 64-bit slot and
 * EFLAGS carries an rflags bitmask, but none are gate-tagged because
 * no shipped CMP consumer steers against segment-selector or rflags
 * vocab today -- the entries stay FT_RAW so future gate tagging is a
 * one-line change without disturbing the slot layout.
 */
const struct struct_field pt_regs_fields[PT_REGS_FIELDS_N] = {
	FIELD(struct pt_regs, r15),
	FIELD(struct pt_regs, r14),
	FIELD(struct pt_regs, r13),
	FIELD(struct pt_regs, r12),
	FIELD(struct pt_regs, rbp),
	FIELD(struct pt_regs, rbx),
	FIELD(struct pt_regs, r11),
	FIELD(struct pt_regs, r10),
	FIELD(struct pt_regs, r9),
	FIELD(struct pt_regs, r8),
	FIELD(struct pt_regs, rax),
	FIELD(struct pt_regs, rcx),
	FIELD(struct pt_regs, rdx),
	FIELD(struct pt_regs, rsi),
	FIELD(struct pt_regs, rdi),
	FIELD(struct pt_regs, orig_rax),
	FIELD(struct pt_regs, rip),
	FIELD(struct pt_regs, cs),
	FIELD(struct pt_regs, eflags),
	FIELD(struct pt_regs, rsp),
	FIELD(struct pt_regs, ss),
};

/* ------------------------------------------------------------------ */
/* struct user_regs_struct -- x86_64 (sys/user.h)                      */
/* ------------------------------------------------------------------ */
/*
 * PTRACE_{GET,SET}REGS payload on x86_64.  Superset of struct pt_regs
 * above: adds the fs_base / gs_base and the ds / es / fs / gs segment
 * selector slots the kernel exposes through the arch_ptrace regs copy
 * path.  All fields are unsigned long long (8 bytes) so field-for-cmp
 * attribution is width-uniform; FT_RAW throughout for the same reason
 * pt_regs above stays FT_RAW.
 */
const struct struct_field user_regs_struct_fields[USER_REGS_STRUCT_FIELDS_N] = {
	FIELD(struct user_regs_struct, r15),
	FIELD(struct user_regs_struct, r14),
	FIELD(struct user_regs_struct, r13),
	FIELD(struct user_regs_struct, r12),
	FIELD(struct user_regs_struct, rbp),
	FIELD(struct user_regs_struct, rbx),
	FIELD(struct user_regs_struct, r11),
	FIELD(struct user_regs_struct, r10),
	FIELD(struct user_regs_struct, r9),
	FIELD(struct user_regs_struct, r8),
	FIELD(struct user_regs_struct, rax),
	FIELD(struct user_regs_struct, rcx),
	FIELD(struct user_regs_struct, rdx),
	FIELD(struct user_regs_struct, rsi),
	FIELD(struct user_regs_struct, rdi),
	FIELD(struct user_regs_struct, orig_rax),
	FIELD(struct user_regs_struct, rip),
	FIELD(struct user_regs_struct, cs),
	FIELD(struct user_regs_struct, eflags),
	FIELD(struct user_regs_struct, rsp),
	FIELD(struct user_regs_struct, ss),
	FIELD(struct user_regs_struct, fs_base),
	FIELD(struct user_regs_struct, gs_base),
	FIELD(struct user_regs_struct, ds),
	FIELD(struct user_regs_struct, es),
	FIELD(struct user_regs_struct, fs),
	FIELD(struct user_regs_struct, gs),
};

#elif defined(__aarch64__)

/* ------------------------------------------------------------------ */
/* struct user_pt_regs -- aarch64 (asm/ptrace.h)                       */
/* ------------------------------------------------------------------ */
/*
 * NT_PRSTATUS regset payload on aarch64.  The 31-slot regs[] array is
 * cataloged as one aggregate FIELD -- naming individual x0..x30 slots
 * would 31x-inflate the CMP reservoir with same-width candidates and
 * dilute attribution across sp / pc / pstate for no steering gain.  The
 * aggregate slot's size exceeds struct_field_for_cmp's max
 * natural_width (8 bytes) so it only ever surfaces as a fit_pick, never
 * as an exact-width match, keeping sp / pc / pstate the preferred
 * attribution targets for scalar CMP hints.  pstate is the PSR-shaped
 * flags word but stays FT_RAW for the same forward-compat reason the
 * x86_64 eflags slot does above.
 */
const struct struct_field pt_regs_fields[PT_REGS_FIELDS_N] = {
	FIELD(struct user_pt_regs, regs),
	FIELD(struct user_pt_regs, sp),
	FIELD(struct user_pt_regs, pc),
	FIELD(struct user_pt_regs, pstate),
};

/* ------------------------------------------------------------------ */
/* struct user_regs_struct -- aarch64 (sys/user.h)                     */
/* ------------------------------------------------------------------ */
/*
 * glibc mirrors the kernel's struct user_pt_regs layout under the
 * struct user_regs_struct name on aarch64 -- same 31 * u64 GPRs plus
 * sp / pc / pstate.  The catalog carries the two names separately so
 * consumers looking up either lookup key resolve without having to
 * know the arch-specific alias, and the leaf tables are declared
 * independently in case a future glibc revision drifts one shape
 * relative to the other.
 */
const struct struct_field user_regs_struct_fields[USER_REGS_STRUCT_FIELDS_N] = {
	FIELD(struct user_regs_struct, regs),
	FIELD(struct user_regs_struct, sp),
	FIELD(struct user_regs_struct, pc),
	FIELD(struct user_regs_struct, pstate),
};

#endif
