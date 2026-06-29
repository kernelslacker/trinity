/*
 * struct_catalog/bpf_classic.c -- classic-BPF struct field tables.
 *
 * Carved out of struct_catalog.c as the next leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the classic-BPF
 * leaf data only -- struct sock_filter (the cBPF instruction word)
 * and struct sock_fprog (the { len, filter } pair passed to seccomp
 * SET_MODE_FILTER, setsockopt(SO_ATTACH_FILTER), and prctl(PR_SET_
 * SECCOMP)).  The two are kept co-located here because sock_fprog's
 * FT_PTR_ARRAY field names "sock_filter" as its elem_struct -- the
 * pointer-fill pass dereferences that name through the catalog to
 * size the sub-array, so the element descriptor has to ship in the
 * same TU as the container.  Symbols flip from static const to const
 * so the spine's .fields = sock_filter_fields / .fields =
 * sock_fprog_fields references resolve via the externs in
 * struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.
 */

#include <stddef.h>
#include <linux/filter.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct sock_filter (sock_fprog.filter array element)                 */
/* ------------------------------------------------------------------ */

/*
 * Classic-BPF instruction word.  Registered so sock_fprog.filter can
 * name it via FT_PTR_ARRAY.elem_struct and the pointer pass knows
 * sizeof(struct sock_filter) for sub-array allocation.  No syscall_
 * struct_args entry: sock_filter is never passed directly as an
 * ARG_STRUCT_PTR slot -- it only appears as the element type of the
 * len-counted array hung off sock_fprog.filter.
 *
 * All four members stay FT_RAW: the live fill is owned by the
 * bespoke bpf_gen_filter() / bpf_gen_seccomp() Markov-chain BPF
 * generators in net/bpf.c, which build well-formed cBPF programs
 * the kernel verifier will actually load.  A flat random splat per
 * field would produce instruction words the verifier rejects on the
 * first opcode read.  These FIELD entries exist so struct_field_for_
 * cmp() can attribute CMP-learned constants at named code / jt / jf
 * / k slots rather than at coincidentally-same-width slots.
 */
const struct struct_field sock_filter_fields[SOCK_FILTER_FIELDS_N] = {
	FIELD(struct sock_filter, code),
	FIELD(struct sock_filter, jt),
	FIELD(struct sock_filter, jf),
	FIELD(struct sock_filter, k),
};

/* ------------------------------------------------------------------ */
/* struct sock_fprog (seccomp SET_MODE_FILTER, SO_ATTACH_FILTER, ...)   */
/* ------------------------------------------------------------------ */

/*
 * Embedded-pointer struct: { u16 len; struct sock_filter *filter; }.
 * filter points at a len-counted array of struct sock_filter -- the
 * kernel reads len first, then dereferences filter for (len *
 * sizeof(sock_filter)) bytes, so a flat memcpy registration would
 * leave the embedded pointer as a garbage value the kernel would
 * dereference.  The catalog already expresses this exact shape via
 * the FT_PTR_ARRAY (elem_struct + len_field) + FT_LEN_COUNT pair
 * used by msghdr.msg_iov / msg_iovlen; the pointer-fill pass
 * allocates a sock_filter[len] sub-buffer, points filter at it, and
 * the length pass writes the coupled count into len.
 *
 * Attribution-only registration: the live fill for the seccomp /
 * setsockopt(SO_ATTACH_FILTER) / prctl(PR_SET_SECCOMP) call sites
 * is owned by the bespoke bpf_gen_seccomp() / bpf_gen_filter()
 * Markov generators in net/bpf.c -- those produce well-formed
 * cBPF the kernel verifier accepts, which a schema-aware FT_RAW
 * splat across sock_filter[] words cannot.  The descriptor still
 * earns its keep by giving struct_field_for_cmp() named len /
 * filter slots and a cataloged elem_struct so CMP-learned
 * constants attribute at the right field rather than at a
 * coincidentally-same-width slot.
 *
 * max_count caps the sub-array to 64 elements -- the speculative
 * allocator path only fires when no bespoke sanitiser has already
 * stamped (a, len) at the slot (i.e. never for the existing
 * seccomp / setsockopt / prctl users), so the bound is purely a
 * safety ceiling on future schema-only callers.  BPF_MAXINSNS is
 * 4096 in the kernel; 64 is well under that and keeps catalog-
 * speculative allocations small.
 */
const struct struct_field sock_fprog_fields[SOCK_FPROG_FIELDS_N] = {
	FIELDX(struct sock_fprog, len, FT_LEN_COUNT,
	       .u.len_of = { .buf_field = "filter" }),
	FIELDX(struct sock_fprog, filter, FT_PTR_ARRAY,
	       .u.ptr_array = { .len_field = "len",
				.elem_struct = "sock_filter",
				.max_count = 64 }),
};
