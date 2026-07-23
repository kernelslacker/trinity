#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#include "cmp_hints.h"
#include "deferred-free.h"		// deferred_free_enqueue_or_leak, zmalloc_tracked
#include "random.h"
#include "rnd.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "trinity.h"			// ARRAY_SIZE

#include "kernel/sched.h"
/*
 * Size used when the slot is declared ARG_STRUCT_PTR_IN but the struct
 * catalog has no entry for (syscall, arg).  Big enough to cover the
 * common kernel-side copy_from_user() sizes (sizeof(struct sched_attr)
 * etc.) without us guessing wrong about the specific layout.
 */
#define STRUCT_PTR_IN_FALLBACK_SIZE	256U




/*
 * ARG_STRUCT_PTR_IN: hand the kernel a heap-allocated buffer sized for
 * the cataloged struct at this (syscall, arg), then per-field
 * schema-aware fill via struct_field_fill_schema_aware().  For
 * unannotated structs every field is FT_RAW and the output matches
 * the historical per-field random splat byte-for-byte.
 *
 * Catalog miss: fall back to STRUCT_PTR_IN_FALLBACK_SIZE bytes of zeros.
 * The slot stays a valid kernel-readable buffer, so the kernel still
 * gets past its first copy_from_user() boundary check; it just won't
 * see varied field content until the catalog learns this syscall.
 *
 * The allocation is enqueued on the deferred-free queue at generation
 * time rather than via the argtype_ops cleanup hook, so a downstream
 * sanitise() that reallocates and overwrites the arg slot doesn't end
 * up double-enqueueing the sanitise's own pointer (which has its own
 * post-handler-driven free path).
 */
unsigned long gen_arg_struct_ptr_in(struct syscallentry *entry __unused__,
					   struct syscallrecord *rec,
					   unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit, rec);
	size = desc ? desc->struct_size : STRUCT_PTR_IN_FALLBACK_SIZE;

	buf = zmalloc_tracked(size);

	if (desc != NULL) {
		struct_field_fill_schema_aware(buf, size, desc, rec);
		struct_field_mutate_one(buf, size, desc, rec);
	}

	deferred_free_enqueue_or_leak(buf);
	return (unsigned long) buf;
}

/*
 * Size used when the slot is declared ARG_STRUCT_PTR_OUT but the struct
 * catalog has no entry for (syscall, arg).  Big enough to cover the
 * common kernel-side copy_to_user() sizes (struct statx is 256 bytes,
 * struct stat ~144, struct sysinfo ~64) without guessing wrong about
 * the specific layout.
 */
#define STRUCT_PTR_OUT_FALLBACK_SIZE	256U

/*
 * Byte the buffer is pre-filled with before the kernel writes into it.
 * Any non-zero, easily-recognisable value works; 0xAA is the historical
 * "uninitialised heap" pattern and survives both the kernel's
 * copy_to_user destination check and direct byte comparison.  Bytes the
 * kernel does not overwrite remain 0xAA, which lets a future post-
 * validation pass tell touched-bytes apart from untouched-bytes
 * without an explicit length out-parameter.
 */
#define STRUCT_PTR_OUT_POISON_BYTE	0xAAU

/*
 * ARG_STRUCT_PTR_OUT: hand the kernel a heap-allocated buffer sized for
 * the cataloged struct at this (syscall, arg) and pre-filled with a
 * recognisable poison byte (0xAA).  The kernel's copy_to_user() lands
 * on a buffer of exactly the right size and the post handler sees the
 * kernel's writes against a known background pattern.
 *
 * Differs from ARG_STRUCT_PTR_IN in two ways: there is no per-field
 * random splat (the kernel writes the bytes, the fuzzer does not read
 * them as input) and the buffer is poison-filled rather than zero-
 * filled so untouched-bytes are visually distinct.
 *
 * Catalog miss: fall back to STRUCT_PTR_OUT_FALLBACK_SIZE bytes of
 * poison.  The slot stays a valid kernel-writable buffer big enough for
 * the largest struct in our migration list (struct statx), so the
 * kernel still copies its full output without truncation; once the
 * catalog learns the syscall, the allocation shrinks to the exact
 * struct size.
 *
 * The allocation is enqueued on the deferred-free queue at generation
 * time, mirroring ARG_STRUCT_PTR_IN: several callers we expect to
 * migrate still carry sanitise/post pairs that snapshot the pointer
 * for re-read in the post handler, and the deferred queue keeps the
 * buffer alive long enough for that re-read while the post handler's
 * own free path remains independent.
 *
 * Not yet done: post-validation that checks whether the 0xAA canary
 * was overwritten.  Needs the catalog in place first so the per-slot
 * allocation is actually reaching the kernel before we start
 * asserting on the bytes the kernel wrote back.
 */
unsigned long gen_arg_struct_ptr_out(struct syscallentry *entry __unused__,
					    struct syscallrecord *rec,
					    unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit, rec);
	size = desc ? desc->struct_size : STRUCT_PTR_OUT_FALLBACK_SIZE;

	buf = zmalloc_tracked(size);
	memset(buf, STRUCT_PTR_OUT_POISON_BYTE, size);

	deferred_free_enqueue_or_leak(buf);
	return (unsigned long) buf;
}

/*
 * ARG_STRUCT_PTR_INOUT: ioctl-shaped slots where the kernel reads input
 * fields off the buffer and then writes output bytes back to it.  The
 * input half needs the same schema-aware fill as ARG_STRUCT_PTR_IN
 * -- a poison-filled buffer makes every input field look like 0xAAAA...
 * and the kernel rejects the call before it ever exercises the output
 * path.  Field-fill via struct_field_fill_schema_aware(), then hand
 * the buffer over; the kernel's writes land on whatever fields it
 * chooses to overwrite.
 *
 * Catalog miss: fall back to STRUCT_PTR_IN_FALLBACK_SIZE bytes of zeros,
 * same as the IN path -- zeros are a valid input shape for most
 * extensible structs (size-word-first ABIs treat zero as "minimum
 * version") and keep the kernel past its first copy_from_user() bounds
 * check.
 *
 * Output-side validation (canary on the written-back bytes, so a post
 * handler can tell touched-bytes from untouched-bytes) is not done
 * here -- it needs the catalog to learn the input shape first, and
 * conflating the two changes would make the per-field splat
 * unreviewable.  The job here is only to stop sending all-0xAA as
 * INOUT input.
 *
 * Deferred-free / sanitise-overwrite handling matches the IN path.
 */
unsigned long gen_arg_struct_ptr_inout(struct syscallentry *entry __unused__,
					      struct syscallrecord *rec,
					      unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit, rec);
	size = desc ? desc->struct_size : STRUCT_PTR_IN_FALLBACK_SIZE;

	buf = zmalloc_tracked(size);

	if (desc != NULL) {
		struct_field_fill_schema_aware(buf, size, desc, rec);
		struct_field_mutate_one(buf, size, desc, rec);
	}

	deferred_free_enqueue_or_leak(buf);
	return (unsigned long) buf;
}

/*
 * Per-struct-name table of older ABI sizes for extensible structs.  The
 * kernel's copy_struct_from_user() path branches heavily on the size
 * word: smaller-than-current is the "old userspace, new kernel" leg, and
 * exact older-ABI sizes (CLONE_ARGS_SIZE_VER0/1/2, SCHED_ATTR_SIZE_VER0
 * etc) walk a different validator than the current sizeof().  Picking
 * these sizes explicitly keeps the old-ABI branches exercised long after
 * the catalog's struct_size has grown past them.
 */
struct struct_old_abi_sizes {
	const char *name;
	const unsigned int *sizes;
	unsigned int num_sizes;
};

static const unsigned int clone_args_old_sizes[] = { 64, 80, 88 };
static const unsigned int sched_attr_old_sizes[] = { 48, 56 };
static const unsigned int mount_attr_old_sizes[] = { 32 };

static const struct struct_old_abi_sizes struct_old_abi_table[] = {
	{ "clone_args",	clone_args_old_sizes,	ARRAY_SIZE(clone_args_old_sizes) },
	{ "sched_attr",	sched_attr_old_sizes,	ARRAY_SIZE(sched_attr_old_sizes) },
	{ "mount_attr",	mount_attr_old_sizes,	ARRAY_SIZE(mount_attr_old_sizes) },
};

static const struct struct_old_abi_sizes *lookup_old_abi(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(struct_old_abi_table); i++) {
		if (strcmp(struct_old_abi_table[i].name, name) == 0)
			return &struct_old_abi_table[i];
	}
	return NULL;
}

/*
 * Find the catalog struct paired with this syscall by scanning its
 * argtype slots for an ARG_STRUCT_PTR_IN / ARG_STRUCT_PTR_OUT and
 * resolving that slot via struct_arg_lookup().  Returns NULL if the
 * syscall has no paired struct ptr slot, or has one but the struct
 * isn't cataloged.
 */
static const struct struct_desc *paired_struct_desc(struct syscallentry *entry,
						    struct syscallrecord *rec)
{
	unsigned int i;

	/* num_args lives in shared writable memory (copy_syscall_table in
	 * tables/tables.c) — a wild-write from a child can drive it past
	 * the 6-slot argtype[] and walk this loop off the entry.  Clamp. */
	for (i = 0; i < entry->num_args && i < ARRAY_SIZE(entry->argtype); i++) {
		enum argtype t = entry->argtype[i];

		if (t == ARG_STRUCT_PTR_IN || t == ARG_STRUCT_PTR_OUT ||
		    t == ARG_STRUCT_PTR_INOUT)
			return struct_arg_lookup(rec->nr, i + 1, rec->do32bit,
						 rec);
	}
	return NULL;
}

/*
 * Catalog-gap fallback cap for ARG_STRUCT_SIZE when no paired struct
 * is registered for this syscall.  Keeps the scalar in a plausible
 * size_t range without spraying ULONG_MAX values into a slot the
 * kernel will trivially reject.
 */
#define ARG_STRUCT_SIZE_FALLBACK_CAP	4096U

/*
 * ARG_STRUCT_SIZE: produce a size value for an extensible-struct
 * syscall's size argument.  These syscalls (clone3, sched_setattr/
 * sched_getattr, openat2, statmount, mount_setattr, open_tree_attr ...)
 * are dispatched by copy_struct_from_user(), which branches on the
 * size word before it ever inspects the struct's fields: an undersize
 * value is rejected outright (-E2BIG/-EINVAL), an oversize value walks
 * a zero-padding leg, and exact older-ABI sizes (CLONE_ARGS_SIZE_VER0
 * etc) walk a different validator than the current sizeof().
 *
 * Distribution (when a paired catalog struct exists):
 *   50%  exact current sizeof()         -- the kernel's fast path
 *   20%  known older-ABI size           -- exercises the size-shrink legs
 *   10%  sizeof+/-1 boundary            -- off-by-one in the size check
 *   10%  0 / small / UINT_MAX / huge    -- structural rejection paths
 *   10%  CMP-hint-derived for this nr   -- learned-from-kernel sizes
 *                                          (lifted to ~25% inside a
 *                                          CMP_RISING_PC_FLAT plateau
 *                                          via cmp_hint_inject_denom)
 *
 * Catalog gap: no paired struct cataloged, so the exact size is not
 * derivable.  Fall back to a bounded random scalar; better than zeroing
 * the slot and starving any field-shape sensitive path of variance.
 */
unsigned long gen_arg_struct_size(struct syscallentry *entry,
					 struct syscallrecord *rec,
					 unsigned int argnum)
{
	const struct struct_desc *desc;
	const struct struct_old_abi_sizes *oa;
	unsigned long hint;
	unsigned int roll;

	/* Opts into the typed-hypothesis live inject arm: ARG_STRUCT_SIZE
	 * is a learned-size scalar slot, the same shape as the typed-safe
	 * size/count/range scalar set the typed store is calibrated for.
	 *
	 * argnum feeds the typed_inject_fill_slot_hist[] placement-proof
	 * counter (bumped inside cmp_hints_try_get_ex only when the LIVE
	 * inject fires and the accept gate passes); no rnd draw and no
	 * behaviour change beyond the observability counter.
	 *
	 * No accept range: this consumer has no declared upper bound to
	 * gate against; the fallback random scalar below clamps at
	 * ARG_STRUCT_SIZE_FALLBACK_CAP only for the no-catalog path. */
	if (ONE_IN(cmp_hint_inject_denom(10)) &&
	    cmp_hints_try_get_ex(rec->nr, rec->do32bit,
				 CMP_HINT_BOUNDARY, 0, true, NULL,
				 argnum,
				 CMP_HINT_CALLSITE_ARG_STRUCT_SIZE, &hint)) {
		credit_cmp_hint_injection(rec, CMP_HINT_CALLSITE_ARG_STRUCT_SIZE);
		return hint;
	}

	desc = paired_struct_desc(entry, rec);
	if (desc == NULL)
		return (unsigned long) rnd_modulo_u32(ARG_STRUCT_SIZE_FALLBACK_CAP);

	roll = rnd_modulo_u32(10);

	/* 50%: exact current sizeof() */
	if (roll < 5)
		return desc->struct_size;

	/* 20%: known older-ABI size, else exact sizeof() */
	if (roll < 7) {
		oa = lookup_old_abi(desc->name);
		if (oa != NULL)
			return oa->sizes[rnd_modulo_u32(oa->num_sizes)];
		return desc->struct_size;
	}

	/* 10%: sizeof +/- 1 boundary */
	if (roll < 8) {
		if (RAND_BOOL())
			return desc->struct_size + 1;
		return desc->struct_size > 0 ? desc->struct_size - 1 : 0;
	}

	/* 20% remaining: structural-rejection stress */
	switch (rnd_modulo_u32(6)) {
	case 0: return 0;
	case 1: return 1 + rnd_modulo_u32(16);
	case 2: return UINT_MAX;
	case 3: return INT_MAX;
	case 4: return ((unsigned long) rand32()) << 16;
	default: return ULONG_MAX;
	}
}
