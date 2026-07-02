#include <limits.h>
#include <sched.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arch.h"
#include "arg-len-semantics.h"
#include "args-internal.h"
#include "argtype-ops.h"
#include "blob_mutator.h"
#ifdef USE_BPF
#include "bpf.h"
#endif
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "net.h"
#include "nodemask.h"
#include "numa.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "strategy.h"	// plateau_rescue_bias_active_for, RRC_CMP_DERIVED
#include "struct_catalog.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"	// num_online_cpus
#include "utils.h"	// zmalloc
#include "fstype.h"
#include "xattr.h"


enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum)
{
	return entry->argtype[argnum - 1];
}


/*
 * Size used when the slot is declared ARG_STRUCT_PTR_IN but the struct
 * catalog has no entry for (syscall, arg).  Big enough to cover the
 * common kernel-side copy_from_user() sizes (sizeof(struct sched_attr)
 * etc.) without us guessing wrong about the specific layout.
 */
#define STRUCT_PTR_IN_FALLBACK_SIZE	256U



/*
 * Per-array consistency check for FT_LEN_* fields carrying a
 * buf_fields[] sibling list.  The pre-pin pass in struct_fill_passes
 * pre-pins one shared count across every listed sibling and writes
 * the LEN slot from that same count, which is sound only when:
 *
 *  1. every resolvable sibling has the same pointer tag -- all
 *     FT_PTR_BYTES, xor all FT_PTR_ARRAY.  A mix would store one
 *     count into a byte buffer (interpreted as bytes) and the same
 *     count into an array slot (interpreted as elements), with no
 *     unit the kernel can read consistently.
 *  2. the LEN field's unit agrees with that tag: FT_LEN_BYTES pairs
 *     with FT_PTR_BYTES, FT_LEN_COUNT with FT_PTR_ARRAY.  A
 *     mismatch (e.g. FT_LEN_BYTES naming an FT_PTR_ARRAY sibling)
 *     would publish a byte count into a slot the kernel reads as
 *     an element count, silently mis-shaping the arg tuple.
 *
 * Resolution uses find_field_index_in() against the same fields[]
 * scope the runtime pre-pin pass uses, so an index that doesn't
 * resolve here is skipped, not flagged -- it cannot contribute to
 * either rule and only means "no claim either way".  A genuine
 * contradiction among the resolved siblings is BUG()'d.
 */
static void validate_len_buf_fields(const struct struct_field *fields,
				    unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		enum field_tag agreed = FT_RAW;
		bool agreed_set = false;
		unsigned int j;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;
		if (f->u.len_of.buf_fields == NULL ||
		    f->u.len_of.n_buf_fields == 0)
			continue;

		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			enum field_tag pt;

			if (p < 0 || (unsigned int) p >= n)
				continue;
			pt = fields[p].tag;
			if (pt != FT_PTR_BYTES && pt != FT_PTR_ARRAY)
				BUG("LEN buf_fields sibling is not FT_PTR_BYTES/ARRAY");
			if (!agreed_set) {
				agreed = pt;
				agreed_set = true;
				continue;
			}
			if (pt != agreed)
				BUG("LEN buf_fields siblings mix FT_PTR_BYTES and FT_PTR_ARRAY");
		}

		if (!agreed_set)
			continue;

		if (f->tag == FT_LEN_BYTES && agreed != FT_PTR_BYTES)
			BUG("FT_LEN_BYTES paired with non-FT_PTR_BYTES sibling");
		if (f->tag == FT_LEN_COUNT && agreed != FT_PTR_ARRAY)
			BUG("FT_LEN_COUNT paired with non-FT_PTR_ARRAY sibling");
	}
}

/*
 * Walk every fields[] array reachable in struct_catalog[]:
 * top-level desc->fields, each variant->fields, each variant->base
 * (when present), and each nested_variant->fields.  Each array is
 * an independent name-resolution scope at runtime, so each is
 * validated against itself the same way the fill paths read it.
 *
 * Catalog data is built from C99 literal initialisers at compile
 * time, so a flagged inconsistency is a structural authoring bug,
 * not runtime drift.  Loud BUG() at first fill turns what would
 * otherwise be a silent mis-generation into a startup failure.
 */
static void validate_struct_catalog(void)
{
	unsigned int i;

	for (i = 0; i < SC_NR_ENTRIES; i++) {
		const struct struct_desc *d = &struct_catalog[i];
		unsigned int v;

		validate_len_buf_fields(d->fields, d->num_fields);

		for (v = 0; v < d->num_variants; v++) {
			const struct union_variant *var = &d->variants[v];
			unsigned int k;

			validate_len_buf_fields(var->fields, var->num_fields);
			if (var->base != NULL)
				validate_len_buf_fields(var->base->fields,
							var->base->num_fields);
			for (k = 0; k < var->num_nested_variants; k++) {
				const struct union_variant *nv =
					&var->nested_variants[k];

				validate_len_buf_fields(nv->fields,
							nv->num_fields);
			}
		}
	}
}

void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec)
{
	static bool catalog_validated;
	const struct union_variant *variant;

	/*
	 * First-call gate: validate every fields[] array in struct_catalog
	 * once per process.  Steady-state cost is one bool test; a
	 * descriptor inconsistency BUG()s here at first generate instead
	 * of silently mis-shaping args at runtime.
	 */
	if (!catalog_validated) {
		validate_struct_catalog();
		catalog_validated = true;
	}

	/*
	 * Arg-derived discriminator resolves up-front from rec; nested
	 * FT_PTR_STRUCT calls thread rec through so a child struct under
	 * a tagged-union parent reads the same syscall args.  Buffer-
	 * derived discriminators can't resolve here -- the buffer is empty
	 * -- so the shared desc->fields[] head pass runs first and writes
	 * the discriminator (e.g. sockaddr_storage's ss_family).  The
	 * per-AF variant fill then runs on the now-populated buffer.
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
		return;
	}

	struct_fill_passes(buf, size, desc->fields, desc->num_fields, rec);

	if (desc->buffer_discrim_size == 0)
		return;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
	}
}

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
static unsigned long gen_arg_struct_ptr_in(struct syscallentry *entry __unused__,
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
static unsigned long gen_arg_struct_ptr_out(struct syscallentry *entry __unused__,
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
static unsigned long gen_arg_struct_ptr_inout(struct syscallentry *entry __unused__,
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

	for (i = 0; i < entry->num_args; i++) {
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
static unsigned long gen_arg_struct_size(struct syscallentry *entry,
					 struct syscallrecord *rec,
					 unsigned int argnum __unused__)
{
	const struct struct_desc *desc;
	const struct struct_old_abi_sizes *oa;
	unsigned long hint;
	unsigned int roll;

	/* Opts into the typed-hypothesis live inject arm: ARG_STRUCT_SIZE
	 * is a learned-size scalar slot, the same shape as the typed-safe
	 * size/count/range scalar set the typed store is calibrated for.
	 *
	 * No accept range: this consumer has no declared upper bound to
	 * gate against; the fallback random scalar below clamps at
	 * ARG_STRUCT_SIZE_FALLBACK_CAP only for the no-catalog path. */
	if (ONE_IN(cmp_hint_inject_denom(10)) &&
	    cmp_hints_try_get_ex(rec->nr, rec->do32bit,
				 CMP_HINT_BOUNDARY, 0, true, NULL, &hint)) {
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

/*
 * Shared cleanup helper for any argtype whose generator hands back a
 * heap allocation that must be released after the syscall returns
 * (ARG_PATHNAME, ARG_SOCKADDR).
 *
 * Read via get_arg_snapshot() so that if the slot opted into the
 * arg_shadow mask, we free the pointer the parent's sanitiser actually
 * handed the kernel rather than whatever a sibling may have stomped
 * into rec->aN after the syscall returned -- the latter is the
 * highest-value site for a wild-free hazard, since deferred_free_enqueue
 * would otherwise feed a non-malloc pointer to the side-set gate.
 * Unopted slots fall through to the live rec->aN, matching the
 * pre-change behaviour.
 */
static void cleanup_deferred_free(struct syscallrecord *rec, unsigned int argnum)
{
	deferred_free_enqueue((void *) get_arg_snapshot(rec, argnum));
}

/*
 * Per-argtype policy descriptor table.
 *
 * Indexed by enum argtype.  Each entry concentrates everything fill_arg,
 * generic_free_arg, and blanket_address_scrub need to know about that
 * argtype: how to produce a value, how to release it afterwards, whether
 * the slot participates in the fd biases, the blanket address scrub, the
 * numeric-substitute fuzzer technique, and whether it has a paired
 * length slot that follows it in the argument list.
 */
const struct argtype_ops argtype_table[] = {
	[ARG_UNDEFINED] = {
		.name = "ARG_UNDEFINED",
		.generate = gen_undefined_arg,
	},
	[ARG_FD] = {
		.name = "ARG_FD",
		.generate = gen_arg_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_LEN] = {
		.name = "ARG_LEN",
		.generate = gen_arg_len,
	},
	[ARG_ADDRESS] = {
		.name = "ARG_ADDRESS",
		.generate = handle_arg_address,
		.default_address_scrub = true,
	},
	[ARG_MODE_T] = {
		.name = "ARG_MODE_T",
		.generate = handle_arg_mode_t,
	},
	[ARG_NON_NULL_ADDRESS] = {
		.name = "ARG_NON_NULL_ADDRESS",
		.generate = gen_arg_non_null_address,
		.default_address_scrub = true,
	},
	[ARG_PID] = {
		.name = "ARG_PID",
		.generate = gen_arg_pid,
		.accepts_numeric_substitute = true,
	},
	[ARG_KEY_SERIAL] = {
		.name = "ARG_KEY_SERIAL",
		.generate = gen_arg_key_serial,
		.accepts_numeric_substitute = true,
	},
	[ARG_TIMERID] = {
		.name = "ARG_TIMERID",
		.generate = gen_arg_timerid,
		.accepts_numeric_substitute = true,
	},
	[ARG_AIO_CTX] = {
		.name = "ARG_AIO_CTX",
		.generate = gen_arg_aio_ctx,
		.accepts_numeric_substitute = true,
	},
	[ARG_SEM_ID] = {
		.name = "ARG_SEM_ID",
		.generate = gen_arg_sem_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_MSG_ID] = {
		.name = "ARG_MSG_ID",
		.generate = gen_arg_msg_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_SYSV_SHM] = {
		.name = "ARG_SYSV_SHM",
		.generate = gen_arg_sysv_shm,
		.accepts_numeric_substitute = true,
	},
	[ARG_RANGE] = {
		.name = "ARG_RANGE",
		.generate = handle_arg_range,
		.default_address_scrub = true,
	},
	[ARG_OP] = {
		.name = "ARG_OP",
		.generate = handle_arg_op,
	},
	[ARG_LIST] = {
		.name = "ARG_LIST",
		.generate = handle_arg_list,
	},
	[ARG_CPU] = {
		.name = "ARG_CPU",
		.generate = gen_arg_cpu,
	},
	[ARG_NUMA_NODE] = {
		.name = "ARG_NUMA_NODE",
		.generate = gen_arg_numa_node,
		.accepts_numeric_substitute = true,
	},
	[ARG_PATHNAME] = {
		.name = "ARG_PATHNAME",
		.generate = gen_arg_pathname,
		.cleanup = cleanup_deferred_free,
	},
	[ARG_XATTR_NAME] = {
		.name = "ARG_XATTR_NAME",
		.generate = gen_arg_xattr_name,
	},
	[ARG_FSTYPE_NAME] = {
		.name = "ARG_FSTYPE_NAME",
		.generate = gen_arg_fstype_name,
	},
	[ARG_TIMESPEC] = {
		.name = "ARG_TIMESPEC",
		.generate = gen_arg_timespec,
	},
	[ARG_ITIMERVAL] = {
		.name = "ARG_ITIMERVAL",
		.generate = gen_arg_itimerval,
	},
	[ARG_ITIMERSPEC] = {
		.name = "ARG_ITIMERSPEC",
		.generate = gen_arg_itimerspec,
	},
	[ARG_TIMEVAL] = {
		.name = "ARG_TIMEVAL",
		.generate = gen_arg_timeval,
	},
	[ARG_NODEMASK] = {
		.name = "ARG_NODEMASK",
		.generate = gen_arg_nodemask,
	},
	[ARG_CPUMASK] = {
		.name = "ARG_CPUMASK",
		.generate = gen_arg_cpumask,
	},
	[ARG_BUF_SIZED] = {
		.name = "ARG_BUF_SIZED",
		.generate = gen_arg_buf_sized,
		.paired_length = ARG_BUF_LEN,
	},
	[ARG_BUF_LEN] = {
		.name = "ARG_BUF_LEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_IOVEC] = {
		.name = "ARG_IOVEC",
		.generate = handle_arg_iovec,
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVEC_IN] = {
		.name = "ARG_IOVEC_IN",
		.generate = handle_arg_iovec_in,
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVECLEN] = {
		.name = "ARG_IOVECLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_SOCKADDR] = {
		.name = "ARG_SOCKADDR",
		.generate = handle_arg_sockaddr,
		.cleanup = cleanup_deferred_free,
		.paired_length = ARG_SOCKADDRLEN,
	},
	[ARG_SOCKADDRLEN] = {
		.name = "ARG_SOCKADDRLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_MMAP] = {
		.name = "ARG_MMAP",
		.generate = gen_arg_mmap,
	},
	[ARG_SOCKETINFO] = {
		.name = "ARG_SOCKETINFO",
		.generate = gen_arg_socketinfo,
	},
	[ARG_STRUCT_PTR_IN] = {
		.name = "ARG_STRUCT_PTR_IN",
		.generate = gen_arg_struct_ptr_in,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_PTR_OUT] = {
		.name = "ARG_STRUCT_PTR_OUT",
		.generate = gen_arg_struct_ptr_out,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_PTR_INOUT] = {
		.name = "ARG_STRUCT_PTR_INOUT",
		.generate = gen_arg_struct_ptr_inout,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_SIZE] = {
		.name = "ARG_STRUCT_SIZE",
		.generate = gen_arg_struct_size,
	},
	[ARG_FD_BPF_BTF] = {
		.name = "ARG_FD_BPF_BTF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_LINK] = {
		.name = "ARG_FD_BPF_LINK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_MAP] = {
		.name = "ARG_FD_BPF_MAP",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_PROG] = {
		.name = "ARG_FD_BPF_PROG",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EPOLL] = {
		.name = "ARG_FD_EPOLL",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EVENTFD] = {
		.name = "ARG_FD_EVENTFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FANOTIFY] = {
		.name = "ARG_FD_FANOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FS_CTX] = {
		.name = "ARG_FD_FS_CTX",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_INOTIFY] = {
		.name = "ARG_FD_INOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_IO_URING] = {
		.name = "ARG_FD_IO_URING",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_LANDLOCK] = {
		.name = "ARG_FD_LANDLOCK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MEMFD] = {
		.name = "ARG_FD_MEMFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MOUNT] = {
		.name = "ARG_FD_MOUNT",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MQ] = {
		.name = "ARG_FD_MQ",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PERF] = {
		.name = "ARG_FD_PERF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIDFD] = {
		.name = "ARG_FD_PIDFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIPE] = {
		.name = "ARG_FD_PIPE",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SIGNALFD] = {
		.name = "ARG_FD_SIGNALFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SOCKET] = {
		.name = "ARG_FD_SOCKET",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_TIMERFD] = {
		.name = "ARG_FD_TIMERFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
};

const unsigned int argtype_table_size =
	sizeof(argtype_table) / sizeof(argtype_table[0]);

const struct argtype_ops *argtype_get_ops(enum argtype t)
{
	if ((unsigned int) t >= argtype_table_size)
		BUG("argtype_get_ops: argtype out of range\n");
	if (argtype_table[t].generate == NULL)
		BUG("argtype_get_ops: argtype has no generator\n");
	return &argtype_table[t];
}

/*
 * Build the address-scrub slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from copy_syscall_table()
 * in tables.c; the cached mask in entry->address_scrub_mask drives
 * blanket_address_scrub() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype carries the default_address_scrub descriptor flag.
 */
uint8_t compute_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->default_address_scrub)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Bit k set means slot (k+1)'s argtype is ARG_STRUCT_PTR_IN/OUT/INOUT
 * AND the cataloged struct for that (syscall, arg) reaches an
 * FT_ADDRESS field via the pointer chain.  Resolved once at table-init
 * time so the per-dispatch nested_address_scrub() walk short-circuits
 * with a single masked load on the bulk of syscalls (no cataloged
 * struct, or no address-shaped field inside it).
 */
uint8_t compute_nested_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL || entry->name == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		enum argtype t = entry->argtype[i];

		if (t != ARG_STRUCT_PTR_IN &&
		    t != ARG_STRUCT_PTR_OUT &&
		    t != ARG_STRUCT_PTR_INOUT)
			continue;

		/*
		 * Discriminator-aware: any cataloged variant for this slot
		 * carrying an FT_ADDRESS field forces the bit on, because the
		 * live variant resolves per-dispatch and the mask is a
		 * conservative include.  struct_arg_lookup_by_name() returns
		 * only one descriptor and can't represent that OR-across.
		 */
		if (struct_arg_any_has_address_field(entry->name, i + 1))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the cleanup-hook slot bitmap for entry's argtype[] table.  Called
 * once per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->cleanup_arg_mask drives
 * generic_free_arg() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype has a non-NULL .cleanup hook in the descriptor table.
 */
uint8_t compute_cleanup_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->cleanup != NULL)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the fd-arg slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->fd_arg_mask drives the fd-scoreboard
 * update loops in handle_success() / handle_failure() (results.c) without
 * re-running is_fdarg() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype is ARG_FD or any typed-fd argtype.
 */
uint8_t compute_fd_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the ARG_LEN slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->len_arg_mask drives the
 * successful-length scoreboard update in handle_success() (results.c)
 * without re-running get_argtype() per slot.  Bit k (k=0..5) set means
 * slot (k+1)'s argtype is ARG_LEN.
 */
uint8_t compute_len_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (entry->argtype[i] == ARG_LEN)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Precompute arg_params[i].list.all_bits (the OR of every value in the
 * arglist) for each ARG_OP/ARG_LIST slot.  Called once per syscallentry
 * at table-init time from copy_syscall_table() in tables.c so callers
 * that need "all valid bits" (e.g. set_rand_bitmask-style boundary or
 * structured-mutation paths) can read the precomputed mask instead of
 * re-walking values[] on every invocation.  Slots whose argtype is not
 * ARG_OP/ARG_LIST own the .range union member and are left untouched.
 */
void populate_arglist_all_bits(struct syscallentry *entry)
{
	unsigned int i;

	if (entry == NULL)
		return;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		enum argtype t = entry->argtype[i];
		struct arglist *al;
		unsigned long bits = 0;
		unsigned int k;

		if (t != ARG_OP && t != ARG_LIST)
			continue;

		al = &entry->arg_params[i].list;
		if (al->values == NULL || al->num == 0) {
			al->all_bits = 0;
			continue;
		}

		for (k = 0; k < al->num; k++)
			bits |= al->values[k];

		al->all_bits = bits;
	}
}

static unsigned long fill_arg(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	const struct argtype_ops *ops;
	enum argtype t;
	unsigned long val;

	if (argnum > entry->num_args)
		return 0;

	t = get_argtype(entry, argnum);
	ops = argtype_get_ops(t);

	/* Pre-generate bias: for fd-typed args, occasionally re-pick a low
	 * fd that previously succeeded for this exact (syscall, argnum)
	 * slot.  Targets the sweet spot where the kernel accepted the fd
	 * last time, so we keep exercising the post-validation path instead
	 * of bouncing off EBADF/EINVAL on a fresh random pick. */
	if (ops->can_use_success_fd_bias && RAND_BOOL()) {
		int fd = pick_successful_fd(&entry->results[argnum - 1]);

		if (fd >= 0)
			return (unsigned long) fd;
	}

	val = ops->generate(entry, rec, argnum);

	/* Central-generator coverage for the address-family argtypes.
	 *
	 * ARG_NON_NULL_ADDRESS routes through get_non_null_address() ->
	 * get_writable_address() and always returns a trinity-owned RW
	 * scratch page.  ARG_ADDRESS routes through get_address(): the
	 * ~1%-rate NULL arm, the writable-page arm (also via
	 * get_writable_address), and a previous-slot-reuse path whose
	 * +1 / +sizeof() offsets stay within the same RW page after a
	 * non-zero find_previous_arg_address result.  Any non-zero return
	 * therefore points into RW scratch, so stamp dir/owner to promote
	 * the slot out of arg_meta_addr_without_meta.
	 *
	 * Other argtypes stay at the seed defaults: NULL get_address()
	 * results carry no buffer to describe; ARG_RANGE is numeric in
	 * [low, high], not an address; ARG_UNDEFINED mints a writable
	 * address on only one of nine arms and the disambiguation is not
	 * visible from here.
	 *
	 * Publish generation == rec->arg_meta_gen + 1 so arg_meta_init's
	 * preservation gate can distinguish a fresh stamp from stale
	 * residue left by a prior dispatch whose argtype happened to
	 * write the same dir/owner bits.
	 */
	if (val != 0 && (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS)) {
		struct arg_slot_meta *m = &rec->arg_meta[argnum - 1];

		m->dir = ARG_DIR_INOUT;
		m->owner = ARG_OWNER_GENERIC;
		m->generation = rec->arg_meta_gen + 1;
	}

	return val;
}

/* Default-on scrub: any argtype with default_address_scrub set in the
 * descriptor table (today ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE)
 * that ended up aliasing shared_regions or the libc heap arena gets
 * redirected to a writable address before the syscall is issued. Catches
 * the coverage-gap class where per-syscall sanitisers either don't call
 * avoid_shared_buffer_out() or miss specific slots. Length default is
 * page_size (conservative; bare ARG_ADDRESS carries no length info
 * and walking adjacent slots per dispatch is too expensive). */

/*
 * Bounded recursion depth for the nested-address walker.  Real
 * cataloged structs are flat or one level deep (msghdr -> iovec); the
 * cap mirrors STRUCT_ADDRESS_SCAN_MAX_DEPTH in struct_catalog.c so a
 * future cyclic catalog entry cannot drive infinite recursion at
 * dispatch time.
 */
#define NESTED_ADDRESS_SCRUB_MAX_DEPTH	4

/*
 * Stateless pre-deref guard for every struct base
 * scrub_struct_addresses() is about to walk -- the top-level
 * rec->aN slot fed in by nested_address_scrub(), and the
 * FT_PTR_STRUCT / FT_PTR_ARRAY base pointers read out of a parent
 * struct during the walk.  All three are the exact class of value a
 * sibling scribble can replace with garbage between sanitise and
 * dispatch.  Reject when the candidate base either fails the shape
 * predicate (NULL-ish, non-canonical, or misaligned) or falls
 * outside the cached glibc brk arena: a legitimate zmalloc_tracked()
 * struct slot satisfies both, and a scribbled value that aliases
 * neither does not.  Bump nested_scrub_reject_untracked on the reject
 * so a clean run (near-zero rate-of-change) double-checks the guard
 * is not false-rejecting valid bases.  The predicates are
 * lifecycle-independent on purpose: by scrub time the deferred-free
 * ring has already consumed the tracker entries for these pointers,
 * so an alloc_track_lookup()-based gate would false-reject ~100% of
 * legitimately-generated bases.
 */
static bool nested_scrub_base_unsafe(unsigned long base)
{
	const void *p = (const void *) base;

	if (is_corrupt_ptr_shape(p) || !is_in_glibc_heap(p)) {
		__atomic_add_fetch(&shm->stats.nested_scrub_reject_untracked,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	return false;
}

static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   struct syscallrecord *rec,
				   unsigned int depth);

/*
 * Per-field-array scrub sweep: visit every FT_ADDRESS in @fields[0..n)
 * and recurse through FT_PTR_STRUCT / FT_PTR_ARRAY edges.  Shared by
 * the flat desc->fields[] walk and the variant overlay walks
 * (variant->fields, variant->base->fields, matched nested variant's
 * fields), mirroring how struct_field_fill_schema_aware() splits
 * between a flat pass and overlay passes.  @rec is threaded through so
 * a recursed-into child struct can resolve its own variants the same
 * way the FILL path does in struct_field_fill_schema_aware().
 *
 * Sibling LEN lookup uses find_field_index_in() against the same
 * fields[] array currently being walked, matching the runtime
 * pre-pin pass and validate_struct_catalog()'s comment that each
 * fields[] array is an independent name-resolution scope.
 */
static void scrub_field_array(unsigned char *buf, unsigned int size,
			      const struct struct_field *fields,
			      unsigned int num_fields,
			      struct syscallrecord *rec,
			      unsigned int depth)
{
	unsigned int i;

	for (i = 0; i < num_fields; i++) {
		const struct struct_field *f = &fields[i];
		const struct struct_desc *target;
		unsigned long ptr;

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_ADDRESS: {
			/*
			 * Scrub at the field's natural pointer width.
			 * Sub-pointer-sized FT_ADDRESS fields cannot hold a
			 * useful address; skip them rather than scribble
			 * adjacent bytes.
			 */
			if (f->size != sizeof(unsigned long))
				break;
			avoid_shared_buffer_out(
				(unsigned long *)(buf + f->offset), page_size);
			break;
		}
		case FT_PTR_STRUCT:
			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (target == NULL || target->struct_size == 0)
				break;
			if (nested_scrub_base_unsafe(ptr))
				break;
			scrub_struct_addresses((unsigned char *) ptr,
					       target->struct_size,
					       target, rec, depth + 1);
			break;
		case FT_PTR_ARRAY: {
			unsigned long count = 0;
			unsigned long cap;
			int paired;
			unsigned long j;

			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (target == NULL || target->struct_size == 0)
				break;
			if (nested_scrub_base_unsafe(ptr))
				break;

			paired = find_field_index_in(fields, num_fields,
						     f->u.ptr_array.len_field);
			if (paired >= 0)
				count = (unsigned long) read_field_uint(
					buf, &fields[paired]);

			/*
			 * Cap the iteration at the catalog's declared
			 * max_count (or PTR_ARRAY_DEFAULT_MAX) so a sibling-
			 * scribbled len field cannot drive a walk past the
			 * allocation's tail and SEGV the sanitiser.
			 */
			cap = f->u.ptr_array.max_count;
			if (cap == 0)
				cap = PTR_ARRAY_DEFAULT_MAX;
			if (count > cap)
				count = cap;

			for (j = 0; j < count; j++) {
				unsigned char *elem = (unsigned char *) ptr
					+ j * target->struct_size;

				scrub_struct_addresses(elem,
						       target->struct_size,
						       target, rec, depth + 1);
			}
			break;
		}
		default:
			break;
		}
	}
}

/*
 * Mirror struct_variant_overlay_nested() from the FILL path: when an
 * outer variant carries a nested_variants table, re-resolve the
 * sub-variant against the just-filled buffer and scrub variant->base
 * (if set) plus the matched nested->fields[] in the same order FILL
 * wrote them.  Depth-1 only -- struct_desc_resolve_nested_variant()
 * rejects nested-of-nested, matching the FILL contract.
 */
static void scrub_variant_overlay_nested(unsigned char *buf,
					 unsigned int size,
					 const struct union_variant *variant,
					 struct syscallrecord *rec,
					 unsigned int depth)
{
	const struct union_variant *nested;

	if (variant->nested_variants == NULL)
		return;

	nested = struct_desc_resolve_nested_variant(variant, buf, size);
	if (nested == NULL && variant->base == NULL)
		return;

	if (variant->base != NULL)
		scrub_field_array(buf, size,
				  variant->base->fields,
				  variant->base->num_fields, rec, depth);

	if (nested != NULL)
		scrub_field_array(buf, size,
				  nested->fields,
				  nested->num_fields, rec, depth);
}

/*
 * Walk one cataloged-struct buffer and scrub every FT_ADDRESS field,
 * recursing into FT_PTR_STRUCT targets and FT_PTR_ARRAY elements whose
 * element struct is itself cataloged.  FT_PTR_BYTES and the FT_PTR_*
 * pointers themselves are trinity-allocated via zmalloc_tracked() and
 * cannot alias shared_regions[] or the libc brk arena; they are not
 * scrub targets, only recursion edges.
 *
 * Variant-aware: when desc carries variants the active variant
 * resolves the field set the FILL path actually wrote, and a variant-
 * only FT_ADDRESS is reachable only through variant->fields,
 * variant->base->fields, or the matched nested_variant->fields.  The
 * traversal exactly mirrors struct_field_fill_schema_aware() so an
 * arg-derived variant replaces desc->fields, a buffer-derived variant
 * overlays it, and nested overlays apply on top -- the scrub visits
 * every byte the fill could have written an FT_ADDRESS into.  Without
 * this mirroring a variant-only FT_ADDRESS field is never scrubbed,
 * leaving it free to alias a shared sibling buffer and re-open the
 * cross-child corruption window the top-level scrub closes.
 */
static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   struct syscallrecord *rec,
				   unsigned int depth)
{
	const struct union_variant *variant;

	if (buf == NULL || desc == NULL ||
	    depth >= NESTED_ADDRESS_SCRUB_MAX_DEPTH)
		return;

	/*
	 * Range-gate the whole walk before touching @buf.  At depth 0
	 * @buf is the caller-supplied syscall slot (rec->aN); at depth
	 * >= 1 it is a pointer value read out of a parent struct.  Both
	 * are the exact class of value a sibling scribble can replace
	 * with garbage between sanitise and dispatch -- defending
	 * against which is the entire reason the scrub exists.  The
	 * field walk below dereferences @buf in two ways that fault on
	 * a stale pointer with no recovery: read_field_uint() does a
	 * memcpy out of buf+offset, and avoid_shared_buffer_out() ->
	 * asb_relocate() reads *addr at the top of its body (the
	 * asb_copy_active sigsetjmp guard covers only the inner
	 * memcpy, not this outer deref).  The per-field bound check
	 * (f->offset + f->size > size) only constrains the walk within
	 * an assumed-valid @size-byte allocation; it does nothing when
	 * @buf itself is unmapped.
	 *
	 * range_readable_user() proves @buf is mapped from cached
	 * state (tracked shared regions + libc heap snapshot) -- a
	 * pure in-process lookup, no deref, cannot fault.  Legit
	 * zmalloc_tracked() targets live in the heap snapshot and
	 * pass; scribbled garbage that aliases neither snapshot fails.
	 * Skip-the-scrub on false is safe: the scrub is purely
	 * defensive, the fuzzed syscall has not yet fired, and falling
	 * through means the kernel sees the pre-scrub argument -- the
	 * exact gap the scrub narrows, not a regression.
	 */
	if (!range_readable_user(buf, size))
		return;

	/*
	 * Arg-derived variant: FILL writes variant->fields[] in place of
	 * desc->fields[].  Mirror exactly -- scrubbing desc->fields[] here
	 * would walk a field set that was never populated by FILL.
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		scrub_field_array(buf, size, variant->fields,
				  variant->num_fields, rec, depth);
		scrub_variant_overlay_nested(buf, size, variant, rec, depth);
		return;
	}

	/*
	 * No arg-derived variant.  FILL runs desc->fields[] first; if the
	 * descriptor carries a buffer-derived discriminator the resolved
	 * variant is then overlaid on top.  Mirror exactly.
	 */
	scrub_field_array(buf, size, desc->fields, desc->num_fields,
			  rec, depth);

	if (desc->buffer_discrim_size == 0)
		return;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		scrub_field_array(buf, size, variant->fields,
				  variant->num_fields, rec, depth);
		scrub_variant_overlay_nested(buf, size, variant, rec, depth);
	}
}

static void nested_address_scrub(struct syscallentry *entry,
				 struct syscallrecord *rec)
{
	uint8_t mask = entry->nested_address_scrub_mask;

	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		const struct struct_desc *desc;
		unsigned long slot;

		switch (i) {
		case 1: slot = rec->a1; break;
		case 2: slot = rec->a2; break;
		case 3: slot = rec->a3; break;
		case 4: slot = rec->a4; break;
		case 5: slot = rec->a5; break;
		case 6: slot = rec->a6; break;
		default: slot = 0; break;
		}

		desc = struct_arg_lookup(rec->nr, i, rec->do32bit, rec);
		if (slot != 0 && desc != NULL &&
		    !nested_scrub_base_unsafe(slot))
			scrub_struct_addresses((unsigned char *) slot,
					       desc->struct_size, desc,
					       rec, 0);
		mask &= (uint8_t)(mask - 1);
	}
}

/*
 * Map a slot's argtype to a coarse default ownership/direction descriptor.
 * Broad best-effort seed: the structurally clear argtypes (curated input
 * buffers, the in/out/inout struct pointer trio, fd-backed handles) get a
 * non-default classification; the truly generic address-family slots
 * (ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE) and bare scalars stay at
 * dir/owner == NONE so the central-generator-coverage row above this one
 * can attribute the slots it fills.  SHADOW: no caller of arg_meta_init
 * consults the result for a decision.
 */
static void argtype_default_meta(enum argtype t, uint8_t *dir, uint8_t *owner,
				 uint32_t *flags)
{
	*dir = ARG_DIR_NONE;
	*owner = ARG_OWNER_NONE;
	*flags = 0;

	switch (t) {
	case ARG_STRUCT_PTR_IN:
	case ARG_IOVEC_IN:
	case ARG_PATHNAME:
	case ARG_XATTR_NAME:
	case ARG_FSTYPE_NAME:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_NODEMASK:
	case ARG_CPUMASK:
		*dir = ARG_DIR_IN;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_STRUCT_PTR_OUT:
		*dir = ARG_DIR_OUT;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_STRUCT_PTR_INOUT:
	case ARG_IOVEC:
	case ARG_BUF_SIZED:
		*dir = ARG_DIR_INOUT;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED;
		break;
	case ARG_SOCKADDR:
		*dir = ARG_DIR_OPTIONAL_IN;
		*owner = ARG_OWNER_GENERIC;
		*flags = ARG_META_FLAG_CURATED | ARG_META_FLAG_ALLOW_NULL;
		break;
	default:
		if (is_fdarg(t))
			*owner = ARG_OWNER_EXTERNAL;
		break;
	}
}

void arg_meta_init(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint32_t generation = ++rec->arg_meta_gen;
	uint32_t prev_generation = generation - 1;
	unsigned int i;

	for (i = 0; i < 6; i++) {
		enum argtype t = (i < entry->num_args)
				? entry->argtype[i] : ARG_UNDEFINED;
		struct arg_slot_meta *m = &rec->arg_meta[i];
		uint32_t stored_gen = m->generation;
		uint8_t dir, owner;
		uint32_t flags;
		bool prestamped = (stored_gen == generation);

		/* Stale-sidecar tripwire: a non-zero stored generation that
		 * is neither the previous dispatch's value nor this dispatch's
		 * own generation (which fill_arg stamps when its central-
		 * generator coverage classifies an address-family slot) means
		 * an init pass was skipped (missed reset) or the rec was
		 * wholesale-stomped. */
		if (stored_gen != 0 && stored_gen != prev_generation &&
		    !prestamped)
			__atomic_add_fetch(&shm->stats.arg_meta_argtype_stale,
					   1, __ATOMIC_RELAXED);

		argtype_default_meta(t, &dir, &owner, &flags);

		/* Adopt fill_arg's central-generator stamp for the address-
		 * family argtypes when the prestamp signal proves the slot's
		 * dir/owner came from this dispatch's mint, not stale residue
		 * from a prior dispatch's argtype.  ARG_RANGE is in the gate
		 * for symmetry with the credit set below; fill_arg never
		 * stamps it (returns a numeric value, not an address) so the
		 * prestamped branch is never taken. */
		if (prestamped &&
		    (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS ||
		     t == ARG_RANGE)) {
			dir = m->dir;
			owner = m->owner;
		}

		*m = (struct arg_slot_meta){
			.dir = dir,
			.owner = owner,
			.flags = flags,
			.generation = generation,
		};

		if (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS ||
		    t == ARG_RANGE) {
			if (dir != ARG_DIR_NONE || owner != ARG_OWNER_NONE ||
			    flags != 0)
				__atomic_add_fetch(&shm->stats.arg_meta_addr_with_meta,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.arg_meta_addr_without_meta,
						   1, __ATOMIC_RELAXED);
		}
	}
}

void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint8_t mask = entry->address_scrub_mask;

	/* Most syscalls have no scrub-eligible slots; skip the walk entirely
	 * via the cached mask instead of running argtype_get_ops() per arg. */
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		unsigned long *slot;

		switch (i) {
		case 1: slot = &rec->a1; break;
		case 2: slot = &rec->a2; break;
		case 3: slot = &rec->a3; break;
		case 4: slot = &rec->a4; break;
		case 5: slot = &rec->a5; break;
		case 6: slot = &rec->a6; break;
		default: slot = NULL; break;
		}
		if (slot != NULL)
			avoid_shared_buffer_out(slot, page_size);
		__atomic_add_fetch(&shm->stats.blanket_address_scrub_slots_walked,
				   1, __ATOMIC_RELAXED);
		mask &= (uint8_t)(mask - 1);
	}

	/* SHADOW: contradiction census between the blanket's coverage
	 * (entry->address_scrub_mask) and the per-slot sidecar dir seeded
	 * by arg_meta_init().  Telemetry only -- the live walk above is
	 * byte-unchanged. */
	for (unsigned int s = 0; s < entry->num_args && s < 6; s++) {
		uint8_t dir = rec->arg_meta[s].dir;

		if (entry->address_scrub_mask & (uint8_t)(1u << s)) {
			if (dir == ARG_DIR_IN || dir == ARG_DIR_INOUT)
				__atomic_add_fetch(&shm->stats.arg_meta_scrub_would_destroy_in,
						   1, __ATOMIC_RELAXED);
		} else if (dir == ARG_DIR_OUT) {
			__atomic_add_fetch(&shm->stats.arg_meta_scrub_would_preserve_out,
					   1, __ATOMIC_RELAXED);
		}
	}

	nested_address_scrub(entry, rec);
}

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec)
{
	/* Defensive: zero arg slots so any ARG_UNDEFINED entry doesn't
	 * inherit stale values from the previous syscall's record.  Also
	 * zero the post_state snapshot slot — sanitisers that use it
	 * allocate fresh in this dispatch, and a stale value left by a
	 * previous syscall (e.g. one whose post handler did not reach the
	 * deferred_freeptr) would otherwise survive into a post handler
	 * that now reads it as a live pointer.
	 *
	 * Only zero the slots that won't be overwritten below by fill_arg();
	 * the bulk memset of all six was wasted work for the common case of
	 * 4-6 argument syscalls. Switch fall-through unrolls the per-slot
	 * zero so the compiler can pick an efficient sequence. */
	switch (entry->num_args) {
	case 0: rec->a1 = 0; /* fall through */
	case 1: rec->a2 = 0; /* fall through */
	case 2: rec->a3 = 0; /* fall through */
	case 3: rec->a4 = 0; /* fall through */
	case 4: rec->a5 = 0; /* fall through */
	case 5: rec->a6 = 0; /* fall through */
	default: break;
	}
	rec->post_state = 0;

	/* num_args is the authority for which slots are present.
	 * Don't gate on argtype[i] != 0 — ARG_UNDEFINED is enum value 0,
	 * which would silently skip filling those slots even though
	 * fill_arg() handles ARG_UNDEFINED by returning a random value. */
	if (entry->num_args >= 1)
		rec->a1 = fill_arg(entry, rec, 1);
	if (entry->num_args >= 2)
		rec->a2 = fill_arg(entry, rec, 2);
	if (entry->num_args >= 3)
		rec->a3 = fill_arg(entry, rec, 3);
	if (entry->num_args >= 4)
		rec->a4 = fill_arg(entry, rec, 4);
	if (entry->num_args >= 5)
		rec->a5 = fill_arg(entry, rec, 5);
	if (entry->num_args >= 6)
		rec->a6 = fill_arg(entry, rec, 6);
}

void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint8_t mask;

	BUG_ON(entry == NULL);

	/* Most syscalls own no freeable resources in any slot; the cached
	 * cleanup_arg_mask lets us skip the per-arg argtype_get_ops() walk
	 * outright in that common case. */
	mask = entry->cleanup_arg_mask;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		enum argtype t = get_argtype(entry, i);
		const struct argtype_ops *ops = argtype_get_ops(t);

		deferred_free_set_cleanup_argtype(t);
		ops->cleanup(rec, i);
		deferred_free_set_cleanup_argtype(ARG_UNDEFINED);
		mask &= (uint8_t)(mask - 1);
	}
}

void generate_syscall_args(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	struct childdata *child;

	srec_publish_begin(rec);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL) {
		srec_publish_end(rec);
		return;
	}
	__atomic_store_n(&rec->state, PREP, __ATOMIC_RELAXED);

	/* reset the per-call cmp-hint latch so each new
	 * call starts with a fresh "no hint injected yet" state.  Any of
	 * the four argtype-handler callsites below that pulls a hint via
	 * cmp_hints_try_get() sets the flag through credit_cmp_hint_injection
	 * before the dispatch lands; kcov_collect()'s found_new branch then
	 * reads it to credit per_syscall_cmp_hint_pc_wins[nr].  Parent-
	 * context this_child()==NULL skips the clear -- the flag has no
	 * parent-side consumer. */
	child = this_child();
	if (child != NULL) {
		child->cmp_hint_injected_this_call = false;
		/* SHADOW feedback scoring stash starts each call empty
		 * ([11-feedback-loop]).  cmp_hints_try_get_ex pushes; the
		 * dispatch_step tail drains and credits via one of the
		 * cmp_hints_feedback_credit_* helpers.  Resetting here too
		 * means a parent dispatch that bailed before reaching the
		 * credit drain cannot leak its stash into the next call. */
		cmp_hints_feedback_reset_stash();
	}

	/* Reset post_state on every syscall step, before any branch.
	 * generic_sanitise() also clears it, but the minicorpus-replay
	 * path below skips generic_sanitise entirely; without this hoist,
	 * a sanitise-less syscall whose prior post handler did not reach
	 * deferred_freeptr would leave a stale pointer in post_state for
	 * the next syscall's post handler to dereference. */
	rec->post_state = 0;
	/* Same hoist for the per-rec owned-pointer list: rec_owned_drain
	 * zeros owned_count after every dispatched call, but the drain
	 * site is in handle_syscall_ret -- a minicorpus-replay step that
	 * inherits a rec where the previous dispatch never reached the
	 * drain (e.g. the child died between BEFORE and AFTER and the
	 * rec is re-used after fork) could otherwise see a stale owned[]
	 * entry and free a pointer the new caller never owned.  Hoisting
	 * the reset here matches the post_state contract above. */
	rec->owned_count = 0;
	/* Same hoist for arg_snapshot_mask: defaults to "nothing shadowed"
	 * so get_arg_snapshot() in any unrelated handler that somehow gets
	 * called against this rec (e.g. an early validate_arg_coupling
	 * rejection in __do_syscall before the dispatch-time snapshot
	 * runs) sees the live slot instead of a stale shadow from a
	 * previous dispatch.  The real snapshot is taken in __do_syscall
	 * after the second blanket_address_scrub, from the local a1..a6
	 * values that are actually passed to the kernel. */
	rec->arg_snapshot_mask = 0;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		arg_meta_init(entry, rec);
		blanket_address_scrub(entry, rec);
		srec_publish_end(rec);
		return;
	}

	generic_sanitise(entry, rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);
	arg_meta_init(entry, rec);
	blanket_address_scrub(entry, rec);

	srec_publish_end(rec);
}
