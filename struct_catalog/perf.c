/*
 * struct_catalog/perf.c -- perf_event_attr field and variant tables.
 *
 * perf_event_attr_fields and perf_event_attr_variants are `const` (not
 * `static const`) so the spine's .fields=/.variants= references resolve
 * via the externs in struct_catalog-internal.h.  struct_catalog.h and
 * arch.h are #included unconditionally so this TU is never empty.
 */

#include <stddef.h>
#include <time.h>
#include <linux/hw_breakpoint.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "perf.h"		/* random_tracepoint_config -- FT_PICKER for TRACEPOINT.config */
#include "perf_event.h"

/* ------------------------------------------------------------------ */
/* struct perf_event_attr (perf_event_open)                            */
/* ------------------------------------------------------------------ */

/*
 * perf_event_attr is the rare cataloged struct whose live fill path
 * the schema does NOT drive.  sanitise_perf_event_open() in
 * syscalls/perf_event_open.c hand-rolls a coherent (type, config)
 * tuple via pick_perf_tuple() and overwrites rec->a1 with its own
 * buffer; the schema-aware fill produced upstream is discarded on
 * every iteration.  The catalog therefore exists for two forward-
 * infra purposes:
 *
 *   1. type-scoped CMP attribution.  struct_field_for_cmp() prefers
 *      a same-width FT_ENUM / FT_FLAGS / FT_VERSION_MAGIC slot over
 *      an FT_RAW one, so a learned constant (KCOV CMP) lands on the
 *      named gate (type, size, sample_type, ...) rather than a
 *      coincidentally-same-width opaque slot.  No live consumer is
 *      wired today; this awaits the cmp_hints recording-path lift.
 *   2. per-type variant infra.  Only type-independent shared fields
 *      are annotated here; per-PERF_TYPE_* sub-variants for
 *      config / bp_* / config1 / config2 land once the buffer-
 *      discriminator is wired and `type` (offset 0) becomes the
 *      desc-level discriminator.
 *
 * Bit-field flag group at offset 40 (disabled..sigtrap, ~36 single-
 * bit flags + precise_ip:2 + __reserved_1:26) is annotated below via
 * PERF_ATTR_FLAG_MASK; the explicit hand-built mask doesn't compose
 * with offsetof so the field uses an explicit { .offset = 40 }.
 */

/*
 * type (offset 0): PERF_TYPE_* major-type discriminator.  Six legal
 * values today; vendor PMU type IDs >= PERF_TYPE_MAX are dynamically
 * registered and not enumerable at compile time.  Buffer-discriminator
 * infra reads this slot to select the per-type config / bp_* /
 * config1 / config2 variant.
 */
static const unsigned long perf_type_values[] = {
	PERF_TYPE_HARDWARE,
	PERF_TYPE_SOFTWARE,
	PERF_TYPE_TRACEPOINT,
	PERF_TYPE_HW_CACHE,
	PERF_TYPE_RAW,
	PERF_TYPE_BREAKPOINT,
};

/*
 * size (offset 4): ABI version stamp.  The kernel accepts any prior
 * PERF_ATTR_SIZE_VER* and zero-pads to its own sizeof; non-version
 * values bounce on -E2BIG / -EINVAL.  Mirrors perf_event_attr_known_
 * sizes[] in syscalls/perf_event_open.c so the hand-rolled csfu and
 * the schema-aware CMP attribution share the same vocabulary.
 */
static const unsigned long perf_attr_known_sizes[] = {
	PERF_ATTR_SIZE_VER0,
	PERF_ATTR_SIZE_VER1,
	PERF_ATTR_SIZE_VER2,
	PERF_ATTR_SIZE_VER3,
	PERF_ATTR_SIZE_VER4,
	PERF_ATTR_SIZE_VER5,
	PERF_ATTR_SIZE_VER6,
	PERF_ATTR_SIZE_VER7,
	PERF_ATTR_SIZE_VER8,
	PERF_ATTR_SIZE_VER9,
};

/*
 * sample_type (offset 24): PERF_SAMPLE_* bits 0..24.  The kernel
 * branches heavily on these in the overflow/sample path -- attributing
 * a learned constant to this field's vocab is high signal.
 */
#define PERF_SAMPLE_MASK ( \
	PERF_SAMPLE_IP            | PERF_SAMPLE_TID             | \
	PERF_SAMPLE_TIME          | PERF_SAMPLE_ADDR            | \
	PERF_SAMPLE_READ          | PERF_SAMPLE_CALLCHAIN       | \
	PERF_SAMPLE_ID            | PERF_SAMPLE_CPU             | \
	PERF_SAMPLE_PERIOD        | PERF_SAMPLE_STREAM_ID       | \
	PERF_SAMPLE_RAW           | PERF_SAMPLE_BRANCH_STACK    | \
	PERF_SAMPLE_REGS_USER     | PERF_SAMPLE_STACK_USER      | \
	PERF_SAMPLE_WEIGHT        | PERF_SAMPLE_DATA_SRC        | \
	PERF_SAMPLE_IDENTIFIER    | PERF_SAMPLE_TRANSACTION     | \
	PERF_SAMPLE_REGS_INTR     | PERF_SAMPLE_PHYS_ADDR       | \
	PERF_SAMPLE_AUX           | PERF_SAMPLE_CGROUP          | \
	PERF_SAMPLE_DATA_PAGE_SIZE | PERF_SAMPLE_CODE_PAGE_SIZE | \
	PERF_SAMPLE_WEIGHT_STRUCT)

/*
 * read_format (offset 32): PERF_FORMAT_* bits 0..4 controlling the
 * layout of read() on a perf event fd.
 */
#define PERF_FORMAT_MASK ( \
	PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | \
	PERF_FORMAT_ID                 | PERF_FORMAT_GROUP              | \
	PERF_FORMAT_LOST)

/*
 * branch_sample_type (offset 72): PERF_SAMPLE_BRANCH_* bits 0..19.
 * Only consulted when sample_type carries PERF_SAMPLE_BRANCH_STACK;
 * harmless garbage otherwise, so unconditional FT_FLAGS is correct.
 */
#define PERF_SAMPLE_BRANCH_MASK ( \
	PERF_SAMPLE_BRANCH_USER       | PERF_SAMPLE_BRANCH_KERNEL      | \
	PERF_SAMPLE_BRANCH_HV         | PERF_SAMPLE_BRANCH_ANY         | \
	PERF_SAMPLE_BRANCH_ANY_CALL   | PERF_SAMPLE_BRANCH_ANY_RETURN  | \
	PERF_SAMPLE_BRANCH_IND_CALL   | PERF_SAMPLE_BRANCH_ABORT_TX    | \
	PERF_SAMPLE_BRANCH_IN_TX      | PERF_SAMPLE_BRANCH_NO_TX       | \
	PERF_SAMPLE_BRANCH_COND       | PERF_SAMPLE_BRANCH_CALL_STACK  | \
	PERF_SAMPLE_BRANCH_IND_JUMP   | PERF_SAMPLE_BRANCH_CALL        | \
	PERF_SAMPLE_BRANCH_NO_FLAGS   | PERF_SAMPLE_BRANCH_NO_CYCLES   | \
	PERF_SAMPLE_BRANCH_TYPE_SAVE  | PERF_SAMPLE_BRANCH_HW_INDEX    | \
	PERF_SAMPLE_BRANCH_PRIV_SAVE  | PERF_SAMPLE_BRANCH_COUNTERS)

/*
 * clockid (offset 92): __s32, consulted only when the use_clockid
 * flag is set.  The kernel accepts the standard POSIX CLOCK_* IDs
 * plus a couple of perf-rejected ones so the rejection path also
 * gets exercised when use_clockid is on.
 */
static const unsigned long clockid_values[] = {
	CLOCK_REALTIME,
	CLOCK_MONOTONIC,
	CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID,
	CLOCK_MONOTONIC_RAW,
	CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE,
	CLOCK_BOOTTIME,
	CLOCK_TAI,
};

/*
 * Off-40 bit-field flag mask.  perf_event_attr packs 36 single-bit
 * flags plus precise_ip:2 plus __reserved_1:26 into a u64 starting at
 * offset 40, the packed perf flag word.  Trinity cannot use
 * offsetof on a bit-field member, so the catalog entry uses an
 * explicit { .offset = 40, .size = 8 } and this mask is hand-built
 * from the named bit positions:
 *
 *   - bits 0..14   single-bit flags: disabled, inherit, pinned,
 *                  exclusive, exclude_user, exclude_kernel,
 *                  exclude_hv, exclude_idle, mmap, comm, freq,
 *                  inherit_stat, enable_on_exec, task, watermark
 *   - bits 15..16  precise_ip (0..3 value, NOT a flag) -- excluded
 *                  so FT_FLAGS leaves it 0 (broadest "arbitrary skid"
 *                  path).  An ε-random splat across the 4 legal values
 *                  is intentionally deferred.
 *   - bits 17..37  single-bit flags: mmap_data, sample_id_all,
 *                  exclude_host, exclude_guest,
 *                  exclude_callchain_kernel, exclude_callchain_user,
 *                  mmap2, comm_exec, use_clockid, context_switch,
 *                  write_backward, namespaces, ksymbol, bpf_event,
 *                  aux_output, cgroup, text_poke, build_id,
 *                  inherit_thread, remove_on_exec, sigtrap
 *   - bits 38..63  __reserved_1 (26 bits) -- excluded so FT_FLAGS
 *                  never trips the kernel's reserved-nonzero
 *                  -EINVAL gate.
 *
 * Sums to 36 bits set.  This is the only hand-built-from-bitfield
 * mask in the catalog; a generic FT_BITFIELD_RUN sidecar would be
 * cleaner but isn't worth the infra for one struct whose schema fill
 * is discarded by sanitise_perf_event_open anyway.
 *
 * Constants use 1ULL so the OR-chain evaluates as u64; the implicit
 * narrowing to .u.flags.mask's unsigned long type silently drops
 * bits 32..37 (cgroup, text_poke, build_id, inherit_thread,
 * remove_on_exec, sigtrap) on 32-bit builds.  Acceptable: trinity's
 * primary target is 64-bit, the live fill path is discarded
 * regardless, and the truncation only narrows the CMP-attribution
 * vocab on 32-bit -- never produces an invalid value.
 */
#define PERF_ATTR_FLAG_MASK ( \
	(1ULL << 0)  | (1ULL << 1)  | (1ULL << 2)  | (1ULL << 3)  | \
	(1ULL << 4)  | (1ULL << 5)  | (1ULL << 6)  | (1ULL << 7)  | \
	(1ULL << 8)  | (1ULL << 9)  | (1ULL << 10) | (1ULL << 11) | \
	(1ULL << 12) | (1ULL << 13) | (1ULL << 14) | \
	/* bits 15..16 skipped: precise_ip is a 2-bit value */ \
	(1ULL << 17) | (1ULL << 18) | (1ULL << 19) | (1ULL << 20) | \
	(1ULL << 21) | (1ULL << 22) | (1ULL << 23) | (1ULL << 24) | \
	(1ULL << 25) | (1ULL << 26) | (1ULL << 27) | (1ULL << 28) | \
	(1ULL << 29) | (1ULL << 30) | (1ULL << 31) | (1ULL << 32) | \
	(1ULL << 33) | (1ULL << 34) | (1ULL << 35) | (1ULL << 36) | \
	(1ULL << 37) \
	/* bits 38..63: __reserved_1, skipped */ \
)

/*
 * aux_action (offset 116): u32 with 3 valid bits packed at the low
 * end (aux_start_paused, aux_pause, aux_resume in upstream uapi;
 * trinity's perf_event.h vintage exposes the slot as a plain u32 so
 * the bit names aren't visible here).  The remaining 29 bits are
 * reserved and rejected nonzero by the kernel.
 */
#define PERF_AUX_ACTION_MASK ((1UL << 0) | (1UL << 1) | (1UL << 2))

const struct struct_field perf_event_attr_fields[PERF_EVENT_ATTR_FIELDS_N] = {
	FIELDX(struct perf_event_attr, type, FT_ENUM,
	       .u.enum_ = { perf_type_values, ARRAY_SIZE(perf_type_values) },
	       .mutate_weight = 200),
	FIELDX(struct perf_event_attr, size, FT_VERSION_MAGIC,
	       .u.vals = perf_attr_known_sizes,
	       .mutate_weight = 80),
	/*
	 * config: meaning depends on `type`.  HARDWARE -> perf_hw_id,
	 * SOFTWARE -> perf_sw_ids, HW_CACHE -> packed (cache, op,
	 * result) triple, BREAKPOINT -> ignored, RAW/TRACEPOINT ->
	 * vendor-/runtime-specific.  Per-type variants are intentionally
	 * deferred pending buffer-discriminator infra to select among them.
	 */
	FIELD(struct perf_event_attr, config),
	/* sample_period / sample_freq anon union; `freq` flag picks. */
	FIELD(struct perf_event_attr, sample_period),
	FIELDX(struct perf_event_attr, sample_type, FT_FLAGS,
	       .u.flags.mask = PERF_SAMPLE_MASK,
	       .mutate_weight = 100),
	FIELDX(struct perf_event_attr, read_format, FT_FLAGS,
	       .u.flags.mask = PERF_FORMAT_MASK,
	       .mutate_weight = 80),
	/*
	 * Off-40 bit-field flag group (disabled..sigtrap).  Cannot use
	 * FIELDX -- offsetof on a bit-field member is invalid -- so the
	 * struct literal carries the offset/size explicitly.  Mask
	 * construction documented above PERF_ATTR_FLAG_MASK.
	 */
	{ .name		= "flags_bitfield",
	  .offset	= 40,
	  .size		= 8,
	  .tag		= FT_FLAGS,
	  .mutate_weight = 100,
	  .u.flags.mask = PERF_ATTR_FLAG_MASK },
	/* wakeup_events / wakeup_watermark anon union; `watermark` flag picks. */
	FIELD(struct perf_event_attr, wakeup_events),
	/*
	 * bp_type / bp_addr / bp_len are interpreted only when
	 * type == PERF_TYPE_BREAKPOINT; otherwise the slots double as
	 * config1 / config2 and carry PMU-specific extension words.
	 * Per-type variants for bp_type/bp_addr/bp_len (vs
	 * config1/config2) are not yet annotated.
	 */
	FIELD(struct perf_event_attr, bp_type),
	FIELD(struct perf_event_attr, bp_addr),
	FIELD(struct perf_event_attr, bp_len),
	FIELDX(struct perf_event_attr, branch_sample_type, FT_FLAGS,
	       .u.flags.mask = PERF_SAMPLE_BRANCH_MASK,
	       .mutate_weight = 80),
	/*
	 * sample_regs_user / sample_regs_intr: bit-per-register mask,
	 * arch-specific (asm/perf_regs.h per architecture).  No
	 * portable enum.  TODO: arch-conditional mask once a precedent
	 * for arch-#ifdef catalog content lands.
	 */
	FIELD(struct perf_event_attr, sample_regs_user),
	FIELDX(struct perf_event_attr, sample_stack_user, FT_RANGE,
	       .u.range = { 0, 65528 },
	       .mutate_weight = 60),
	FIELDX(struct perf_event_attr, clockid, FT_ENUM,
	       .u.enum_ = { clockid_values, ARRAY_SIZE(clockid_values) },
	       .mutate_weight = 60),
	FIELD(struct perf_event_attr, sample_regs_intr),
	FIELD(struct perf_event_attr, aux_watermark),
	FIELDX(struct perf_event_attr, sample_max_stack, FT_RANGE,
	       .u.range = { 0, 255 },
	       .mutate_weight = 60),
	FIELD(struct perf_event_attr, aux_sample_size),
	/*
	 * aux_action: 3 valid bits (aux_start_paused / aux_pause /
	 * aux_resume) packed into a u32 with 29 reserved bits.  Mask
	 * documented above PERF_AUX_ACTION_MASK.
	 */
	FIELDX(struct perf_event_attr, aux_action, FT_FLAGS,
	       .u.flags.mask = PERF_AUX_ACTION_MASK,
	       .mutate_weight = 60),
	FIELD(struct perf_event_attr, sig_data),
	FIELD(struct perf_event_attr, config3),
};

/*
 * Per-type sub-variants.  `type` at offset 0 is the discriminator;
 * the desc-level buffer_discrim_offset/size below reads it back after
 * the shared scalar pass has written a known PERF_TYPE_* value (the
 * type FT_ENUM above promotes the discriminator into a known-value
 * draw so the variant fires reliably, not once per 4 billion fills).
 *
 * The kernel reinterprets config / config1 / config2 (bp_addr / bp_len)
 * per type:
 *
 *   HARDWARE   -> config = perf_hw_id (PERF_COUNT_HW_*)
 *   SOFTWARE   -> config = perf_sw_ids (PERF_COUNT_SW_*)
 *   HW_CACHE   -> config = packed (cache_id, op_id, result_id) triple
 *   BREAKPOINT -> config ignored; bp_type / bp_addr / bp_len are live
 *   TRACEPOINT -> config = tracefs event id (live tracepoint-id pool)
 *   RAW        -> config = vendor-specific PMU counter id
 *
 * Variants override the corresponding shared fields[] entries; fields
 * not listed in the variant retain their shared-pass values.  Unknown
 * type values (vendor PMU type ids >= PERF_TYPE_MAX) fall through to
 * the shared fields[] alone, which matches the kernel's perf_pmu
 * lookup path for dynamic PMU types.
 *
 * The schema-aware fill is discarded by sanitise_perf_event_open()
 * regardless (it overwrites rec->a1 with the hand-rolled csfu buffer),
 * so these variants are forward infra for type-scoped CMP attribution
 * via struct_field_for_cmp() once the cmp_hints recording path
 * acquires a consumer.
 */

/*
 * PERF_TYPE_HARDWARE: config low 32 bits select a generalised event;
 * high 32 bits carry an optional PMU type id (left zero == core PMU).
 * Cataloguing only the low-half PERF_COUNT_HW_* values; the PMU-type-
 * id extension is a runtime-registered range not enumerable at compile
 * time.
 */
static const unsigned long perf_hw_ids[] = {
	PERF_COUNT_HW_CPU_CYCLES,
	PERF_COUNT_HW_INSTRUCTIONS,
	PERF_COUNT_HW_CACHE_REFERENCES,
	PERF_COUNT_HW_CACHE_MISSES,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
	PERF_COUNT_HW_BRANCH_MISSES,
	PERF_COUNT_HW_BUS_CYCLES,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
	PERF_COUNT_HW_REF_CPU_CYCLES,
};

/*
 * PERF_TYPE_SOFTWARE: config is the perf_sw_ids enum; all 12 entries
 * are stable uapi.
 */
static const unsigned long perf_sw_ids[] = {
	PERF_COUNT_SW_CPU_CLOCK,
	PERF_COUNT_SW_TASK_CLOCK,
	PERF_COUNT_SW_PAGE_FAULTS,
	PERF_COUNT_SW_CONTEXT_SWITCHES,
	PERF_COUNT_SW_CPU_MIGRATIONS,
	PERF_COUNT_SW_PAGE_FAULTS_MIN,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ,
	PERF_COUNT_SW_ALIGNMENT_FAULTS,
	PERF_COUNT_SW_EMULATION_FAULTS,
	PERF_COUNT_SW_DUMMY,
	PERF_COUNT_SW_BPF_OUTPUT,
	PERF_COUNT_SW_CGROUP_SWITCHES,
};

static const struct struct_field perf_event_attr_hardware_variant_fields[] = {
	FIELDX(struct perf_event_attr, config, FT_ENUM,
	       .u.enum_ = { perf_hw_ids, ARRAY_SIZE(perf_hw_ids) },
	       .mutate_weight = 120),
};

static const struct struct_field perf_event_attr_software_variant_fields[] = {
	FIELDX(struct perf_event_attr, config, FT_ENUM,
	       .u.enum_ = { perf_sw_ids, ARRAY_SIZE(perf_sw_ids) },
	       .mutate_weight = 120),
};

/*
 * PERF_TYPE_HW_CACHE: config is a packed bitfield-in-a-u64:
 *
 *     config = cache_id | (op_id << 8) | (result_id << 16)
 *
 * with cache_id < PERF_COUNT_HW_CACHE_MAX (7), op_id <
 * PERF_COUNT_HW_CACHE_OP_MAX (3), result_id <
 * PERF_COUNT_HW_CACHE_RESULT_MAX (2).  The kernel rejects triples
 * with any sub-field >= its _MAX.  None of the catalog tags model
 * three composing enums at sub-byte offsets (the schema keys fields
 * by byte offset/size, so three enums would all claim offset 8 with
 * overlapping writes -- the union-collision problem flagged in the
 * design doc), so the variant uses a curated FT_ENUM over the 42
 * pre-packed legal triples: 7 caches * 3 ops * 2 results.
 *
 * This mirrors random_cache_config() in syscalls/perf_event_open.c
 * (the same {L1D, L1I, LL, DTLB, ITLB, BPU, NODE} *
 * {READ, WRITE, PREFETCH} * {ACCESS, MISS} cross-product) so the
 * hand-rolled csfu path and the schema-aware CMP attribution share
 * the same packed-config vocabulary.  Out-of-range sub-field probes
 * (cache_id=7, op_id=3, ...) are intentionally not in the curated
 * set; the hand-rolled path covers them already via its RAND_BYTE()
 * arms, and adding them here would defeat the validator-passing
 * intent of an FT_ENUM draw.
 */
#define HW_CACHE_PACKED(cache, op, result) \
	((unsigned long) (cache) | \
	 ((unsigned long) (op) << 8) | \
	 ((unsigned long) (result) << 16))

#define HW_CACHE_TRIPLES_FOR_CACHE(cache) \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_READ, \
			PERF_COUNT_HW_CACHE_RESULT_ACCESS), \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_READ, \
			PERF_COUNT_HW_CACHE_RESULT_MISS), \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_WRITE, \
			PERF_COUNT_HW_CACHE_RESULT_ACCESS), \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_WRITE, \
			PERF_COUNT_HW_CACHE_RESULT_MISS), \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_PREFETCH, \
			PERF_COUNT_HW_CACHE_RESULT_ACCESS), \
	HW_CACHE_PACKED((cache), PERF_COUNT_HW_CACHE_OP_PREFETCH, \
			PERF_COUNT_HW_CACHE_RESULT_MISS)

static const unsigned long hw_cache_packed_values[] = {
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_L1D),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_L1I),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_LL),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_DTLB),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_ITLB),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_BPU),
	HW_CACHE_TRIPLES_FOR_CACHE(PERF_COUNT_HW_CACHE_NODE),
};

static const struct struct_field perf_event_attr_hw_cache_variant_fields[] = {
	FIELDX(struct perf_event_attr, config, FT_ENUM,
	       .u.enum_ = { hw_cache_packed_values,
			    ARRAY_SIZE(hw_cache_packed_values) },
	       .mutate_weight = 120),
};

/*
 * PERF_TYPE_BREAKPOINT: config is ignored; bp_type / bp_addr / bp_len
 * carry the breakpoint shape.  Mirrors setup_breakpoints() in
 * syscalls/perf_event_open.c so the hand-rolled csfu path and the
 * schema-aware CMP attribution agree on the vocabulary:
 *
 *   bp_type -> HW_BREAKPOINT_{EMPTY, R, W, RW, X, INVALID}
 *   bp_addr -> watchable address (FT_ADDRESS plants get_address())
 *   bp_len  -> HW_BREAKPOINT_LEN_{1,2,3,4,5,6,7,8}
 *
 * INVALID (== R | W | X == 7) is included so the kernel's rejection
 * path also gets exercised.  Odd lengths (3, 5, 6, 7) are in the
 * vocab because setup_breakpoints() draws them too -- the kernel
 * rejects non-{1,2,4,8} bp_len on most arches, so they probe the
 * validator gate.
 *
 * bp_addr's FT_ADDRESS is latent documentation for perf today
 * because sanitise_perf_event_open() discards the schema-filled
 * buffer and setup_breakpoints() plants its own get_address() value
 * into the csfu buffer.  The reachability walker
 * (struct_desc_has_address_field()) and the runtime nested-address
 * scrub (scrub_struct_addresses() in generate-args.c) are both now
 * variant-aware, so the bp_addr annotation does flow through to the
 * scrub mask -- the perf slot just doesn't currently route through
 * the generic struct buffer the scrub guards.  Any future cataloged
 * struct that places FT_ADDRESS only inside a variant inherits the
 * scrub from this plumbing without extra annotation.
 *
 * `config` is not listed in the variant -- the shared pass leaves it
 * at FT_RAW, the kernel ignores it for BREAKPOINT, and there is no
 * FT_RESERVED tag today that would force it to zero.  Cost is one
 * splattered u64 the kernel discards; benefit of adding one is nil.
 */
static const unsigned long hw_breakpoint_values[] = {
	HW_BREAKPOINT_EMPTY,
	HW_BREAKPOINT_R,
	HW_BREAKPOINT_W,
	HW_BREAKPOINT_RW,
	HW_BREAKPOINT_X,
	HW_BREAKPOINT_INVALID,
};

static const unsigned long hw_breakpoint_len_values[] = {
	HW_BREAKPOINT_LEN_1,
	HW_BREAKPOINT_LEN_2,
	HW_BREAKPOINT_LEN_3,
	HW_BREAKPOINT_LEN_4,
	HW_BREAKPOINT_LEN_5,
	HW_BREAKPOINT_LEN_6,
	HW_BREAKPOINT_LEN_7,
	HW_BREAKPOINT_LEN_8,
};

static const struct struct_field perf_event_attr_breakpoint_variant_fields[] = {
	FIELDX(struct perf_event_attr, bp_type, FT_ENUM,
	       .u.enum_ = { hw_breakpoint_values,
			    ARRAY_SIZE(hw_breakpoint_values) },
	       .mutate_weight = 120),
	FIELDX(struct perf_event_attr, bp_addr, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELDX(struct perf_event_attr, bp_len, FT_ENUM,
	       .u.enum_ = { hw_breakpoint_len_values,
			    ARRAY_SIZE(hw_breakpoint_len_values) },
	       .mutate_weight = 100),
};

/*
 * PERF_TYPE_TRACEPOINT: config is sourced via FT_PICKER from the
 * runtime tracepoint-id pool seeded by init_tracepoint_ids() from
 * /sys/kernel/tracing/events/<subsys>/<event>/id.  random_tracepoint_
 * config() draws a live id ~7/8 of the time when the pool is
 * non-empty and falls back to a random u32/u64 internally on every
 * other path (pool empty, no tracefs mounted, no CONFIG_TRACING),
 * so the structured fill always produces a usable u64 and never
 * wedges the slot.  Naming a live id lets the call land past
 * perf_tracepoint_event_init()'s -ENOENT gate so the deep
 * perf_trace_event_init / perf_trace_buf_alloc / kprobe / uprobe
 * paths actually receive fuzz traffic.
 *
 * PERF_TYPE_RAW: config is a vendor-specific PMU counter id
 * (Intel/AMD/ARM/POWER per-uarch raw event encoding).  There is no
 * portable enum; the shared fields[]' FT_RAW config survives
 * unchanged, and the variant stays declared with NULL fields[] /
 * num_fields=0 so the resolver still returns a named variant
 * (rather than NULL == "unknown type") for future CMP-attribution
 * scoping.  config1 / config2 may also carry vendor-specific
 * extension bytes -- also FT_RAW.
 */

static const struct struct_field perf_event_attr_tracepoint_variant_fields[] = {
	FIELDX(struct perf_event_attr, config, FT_PICKER,
	       .u.picker.pick = random_tracepoint_config,
	       .mutate_weight = 120),
};

const struct union_variant perf_event_attr_variants[PERF_EVENT_ATTR_VARIANTS_N] = {
	{
		.discrim_value	= PERF_TYPE_HARDWARE,
		.name		= "HARDWARE",
		.fields		= perf_event_attr_hardware_variant_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_hardware_variant_fields),
	},
	{
		.discrim_value	= PERF_TYPE_SOFTWARE,
		.name		= "SOFTWARE",
		.fields		= perf_event_attr_software_variant_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_software_variant_fields),
	},
	{
		.discrim_value	= PERF_TYPE_HW_CACHE,
		.name		= "HW_CACHE",
		.fields		= perf_event_attr_hw_cache_variant_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_hw_cache_variant_fields),
	},
	{
		.discrim_value	= PERF_TYPE_BREAKPOINT,
		.name		= "BREAKPOINT",
		.fields		= perf_event_attr_breakpoint_variant_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_breakpoint_variant_fields),
	},
	{
		.discrim_value	= PERF_TYPE_TRACEPOINT,
		.name		= "TRACEPOINT",
		.fields		= perf_event_attr_tracepoint_variant_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_tracepoint_variant_fields),
	},
	{
		.discrim_value	= PERF_TYPE_RAW,
		.name		= "RAW",
		.fields		= NULL,
		.num_fields	= 0,
	},
};
