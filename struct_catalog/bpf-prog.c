/*
 * struct_catalog/bpf-prog.c -- BPF_PROG_* command family field tables
 * carved out of struct_catalog/bpf.c.
 *
 * Tables are `const` (not `static const`) so the aggregator variant
 * table's designated-init `.fields =` references resolve via the
 * externs in struct_catalog-internal.h.  struct_catalog.h and arch.h
 * are #included unconditionally so this TU is never empty when USE_BPF
 * is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_BPF
#include "bpf.h"

/*
 * PROG_LOAD flag mask.  The trailing #ifdef arms cover names that
 * older /usr/include/linux/bpf.h vintages may not declare; missing
 * names contribute zero to the mask and the kernel still rejects
 * bits outside its own contemporary mask before any field-level
 * validation runs.
 */
#define PROG_LOAD_FLAGS_MASK ( \
	BPF_F_STRICT_ALIGNMENT | BPF_F_ANY_ALIGNMENT | \
	BPF_F_TEST_RND_HI32 | BPF_F_TEST_STATE_FREQ | BPF_F_SLEEPABLE | \
	BPF_F_XDP_HAS_FRAGS)

#ifdef BPF_F_XDP_DEV_BOUND_ONLY
# define PROG_LOAD_FLAGS_XDP_DEV	BPF_F_XDP_DEV_BOUND_ONLY
#else
# define PROG_LOAD_FLAGS_XDP_DEV	0UL
#endif
#ifdef BPF_F_TEST_REG_INVARIANTS
# define PROG_LOAD_FLAGS_TEST_REG	BPF_F_TEST_REG_INVARIANTS
#else
# define PROG_LOAD_FLAGS_TEST_REG	0UL
#endif

#define PROG_LOAD_FLAGS_FULL_MASK ( \
	PROG_LOAD_FLAGS_MASK | PROG_LOAD_FLAGS_XDP_DEV | \
	PROG_LOAD_FLAGS_TEST_REG | BPF_F_TOKEN_FD)

/*
 * PROG_LOAD variant.  Two pointer/length pairs land here:
 *   - insns + insn_cnt as FT_BPF_PROGRAM/FT_LEN_COUNT.  Fill delegates
 *     to net/bpf/ebpf.c's three-tier generator (~50% valid, 25% boundary,
 *     25% chaos) via ebpf_gen_program_into(), so the schema-mutation
 *     path produces the same verifier-reachable instruction streams as
 *     the live BPF_PROG_LOAD sanitiser instead of a per-insn random
 *     splat that the verifier would reject on first sight.  insn_cnt
 *     reports the generator's actual emit count, not a pre-rolled cap.
 *   - log_buf + log_size as FT_PTR_BYTES/FT_LEN_BYTES with the
 *     buffer optional (~80% present per the schema default) so the
 *     NULL-log path also gets reached.
 *
 * license / func_info_* / line_info_* / core_relos / fd_array and
 * the signature/keyring fields stay FT_RAW: a schema-driven random
 * splat in those slots would just bounce at copy_from_user / parser
 * boundaries.  bpf_insn keeps its 8-byte catalog entry below for KCOV-
 * compare attribution on code/imm even though FILL no longer reaches
 * it via FT_PTR_ARRAY.
 *
 * The attach_prog_fd / attach_btf_obj_fd anonymous union picks
 * attach_prog_fd as the canonical slot (more common arm); the
 * kernel reads the same bytes either way.
 *
 * Older uapi vintages may lack signature / signature_size /
 * keyring_id; those references are intentionally skipped rather than
 * gated on #ifdef offsetof which the preprocessor doesn't support.
 */
const struct struct_field bpf_attr_PROG_LOAD_fields[BPF_ATTR_PROG_LOAD_FIELDS_N] = {
	FIELDX(union bpf_attr, prog_type, FT_ENUM,
	       .u.enum_ = { bpf_prog_types, ARRAY_SIZE(bpf_prog_types) },
	       .mutate_weight = 200),
	FIELDX(union bpf_attr, insn_cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_field = "insns" },
	       .mutate_weight = 40),
	FIELDX(union bpf_attr, insns, FT_BPF_PROGRAM,
	       .mutate_weight = 150),
	FIELD(union bpf_attr, license),
	FIELDX(union bpf_attr, log_level, FT_FLAGS,
	       .u.flags.mask = 0x7),
	FIELDX(union bpf_attr, log_size, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "log_buf", .optional = true }),
	FIELDX(union bpf_attr, log_buf, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "log_size",
				.optional = true,
				.max_bytes = 4096 }),
	FIELD(union bpf_attr, kern_version),
	FIELDX(union bpf_attr, prog_flags, FT_FLAGS,
	       .u.flags.mask = PROG_LOAD_FLAGS_FULL_MASK),
	FIELD(union bpf_attr, prog_name),
	FIELD(union bpf_attr, prog_ifindex),
	FIELDX(union bpf_attr, expected_attach_type, FT_ENUM,
	       .u.enum_ = { bpf_attach_types, ARRAY_SIZE(bpf_attach_types) }),
	FIELDX(union bpf_attr, prog_btf_fd, FT_FD),
	FIELD(union bpf_attr, func_info_rec_size),
	FIELD(union bpf_attr, func_info),
	FIELD(union bpf_attr, func_info_cnt),
	FIELD(union bpf_attr, line_info_rec_size),
	FIELD(union bpf_attr, line_info),
	FIELD(union bpf_attr, line_info_cnt),
	FIELD(union bpf_attr, attach_btf_id),
	FIELDX(union bpf_attr, attach_prog_fd, FT_FD),
	FIELD(union bpf_attr, core_relo_cnt),
	FIELD(union bpf_attr, fd_array),
	FIELD(union bpf_attr, core_relos),
	FIELD(union bpf_attr, core_relo_rec_size),
	FIELD(union bpf_attr, log_true_size),
};

/*
 * PROG_ATTACH attach_flags mask.  REPLACE/BEFORE/AFTER/ID/LINK predate
 * the trinity baseline header vintage; BPF_F_PREORDER was appended
 * later (absent before 6.13), so give it the same #ifdef contribute-0
 * arm the MAP_CREATE / PROG_LOAD masks use for their late-arrival
 * flags rather than referencing it unconditionally.
 */
#ifdef BPF_F_PREORDER
# define PROG_ATTACH_FLAGS_PREORDER	BPF_F_PREORDER
#else
# define PROG_ATTACH_FLAGS_PREORDER	0UL
#endif

#define PROG_ATTACH_FLAGS_MASK ( \
	BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI | BPF_F_REPLACE | \
	BPF_F_BEFORE | BPF_F_AFTER | BPF_F_ID | PROG_ATTACH_FLAGS_PREORDER | \
	BPF_F_LINK)

/*
 * PROG_ATTACH variant.  The target_fd/target_ifindex and
 * relative_fd/relative_id anonymous unions each get one FT_FD
 * annotation at the shared offset -- picking the broader-semantic
 * arm; the kernel reads the same bytes either way.  expected_revision
 * stays FT_RAW: it's a u64 opaque revision counter that doesn't gate
 * any first-pass validation.
 */
const struct struct_field bpf_attr_PROG_ATTACH_fields[BPF_ATTR_PROG_ATTACH_FIELDS_N] = {
	FIELDX(union bpf_attr, target_fd, FT_FD),
	FIELDX(union bpf_attr, attach_bpf_fd, FT_FD),
	FIELDX(union bpf_attr, attach_type, FT_ENUM,
	       .u.enum_ = { bpf_attach_types, ARRAY_SIZE(bpf_attach_types) },
	       .mutate_weight = 200),
	FIELDX(union bpf_attr, attach_flags, FT_FLAGS,
	       .u.flags.mask = PROG_ATTACH_FLAGS_MASK,
	       .mutate_weight = 80),
	FIELDX(union bpf_attr, replace_bpf_fd, FT_FD),
	FIELDX(union bpf_attr, relative_fd, FT_FD),
	FIELD(union bpf_attr, expected_revision),
};

const struct struct_field bpf_attr_PROG_BIND_MAP_fields[BPF_ATTR_PROG_BIND_MAP_FIELDS_N] = {
	FIELDX(union bpf_attr, prog_bind_map.prog_fd, FT_FD),
	FIELDX(union bpf_attr, prog_bind_map.map_fd, FT_FD),
	FIELD(union bpf_attr, prog_bind_map.flags),
};

/*
 * BPF_PROG_QUERY query variant.  prog_cnt is the single LEN slot
 * that gates four sibling arrays (prog_ids + prog_attach_flags +
 * link_ids + link_attach_flags) -- the heaviest multi-pair user in
 * the catalog so far.  The pre-pin pass rolls one count and pins it
 * on every listed sibling so the kernel sees coherent (cnt, ptrs)
 * shapes rather than four independently rolled counts.
 *
 * All four arrays carry kernel-output values; the schema fill pre-
 * allocates the buffers and the kernel overwrites them on success.
 * Optional arms keep the NULL-pointer path also exercised on the
 * three non-required slots.
 */
const char *const bpf_attr_query_arrays[BPF_ATTR_QUERY_ARRAYS_N] = {
	"query.prog_ids",
	"query.prog_attach_flags",
	"query.link_ids",
	"query.link_attach_flags",
};

const struct struct_field bpf_attr_QUERY_fields[BPF_ATTR_QUERY_FIELDS_N] = {
	FIELDX(union bpf_attr, query.target_fd, FT_FD),
	FIELDX(union bpf_attr, query.attach_type, FT_ENUM,
	       .u.enum_ = { bpf_attach_types, ARRAY_SIZE(bpf_attach_types) },
	       .mutate_weight = 150),
	FIELDX(union bpf_attr, query.query_flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_QUERY_EFFECTIVE),
	FIELD(union bpf_attr, query.attach_flags),
	FIELDX(union bpf_attr, query.prog_ids, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint32_t),
				.max_count = 64 }),
	FIELDX(union bpf_attr, query.prog_cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_query_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_query_arrays) }),
	FIELDX(union bpf_attr, query.prog_attach_flags, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint32_t),
				.max_count = 64 }),
	FIELDX(union bpf_attr, query.link_ids, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint32_t),
				.max_count = 64 }),
	FIELDX(union bpf_attr, query.link_attach_flags, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint32_t),
				.max_count = 64 }),
	FIELD(union bpf_attr, query.revision),
};

/*
 * BPF_PROG_TEST_RUN test variant.  Two pointer pairs (data_in/out,
 * ctx_in/out) plus repeat / cpu / batch_size as ranges to keep the
 * call from burning CPU forever on a max-u32 repeat draw or
 * bouncing on -EINVAL when cpu exceeds num_possible_cpus().
 *
 * retval / duration are kernel outputs; FT_RAW pre-fill is harmless,
 * the kernel overwrites them.  ctx_in/out are optional -- the
 * standard test path only requires the data pair.
 */
#define TEST_RUN_FLAGS_MASK \
	(BPF_F_TEST_RUN_ON_CPU | BPF_F_TEST_XDP_LIVE_FRAMES)

const struct struct_field bpf_attr_TEST_fields[BPF_ATTR_TEST_FIELDS_N] = {
	FIELDX(union bpf_attr, test.prog_fd, FT_FD),
	FIELD(union bpf_attr, test.retval),
	FIELDX(union bpf_attr, test.data_size_in, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "test.data_in", .optional = true }),
	FIELDX(union bpf_attr, test.data_size_out, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "test.data_out", .optional = true }),
	FIELDX(union bpf_attr, test.data_in, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "test.data_size_in",
				.optional = true,
				.max_bytes = 65536 }),
	FIELDX(union bpf_attr, test.data_out, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "test.data_size_out",
				.optional = true,
				.max_bytes = 65536 }),
	FIELDX(union bpf_attr, test.repeat, FT_RANGE,
	       .u.range = { 0, 1024 }),
	FIELD(union bpf_attr, test.duration),
	FIELDX(union bpf_attr, test.ctx_size_in, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "test.ctx_in", .optional = true }),
	FIELDX(union bpf_attr, test.ctx_size_out, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "test.ctx_out", .optional = true }),
	FIELDX(union bpf_attr, test.ctx_in, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "test.ctx_size_in",
				.optional = true,
				.max_bytes = 4096 }),
	FIELDX(union bpf_attr, test.ctx_out, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "test.ctx_size_out",
				.optional = true,
				.max_bytes = 4096 }),
	FIELDX(union bpf_attr, test.flags, FT_FLAGS,
	       .u.flags.mask = TEST_RUN_FLAGS_MASK),
	FIELDX(union bpf_attr, test.cpu, FT_RANGE,
	       .u.range = { 0, 1024 }),
	FIELDX(union bpf_attr, test.batch_size, FT_RANGE,
	       .u.range = { 0, 1024 }),
};

/*
 * BPF_PROG_STREAM_READ_BY_FD prog_stream_read variant.  The
 * prog_stream_read named member is a recent addition to union bpf_attr
 * (absent through 6.18), so the whole table -- and the variant entry
 * that references it plus BPF_PROG_STREAM_READ_BY_FD below -- is gated
 * on USE_BPF_PROG_STREAM_READ (a configure probe): offsetof() against
 * the member can't be #ifdef-shimmed on a header that lacks it.
 */
#ifdef USE_BPF_PROG_STREAM_READ
const struct struct_field bpf_attr_PROG_STREAM_READ_fields[BPF_ATTR_PROG_STREAM_READ_FIELDS_N] = {
	FIELDX(union bpf_attr, prog_stream_read.stream_buf, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "prog_stream_read.stream_buf_len",
				.optional = true,
				.max_bytes = 4096 }),
	FIELDX(union bpf_attr, prog_stream_read.stream_buf_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "prog_stream_read.stream_buf",
			     .optional = true }),
	FIELD(union bpf_attr, prog_stream_read.stream_id),
	FIELDX(union bpf_attr, prog_stream_read.prog_fd, FT_FD),
};
#endif

/*
 * bpf_insn registration -- retained as an 8-byte CMP-attribution shape
 * so a learned KCOV-compare constant on code / off / imm can be
 * attributed back to the right field by struct_field_for_cmp().
 * PROG_LOAD's insns FILL now flows through FT_BPF_PROGRAM (which calls
 * net/bpf/ebpf.c's generator) rather than splatting random bpf_insn
 * elements via FT_PTR_ARRAY, but the per-field shape is still the
 * vocabulary the CMP-hint path reasons over.
 */
const struct struct_field bpf_insn_fields[BPF_INSN_FIELDS_N] = {
	FIELD(struct bpf_insn, code),
	FIELD(struct bpf_insn, off),
	FIELD(struct bpf_insn, imm),
};

#endif /* USE_BPF */
