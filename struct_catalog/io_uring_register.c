/*
 * struct_catalog/io_uring_register.c -- io_uring_setup / io_uring_register
 * per-opcode struct field tables and the tagged-union variant table.
 *
 * Carved out of struct_catalog.c as the fourth leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the
 * io_uring_params field table plus every io_uring_register-family
 * variant payload field table and the io_uring_register_variants[]
 * tagged-union table.  Symbols flip from static const to const so the
 * spine's .fields = io_uring_params_fields and .variants =
 * io_uring_register_variants references resolve via the externs in
 * struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.
 */

#include <stddef.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/io_uring.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct io_uring_params (io_uring_setup)                             */
/* ------------------------------------------------------------------ */

/*
 * IORING_SETUP_* vocabulary for io_uring_params.flags.  Mirrors the
 * curated set in io_uring_setup.c's set_rand_bitmask() array — kept in
 * sync by reviewer reading the uapi diff.  Compat #ifndef arms cover
 * bits the system header may pre-date; newer bits (CQE_MIXED, SQE_MIXED,
 * SQ_REWIND in io_uring_setup.c) are deliberately omitted here since
 * neither <linux/io_uring.h> nor the upstream uapi exposes them yet.
 */
#ifndef IORING_SETUP_NO_MMAP
#define IORING_SETUP_NO_MMAP		(1U << 14)
#define IORING_SETUP_REGISTERED_FD_ONLY	(1U << 15)
#endif
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY		(1U << 16)
#endif
#ifndef IORING_SETUP_HYBRID_IOPOLL
#define IORING_SETUP_HYBRID_IOPOLL	(1U << 17)
#endif

#define IORING_SETUP_MASK \
	(IORING_SETUP_IOPOLL          | IORING_SETUP_SQPOLL          | \
	 IORING_SETUP_SQ_AFF          | IORING_SETUP_CQSIZE          | \
	 IORING_SETUP_CLAMP           | IORING_SETUP_ATTACH_WQ       | \
	 IORING_SETUP_R_DISABLED      | IORING_SETUP_SUBMIT_ALL      | \
	 IORING_SETUP_COOP_TASKRUN    | IORING_SETUP_TASKRUN_FLAG    | \
	 IORING_SETUP_SQE128          | IORING_SETUP_CQE32           | \
	 IORING_SETUP_SINGLE_ISSUER   | IORING_SETUP_DEFER_TASKRUN   | \
	 IORING_SETUP_NO_MMAP         | IORING_SETUP_REGISTERED_FD_ONLY | \
	 IORING_SETUP_NO_SQARRAY      | IORING_SETUP_HYBRID_IOPOLL)

/*
 * sq_entries / cq_entries: the kernel rounds up to power-of-two via
 * roundup_pow_of_two() regardless of the value passed, so FT_RANGE would
 * only obscure the rare interesting cases (zero -> -EINVAL; values above
 * IORING_MAX_ENTRIES -> capped).  Leave FT_RAW and lean on the mutate
 * weight to shake those edges out; cq_entries is also gated by SETUP_CQSIZE
 * so the field is silently ignored most of the time.
 *
 * features is kernel-written output; sq_off / cq_off are
 * io_sqring_offsets / io_cqring_offsets, also output-only, and stay
 * uncataloged until an OUTPUT-fill mode exists.  resv[3] is rejected by
 * the kernel's memchr_inv() check on non-zero, so FT_RAW on a zeroed
 * buffer is the right answer.
 */
const struct struct_field io_uring_params_fields[IO_URING_PARAMS_FIELDS_N] = {
	FIELDX(struct io_uring_params, sq_entries, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct io_uring_params, cq_entries, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct io_uring_params, flags, FT_FLAGS,
	       .u.flags.mask = IORING_SETUP_MASK,
	       .mutate_weight = 100),
	FIELD(struct io_uring_params, sq_thread_cpu),
	FIELD(struct io_uring_params, sq_thread_idle),
	FIELD(struct io_uring_params, features),
	FIELDX(struct io_uring_params, wq_fd, FT_FD,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* io_uring_register per-opcode variants                                */
/* ------------------------------------------------------------------ */

/*
 * IORING_REGISTER_EVENTFD (opcode 4): arg points at a bare int fd; no
 * enclosing struct.  The variant fields[] still describes the one
 * scalar so CMP attribution and any future schema fill see "fd at
 * offset 0".  sanitise_io_uring_register seeds it from OBJ_FD_EVENTFD
 * regardless.
 */
const struct struct_field io_uring_register_eventfd_fields[IO_URING_REGISTER_EVENTFD_FIELDS_N] = {
	{ .name = "fd", .offset = 0, .size = sizeof(int),
	  .tag = FT_FD, .mutate_weight = 100 },
};

/*
 * IORING_REGISTER_FILES_UPDATE (opcode 6) / arg = struct
 * io_uring_rsrc_update.  offset is the slot index into the fixed-file
 * table -- the kernel rejects anything past the registered count, so a
 * small range surfaces in-range hits.  resv must be zero or the kernel
 * rejects on -EINVAL.  data is a u64 user pointer to the fd[] payload;
 * sanitise_io_uring_register fills it from OBJ_FD pools.
 */
const struct struct_field io_uring_register_files_update_fields[IO_URING_REGISTER_FILES_UPDATE_FIELDS_N] = {
	FIELDX(struct io_uring_rsrc_update, offset, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 },
	       .mutate_weight = 80),
	FIELD(struct io_uring_rsrc_update, resv),
	FIELD(struct io_uring_rsrc_update, data),
};

/*
 * IORING_REGISTER_FILE_ALLOC_RANGE (opcode 25) / arg = struct
 * io_uring_file_index_range.  off and len name a half-open
 * [off, off + len) span the kernel uses to reserve sparse slots; the
 * overflow-probe path lives in sanitise_io_uring_register.  resv must
 * be zero.
 */
const struct struct_field io_uring_register_file_alloc_range_fields[IO_URING_REGISTER_FILE_ALLOC_RANGE_FIELDS_N] = {
	FIELDX(struct io_uring_file_index_range, off, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 80),
	FIELDX(struct io_uring_file_index_range, len, FT_RANGE,
	       .u.range = { .lo = 1, .hi = 16 },
	       .mutate_weight = 80),
	FIELD(struct io_uring_file_index_range, resv),
};

/*
 * IORING_REGISTER_PBUF_RING (opcode 22) / IORING_UNREGISTER_PBUF_RING
 * (opcode 23) / arg = struct io_uring_buf_reg.  ring_addr is a u64
 * user pointer to the buffer ring; the hand-rolled fill points it at
 * a real mapping.  ring_entries must be power-of-two and is seeded
 * 16..128 by sanitise_io_uring_register -- FT_RAW captures the
 * occasional non-pow2 / zero rejection edges the CMP path cares about.
 * bgid is the buffer-group id; flags carry the IOU_PBUF_RING_* mask.
 * resv[3] is reserved (must be zero, untouched by FT_RAW at size 24).
 */
#define IOU_PBUF_RING_MASK \
	(IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC)

const struct struct_field io_uring_register_pbuf_ring_fields[IO_URING_REGISTER_PBUF_RING_FIELDS_N] = {
	FIELD(struct io_uring_buf_reg, ring_addr),
	FIELDX(struct io_uring_buf_reg, ring_entries, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct io_uring_buf_reg, bgid, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELDX(struct io_uring_buf_reg, flags, FT_FLAGS,
	       .u.flags.mask = IOU_PBUF_RING_MASK,
	       .mutate_weight = 80),
	FIELD(struct io_uring_buf_reg, resv),
};

/*
 * IORING_REGISTER_SYNC_CANCEL (opcode 24) / arg = struct
 * io_uring_sync_cancel_reg.  The largest single-struct variant
 * (64 bytes) and the one that drives io_uring_register_args.struct_size.
 * addr is a u64 userdata matcher (kernel compares it against in-flight
 * requests); fd is the target fd; flags carry the
 * IORING_ASYNC_CANCEL_* mask the kernel dispatches on; opcode is a
 * single byte the cancellation matches against the original SQE
 * opcode.  timeout is __kernel_timespec (16 bytes, FT_RAW no-op) and
 * the pad / pad2 trailers are pure alignment padding so they stay
 * out of the field table entirely.
 */
#define IORING_ASYNC_CANCEL_MASK \
	(IORING_ASYNC_CANCEL_ALL      | IORING_ASYNC_CANCEL_FD       | \
	 IORING_ASYNC_CANCEL_ANY      | IORING_ASYNC_CANCEL_FD_FIXED | \
	 IORING_ASYNC_CANCEL_USERDATA | IORING_ASYNC_CANCEL_OP)

const struct struct_field io_uring_register_sync_cancel_fields[IO_URING_REGISTER_SYNC_CANCEL_FIELDS_N] = {
	FIELD(struct io_uring_sync_cancel_reg, addr),
	FIELDX(struct io_uring_sync_cancel_reg, fd, FT_FD,
	       .mutate_weight = 80),
	FIELDX(struct io_uring_sync_cancel_reg, flags, FT_FLAGS,
	       .u.flags.mask = IORING_ASYNC_CANCEL_MASK,
	       .mutate_weight = 80),
	FIELD(struct io_uring_sync_cancel_reg, opcode),
};

/*
 * Array-shaped register opcodes.  arg points at a bare element array;
 * the count lives in rec->a4.  The variant fields[] describes the
 * layout of ONE element (the kernel CMPs each element against the
 * same constants regardless of index, so attributing to the element
 * is approximately correct for CMP purposes).  effective_size is the
 * size of one element; array-aware fill is not modelled (would need
 * net-new infra in generate-args.c and the live fill path is fully
 * hand-rolled in sanitise_io_uring_register either way).
 */

/*
 * IORING_REGISTER_RESTRICTIONS (opcode 11) / arg = struct
 * io_uring_restriction[].  Per-element opcode picks among the four
 * IORING_RESTRICTION_* discriminators which in turn decide whether
 * the anonymous-union byte at offset 2 is interpreted as register_op,
 * sqe_op, or sqe_flags.  The blind-fd (fd == -1) task-scoped path in
 * sanitise_io_uring_register wraps the element in
 * io_uring_task_restriction; the catalog models the real-fd flat
 * element only.
 */
const unsigned long io_uring_restriction_opcodes[IO_URING_RESTRICTION_OPCODES_N] = {
	IORING_RESTRICTION_REGISTER_OP,
	IORING_RESTRICTION_SQE_OP,
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
};

const struct struct_field io_uring_register_restriction_fields[IO_URING_REGISTER_RESTRICTION_FIELDS_N] = {
	FIELDX(struct io_uring_restriction, opcode, FT_ENUM,
	       .u.enum_ = { .vals = io_uring_restriction_opcodes,
			    .n = ARRAY_SIZE(io_uring_restriction_opcodes) },
	       .mutate_weight = 80),
	FIELD(struct io_uring_restriction, register_op),
	FIELD(struct io_uring_restriction, resv),
	FIELD(struct io_uring_restriction, resv2),
};

/*
 * IORING_REGISTER_NAPI (27) / IORING_UNREGISTER_NAPI (28) / arg =
 * struct io_uring_napi.  opcode picks IO_URING_NAPI_REGISTER_OP /
 * STATIC_ADD_ID / STATIC_DEL_ID; for REGISTER_OP, op_param is a
 * tracking-strategy enum (DYNAMIC/STATIC/INACTIVE), otherwise it is a
 * napi id -- FT_ENUM is documentation-grade for the register-op case
 * and a harmless small-int hint for the add/del cases.  resv/pad must
 * be zero.  UNREGISTER ignores most fields but shares the layout.
 */
const unsigned long io_uring_napi_opcodes[IO_URING_NAPI_OPCODES_N] = {
	IO_URING_NAPI_REGISTER_OP,
	IO_URING_NAPI_STATIC_ADD_ID,
	IO_URING_NAPI_STATIC_DEL_ID,
};

const unsigned long io_uring_napi_tracking_strategies[IO_URING_NAPI_TRACKING_STRATEGIES_N] = {
	IO_URING_NAPI_TRACKING_DYNAMIC,
	IO_URING_NAPI_TRACKING_STATIC,
	IO_URING_NAPI_TRACKING_INACTIVE,
};

const struct struct_field io_uring_register_napi_fields[IO_URING_REGISTER_NAPI_FIELDS_N] = {
	FIELD(struct io_uring_napi, busy_poll_to),
	FIELDX(struct io_uring_napi, prefer_busy_poll, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 1 },
	       .mutate_weight = 60),
	FIELDX(struct io_uring_napi, opcode, FT_ENUM,
	       .u.enum_ = { .vals = io_uring_napi_opcodes,
			    .n = ARRAY_SIZE(io_uring_napi_opcodes) },
	       .mutate_weight = 80),
	FIELD(struct io_uring_napi, pad),
	FIELDX(struct io_uring_napi, op_param, FT_ENUM,
	       .u.enum_ = { .vals = io_uring_napi_tracking_strategies,
			    .n = ARRAY_SIZE(io_uring_napi_tracking_strategies) },
	       .mutate_weight = 60),
	FIELD(struct io_uring_napi, resv),
};

/*
 * IORING_REGISTER_CLOCK (29) / arg = struct io_uring_clock_register.
 * Kernel validates clockid against a two-entry allowlist
 * (CLOCK_MONOTONIC / CLOCK_BOOTTIME); anything else gives -EINVAL.
 * __resv must be zero.
 */
const unsigned long io_uring_clock_ids[IO_URING_CLOCK_IDS_N] = {
	CLOCK_MONOTONIC,
	CLOCK_BOOTTIME,
};

const struct struct_field io_uring_register_clock_fields[IO_URING_REGISTER_CLOCK_FIELDS_N] = {
	FIELDX(struct io_uring_clock_register, clockid, FT_ENUM,
	       .u.enum_ = { .vals = io_uring_clock_ids,
			    .n = ARRAY_SIZE(io_uring_clock_ids) },
	       .mutate_weight = 90),
	FIELD(struct io_uring_clock_register, __resv),
};

/*
 * IORING_REGISTER_CLONE_BUFFERS (30) / arg = struct
 * io_uring_clone_buffers.  src_fd is a source io_uring ring fd; the
 * hand-rolled fill path seeds it from the ring pool.  flags carry the
 * IORING_REGISTER_SRC_REGISTERED / DST_REPLACE pair.  src_off / dst_off
 * / nr are small slot indices.  pad[3] must be zero.
 */
#define IORING_CLONE_BUFFERS_FLAGS_MASK \
	(IORING_REGISTER_SRC_REGISTERED | IORING_REGISTER_DST_REPLACE)

const struct struct_field io_uring_register_clone_buffers_fields[IO_URING_REGISTER_CLONE_BUFFERS_FIELDS_N] = {
	FIELDX(struct io_uring_clone_buffers, src_fd, FT_FD,
	       .mutate_weight = 80),
	FIELDX(struct io_uring_clone_buffers, flags, FT_FLAGS,
	       .u.flags.mask = IORING_CLONE_BUFFERS_FLAGS_MASK,
	       .mutate_weight = 80),
	FIELDX(struct io_uring_clone_buffers, src_off, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELDX(struct io_uring_clone_buffers, dst_off, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELDX(struct io_uring_clone_buffers, nr, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELD(struct io_uring_clone_buffers, pad),
};

/*
 * IORING_REGISTER_PBUF_STATUS (26) / arg = struct io_uring_buf_status.
 * Mostly output: kernel writes head + resv[8].  buf_group is the only
 * real input; resv must be zero on the way in.
 */
const struct struct_field io_uring_register_pbuf_status_fields[IO_URING_REGISTER_PBUF_STATUS_FIELDS_N] = {
	FIELDX(struct io_uring_buf_status, buf_group, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELD(struct io_uring_buf_status, head),
	FIELD(struct io_uring_buf_status, resv),
};

/*
 * IORING_REGISTER_FILES2 (13) / IORING_REGISTER_BUFFERS2 (15) /
 * arg = struct io_uring_rsrc_register.  nr is the count; flags carry
 * the IORING_RSRC_REGISTER_SPARSE bit; data/tags are __aligned_u64
 * user pointers to the fd[]/iovec[] payload and tag[] array (the
 * hand-rolled fill owns pointer seeding).  resv2 must be zero.
 * FILES2 and BUFFERS2 share the struct -- one fields[], two keys.
 */
#define IORING_RSRC_REGISTER_FLAGS_MASK	(IORING_RSRC_REGISTER_SPARSE)

const struct struct_field io_uring_register_rsrc_register_fields[IO_URING_REGISTER_RSRC_REGISTER_FIELDS_N] = {
	FIELDX(struct io_uring_rsrc_register, nr, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 80),
	FIELDX(struct io_uring_rsrc_register, flags, FT_FLAGS,
	       .u.flags.mask = IORING_RSRC_REGISTER_FLAGS_MASK,
	       .mutate_weight = 80),
	FIELD(struct io_uring_rsrc_register, resv2),
	FIELD(struct io_uring_rsrc_register, data),
	FIELD(struct io_uring_rsrc_register, tags),
};

/*
 * IORING_REGISTER_FILES_UPDATE2 (14) / IORING_REGISTER_BUFFERS_UPDATE
 * (16) / arg = struct io_uring_rsrc_update2.  offset is a small slot
 * index; data/tags are user pointers; nr is the count.  resv / resv2
 * must be zero.  Both opcodes share the struct -- one fields[], two
 * keys.
 */
const struct struct_field io_uring_register_rsrc_update2_fields[IO_URING_REGISTER_RSRC_UPDATE2_FIELDS_N] = {
	FIELDX(struct io_uring_rsrc_update2, offset, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 },
	       .mutate_weight = 80),
	FIELD(struct io_uring_rsrc_update2, resv),
	FIELD(struct io_uring_rsrc_update2, data),
	FIELD(struct io_uring_rsrc_update2, tags),
	FIELDX(struct io_uring_rsrc_update2, nr, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 80),
	FIELD(struct io_uring_rsrc_update2, resv2),
};

/*
 * IORING_REGISTER_PROBE (8) / arg = struct io_uring_probe + flex
 * ops[].  Output-heavy: kernel fills ops[] up to ops_len entries.
 * Header-only variant -- the 16-byte fixed prefix.  ops_len is the
 * caller-supplied capacity; everything else must be zero on input.
 * The flex ops[] array is owned by the hand-rolled fill path (no
 * array-aware schema model today).
 */
const struct struct_field io_uring_register_probe_fields[IO_URING_REGISTER_PROBE_FIELDS_N] = {
	FIELD(struct io_uring_probe, last_op),
	FIELDX(struct io_uring_probe, ops_len, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 60),
	FIELD(struct io_uring_probe, resv),
	FIELD(struct io_uring_probe, resv2),
};

/*
 * Per-opcode variant table.  rec->a2 carries the opcode at sanitise
 * and post time; struct_desc_resolve_variant() picks the matching
 * variant.  Opcodes without an entry fall through to the empty shared
 * prefix (no schema fill, no CMP attribution scope).  Not all opcodes
 * have variant entries yet.
 */
const struct union_variant io_uring_register_variants[IO_URING_REGISTER_VARIANTS_N] = {
	{
		.discrim_value	= IORING_REGISTER_EVENTFD,
		.name		= "EVENTFD",
		.fields		= io_uring_register_eventfd_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_eventfd_fields),
		.effective_size	= sizeof(int),
	},
	{
		.discrim_value	= IORING_REGISTER_FILES_UPDATE,
		.name		= "FILES_UPDATE",
		.fields		= io_uring_register_files_update_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_files_update_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_update),
	},
	{
		.discrim_value	= IORING_REGISTER_FILE_ALLOC_RANGE,
		.name		= "FILE_ALLOC_RANGE",
		.fields		= io_uring_register_file_alloc_range_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_file_alloc_range_fields),
		.effective_size	= sizeof(struct io_uring_file_index_range),
	},
	{
		.discrim_value	= IORING_REGISTER_PBUF_RING,
		.name		= "PBUF_RING",
		.fields		= io_uring_register_pbuf_ring_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_pbuf_ring_fields),
		.effective_size	= sizeof(struct io_uring_buf_reg),
	},
	{
		.discrim_value	= IORING_UNREGISTER_PBUF_RING,
		.name		= "UNREGISTER_PBUF_RING",
		.fields		= io_uring_register_pbuf_ring_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_pbuf_ring_fields),
		.effective_size	= sizeof(struct io_uring_buf_reg),
	},
	{
		.discrim_value	= IORING_REGISTER_SYNC_CANCEL,
		.name		= "SYNC_CANCEL",
		.fields		= io_uring_register_sync_cancel_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_sync_cancel_fields),
		.effective_size	= sizeof(struct io_uring_sync_cancel_reg),
	},
	/*
	 * Array-shaped opcodes below: variant fields[] describes one
	 * element, effective_size is sizeof(one element).  The full
	 * payload length depends on rec->a4 (element count) and is owned
	 * by the hand-rolled fill path.
	 */
	{
		.discrim_value	= IORING_REGISTER_BUFFERS,
		.name		= "BUFFERS",
		.fields		= iovec_fields,
		.num_fields	= ARRAY_SIZE(iovec_fields),
		.effective_size	= sizeof(struct iovec),
	},
	{
		.discrim_value	= IORING_UNREGISTER_BUFFERS,
		.name		= "UNREGISTER_BUFFERS",
		.fields		= iovec_fields,
		.num_fields	= ARRAY_SIZE(iovec_fields),
		.effective_size	= sizeof(struct iovec),
	},
	/*
	 * FILES / UNREGISTER_FILES: arg is a bare int[] of fds.  No
	 * fields[] -- a trivial scalar array has nothing useful for CMP
	 * to attribute and the hand-rolled fill owns the -1 sparse-hole
	 * seeding.  effective_size names one element so a future
	 * array-aware consumer can still size the payload.
	 */
	{
		.discrim_value	= IORING_REGISTER_FILES,
		.name		= "FILES",
		.fields		= NULL,
		.num_fields	= 0,
		.effective_size	= sizeof(int),
	},
	{
		.discrim_value	= IORING_UNREGISTER_FILES,
		.name		= "UNREGISTER_FILES",
		.fields		= NULL,
		.num_fields	= 0,
		.effective_size	= sizeof(int),
	},
	{
		.discrim_value	= IORING_REGISTER_RESTRICTIONS,
		.name		= "RESTRICTIONS",
		.fields		= io_uring_register_restriction_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_restriction_fields),
		.effective_size	= sizeof(struct io_uring_restriction),
	},
	/*
	 * IOWQ_MAX_WORKERS: arg is __u32[2] (bounded/unbounded worker
	 * caps).  No fields[] -- trivial scalar array, hand-rolled fill
	 * owns it.
	 */
	{
		.discrim_value	= IORING_REGISTER_IOWQ_MAX_WORKERS,
		.name		= "IOWQ_MAX_WORKERS",
		.fields		= NULL,
		.num_fields	= 0,
		.effective_size	= 2 * sizeof(__u32),
	},
	/*
	 * RING_FDS / UNREGISTER_RING_FDS: array of io_uring_rsrc_update;
	 * element layout is the same as FILES_UPDATE so the variant
	 * fields[] is reused.  Hand-rolled fill seeds data from the
	 * io_uring fd pool.
	 */
	{
		.discrim_value	= IORING_REGISTER_RING_FDS,
		.name		= "RING_FDS",
		.fields		= io_uring_register_files_update_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_files_update_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_update),
	},
	{
		.discrim_value	= IORING_UNREGISTER_RING_FDS,
		.name		= "UNREGISTER_RING_FDS",
		.fields		= io_uring_register_files_update_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_files_update_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_update),
	},
	/*
	 * NAPI / UNREGISTER_NAPI share struct io_uring_napi (16B).  The
	 * kernel ignores most fields on unregister; same variant fields[]
	 * is correct for both.
	 */
	{
		.discrim_value	= IORING_REGISTER_NAPI,
		.name		= "NAPI",
		.fields		= io_uring_register_napi_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_napi_fields),
		.effective_size	= sizeof(struct io_uring_napi),
	},
	{
		.discrim_value	= IORING_UNREGISTER_NAPI,
		.name		= "UNREGISTER_NAPI",
		.fields		= io_uring_register_napi_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_napi_fields),
		.effective_size	= sizeof(struct io_uring_napi),
	},
	{
		.discrim_value	= IORING_REGISTER_CLOCK,
		.name		= "CLOCK",
		.fields		= io_uring_register_clock_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_clock_fields),
		.effective_size	= sizeof(struct io_uring_clock_register),
	},
	{
		.discrim_value	= IORING_REGISTER_CLONE_BUFFERS,
		.name		= "CLONE_BUFFERS",
		.fields		= io_uring_register_clone_buffers_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_clone_buffers_fields),
		.effective_size	= sizeof(struct io_uring_clone_buffers),
	},
	{
		.discrim_value	= IORING_REGISTER_PBUF_STATUS,
		.name		= "PBUF_STATUS",
		.fields		= io_uring_register_pbuf_status_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_pbuf_status_fields),
		.effective_size	= sizeof(struct io_uring_buf_status),
	},
	/*
	 * FILES2 / BUFFERS2 share struct io_uring_rsrc_register (32B).
	 * FILES_UPDATE2 / BUFFERS_UPDATE share struct io_uring_rsrc_update2
	 * (32B).  One fields[] per struct, two keys each.
	 */
	{
		.discrim_value	= IORING_REGISTER_FILES2,
		.name		= "FILES2",
		.fields		= io_uring_register_rsrc_register_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_rsrc_register_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_register),
	},
	{
		.discrim_value	= IORING_REGISTER_BUFFERS2,
		.name		= "BUFFERS2",
		.fields		= io_uring_register_rsrc_register_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_rsrc_register_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_register),
	},
	{
		.discrim_value	= IORING_REGISTER_FILES_UPDATE2,
		.name		= "FILES_UPDATE2",
		.fields		= io_uring_register_rsrc_update2_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_rsrc_update2_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_update2),
	},
	{
		.discrim_value	= IORING_REGISTER_BUFFERS_UPDATE,
		.name		= "BUFFERS_UPDATE",
		.fields		= io_uring_register_rsrc_update2_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_rsrc_update2_fields),
		.effective_size	= sizeof(struct io_uring_rsrc_update2),
	},
	/*
	 * PROBE: header-only variant (16B).  ops[] flex array is
	 * output-side and lives in the hand-rolled fill path; not
	 * modelled in the schema.
	 */
	{
		.discrim_value	= IORING_REGISTER_PROBE,
		.name		= "PROBE",
		.fields		= io_uring_register_probe_fields,
		.num_fields	= ARRAY_SIZE(io_uring_register_probe_fields),
		.effective_size	= sizeof(struct io_uring_probe),
	},
	/*
	 * No-arg opcodes -- intentionally absent from this table:
	 *   IORING_REGISTER_PERSONALITY (9):   returns an id; arg ignored.
	 *   IORING_UNREGISTER_PERSONALITY (10): id passed in nr_args/a4.
	 *   IORING_REGISTER_ENABLE_RINGS (12): no arg.
	 * The absence is deliberate, not an oversight; no variant means
	 * no schema fill and no opcode-scoped CMP attribution -- correct
	 * for opcodes whose arg slot is unused or a bare id.
	 */
};

/*
 * Compile-time guard on the io_uring_register_args descriptor: its
 * struct_size is hand-set to 64 (the largest projected single-struct
 * variant, io_uring_sync_cancel_reg) and the schema-aware fill reads /
 * writes that many bytes per variant.  If a uapi struct quietly grows
 * past 64 -- or a new variant is added with a payload that does -- the
 * fill path would walk past the catalog's declared buffer.  Fail the
 * build here instead.  One assert per variant; the kernel uapi struct
 * name is hard-coded from the variant's .fields[] above.
 *
 * Variants whose payload is a bare scalar, fd, or array of scalars
 * (EVENTFD, FILES, UNREGISTER_FILES, IOWQ_MAX_WORKERS) intentionally
 * have no assert: there is no payload struct type to size-check, and
 * inventing one to assert would be noise.
 */
#define IO_URING_REGISTER_VARIANT_FITS(type, variant) \
	_Static_assert(sizeof(type) <= 64, \
		"io_uring_register variant " #variant " exceeds struct_size 64")

IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_update, FILES_UPDATE);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_file_index_range, FILE_ALLOC_RANGE);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_buf_reg, PBUF_RING);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_buf_reg, UNREGISTER_PBUF_RING);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_sync_cancel_reg, SYNC_CANCEL);
IO_URING_REGISTER_VARIANT_FITS(struct iovec, BUFFERS);
IO_URING_REGISTER_VARIANT_FITS(struct iovec, UNREGISTER_BUFFERS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_restriction, RESTRICTIONS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_update, RING_FDS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_update, UNREGISTER_RING_FDS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_napi, NAPI);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_napi, UNREGISTER_NAPI);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_clock_register, CLOCK);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_clone_buffers, CLONE_BUFFERS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_buf_status, PBUF_STATUS);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_register, FILES2);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_register, BUFFERS2);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_update2, FILES_UPDATE2);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_rsrc_update2, BUFFERS_UPDATE);
IO_URING_REGISTER_VARIANT_FITS(struct io_uring_probe, PROBE);

#undef IO_URING_REGISTER_VARIANT_FITS
