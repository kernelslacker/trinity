/*
 * struct_catalog/bpf-task-storage.c -- task / iter / stats / token /
 * raw-tracepoint cmd family field tables carved out of
 * struct_catalog/bpf.c.  Covers the smaller BPF cmd variants that
 * each live in their own named-union member: BPF_TASK_FD_QUERY,
 * BPF_ENABLE_STATS, BPF_ITER_CREATE, BPF_RAW_TRACEPOINT_OPEN, and
 * BPF_TOKEN_CREATE.
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

const struct struct_field bpf_attr_ENABLE_STATS_fields[BPF_ATTR_ENABLE_STATS_FIELDS_N] = {
	/*
	 * enum bpf_stats_type is a tiny set today (RUN_TIME_NS only);
	 * a dedicated enum vocab is overkill -- FT_RANGE keeps the
	 * value bounded near the legal range without committing to
	 * a vocab that turns stale on every uapi bump.
	 */
	FIELDX(union bpf_attr, enable_stats.type, FT_RANGE,
	       .u.range = { 0, 8 }),
};

const struct struct_field bpf_attr_ITER_CREATE_fields[BPF_ATTR_ITER_CREATE_FIELDS_N] = {
	FIELDX(union bpf_attr, iter_create.link_fd, FT_FD),
	FIELD(union bpf_attr, iter_create.flags),
};

const struct struct_field bpf_attr_TOKEN_CREATE_fields[BPF_ATTR_TOKEN_CREATE_FIELDS_N] = {
	FIELD(union bpf_attr, token_create.flags),
	FIELDX(union bpf_attr, token_create.bpffs_fd, FT_FD),
};

/*
 * BPF_TASK_FD_QUERY task_fd_query variant.  buf is the kernel-
 * writable name/symbol/filename buffer; non-optional because a NULL
 * buffer bounces on the up-front -EFAULT before the per-fd-type
 * dispatch.  prog_id / fd_type / probe_offset / probe_addr are
 * kernel outputs that we still pre-fill so the slot is well-defined
 * if the call fails before the kernel writes them.
 */
const struct struct_field bpf_attr_TASK_FD_QUERY_fields[BPF_ATTR_TASK_FD_QUERY_FIELDS_N] = {
	FIELD(union bpf_attr, task_fd_query.pid),
	FIELDX(union bpf_attr, task_fd_query.fd, FT_FD),
	FIELD(union bpf_attr, task_fd_query.flags),
	FIELDX(union bpf_attr, task_fd_query.buf_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "task_fd_query.buf" }),
	FIELDX(union bpf_attr, task_fd_query.buf, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "task_fd_query.buf_len",
				.max_bytes = 256 }),
	FIELD(union bpf_attr, task_fd_query.prog_id),
	FIELD(union bpf_attr, task_fd_query.fd_type),
	FIELD(union bpf_attr, task_fd_query.probe_offset),
	FIELD(union bpf_attr, task_fd_query.probe_addr),
};

/*
 * BPF_RAW_TRACEPOINT_OPEN raw_tracepoint variant.  name is a u64 user
 * pointer to a NUL-terminated tracepoint name string -- the kernel
 * runs strndup_user on it, so an unterminated buffer wastes the
 * call.  64 bytes is generous for any real tracepoint identifier.
 * The u32 hole between prog_fd and cookie is uapi padding; leaving
 * it unannotated is the right call -- the kernel ignores it.
 */
const struct struct_field bpf_attr_RAW_TRACEPOINT_fields[BPF_ATTR_RAW_TRACEPOINT_FIELDS_N] = {
	FIELDX(union bpf_attr, raw_tracepoint.name, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.max_bytes = 64 }),
	FIELDX(union bpf_attr, raw_tracepoint.prog_fd, FT_FD),
	FIELD(union bpf_attr, raw_tracepoint.cookie),
};

#endif /* USE_BPF */
