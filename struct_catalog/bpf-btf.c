/*
 * struct_catalog/bpf-btf.c -- BTF-family command field tables carved
 * out of struct_catalog/bpf.c.  Covers BPF_BTF_LOAD (the BTF blob
 * upload) and BPF_OBJ_GET_INFO_BY_FD (the generic-fd info-query slot
 * the kernel routes to the prog / map / link / btf info dispatch
 * through the underlying file ops).
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
 * BPF_BTF_LOAD btf_load variant.  Random bytes in btf fail the BTF
 * magic check (0xEB9F) and bounce on -EINVAL before reaching the
 * verifier proper -- currently acceptable; planting the magic via
 * FT_VERSION_MAGIC would widen coverage past the magic gate but is
 * intentionally deferred.  btf_log_buf is optional so the no-log
 * path runs too.
 */
const struct struct_field bpf_attr_BTF_LOAD_fields[BPF_ATTR_BTF_LOAD_FIELDS_N] = {
	FIELDX(union bpf_attr, btf, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "btf_size",
				.max_bytes = 4096 }),
	FIELDX(union bpf_attr, btf_log_buf, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "btf_log_size",
				.optional = true,
				.max_bytes = 4096 }),
	FIELDX(union bpf_attr, btf_size, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "btf" }),
	FIELDX(union bpf_attr, btf_log_size, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "btf_log_buf", .optional = true }),
	FIELDX(union bpf_attr, btf_log_level, FT_FLAGS,
	       .u.flags.mask = 0x7),
	FIELD(union bpf_attr, btf_log_true_size),
	FIELDX(union bpf_attr, btf_flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_TOKEN_FD),
	FIELDX(union bpf_attr, btf_token_fd, FT_FD),
};

/*
 * BPF_OBJ_GET_INFO_BY_FD info variant.  bpf_fd is the generic-fd
 * slot (kernel handles prog/map/link/btf dispatch via the fd's
 * underlying file ops).  info is a kernel-writable buffer; the
 * pre-fill bytes get overwritten on success, but we still need the
 * (ptr, len) pair to be internally consistent so the kernel's
 * up-front bounds check passes.  Not optional -- a NULL info buffer
 * just bounces on -EFAULT before reaching the info_by_fd dispatch.
 */
const struct struct_field bpf_attr_INFO_fields[BPF_ATTR_INFO_FIELDS_N] = {
	FIELDX(union bpf_attr, info.bpf_fd, FT_FD),
	FIELDX(union bpf_attr, info.info_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "info.info" }),
	FIELDX(union bpf_attr, info.info, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "info.info_len",
				.max_bytes = 4096 }),
};

#endif /* USE_BPF */
