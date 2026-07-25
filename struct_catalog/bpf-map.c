/*
 * struct_catalog/bpf-map.c -- BPF_MAP_* command family field tables
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
 * MAP_CREATE flag mask.  Names absent from the local uapi header
 * vintage drop out via #ifdef so an older /usr/include/linux/bpf.h
 * doesn't break the build; the cost is a tiny gap in the mask which
 * the kernel still rejects up-stream of any field-level validation.
 */
#define MAP_CREATE_FLAGS_MASK ( \
	BPF_F_NO_PREALLOC | BPF_F_NO_COMMON_LRU | BPF_F_NUMA_NODE | \
	BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_STACK_BUILD_ID | \
	BPF_F_ZERO_SEED | BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG | \
	BPF_F_CLONE | BPF_F_MMAPABLE | BPF_F_INNER_MAP | BPF_F_LINK)

#ifdef BPF_F_PRESERVE_ELEMS
# define MAP_CREATE_FLAGS_PRESERVE	BPF_F_PRESERVE_ELEMS
#else
# define MAP_CREATE_FLAGS_PRESERVE	0UL
#endif
#ifdef BPF_F_VTYPE_BTF_OBJ_FD
# define MAP_CREATE_FLAGS_VTYPE	BPF_F_VTYPE_BTF_OBJ_FD
#else
# define MAP_CREATE_FLAGS_VTYPE	0UL
#endif
#ifdef BPF_F_TOKEN_FD
# define MAP_CREATE_FLAGS_TOKEN_FD	BPF_F_TOKEN_FD
#else
# define MAP_CREATE_FLAGS_TOKEN_FD	0UL
#endif

#define MAP_CREATE_FLAGS_FULL_MASK \
	(MAP_CREATE_FLAGS_MASK | MAP_CREATE_FLAGS_PRESERVE | \
	 MAP_CREATE_FLAGS_VTYPE | MAP_CREATE_FLAGS_TOKEN_FD)

/*
 * MAP_CREATE variant: every gate field that the kernel validates
 * before reaching the map-type-specific code in map_create() lands
 * here.  Ranges mirror sanitise_bpf today (1024 / 65536 / 1024) so
 * a CMP-driven hint that the kernel compared a u32 against a small
 * constant lands on the field most likely to satisfy validation.
 *
 * Fields absent from older uapi headers (excl_prog_hash /
 * excl_prog_hash_size) are intentionally not annotated; adding
 * offsetof references against a union member the header doesn't
 * declare would break the build on older distros, and the kernel
 * still accepts a zero-fill in those bytes.
 */
const struct struct_field bpf_attr_MAP_CREATE_fields[BPF_ATTR_MAP_CREATE_FIELDS_N] = {
	FIELDX(union bpf_attr, map_type, FT_ENUM,
	       .u.enum_ = { bpf_map_types, ARRAY_SIZE(bpf_map_types) },
	       .mutate_weight = 200),
	FIELDX(union bpf_attr, key_size, FT_RANGE,
	       .u.range = { 0, 1024 }),
	FIELDX(union bpf_attr, value_size, FT_RANGE,
	       .u.range = { 0, 65536 }),
	FIELDX(union bpf_attr, max_entries, FT_RANGE,
	       .u.range = { 0, 1024 }),
	FIELDX(union bpf_attr, map_flags, FT_FLAGS,
	       .u.flags.mask = MAP_CREATE_FLAGS_FULL_MASK,
	       .mutate_weight = 80),
	FIELDX(union bpf_attr, inner_map_fd, FT_FD),
	FIELDX(union bpf_attr, numa_node, FT_RANGE,
	       .u.range = { 0, 255 }),
	FIELD(union bpf_attr, map_name),
	FIELD(union bpf_attr, map_ifindex),
	FIELDX(union bpf_attr, btf_fd, FT_FD),
	FIELD(union bpf_attr, btf_key_type_id),
	FIELD(union bpf_attr, btf_value_type_id),
	FIELD(union bpf_attr, btf_vmlinux_value_type_id),
	FIELD(union bpf_attr, map_extra),
	FIELDX(union bpf_attr, value_type_btf_obj_fd, FT_FD),
	FIELDX(union bpf_attr, map_token_fd, FT_FD),
};

/*
 * MAP_ELEM variant covers MAP_LOOKUP / UPDATE / DELETE /
 * GET_NEXT_KEY / FREEZE / LOOKUP_AND_DELETE.  All read off the
 * same anonymous struct: map_fd + key + (value|next_key union) +
 * flags.  Key/value sizes are fixed maxes here (1024 / 65536); a
 * map-aware sizing pass (look up the actual map's key_size /
 * value_size at fill time) is bigger and lives in a later phase.
 * The kernel still bounds-checks every (ptr, size) shape against
 * the map's declared sizes, so the worst-case fallout from an
 * overshoot is -EINVAL.
 */
const struct struct_field bpf_attr_MAP_ELEM_fields[BPF_ATTR_MAP_ELEM_FIELDS_N] = {
	FIELDX(union bpf_attr, map_fd, FT_FD,
	       .mutate_weight = 150),
	FIELDX(union bpf_attr, key, FT_PTR_BYTES,
	       .u.ptr_bytes = { .max_bytes = 1024 },
	       .mutate_weight = 120),
	FIELDX(union bpf_attr, value, FT_PTR_BYTES,
	       .u.ptr_bytes = { .max_bytes = 65536 },
	       .mutate_weight = 120),
	FIELDX(union bpf_attr, flags, FT_FLAGS,
	       .u.flags.mask = (BPF_ANY | BPF_NOEXIST | BPF_EXIST |
				BPF_F_LOCK)),
};

/*
 * BPF_MAP_*_BATCH batch variant.  count gates keys+values together
 * (multi-pair).  in_batch is the optional iterator-state buffer
 * (NULL-to-start); out_batch is non-optional because the kernel
 * writes the next iterator state into it.  Element size for keys /
 * values uses a generous 8-byte default -- map-aware sizing (read
 * the map_fd's key_size / value_size at fill time) lives in a
 * follow-up; today an undersized buffer -EINVALs cleanly.
 */
const char *const bpf_attr_batch_arrays[BPF_ATTR_BATCH_ARRAYS_N] = {
	"batch.keys",
	"batch.values",
};

#define BATCH_ELEM_FLAGS_MASK \
	(BPF_ANY | BPF_NOEXIST | BPF_EXIST | BPF_F_LOCK)

const struct struct_field bpf_attr_BATCH_fields[BPF_ATTR_BATCH_FIELDS_N] = {
	FIELDX(union bpf_attr, batch.in_batch, FT_PTR_BYTES,
	       .u.ptr_bytes = { .optional = true, .max_bytes = 1024 }),
	FIELDX(union bpf_attr, batch.out_batch, FT_PTR_BYTES,
	       .u.ptr_bytes = { .max_bytes = 1024 }),
	FIELDX(union bpf_attr, batch.keys, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 64 }),
	FIELDX(union bpf_attr, batch.values, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 64 }),
	FIELDX(union bpf_attr, batch.count, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_batch_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_batch_arrays) }),
	FIELDX(union bpf_attr, batch.map_fd, FT_FD),
	FIELDX(union bpf_attr, batch.elem_flags, FT_FLAGS,
	       .u.flags.mask = BATCH_ELEM_FLAGS_MASK),
	FIELD(union bpf_attr, batch.flags),
};

#endif /* USE_BPF */
