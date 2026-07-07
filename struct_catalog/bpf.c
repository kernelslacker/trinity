/*
 * struct_catalog/bpf.c -- union bpf_attr per-cmd field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.variants =` / `.fields =` references resolve via the externs in
 * struct_catalog-internal.h.  struct_catalog.h and arch.h are #included
 * unconditionally so this TU is never empty when USE_BPF is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_BPF
#include <linux/netfilter.h>

#include "bpf.h"


/*
 * Shared with syscalls/bpf.c via include/bpf.h.  Lives here so the
 * FT_ENUM annotation on union bpf_attr.map_type and sanitise_bpf's
 * map_type pick share a single vocabulary.
 */
const unsigned long bpf_map_types[] = {
	BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE, BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE, BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS, BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE, BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE, BPF_MAP_TYPE_ARENA,
	BPF_MAP_TYPE_INSN_ARRAY, BPF_MAP_TYPE_RHASH,
};
const unsigned int bpf_map_types_count = ARRAY_SIZE(bpf_map_types);

const unsigned long bpf_prog_types[] = {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL,
	BPF_PROG_TYPE_NETFILTER,
};
const unsigned int bpf_prog_types_count = ARRAY_SIZE(bpf_prog_types);

/* Attach types not present in older /usr/include/linux/bpf.h. */
#ifndef BPF_TRACE_KPROBE_SESSION
#define BPF_TRACE_KPROBE_SESSION	56
#endif
#ifndef BPF_TRACE_UPROBE_SESSION
#define BPF_TRACE_UPROBE_SESSION	57
#endif
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION		58
#endif
#ifndef BPF_TRACE_FENTRY_MULTI
#define BPF_TRACE_FENTRY_MULTI		59
#endif
#ifndef BPF_TRACE_FEXIT_MULTI
#define BPF_TRACE_FEXIT_MULTI		60
#endif
#ifndef BPF_TRACE_FSESSION_MULTI
#define BPF_TRACE_FSESSION_MULTI	61
#endif

const unsigned long bpf_attach_types[] = {
	BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE, BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG,
	BPF_LIRC_MODE2, BPF_FLOW_DISSECTOR,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG, BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT, BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP, BPF_TRACE_FENTRY, BPF_TRACE_FEXIT,
	BPF_MODIFY_RETURN, BPF_LSM_MAC, BPF_TRACE_ITER,
	BPF_CGROUP_INET4_GETPEERNAME, BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME, BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_XDP_DEVMAP, BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_XDP_CPUMAP, BPF_SK_LOOKUP, BPF_XDP,
	BPF_SK_SKB_VERDICT,
	BPF_SK_REUSEPORT_SELECT, BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
	BPF_PERF_EVENT, BPF_TRACE_KPROBE_MULTI,
	BPF_LSM_CGROUP, BPF_STRUCT_OPS, BPF_NETFILTER,
	BPF_TCX_INGRESS, BPF_TCX_EGRESS,
	BPF_TRACE_UPROBE_MULTI,
	BPF_CGROUP_UNIX_CONNECT, BPF_CGROUP_UNIX_SENDMSG,
	BPF_CGROUP_UNIX_RECVMSG, BPF_CGROUP_UNIX_GETPEERNAME,
	BPF_CGROUP_UNIX_GETSOCKNAME,
	BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
	BPF_TRACE_KPROBE_SESSION, BPF_TRACE_UPROBE_SESSION,
	BPF_TRACE_FSESSION,
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
};
const unsigned int bpf_attach_types_count = ARRAY_SIZE(bpf_attach_types);

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
const struct struct_field bpf_attr_MAP_CREATE_fields[] = {
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
const struct struct_field bpf_attr_PROG_LOAD_fields[] = {
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
const struct struct_field bpf_attr_PROG_ATTACH_fields[] = {
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

/*
 * OBJ (BPF_OBJ_PIN / BPF_OBJ_GET) file_flags mask.  RDONLY/WRONLY
 * share their bit values with the map_flags mask; PATH_FD is OBJ-
 * specific and (along with the path_fd field it gates) was added
 * later but is present in the local uapi vintage.
 */
#define OBJ_FILE_FLAGS_MASK	(BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_PATH_FD)

/*
 * OBJ variant.  pathname is the only string-shaped slot in the
 * catalog so far -- FT_PTR_BYTES with null_terminated = true so
 * strnlen_user / the path walker see a NUL-terminated buffer.  No
 * len-pair field: the kernel uses strnlen_user on the buffer and
 * trusts the NUL it finds.
 */
const struct struct_field bpf_attr_OBJ_fields[] = {
	FIELDX(union bpf_attr, pathname, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.max_bytes = 256 },
	       .mutate_weight = 150),
	FIELDX(union bpf_attr, bpf_fd, FT_FD),
	FIELDX(union bpf_attr, file_flags, FT_FLAGS,
	       .u.flags.mask = OBJ_FILE_FLAGS_MASK),
	FIELDX(union bpf_attr, path_fd, FT_FD),
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
const struct struct_field bpf_attr_MAP_ELEM_fields[] = {
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
 * GET_ID variant covers BPF_*_GET_NEXT_ID and BPF_*_GET_FD_BY_ID.
 * The id-shaped fields stay FT_RAW because the kernel iterates
 * IDs linearly and a random u32 typically misses; CMP-hint
 * attribution still scopes here once the cmd matches.
 * fd_by_id_token_fd is an FT_FD slot honoured on the BY_ID arms; it
 * was added to union bpf_attr in 6.13, so its field entry (and the
 * BTF_GET_FD_BY_ID effective_size that reaches for it below) is gated
 * on USE_BPF_FD_BY_ID_TOKEN_FD -- offsetof() can't be #ifdef-shimmed
 * against a member the header doesn't declare.
 */
const struct struct_field bpf_attr_GET_ID_fields[] = {
	FIELD(union bpf_attr, start_id),
	FIELD(union bpf_attr, next_id),
	FIELDX(union bpf_attr, open_flags, FT_FLAGS,
	       .u.flags.mask = (BPF_F_RDONLY | BPF_F_WRONLY)),
#ifdef USE_BPF_FD_BY_ID_TOKEN_FD
	FIELDX(union bpf_attr, fd_by_id_token_fd, FT_FD),
#endif
};

/*
 * The remaining annotated variants live inside NAMED struct
 * members of union bpf_attr (link_update.*, link_detach.*, ...),
 * so offsetof and the schema field names use dotted forms.
 * find_field_index_in walks the local fields[] by strcmp on the
 * dotted name; FT_LEN_BYTES.buf_field below uses the same form
 * so the pairing resolves.
 *
 * BPF_PROG_ASSOC_STRUCT_OPS is one of the variants in this tail
 * group per the design doc, but the prog_assoc_struct_ops named
 * struct member is absent from the local uapi vintage; the cmd
 * itself is only available via syscalls/bpf.c's fallback #define.
 * Intentionally skipped.
 */
const struct struct_field bpf_attr_LINK_UPDATE_fields[] = {
	FIELDX(union bpf_attr, link_update.link_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.new_prog_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_REPLACE),
	FIELDX(union bpf_attr, link_update.old_prog_fd, FT_FD),
};

const struct struct_field bpf_attr_LINK_DETACH_fields[] = {
	FIELDX(union bpf_attr, link_detach.link_fd, FT_FD),
};

const struct struct_field bpf_attr_ENABLE_STATS_fields[] = {
	/*
	 * enum bpf_stats_type is a tiny set today (RUN_TIME_NS only);
	 * a dedicated enum vocab is overkill -- FT_RANGE keeps the
	 * value bounded near the legal range without committing to
	 * a vocab that turns stale on every uapi bump.
	 */
	FIELDX(union bpf_attr, enable_stats.type, FT_RANGE,
	       .u.range = { 0, 8 }),
};

const struct struct_field bpf_attr_ITER_CREATE_fields[] = {
	FIELDX(union bpf_attr, iter_create.link_fd, FT_FD),
	FIELD(union bpf_attr, iter_create.flags),
};

const struct struct_field bpf_attr_PROG_BIND_MAP_fields[] = {
	FIELDX(union bpf_attr, prog_bind_map.prog_fd, FT_FD),
	FIELDX(union bpf_attr, prog_bind_map.map_fd, FT_FD),
	FIELD(union bpf_attr, prog_bind_map.flags),
};

const struct struct_field bpf_attr_TOKEN_CREATE_fields[] = {
	FIELD(union bpf_attr, token_create.flags),
	FIELDX(union bpf_attr, token_create.bpffs_fd, FT_FD),
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
const char *const bpf_attr_query_arrays[] = {
	"query.prog_ids",
	"query.prog_attach_flags",
	"query.link_ids",
	"query.link_attach_flags",
};

const struct struct_field bpf_attr_QUERY_fields[] = {
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
 * BPF_TASK_FD_QUERY task_fd_query variant.  buf is the kernel-
 * writable name/symbol/filename buffer; non-optional because a NULL
 * buffer bounces on the up-front -EFAULT before the per-fd-type
 * dispatch.  prog_id / fd_type / probe_offset / probe_addr are
 * kernel outputs that we still pre-fill so the slot is well-defined
 * if the call fails before the kernel writes them.
 */
const struct struct_field bpf_attr_TASK_FD_QUERY_fields[] = {
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
 * BPF_BTF_LOAD btf_load variant.  Random bytes in btf fail the BTF
 * magic check (0xEB9F) and bounce on -EINVAL before reaching the
 * verifier proper -- currently acceptable; planting the magic via
 * FT_VERSION_MAGIC would widen coverage past the magic gate but is
 * intentionally deferred.  btf_log_buf is optional so the no-log
 * path runs too.
 */
const struct struct_field bpf_attr_BTF_LOAD_fields[] = {
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
 * BPF_MAP_*_BATCH batch variant.  count gates keys+values together
 * (multi-pair).  in_batch is the optional iterator-state buffer
 * (NULL-to-start); out_batch is non-optional because the kernel
 * writes the next iterator state into it.  Element size for keys /
 * values uses a generous 8-byte default -- map-aware sizing (read
 * the map_fd's key_size / value_size at fill time) lives in a
 * follow-up; today an undersized buffer -EINVALs cleanly.
 */
const char *const bpf_attr_batch_arrays[] = {
	"batch.keys",
	"batch.values",
};

#define BATCH_ELEM_FLAGS_MASK \
	(BPF_ANY | BPF_NOEXIST | BPF_EXIST | BPF_F_LOCK)

const struct struct_field bpf_attr_BATCH_fields[] = {
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

const struct struct_field bpf_attr_TEST_fields[] = {
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
 * BPF_OBJ_GET_INFO_BY_FD info variant.  bpf_fd is the generic-fd
 * slot (kernel handles prog/map/link/btf dispatch via the fd's
 * underlying file ops).  info is a kernel-writable buffer; the
 * pre-fill bytes get overwritten on success, but we still need the
 * (ptr, len) pair to be internally consistent so the kernel's
 * up-front bounds check passes.  Not optional -- a NULL info buffer
 * just bounces on -EFAULT before reaching the info_by_fd dispatch.
 */
const struct struct_field bpf_attr_INFO_fields[] = {
	FIELDX(union bpf_attr, info.bpf_fd, FT_FD),
	FIELDX(union bpf_attr, info.info_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "info.info" }),
	FIELDX(union bpf_attr, info.info, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "info.info_len",
				.max_bytes = 4096 }),
};

/*
 * BPF_RAW_TRACEPOINT_OPEN raw_tracepoint variant.  name is a u64 user
 * pointer to a NUL-terminated tracepoint name string -- the kernel
 * runs strndup_user on it, so an unterminated buffer wastes the
 * call.  64 bytes is generous for any real tracepoint identifier.
 * The u32 hole between prog_fd and cookie is uapi padding; leaving
 * it unannotated is the right call -- the kernel ignores it.
 */
const struct struct_field bpf_attr_RAW_TRACEPOINT_fields[] = {
	FIELDX(union bpf_attr, raw_tracepoint.name, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.max_bytes = 64 }),
	FIELDX(union bpf_attr, raw_tracepoint.prog_fd, FT_FD),
	FIELD(union bpf_attr, raw_tracepoint.cookie),
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
const struct struct_field bpf_attr_PROG_STREAM_READ_fields[] = {
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
 * LINK_CREATE outer variant.  attach_type is the inner discriminator
 * for the link_create tail sub-union -- nested_variants[] is not yet
 * populated with the per-attach-type tails.  The four head fields
 * (prog_fd/map_fd, target_fd/target_ifindex, attach_type, flags) sit
 * at the union's offsets 0/4/8/12 and are shared across every
 * sub-variant, so they live here on the outer variant rather than
 * being repeated on each arm.
 *
 * The two anonymous unions (prog_fd|map_fd, target_fd|target_ifindex)
 * each get one FT_FD slot; the kernel reads the same bytes either
 * way, and the broader-semantic arm (prog_fd, target_fd) is the more
 * common live shape.
 *
 * flags annotated FT_RAW: the mask is per-attach-type and the head
 * field can't express that -- leaving it as a random splat lets the
 * verifier reject unknown bits without us committing to a wrong-
 * per-attach mask.  Revisit by moving flags onto each sub-variant.
 */
const struct struct_field bpf_attr_LINK_CREATE_fields[] = {
	FIELDX(union bpf_attr, link_create.prog_fd, FT_FD),
	FIELDX(union bpf_attr, link_create.target_fd, FT_FD),
	FIELDX(union bpf_attr, link_create.attach_type, FT_ENUM,
	       .u.enum_ = { bpf_attach_types, ARRAY_SIZE(bpf_attach_types) },
	       .mutate_weight = 200),
	FIELD(union bpf_attr, link_create.flags),
};

/*
 * BASE sub-variant.  Catch-all for attach types that have no
 * specific arm (BPF_FLOW_DISSECTOR, BPF_SK_LOOKUP, ...).  Also runs
 * unconditionally as the shared head pass before any specific arm
 * overlays its tail -- the TRACING arm relies on this for the
 * target_btf_id slot it overlays a cookie on top of.
 */
const struct struct_field bpf_attr_LINK_CREATE_BASE_fields[] = {
	FIELD(union bpf_attr, link_create.target_btf_id),
};

const struct union_variant bpf_attr_LINK_CREATE_base = {
	.name		= "LINK_CREATE/BASE",
	.fields		= bpf_attr_LINK_CREATE_BASE_fields,
	.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_BASE_fields),
	.effective_size	= offsetof(union bpf_attr, link_create.target_btf_id) +
			  sizeof(((union bpf_attr *)NULL)->link_create.target_btf_id),
};

/*
 * Per-attach-type discriminator-value sets for the link_create
 * sub-variants.  Single-value arms use the .discrim_value scalar on
 * the union_variant entry; multi-value arms (TRACING here, CGROUP
 * later) use .discrim_values[] so one entry covers them all.
 *
 * TRACING covers the fentry/fexit/modify-return/LSM/raw-tp/fsession
 * family -- any attach type that the kernel routes through the
 * tracing-link path, all of which share the (target_btf_id, cookie)
 * tail shape on top of the BASE arm's target_btf_id slot.
 */
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION		58
#endif

const unsigned long bpf_attach_types_tracing[] = {
	BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN,
	BPF_LSM_MAC, BPF_LSM_CGROUP, BPF_TRACE_RAW_TP,
	BPF_TRACE_FSESSION,
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
};

/*
 * ITER sub-variant: iter_info is a user pointer to a bpf_iter_link_info
 * blob the verifier walks; the schema fill plants random bytes so the
 * kernel's first-pass copy_from_user succeeds and the iter-type
 * dispatch runs.  iter_info_len pairs back via FT_LEN_BYTES.
 */
const struct struct_field bpf_attr_LINK_CREATE_ITER_fields[] = {
	FIELDX(union bpf_attr, link_create.iter_info, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "link_create.iter_info_len",
				.optional = true,
				.max_bytes = 128 }),
	FIELDX(union bpf_attr, link_create.iter_info_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "link_create.iter_info",
			     .optional = true }),
};

/*
 * PERF_EVENT sub-variant: a single u64 cookie at the inner-union
 * leading offset.  Random bytes are fine -- the kernel passes the
 * value through verbatim to BPF helpers without interpretation.
 */
const struct struct_field bpf_attr_LINK_CREATE_PERF_EVENT_fields[] = {
	FIELD(union bpf_attr, link_create.perf_event.bpf_cookie),
};

/*
 * TRACING sub-variant: overlays a u64 cookie on top of the BASE arm's
 * target_btf_id (the inner struct's first 4 bytes alias the BASE
 * target_btf_id slot per the uapi comment).  cookie lives at offset 8
 * within the inner struct -- u64 natural alignment puts it after
 * 4 bytes of pad, not immediately after target_btf_id as the spec
 * draft assumed.  effective_size therefore lands at 32, not 28.
 */
const struct struct_field bpf_attr_LINK_CREATE_TRACING_fields[] = {
	FIELD(union bpf_attr, link_create.tracing.cookie),
};

/*
 * NETFILTER / TCX / NETKIT / CGROUP_MULTI sub-variants for
 * LINK_CREATE.  Three share an identical inner layout
 * (relative_fd|relative_id + expected_revision); the cgroup arm
 * claims every BPF_CGROUP_* attach type via discrim_values[] so one
 * entry covers the ~28-way fan-out without cloning.
 *
 * Netfilter's hooknum is bounded by NF_INET_NUMHOOKS (5 hooks,
 * PREROUTING..POSTROUTING); pf is a small fixed NFPROTO_* set --
 * INET/IPV4/IPV6/ARP/NETDEV/BRIDGE -- without which the kernel's
 * dispatch never reaches the per-pf hook list.
 */
const unsigned long netfilter_pfs[] = {
	NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6,
	NFPROTO_ARP, NFPROTO_NETDEV, NFPROTO_BRIDGE,
};

const struct struct_field bpf_attr_LINK_CREATE_NETFILTER_fields[] = {
	FIELDX(union bpf_attr, link_create.netfilter.pf, FT_ENUM,
	       .u.enum_ = { netfilter_pfs, ARRAY_SIZE(netfilter_pfs) },
	       .mutate_weight = 150),
	FIELDX(union bpf_attr, link_create.netfilter.hooknum, FT_RANGE,
	       .u.range = { 0, NF_INET_NUMHOOKS - 1 }),
	FIELD(union bpf_attr, link_create.netfilter.priority),
	FIELDX(union bpf_attr, link_create.netfilter.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_NETFILTER_IP_DEFRAG),
};

/*
 * TCX and NETKIT share the layout (relative_fd|relative_id +
 * expected_revision); the field annotations differ only in dotted
 * path so the two are typed out separately rather than aliased.
 */
const struct struct_field bpf_attr_LINK_CREATE_TCX_fields[] = {
	FIELDX(union bpf_attr, link_create.tcx.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.tcx.expected_revision),
};

const struct struct_field bpf_attr_LINK_CREATE_NETKIT_fields[] = {
	FIELDX(union bpf_attr, link_create.netkit.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.netkit.expected_revision),
};

/*
 * The link_create.cgroup named member (mprog relative_fd /
 * expected_revision for cgroup links) was added in 6.13, so this table
 * and its nested-variant entry below are gated on
 * USE_BPF_LINK_CREATE_CGROUP.  When absent, cgroup attach types fall
 * through to the LINK_CREATE base pass rather than this arm.
 */
#ifdef USE_BPF_LINK_CREATE_CGROUP
const struct struct_field bpf_attr_LINK_CREATE_CGROUP_fields[] = {
	FIELDX(union bpf_attr, link_create.cgroup.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.cgroup.expected_revision),
};
#endif

const unsigned long bpf_attach_types_tcx[] = {
	BPF_TCX_INGRESS, BPF_TCX_EGRESS,
};

const unsigned long bpf_attach_types_netkit[] = {
	BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
};

/*
 * CGROUP_MULTI claims every BPF_CGROUP_* attach type.  The cgroup
 * arm's inner struct is shared across all of them; per-attach
 * semantics live in kernel/bpf/cgroup.c and don't affect the wire
 * shape sanitise produces.
 */
const unsigned long bpf_attach_types_cgroup[] = {
	BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_SOCK_OPS,
	BPF_CGROUP_DEVICE,
	BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG, BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT, BPF_CGROUP_SETSOCKOPT,
	BPF_CGROUP_INET4_GETPEERNAME, BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME, BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_CGROUP_UNIX_CONNECT, BPF_CGROUP_UNIX_SENDMSG,
	BPF_CGROUP_UNIX_RECVMSG, BPF_CGROUP_UNIX_GETPEERNAME,
	BPF_CGROUP_UNIX_GETSOCKNAME,
};

/*
 * KPROBE_MULTI / UPROBE_MULTI sub-variants.  Both gate three or four
 * sibling pointer arrays with a single cnt slot, exercising the new
 * multi-pair LEN extension (buf_fields[]).  cookies (KPROBE) /
 * ref_ctr_offsets+cookies (UPROBE) stay optional via .max_count and
 * the pre-pin pass treats them uniformly with the required siblings.
 *
 * The element type is scalar (u64 for symbol pointers, addresses,
 * file offsets, cookies) -- this is the first user of FT_PTR_ARRAY's
 * elem_size override path that lets the pointer pass size its
 * sub-buffer without a cataloged elem_struct.
 */
const unsigned long bpf_attach_types_kprobe_multi[] = {
	BPF_TRACE_KPROBE_MULTI, BPF_TRACE_KPROBE_SESSION,
};

const char *const bpf_attr_link_create_kprobe_multi_arrays[] = {
	"link_create.kprobe_multi.syms",
	"link_create.kprobe_multi.addrs",
	"link_create.kprobe_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_KPROBE_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.kprobe_multi.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_KPROBE_MULTI_RETURN),
	FIELDX(union bpf_attr, link_create.kprobe_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_kprobe_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_kprobe_multi_arrays) }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.syms, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.addrs, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
};

const unsigned long bpf_attach_types_uprobe_multi[] = {
	BPF_TRACE_UPROBE_MULTI, BPF_TRACE_UPROBE_SESSION,
};

const char *const bpf_attr_link_create_uprobe_multi_arrays[] = {
	"link_create.uprobe_multi.offsets",
	"link_create.uprobe_multi.ref_ctr_offsets",
	"link_create.uprobe_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_UPROBE_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.uprobe_multi.path, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.optional = true,
				.max_bytes = 256 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.offsets, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.ref_ctr_offsets, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_uprobe_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_uprobe_multi_arrays) }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_UPROBE_MULTI_RETURN),
	FIELD(union bpf_attr, link_create.uprobe_multi.pid),
};

/*
 * LINK_CREATE nested sub-variant table.  attach_type read off the
 * just-filled buffer at offset 8 (relative to the union, equal to
 * link_create.attach_type since link_create is at union offset 0)
 * selects which entry's tail fields[] overlay onto the BASE pass.
 */
const struct union_variant bpf_attr_LINK_CREATE_nested[] = {
	{
		.discrim_value	= BPF_TRACE_ITER,
		.name		= "LINK_CREATE/ITER",
		.fields		= bpf_attr_LINK_CREATE_ITER_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_ITER_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.iter_info_len) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.iter_info_len),
	},
	{
		.discrim_value	= BPF_PERF_EVENT,
		.name		= "LINK_CREATE/PERF_EVENT",
		.fields		= bpf_attr_LINK_CREATE_PERF_EVENT_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_PERF_EVENT_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.perf_event.bpf_cookie) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.perf_event.bpf_cookie),
	},
	{
		.discrim_values	    = bpf_attach_types_tracing,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tracing),
		.name		= "LINK_CREATE/TRACING",
		.fields		= bpf_attr_LINK_CREATE_TRACING_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TRACING_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tracing.cookie) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tracing.cookie),
	},
	{
		.discrim_values	    = bpf_attach_types_kprobe_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_kprobe_multi),
		.name		= "LINK_CREATE/KPROBE_MULTI",
		.fields		= bpf_attr_LINK_CREATE_KPROBE_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_KPROBE_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.kprobe_multi.cookies) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.kprobe_multi.cookies),
	},
	{
		.discrim_values	    = bpf_attach_types_uprobe_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_uprobe_multi),
		.name		= "LINK_CREATE/UPROBE_MULTI",
		.fields		= bpf_attr_LINK_CREATE_UPROBE_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_UPROBE_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.uprobe_multi.pid) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.uprobe_multi.pid),
	},
	{
		.discrim_value	= BPF_NETFILTER,
		.name		= "LINK_CREATE/NETFILTER",
		.fields		= bpf_attr_LINK_CREATE_NETFILTER_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_NETFILTER_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.netfilter.flags) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.netfilter.flags),
	},
	{
		.discrim_values	    = bpf_attach_types_tcx,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tcx),
		.name		= "LINK_CREATE/TCX",
		.fields		= bpf_attr_LINK_CREATE_TCX_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TCX_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tcx.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tcx.expected_revision),
	},
	{
		.discrim_values	    = bpf_attach_types_netkit,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_netkit),
		.name		= "LINK_CREATE/NETKIT",
		.fields		= bpf_attr_LINK_CREATE_NETKIT_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_NETKIT_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.netkit.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.netkit.expected_revision),
	},
#ifdef USE_BPF_LINK_CREATE_CGROUP
	{
		.discrim_values	    = bpf_attach_types_cgroup,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_cgroup),
		.name		= "LINK_CREATE/CGROUP",
		.fields		= bpf_attr_LINK_CREATE_CGROUP_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_CGROUP_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.cgroup.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.cgroup.expected_revision),
	},
#endif
};

/*
 * bpf_insn registration -- retained as an 8-byte CMP-attribution shape
 * so a learned KCOV-compare constant on code / off / imm can be
 * attributed back to the right field by struct_field_for_cmp().
 * PROG_LOAD's insns FILL now flows through FT_BPF_PROGRAM (which calls
 * net/bpf/ebpf.c's generator) rather than splatting random bpf_insn
 * elements via FT_PTR_ARRAY, but the per-field shape is still the
 * vocabulary the CMP-hint path reasons over.
 */
const struct struct_field bpf_insn_fields[] = {
	FIELD(struct bpf_insn, code),
	FIELD(struct bpf_insn, off),
	FIELD(struct bpf_insn, imm),
};

/*
 * Tagged-union variant table.  rec->a1 carries the bpf cmd at sanitise
 * and post time; the discriminator scan picks the matching variant.
 * Variants annotated incrementally as the catalog grows; cmds without
 * an entry fall through to the empty shared prefix.
 */
const struct union_variant bpf_attr_variants[] = {
	{
		.discrim_value	= BPF_MAP_CREATE,
		.name		= "MAP_CREATE",
		.fields		= bpf_attr_MAP_CREATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_CREATE_fields),
		.effective_size	= offsetof(union bpf_attr, map_token_fd) +
				  sizeof(((union bpf_attr *)NULL)->map_token_fd),
	},
	{
		.discrim_value	= BPF_PROG_LOAD,
		.name		= "PROG_LOAD",
		.fields		= bpf_attr_PROG_LOAD_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_LOAD_fields),
		.effective_size	= offsetof(union bpf_attr, prog_token_fd) +
				  sizeof(((union bpf_attr *)NULL)->prog_token_fd),
	},
	{
		.discrim_value	= BPF_PROG_ATTACH,
		.name		= "PROG_ATTACH",
		.fields		= bpf_attr_PROG_ATTACH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_ATTACH_fields),
		.effective_size	= offsetof(union bpf_attr, expected_revision) +
				  sizeof(((union bpf_attr *)NULL)->expected_revision),
	},
	{
		.discrim_value	= BPF_PROG_DETACH,
		.name		= "PROG_DETACH",
		.fields		= bpf_attr_PROG_ATTACH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_ATTACH_fields),
		.effective_size	= offsetof(union bpf_attr, expected_revision) +
				  sizeof(((union bpf_attr *)NULL)->expected_revision),
	},
	{
		.discrim_value	= BPF_OBJ_PIN,
		.name		= "OBJ_PIN",
		.fields		= bpf_attr_OBJ_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_OBJ_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_OBJ_GET,
		.name		= "OBJ_GET",
		.fields		= bpf_attr_OBJ_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_OBJ_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_LOOKUP_ELEM,
		.name		= "MAP_LOOKUP_ELEM",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_UPDATE_ELEM,
		.name		= "MAP_UPDATE_ELEM",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_DELETE_ELEM,
		.name		= "MAP_DELETE_ELEM",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_GET_NEXT_KEY,
		.name		= "MAP_GET_NEXT_KEY",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_LOOKUP_AND_DELETE_ELEM,
		.name		= "MAP_LOOKUP_AND_DELETE_ELEM",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_MAP_FREEZE,
		.name		= "MAP_FREEZE",
		.fields		= bpf_attr_MAP_ELEM_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_ELEM_fields),
		.effective_size	= 32,
	},
	{
		.discrim_value	= BPF_PROG_GET_NEXT_ID,
		.name		= "PROG_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, next_id) +
				  sizeof(((union bpf_attr *)NULL)->next_id),
	},
	{
		.discrim_value	= BPF_MAP_GET_NEXT_ID,
		.name		= "MAP_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, next_id) +
				  sizeof(((union bpf_attr *)NULL)->next_id),
	},
	{
		.discrim_value	= BPF_PROG_GET_FD_BY_ID,
		.name		= "PROG_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, prog_id) +
				  sizeof(((union bpf_attr *)NULL)->prog_id),
	},
	{
		.discrim_value	= BPF_MAP_GET_FD_BY_ID,
		.name		= "MAP_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, open_flags) +
				  sizeof(((union bpf_attr *)NULL)->open_flags),
	},
	{
		.discrim_value	= BPF_BTF_GET_FD_BY_ID,
		.name		= "BTF_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
#ifdef USE_BPF_FD_BY_ID_TOKEN_FD
		.effective_size	= offsetof(union bpf_attr, fd_by_id_token_fd) +
				  sizeof(((union bpf_attr *)NULL)->fd_by_id_token_fd),
#else
		.effective_size	= offsetof(union bpf_attr, open_flags) +
				  sizeof(((union bpf_attr *)NULL)->open_flags),
#endif
	},
	{
		.discrim_value	= BPF_BTF_GET_NEXT_ID,
		.name		= "BTF_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, next_id) +
				  sizeof(((union bpf_attr *)NULL)->next_id),
	},
	{
		.discrim_value	= BPF_LINK_GET_FD_BY_ID,
		.name		= "LINK_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= offsetof(union bpf_attr, link_id) +
				  sizeof(((union bpf_attr *)NULL)->link_id),
	},
	{
		.discrim_value	= BPF_LINK_GET_NEXT_ID,
		.name		= "LINK_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_LINK_UPDATE,
		.name		= "LINK_UPDATE",
		.fields		= bpf_attr_LINK_UPDATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_UPDATE_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->link_update),
	},
	{
		.discrim_value	= BPF_LINK_DETACH,
		.name		= "LINK_DETACH",
		.fields		= bpf_attr_LINK_DETACH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_DETACH_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->link_detach),
	},
	{
		.discrim_value	= BPF_ENABLE_STATS,
		.name		= "ENABLE_STATS",
		.fields		= bpf_attr_ENABLE_STATS_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_ENABLE_STATS_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->enable_stats),
	},
	{
		.discrim_value	= BPF_ITER_CREATE,
		.name		= "ITER_CREATE",
		.fields		= bpf_attr_ITER_CREATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_ITER_CREATE_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->iter_create),
	},
	{
		.discrim_value	= BPF_PROG_BIND_MAP,
		.name		= "PROG_BIND_MAP",
		.fields		= bpf_attr_PROG_BIND_MAP_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_BIND_MAP_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->prog_bind_map),
	},
	{
		.discrim_value	= BPF_TOKEN_CREATE,
		.name		= "TOKEN_CREATE",
		.fields		= bpf_attr_TOKEN_CREATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_TOKEN_CREATE_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->token_create),
	},
#ifdef USE_BPF_PROG_STREAM_READ
	{
		.discrim_value	= BPF_PROG_STREAM_READ_BY_FD,
		.name		= "PROG_STREAM_READ_BY_FD",
		.fields		= bpf_attr_PROG_STREAM_READ_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_STREAM_READ_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->prog_stream_read),
	},
#endif
	{
		.discrim_value	= BPF_PROG_QUERY,
		.name		= "QUERY",
		.fields		= bpf_attr_QUERY_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_QUERY_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->query),
	},
	{
		.discrim_value	= BPF_TASK_FD_QUERY,
		.name		= "TASK_FD_QUERY",
		.fields		= bpf_attr_TASK_FD_QUERY_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_TASK_FD_QUERY_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->task_fd_query),
	},
	{
		.discrim_value	= BPF_BTF_LOAD,
		.name		= "BTF_LOAD",
		.fields		= bpf_attr_BTF_LOAD_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_BTF_LOAD_fields),
		/*
		 * BTF_LOAD lives in an unnamed anonymous struct rather than
		 * a named tag, so sizeof reaches for btf_token_fd's offset +
		 * size; no convenient sizeof(attr->btf_load) handle exists.
		 */
		.effective_size	= offsetof(union bpf_attr, btf_token_fd) +
				  sizeof(((union bpf_attr *)NULL)->btf_token_fd),
	},
	{
		.discrim_value	= BPF_MAP_LOOKUP_BATCH,
		.name		= "MAP_LOOKUP_BATCH",
		.fields		= bpf_attr_BATCH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_BATCH_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->batch),
	},
	{
		.discrim_value	= BPF_MAP_LOOKUP_AND_DELETE_BATCH,
		.name		= "MAP_LOOKUP_AND_DELETE_BATCH",
		.fields		= bpf_attr_BATCH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_BATCH_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->batch),
	},
	{
		.discrim_value	= BPF_MAP_UPDATE_BATCH,
		.name		= "MAP_UPDATE_BATCH",
		.fields		= bpf_attr_BATCH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_BATCH_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->batch),
	},
	{
		.discrim_value	= BPF_MAP_DELETE_BATCH,
		.name		= "MAP_DELETE_BATCH",
		.fields		= bpf_attr_BATCH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_BATCH_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->batch),
	},
	{
		.discrim_value	= BPF_PROG_TEST_RUN,
		.name		= "TEST",
		.fields		= bpf_attr_TEST_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_TEST_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->test),
	},
	{
		.discrim_value	= BPF_OBJ_GET_INFO_BY_FD,
		.name		= "OBJ_GET_INFO_BY_FD",
		.fields		= bpf_attr_INFO_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_INFO_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->info),
	},
	{
		.discrim_value	= BPF_RAW_TRACEPOINT_OPEN,
		.name		= "RAW_TRACEPOINT_OPEN",
		.fields		= bpf_attr_RAW_TRACEPOINT_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_RAW_TRACEPOINT_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->raw_tracepoint),
	},
	{
		.discrim_value	= BPF_LINK_CREATE,
		.name		= "LINK_CREATE",
		.fields		= bpf_attr_LINK_CREATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->link_create),
		/*
		 * attach_type is the inner discriminator; sub-variants in
		 * nested_variants[] are not yet populated.  base runs first
		 * so the catch-all target_btf_id slot is filled before any
		 * specific arm overlays its tail.
		 */
		.nested_discrim_offset = offsetof(union bpf_attr, link_create.attach_type),
		.nested_discrim_size   = 4,
		.base		= &bpf_attr_LINK_CREATE_base,
		.nested_variants     = bpf_attr_LINK_CREATE_nested,
		.num_nested_variants = ARRAY_SIZE(bpf_attr_LINK_CREATE_nested),
	},
};
#endif /* USE_BPF */
