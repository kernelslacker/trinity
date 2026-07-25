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
const unsigned long bpf_map_types[BPF_MAP_TYPES_N] = {
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

const unsigned long bpf_prog_types[BPF_PROG_TYPES_N] = {
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

/*
 * uprobe_multi.flags bit added in v7.2-rc1: when set, the kernel reads
 * link_create.uprobe_multi.path_fd as an fd referring to the target
 * binary instead of copying path in as a filename string.  Fallback to
 * the upstream value so older /usr/include/linux/bpf.h still builds.
 */
#ifndef BPF_F_UPROBE_MULTI_PATH_FD
#define BPF_F_UPROBE_MULTI_PATH_FD	(1U << 1)
#endif

const unsigned long bpf_attach_types[BPF_ATTACH_TYPES_N] = {
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

const struct struct_field bpf_attr_TOKEN_CREATE_fields[] = {
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
#ifndef USE_BPF_LINK_CREATE_TRACING_MULTI
	/*
	 * Older uapi without link_create.tracing_multi: fall back to
	 * this arm's (target_btf_id, cookie) overlay so the multi
	 * attach types still get a cataloged tail.  When the gate is
	 * on they migrate to the TRACING_MULTI arm below.
	 */
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
#endif
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
	       .u.flags.mask = BPF_F_UPROBE_MULTI_RETURN |
			       BPF_F_UPROBE_MULTI_PATH_FD),
	FIELD(union bpf_attr, link_create.uprobe_multi.pid),
};

/*
 * TRACING_MULTI sub-variant: attaches a single tracing program to a
 * set of kernel functions in one call.  ids[] is the btf_id array of
 * targets, cookies[] the paired per-target cookie array, cnt bounds
 * both -- the FT_LEN_COUNT tail sizes both sibling pointer arrays off
 * the single count field, same shape as the *probe_multi arms.
 *
 * Gated on USE_BPF_LINK_CREATE_TRACING_MULTI because the tracing_multi
 * named union member postdates the trinity baseline and struct members
 * can't be #ifndef-shimmed -- offsetof() needs the real member.  When
 * the gate is off the multi attach types stay in
 * bpf_attach_types_tracing[] above and fall through to the TRACING
 * arm's (target_btf_id, cookie) overlay.
 */
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
const unsigned long bpf_attach_types_tracing_multi[] = {
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
};

const char *const bpf_attr_link_create_tracing_multi_arrays[] = {
	"link_create.tracing_multi.ids",
	"link_create.tracing_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_TRACING_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.tracing_multi.ids, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.tracing_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.tracing_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_tracing_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_tracing_multi_arrays) }),
};
#endif

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
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
	{
		.discrim_values	    = bpf_attach_types_tracing_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tracing_multi),
		.name		= "LINK_CREATE/TRACING_MULTI",
		.fields		= bpf_attr_LINK_CREATE_TRACING_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TRACING_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tracing_multi.cnt) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tracing_multi.cnt),
	},
#endif
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
