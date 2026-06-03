/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * Provides a static catalog of known struct types (with per-field offset
 * and size), a table mapping syscall args to those struct types, and a
 * fast nr-indexed lookup built at init time.
 *
 * The field-for-CMP heuristic uses value magnitude to narrow which field
 * a kernel CMP constant was most likely comparing against.
 */

#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sched.h>
#include <time.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>
#include <linux/landlock.h>
#include <mqueue.h>

#include "config.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#endif

#include "struct_catalog.h"
#include "arch.h"
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * FIELD(S, m): the FT_RAW shortcut.  Tag, weight, and the .u payload
 * stay zero-initialised, so the field falls through to the historical
 * per-field random splat.  Existing entries keep this form.
 */
#define FIELD(S, m) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m) }

/*
 * FIELDX(S, m, TAG, ...): the semantic form.  Trailing __VA_ARGS__
 * carries the tag-specific designated initialisers, typically
 * .u.<arm> = { ... } and/or .mutate_weight = N.
 */
#define FIELDX(S, m, TAG, ...) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m), \
	  .tag = (TAG), \
	  __VA_ARGS__ }

/* ------------------------------------------------------------------ */
/* struct timex (adjtimex, clock_adjtime)                               */
/* ------------------------------------------------------------------ */

static const struct struct_field timex_fields[] = {
	FIELD(struct timex, modes),
	FIELD(struct timex, offset),
	FIELD(struct timex, freq),
	FIELD(struct timex, maxerror),
	FIELD(struct timex, esterror),
	FIELD(struct timex, status),
	FIELD(struct timex, constant),
	FIELD(struct timex, precision),
	FIELD(struct timex, tolerance),
	FIELD(struct timex, tick),
	FIELD(struct timex, ppsfreq),
	FIELD(struct timex, jitter),
	FIELD(struct timex, shift),
	FIELD(struct timex, stabil),
	FIELD(struct timex, jitcnt),
	FIELD(struct timex, calcnt),
	FIELD(struct timex, errcnt),
	FIELD(struct timex, stbcnt),
};

/* ------------------------------------------------------------------ */
/* struct sched_attr (sched_setattr, sched_getattr)                    */
/* ------------------------------------------------------------------ */

static const struct struct_field sched_attr_fields[] = {
	FIELD(struct sched_attr, size),
	FIELD(struct sched_attr, sched_policy),
	FIELD(struct sched_attr, sched_flags),
	FIELD(struct sched_attr, sched_nice),
	FIELD(struct sched_attr, sched_priority),
	FIELD(struct sched_attr, sched_runtime),
	FIELD(struct sched_attr, sched_deadline),
	FIELD(struct sched_attr, sched_period),
	FIELD(struct sched_attr, sched_util_min),
	FIELD(struct sched_attr, sched_util_max),
};

/* ------------------------------------------------------------------ */
/* struct clone_args (clone3)                                          */
/* ------------------------------------------------------------------ */

static const struct struct_field clone_args_fields[] = {
	FIELD(struct clone_args, flags),
	FIELD(struct clone_args, pidfd),
	FIELD(struct clone_args, child_tid),
	FIELD(struct clone_args, parent_tid),
	FIELD(struct clone_args, exit_signal),
	FIELD(struct clone_args, stack),
	FIELD(struct clone_args, stack_size),
	FIELD(struct clone_args, tls),
	FIELD(struct clone_args, set_tid),
	FIELD(struct clone_args, set_tid_size),
	FIELD(struct clone_args, cgroup),
};

/* ------------------------------------------------------------------ */
/* struct io_uring_params (io_uring_setup)                             */
/* ------------------------------------------------------------------ */

static const struct struct_field io_uring_params_fields[] = {
	FIELD(struct io_uring_params, sq_entries),
	FIELD(struct io_uring_params, cq_entries),
	FIELD(struct io_uring_params, flags),
	FIELD(struct io_uring_params, sq_thread_cpu),
	FIELD(struct io_uring_params, sq_thread_idle),
	FIELD(struct io_uring_params, features),
	FIELD(struct io_uring_params, wq_fd),
};

/* ------------------------------------------------------------------ */
/* struct rlimit (setrlimit, getrlimit, prlimit64)                     */
/* ------------------------------------------------------------------ */

static const struct struct_field rlimit_fields[] = {
	FIELD(struct rlimit, rlim_cur),
	FIELD(struct rlimit, rlim_max),
};

/* ------------------------------------------------------------------ */
/* struct itimerspec (timer_settime, timerfd_settime)                  */
/* ------------------------------------------------------------------ */

static const struct struct_field itimerspec_fields[] = {
	FIELD(struct itimerspec, it_interval.tv_sec),
	FIELD(struct itimerspec, it_interval.tv_nsec),
	FIELD(struct itimerspec, it_value.tv_sec),
	FIELD(struct itimerspec, it_value.tv_nsec),
};

/* ------------------------------------------------------------------ */
/* struct epoll_event (epoll_ctl)                                      */
/* ------------------------------------------------------------------ */

static const struct struct_field epoll_event_fields[] = {
	FIELD(struct epoll_event, events),
};

/* ------------------------------------------------------------------ */
/* struct perf_event_attr (perf_event_open)                            */
/* ------------------------------------------------------------------ */

/*
 * Only the addressable scalar fields are listed; the long bitfield run
 * (disabled, inherit, ..., sigtrap, __reserved_1) cannot be referenced
 * by offsetof and is intentionally omitted.  CMP attribution still
 * benefits from every full-byte field below — particularly type, size,
 * sample_type, read_format, branch_sample_type, sample_regs_*, and the
 * union'd config / bp_addr / bp_len slots that the kernel constantly
 * compares against PERF_* constants.
 */
static const struct struct_field perf_event_attr_fields[] = {
	FIELD(struct perf_event_attr, type),
	FIELD(struct perf_event_attr, size),
	FIELD(struct perf_event_attr, config),
	FIELD(struct perf_event_attr, sample_period),
	FIELD(struct perf_event_attr, sample_type),
	FIELD(struct perf_event_attr, read_format),
	FIELD(struct perf_event_attr, wakeup_events),
	FIELD(struct perf_event_attr, bp_type),
	FIELD(struct perf_event_attr, bp_addr),
	FIELD(struct perf_event_attr, bp_len),
	FIELD(struct perf_event_attr, branch_sample_type),
	FIELD(struct perf_event_attr, sample_regs_user),
	FIELD(struct perf_event_attr, sample_stack_user),
	FIELD(struct perf_event_attr, clockid),
	FIELD(struct perf_event_attr, sample_regs_intr),
	FIELD(struct perf_event_attr, aux_watermark),
	FIELD(struct perf_event_attr, sample_max_stack),
	FIELD(struct perf_event_attr, aux_sample_size),
	FIELD(struct perf_event_attr, aux_action),
	FIELD(struct perf_event_attr, sig_data),
	FIELD(struct perf_event_attr, config3),
};

/* ------------------------------------------------------------------ */
/* struct sigaction (rt_sigaction, sigaction)                          */
/* ------------------------------------------------------------------ */

static const struct struct_field sigaction_fields[] = {
	FIELD(struct sigaction, sa_flags),
};

/* ------------------------------------------------------------------ */
/* struct iovec (msg_iov array element)                                */
/* ------------------------------------------------------------------ */

/*
 * Registered so msghdr.msg_iov can name it via FT_PTR_ARRAY.elem_struct
 * and the pointer pass knows sizeof(struct iovec) for allocation.
 * iov_base is the kernel-dereferenced pointer; FT_ADDRESS routes it
 * through the nested-scrub walker so a fresh get_address() lands in
 * the field and any alias of shared_regions[] / libc brk gets
 * redirected before the syscall fires.  iov_len is paired length-in-
 * bytes of iov_base, so the kernel sees coherent (base, len) per
 * iovec entry instead of NULL + page_size.
 */
static const struct struct_field iovec_fields[] = {
	FIELDX(struct iovec, iov_base, FT_ADDRESS,
	       .mutate_weight = 120),
	FIELDX(struct iovec, iov_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "iov_base" },
	       .mutate_weight = 40),
};

/* ------------------------------------------------------------------ */
/* struct msghdr (sendmsg, recvmsg)                                    */
/* ------------------------------------------------------------------ */

/*
 * msghdr carries three distinct pointer/length pair shapes:
 *
 *   msg_name + msg_namelen      - optional sockaddr pointer, bytes
 *   msg_iov + msg_iovlen        - required iovec array, element count
 *   msg_control + msg_controllen- optional cmsg buffer, bytes
 *
 * Plus msg_flags as a recvmsg/sendmsg MSG_* bitmask.  Each pair is
 * annotated so the schema-aware fill keeps the length and the buffer
 * consistent; the kernel's first-pass sanity checks (msg_iovlen <=
 * UIO_MAXIOV, msg_namelen <= sizeof(sockaddr_storage), wild pointer
 * deref) stop bouncing the call before any family-specific recvmsg /
 * sendmsg path runs.
 *
 * msg_name uses sockaddr_storage as a generic catch-all; a later
 * commit annotates sockaddr_storage with FT_TAGGED_UNION on
 * ss_family and msg_name's sub-buffer will naturally pick up the
 * per-AF_* layout without changing this file.
 */
#define MSGHDR_FLAGS_MASK \
	(MSG_OOB | MSG_PEEK | MSG_DONTROUTE | MSG_CTRUNC | MSG_TRUNC | \
	 MSG_EOR | MSG_DONTWAIT | MSG_CONFIRM | MSG_ERRQUEUE | MSG_NOSIGNAL)

static const struct struct_field msghdr_fields[] = {
	FIELDX(struct msghdr, msg_name, FT_PTR_STRUCT,
	       .u.ptr_struct = { .len_field = "msg_namelen",
				 .struct_name = "sockaddr_storage",
				 .optional = true },
	       .mutate_weight = 120),
	FIELDX(struct msghdr, msg_namelen, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "msg_name", .optional = true },
	       .mutate_weight = 40),
	FIELDX(struct msghdr, msg_iov, FT_PTR_ARRAY,
	       .u.ptr_array = { .len_field = "msg_iovlen",
				.elem_struct = "iovec",
				.max_count = 16 },
	       .mutate_weight = 200),
	FIELDX(struct msghdr, msg_iovlen, FT_LEN_COUNT,
	       .u.len_of = { .buf_field = "msg_iov" },
	       .mutate_weight = 40),
	FIELDX(struct msghdr, msg_control, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "msg_controllen",
				.optional = true,
				.max_bytes = 4096 },
	       .mutate_weight = 150),
	FIELDX(struct msghdr, msg_controllen, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "msg_control", .optional = true },
	       .mutate_weight = 40),
	FIELDX(struct msghdr, msg_flags, FT_FLAGS,
	       .u.flags.mask = MSGHDR_FLAGS_MASK,
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct sockaddr_storage (bind, connect, sendto, ...)                */
/* ------------------------------------------------------------------ */

/*
 * Only ss_family is interesting from a CMP standpoint — the kernel's
 * sockaddr dispatch starts by comparing it against AF_* constants.  The
 * rest of the buffer is opaque padding whose meaning depends entirely on
 * which family the kernel routed to.
 */
static const struct struct_field sockaddr_storage_fields[] = {
	FIELD(struct sockaddr_storage, ss_family),
};

/* ------------------------------------------------------------------ */
/* struct landlock_ruleset_attr (landlock_create_ruleset)              */
/* ------------------------------------------------------------------ */

/*
 * The three fields are u64 bitmasks over disjoint vocab spaces:
 *
 *   handled_access_fs  -> LANDLOCK_ACCESS_FS_*  (bits 0..15)
 *   handled_access_net -> LANDLOCK_ACCESS_NET_* (bits 0..1)
 *   scoped             -> LANDLOCK_SCOPE_*      (bits 0..1)
 *
 * Anything outside its mask makes landlock_create_ruleset return
 * -EINVAL before the ruleset is ever allocated, so an FT_RAW splat
 * almost never reaches security/landlock/ paths.  Mask values are
 * built from the named uapi constants; if a new bit lands upstream
 * the mask needs updating here (caught by reviewer reading uapi diff).
 */
#define LANDLOCK_ACCESS_FS_MASK \
	(LANDLOCK_ACCESS_FS_EXECUTE     | LANDLOCK_ACCESS_FS_WRITE_FILE  | \
	 LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_READ_DIR    | \
	 LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	 LANDLOCK_ACCESS_FS_MAKE_CHAR   | LANDLOCK_ACCESS_FS_MAKE_DIR    | \
	 LANDLOCK_ACCESS_FS_MAKE_REG    | LANDLOCK_ACCESS_FS_MAKE_SOCK   | \
	 LANDLOCK_ACCESS_FS_MAKE_FIFO   | LANDLOCK_ACCESS_FS_MAKE_BLOCK  | \
	 LANDLOCK_ACCESS_FS_MAKE_SYM    | LANDLOCK_ACCESS_FS_REFER       | \
	 LANDLOCK_ACCESS_FS_TRUNCATE    | LANDLOCK_ACCESS_FS_IOCTL_DEV)

#define LANDLOCK_ACCESS_NET_MASK \
	(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

#define LANDLOCK_SCOPE_MASK \
	(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)

static const struct struct_field landlock_ruleset_attr_fields[] = {
	FIELDX(struct landlock_ruleset_attr, handled_access_fs, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_FS_MASK),
	FIELDX(struct landlock_ruleset_attr, handled_access_net, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_NET_MASK),
	FIELDX(struct landlock_ruleset_attr, scoped, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_SCOPE_MASK),
};

/* ------------------------------------------------------------------ */
/* struct mnt_id_req (statmount, listmount)                            */
/* ------------------------------------------------------------------ */

static const struct struct_field mnt_id_req_fields[] = {
	FIELD(struct mnt_id_req, size),
	FIELD(struct mnt_id_req, mnt_id),
	FIELD(struct mnt_id_req, param),
};

/* ------------------------------------------------------------------ */
/* struct __user_cap_header_struct (capset, capget)                    */
/* ------------------------------------------------------------------ */

static const struct struct_field user_cap_header_fields[] = {
	FIELD(struct __user_cap_header_struct, version),
	FIELD(struct __user_cap_header_struct, pid),
};

/* ------------------------------------------------------------------ */
/* struct __user_cap_data_struct (capset, capget)                      */
/* ------------------------------------------------------------------ */

static const struct struct_field user_cap_data_fields[] = {
	FIELD(struct __user_cap_data_struct, effective),
	FIELD(struct __user_cap_data_struct, permitted),
	FIELD(struct __user_cap_data_struct, inheritable),
};

/* ------------------------------------------------------------------ */
/* struct futex_waitv (futex_waitv)                                    */
/* ------------------------------------------------------------------ */

static const struct struct_field futex_waitv_fields[] = {
	FIELD(struct futex_waitv, val),
	FIELD(struct futex_waitv, uaddr),
	FIELD(struct futex_waitv, flags),
};

/* ------------------------------------------------------------------ */
/* stack_t (sigaltstack)                                                */
/* ------------------------------------------------------------------ */

static const struct struct_field stack_t_fields[] = {
	FIELD(stack_t, ss_sp),
	FIELD(stack_t, ss_flags),
	FIELD(stack_t, ss_size),
};

/* ------------------------------------------------------------------ */
/* struct mq_attr (mq_open, mq_getsetattr)                              */
/* ------------------------------------------------------------------ */

static const struct struct_field mq_attr_fields[] = {
	FIELD(struct mq_attr, mq_flags),
	FIELD(struct mq_attr, mq_maxmsg),
	FIELD(struct mq_attr, mq_msgsize),
	FIELD(struct mq_attr, mq_curmsgs),
};

/* ------------------------------------------------------------------ */
/* struct msqid_ds (msgctl IPC_SET path)                                */
/* ------------------------------------------------------------------ */

static const struct struct_field msqid_ds_fields[] = {
	FIELD(struct msqid_ds, msg_perm.mode),
	FIELD(struct msqid_ds, msg_qbytes),
};

/* ------------------------------------------------------------------ */
/* struct sched_param (sched_setparam, sched_setscheduler)              */
/* ------------------------------------------------------------------ */

static const struct struct_field sched_param_fields[] = {
	FIELD(struct sched_param, sched_priority),
};

/* ------------------------------------------------------------------ */
/* union bpf_attr (bpf)                                                */
/* ------------------------------------------------------------------ */

#ifdef USE_BPF
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
	BPF_MAP_TYPE_INSN_ARRAY,
};
const unsigned int bpf_map_types_count = ARRAY_SIZE(bpf_map_types);

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
 * excl_prog_hash_size) are intentionally not annotated this round;
 * adding offsetof references against a union member the header
 * doesn't declare would break the build on older distros, and the
 * kernel still accepts a zero-fill in those bytes.
 */
static const struct struct_field bpf_attr_MAP_CREATE_fields[] = {
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
 * Tagged-union variant table.  rec->a1 carries the bpf cmd at sanitise
 * and post time; the discriminator scan picks the matching variant.
 * Only MAP_CREATE is annotated in this round; the other ~21 variants
 * land in follow-up commits and remain catalog-empty until then.
 */
static const struct union_variant bpf_attr_variants[] = {
	{
		.discrim_value	= BPF_MAP_CREATE,
		.name		= "MAP_CREATE",
		.fields		= bpf_attr_MAP_CREATE_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_MAP_CREATE_fields),
	},
};
#endif

/* ------------------------------------------------------------------ */
/* The catalog itself                                                   */
/* ------------------------------------------------------------------ */

const struct struct_desc struct_catalog[] = {
	{
		.name		= "timex",
		.struct_size	= sizeof(struct timex),
		.fields		= timex_fields,
		.num_fields	= ARRAY_SIZE(timex_fields),
	},
	{
		.name		= "sched_attr",
		.struct_size	= sizeof(struct sched_attr),
		.fields		= sched_attr_fields,
		.num_fields	= ARRAY_SIZE(sched_attr_fields),
	},
	{
		.name		= "clone_args",
		.struct_size	= sizeof(struct clone_args),
		.fields		= clone_args_fields,
		.num_fields	= ARRAY_SIZE(clone_args_fields),
	},
	{
		.name		= "io_uring_params",
		.struct_size	= sizeof(struct io_uring_params),
		.fields		= io_uring_params_fields,
		.num_fields	= ARRAY_SIZE(io_uring_params_fields),
	},
	{
		.name		= "rlimit",
		.struct_size	= sizeof(struct rlimit),
		.fields		= rlimit_fields,
		.num_fields	= ARRAY_SIZE(rlimit_fields),
	},
	{
		.name		= "itimerspec",
		.struct_size	= sizeof(struct itimerspec),
		.fields		= itimerspec_fields,
		.num_fields	= ARRAY_SIZE(itimerspec_fields),
	},
	{
		.name		= "epoll_event",
		.struct_size	= sizeof(struct epoll_event),
		.fields		= epoll_event_fields,
		.num_fields	= ARRAY_SIZE(epoll_event_fields),
	},
	{
		.name		= "perf_event_attr",
		.struct_size	= sizeof(struct perf_event_attr),
		.fields		= perf_event_attr_fields,
		.num_fields	= ARRAY_SIZE(perf_event_attr_fields),
	},
	{
		.name		= "sigaction",
		.struct_size	= sizeof(struct sigaction),
		.fields		= sigaction_fields,
		.num_fields	= ARRAY_SIZE(sigaction_fields),
	},
	{
		.name		= "msghdr",
		.struct_size	= sizeof(struct msghdr),
		.fields		= msghdr_fields,
		.num_fields	= ARRAY_SIZE(msghdr_fields),
	},
	{
		.name		= "sockaddr_storage",
		.struct_size	= sizeof(struct sockaddr_storage),
		.fields		= sockaddr_storage_fields,
		.num_fields	= ARRAY_SIZE(sockaddr_storage_fields),
	},
	{
		.name		= "landlock_ruleset_attr",
		.struct_size	= sizeof(struct landlock_ruleset_attr),
		.fields		= landlock_ruleset_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_ruleset_attr_fields),
	},
	{
		.name		= "mnt_id_req",
		.struct_size	= sizeof(struct mnt_id_req),
		.fields		= mnt_id_req_fields,
		.num_fields	= ARRAY_SIZE(mnt_id_req_fields),
	},
	{
		.name		= "user_cap_header",
		.struct_size	= sizeof(struct __user_cap_header_struct),
		.fields		= user_cap_header_fields,
		.num_fields	= ARRAY_SIZE(user_cap_header_fields),
	},
	{
		.name		= "user_cap_data",
		.struct_size	= sizeof(struct __user_cap_data_struct),
		.fields		= user_cap_data_fields,
		.num_fields	= ARRAY_SIZE(user_cap_data_fields),
	},
	{
		.name		= "futex_waitv",
		.struct_size	= sizeof(struct futex_waitv),
		.fields		= futex_waitv_fields,
		.num_fields	= ARRAY_SIZE(futex_waitv_fields),
	},
	{
		.name		= "stack_t",
		.struct_size	= sizeof(stack_t),
		.fields		= stack_t_fields,
		.num_fields	= ARRAY_SIZE(stack_t_fields),
	},
	{
		.name		= "mq_attr",
		.struct_size	= sizeof(struct mq_attr),
		.fields		= mq_attr_fields,
		.num_fields	= ARRAY_SIZE(mq_attr_fields),
	},
	{
		.name		= "msqid_ds",
		.struct_size	= sizeof(struct msqid_ds),
		.fields		= msqid_ds_fields,
		.num_fields	= ARRAY_SIZE(msqid_ds_fields),
	},
	{
		.name		= "sched_param",
		.struct_size	= sizeof(struct sched_param),
		.fields		= sched_param_fields,
		.num_fields	= ARRAY_SIZE(sched_param_fields),
	},
#ifdef USE_BPF
	{
		.name			= "bpf_attr",
		.struct_size		= sizeof(union bpf_attr),
		/*
		 * Shared prefix is empty: every bpf cmd lives in its own
		 * anonymous union arm with no truly-common fields.  The
		 * tagged-union path takes over via discrim_arg_idx == 1
		 * (bpf cmd lives in rec->a1).
		 */
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 1,
		.variants		= bpf_attr_variants,
		.num_variants		= ARRAY_SIZE(bpf_attr_variants),
	},
#endif
	/*
	 * iovec: registered for name lookup only -- referenced by
	 * msghdr.msg_iov's FT_PTR_ARRAY.elem_struct so the pointer pass
	 * can resolve sizeof(struct iovec) for allocation.  No syscall_
	 * struct_args entry: iovec is not passed directly as an
	 * ARG_STRUCT_PTR slot.  Placed at the tail of the catalog so the
	 * existing struct_catalog[N] indices above stay stable.
	 */
	{
		.name		= "iovec",
		.struct_size	= sizeof(struct iovec),
		.fields		= iovec_fields,
		.num_fields	= ARRAY_SIZE(iovec_fields),
	},
};

const unsigned int struct_catalog_count = ARRAY_SIZE(struct_catalog);

/* ------------------------------------------------------------------ */
/* Syscall -> struct arg mapping                                        */
/* ------------------------------------------------------------------ */

/*
 * Maps (syscall name, 1-based arg index) to the struct type passed at
 * that argument.  Only covers args that are struct pointers filled by
 * a custom sanitise callback.  Terminated by .syscall_name == NULL.
 */
const struct syscall_struct_arg syscall_struct_args[] = {
	/* adjtimex(struct timex *) */
	{ "adjtimex",		1, &struct_catalog[0] },
	/* clock_adjtime(clockid_t, struct timex *) */
	{ "clock_adjtime",	2, &struct_catalog[0] },
	/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
	{ "sched_setattr",	2, &struct_catalog[1] },
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[1] },
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[2] },
	/* io_uring_setup(u32, struct io_uring_params *) */
	{ "io_uring_setup",	2, &struct_catalog[3] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[4] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[4] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[4] },
	{ "prlimit64",		4, &struct_catalog[4] },
	/* timer_settime(timer_t, int, struct itimerspec *, struct itimerspec *) */
	{ "timer_settime",	3, &struct_catalog[5] },
	/* timerfd_settime(int, int, struct itimerspec *, struct itimerspec *) */
	{ "timerfd_settime",	3, &struct_catalog[5] },
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[6] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[7] },
	/* rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t) */
	{ "rt_sigaction",	2, &struct_catalog[8] },
	{ "rt_sigaction",	3, &struct_catalog[8] },
	/* sigaction(int, const struct old_sigaction *, struct old_sigaction *) */
	{ "sigaction",		2, &struct_catalog[8] },
	{ "sigaction",		3, &struct_catalog[8] },
	/* sendmsg(int, const struct msghdr *, int) */
	{ "sendmsg",		2, &struct_catalog[9] },
	/* recvmsg(int, struct msghdr *, int) */
	{ "recvmsg",		2, &struct_catalog[9] },
	/* bind(int, struct sockaddr *, socklen_t) */
	{ "bind",		2, &struct_catalog[10] },
	/* connect(int, struct sockaddr *, socklen_t) */
	{ "connect",		2, &struct_catalog[10] },
	/* sendto(int, const void *, size_t, int, struct sockaddr *, socklen_t) */
	{ "sendto",		5, &struct_catalog[10] },
	/* landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t, u32) */
	{ "landlock_create_ruleset",	1, &struct_catalog[11] },
	/* statmount(const struct mnt_id_req *, struct statmount *, size_t, u32) */
	{ "statmount",		1, &struct_catalog[12] },
	/* listmount(const struct mnt_id_req *, u64 *, size_t, u32) */
	{ "listmount",		1, &struct_catalog[12] },
	/* capset(cap_user_header_t hdr, const cap_user_data_t data) */
	{ "capset",		1, &struct_catalog[13] },
	{ "capset",		2, &struct_catalog[14] },
	/* capget(cap_user_header_t hdr, cap_user_data_t data) */
	{ "capget",		1, &struct_catalog[13] },
	/* futex_waitv(struct futex_waitv *waiters, unsigned int nr, unsigned int flags, struct timespec *timo, clockid_t clockid) */
	{ "futex_waitv",	1, &struct_catalog[15] },
	/* sigaltstack(const stack_t *ss, stack_t *old_ss) */
	{ "sigaltstack",	1, &struct_catalog[16] },
	/* mq_open(const char *, int, mode_t, struct mq_attr *) */
	{ "mq_open",		4, &struct_catalog[17] },
	/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
	{ "mq_getsetattr",	2, &struct_catalog[17] },
	{ "mq_getsetattr",	3, &struct_catalog[17] },
	/* msgctl(int msqid, int cmd, struct msqid_ds *buf) — IPC_SET path */
	{ "msgctl",		3, &struct_catalog[18] },
	/* sched_setparam(pid_t, struct sched_param *) */
	{ "sched_setparam",	2, &struct_catalog[19] },
	/* sched_setscheduler(pid_t, int, struct sched_param *) */
	{ "sched_setscheduler",	3, &struct_catalog[19] },
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[20] },
#endif
	/* sentinel */
	{ NULL, 0, NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr_64[syscall_nr][arg_idx - 1] -> struct_desc* or NULL.
 * desc_by_nr_32[syscall_nr][arg_idx - 1] -> struct_desc* or NULL.
 * Populated at init time by scanning the active syscall table.
 * Split to avoid collisions when biarch builds have different syscall
 * numbers for 32-bit and 64-bit that happen to overlap.
 */
static const struct struct_desc *desc_by_nr_64[MAX_NR_SYSCALL][6];
static const struct struct_desc *desc_by_nr_32[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < struct_catalog_count; i++) {
		if (strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit)
{
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	if (do32bit)
		return desc_by_nr_32[nr][arg_idx - 1];
	return desc_by_nr_64[nr][arg_idx - 1];
}

/*
 * Return the natural byte width needed to represent val:
 *   val < 2^8  -> 1, < 2^16 -> 2, < 2^32 -> 4, else 8.
 */
static unsigned int natural_width(unsigned long val)
{
	if (val < (1UL << 8))
		return 1;
	if (val < (1UL << 16))
		return 2;
	if (val < (1UL << 32))
		return 4;
	return 8;
}

const struct union_variant *
struct_desc_resolve_variant(const struct struct_desc *desc,
			    struct syscallrecord *rec)
{
	unsigned long discrim;
	unsigned int idx;
	unsigned int i;

	if (desc == NULL || rec == NULL)
		return NULL;
	if (desc->variants == NULL || desc->num_variants == 0)
		return NULL;
	idx = desc->discrim_arg_idx;
	if (idx < 1 || idx > 6)
		return NULL;

	switch (idx) {
	case 1: discrim = rec->a1; break;
	case 2: discrim = rec->a2; break;
	case 3: discrim = rec->a3; break;
	case 4: discrim = rec->a4; break;
	case 5: discrim = rec->a5; break;
	case 6: discrim = rec->a6; break;
	default: return NULL;
	}

	for (i = 0; i < desc->num_variants; i++) {
		if (desc->variants[i].discrim_value == discrim)
			return &desc->variants[i];
	}
	return NULL;
}

int struct_field_for_cmp(const struct struct_desc *desc,
			 struct syscallrecord *rec, unsigned long val)
{
	const struct union_variant *variant;
	const struct struct_field *fields;
	unsigned int num_fields;
	unsigned int want = natural_width(val);
	unsigned int i;
	unsigned int exact_seen = 0, fit_seen = 0;
	int exact_pick = -1, fit_pick = -1;

	/*
	 * Variant-scoped candidate pool when the discriminator resolves.
	 * No-match on a tagged-union desc falls through to the shared
	 * desc->fields[] (today an empty prefix for bpf_attr; future
	 * structs with common-prefix fields land there too).
	 */
	variant = struct_desc_resolve_variant(desc, rec);
	if (variant != NULL) {
		fields = variant->fields;
		num_fields = variant->num_fields;
	} else {
		fields = desc->fields;
		num_fields = desc->num_fields;
	}

	/*
	 * Single-pass reservoir sample with two reservoirs:
	 *   exact_pick — uniform random among fields where size == want
	 *   fit_pick   — uniform random among fields where size >= want
	 * Exact match preferred; fit fallback only used when no exact exists.
	 * One scan instead of up to four.
	 */
	for (i = 0; i < num_fields; i++) {
		unsigned int fsize = fields[i].size;

		if (fsize == want) {
			exact_seen++;
			if (rnd_modulo_u32(exact_seen) == 0)
				exact_pick = (int)i;
		}
		if (fsize >= want) {
			fit_seen++;
			if (rnd_modulo_u32(fit_seen) == 0)
				fit_pick = (int)i;
		}
	}

	if (exact_pick >= 0)
		return exact_pick;
	if (fit_pick >= 0)
		return fit_pick;
	return -1;
}

const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx)
{
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx == arg_idx &&
		    strcmp(sa->syscall_name, name) == 0)
			return sa->desc;
	}
	return NULL;
}

/*
 * Bounded recursion depth for the FT_ADDRESS reachability check.  Real
 * cataloged structs are flat or one level deep (msghdr -> iovec); the
 * cap is a safety net against future cyclic catalog entries.
 */
#define STRUCT_ADDRESS_SCAN_MAX_DEPTH	4

static bool struct_desc_has_address_field_depth(const struct struct_desc *desc,
						unsigned int depth)
{
	unsigned int i;

	if (desc == NULL || depth >= STRUCT_ADDRESS_SCAN_MAX_DEPTH)
		return false;

	for (i = 0; i < desc->num_fields; i++) {
		const struct struct_field *f = &desc->fields[i];
		const struct struct_desc *target;

		switch (f->tag) {
		case FT_ADDRESS:
			return true;
		case FT_PTR_STRUCT:
			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (struct_desc_has_address_field_depth(target, depth + 1))
				return true;
			break;
		case FT_PTR_ARRAY:
			target = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (struct_desc_has_address_field_depth(target, depth + 1))
				return true;
			break;
		default:
			break;
		}
	}
	return false;
}

bool struct_desc_has_address_field(const struct struct_desc *desc)
{
	return struct_desc_has_address_field_depth(desc, 0);
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	memset(desc_by_nr_64, 0, sizeof(desc_by_nr_64));
	memset(desc_by_nr_32, 0, sizeof(desc_by_nr_32));

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				desc_by_nr_64[nr][sa->arg_idx - 1] = sa->desc;

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				desc_by_nr_32[nr][sa->arg_idx - 1] = sa->desc;
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL) {
				desc_by_nr_64[nr][sa->arg_idx - 1] = sa->desc;
				desc_by_nr_32[nr][sa->arg_idx - 1] = sa->desc;
			}
		}
	}

	for (i = 0; i < struct_catalog_count; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
