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
#include <fcntl.h>
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

/*
 * ADJ_* mode-bit vocabulary for timex.modes.  Anything outside the
 * mask causes the kernel to reject the call before any clock state is
 * read, so an FT_RAW splat almost never reaches the do_adjtimex()
 * dispatch.  Mask values are stable in linux/timex.h; new ADJ_* bits
 * are rare and caught by reviewer reading the uapi diff.
 */
#define TIMEX_MODES_MASK \
	(ADJ_OFFSET | ADJ_FREQUENCY | ADJ_MAXERROR | ADJ_ESTERROR | \
	 ADJ_STATUS | ADJ_TIMECONST | ADJ_TAI    | ADJ_SETOFFSET | \
	 ADJ_MICRO  | ADJ_NANO      | ADJ_TICK)

static const struct struct_field timex_fields[] = {
	FIELDX(struct timex, modes, FT_FLAGS,
	       .u.flags.mask = TIMEX_MODES_MASK,
	       .mutate_weight = 80),
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
static const struct struct_field io_uring_params_fields[] = {
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

/*
 * EPOLL* event-bit vocabulary for epoll_event.events.  EPOLLEXCLUSIVE
 * and EPOLLWAKEUP postdate older glibc vintages; compat.h declares
 * EPOLLWAKEUP unconditionally and the local #ifdef arm covers
 * EPOLLEXCLUSIVE.  Bits outside the mask either fail the kernel's
 * EP_PRIVATE_BITS check or get silently masked, so a uniform-byte
 * splat almost never produces a useful (op, events) combination.
 */
#ifndef EPOLLEXCLUSIVE
# define EPOLLEXCLUSIVE_COMPAT	(1u << 28)
#else
# define EPOLLEXCLUSIVE_COMPAT	EPOLLEXCLUSIVE
#endif

#define EPOLL_EVENTS_MASK \
	(EPOLLIN     | EPOLLOUT    | EPOLLRDHUP   | EPOLLPRI    | \
	 EPOLLERR    | EPOLLHUP    | EPOLLET      | EPOLLONESHOT | \
	 EPOLLWAKEUP | EPOLLEXCLUSIVE_COMPAT       | \
	 EPOLLRDNORM | EPOLLRDBAND | EPOLLWRNORM  | EPOLLWRBAND | \
	 EPOLLMSG)

static const struct struct_field epoll_event_fields[] = {
	FIELDX(struct epoll_event, events, FT_FLAGS,
	       .u.flags.mask = EPOLL_EVENTS_MASK,
	       .mutate_weight = 80),
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

/*
 * SA_* flag vocabulary for sigaction.sa_flags.  SA_RESTORER is
 * declared by linux/signal.h / asm/signal.h but is intentionally
 * not exposed by glibc's <signal.h>; the local #ifdef arm picks up
 * the architectural value when present and contributes zero
 * otherwise.  Bits outside the kernel-supported mask are silently
 * cleared by the rt_sigaction path, so a uniform-byte splat wastes
 * the field on bits the kernel ignores.
 */
#ifdef SA_RESTORER
# define SIGACTION_FLAGS_RESTORER	SA_RESTORER
#else
# define SIGACTION_FLAGS_RESTORER	0UL
#endif

#define SIGACTION_FLAGS_MASK \
	(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_NODEFER | SA_ONSTACK | \
	 SA_RESETHAND | SA_RESTART   | SA_SIGINFO | \
	 SIGACTION_FLAGS_RESTORER)

static const struct struct_field sigaction_fields[] = {
	FIELDX(struct sigaction, sa_flags, FT_FLAGS,
	       .u.flags.mask = SIGACTION_FLAGS_MASK,
	       .mutate_weight = 80),
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

/*
 * mq_attr.mq_flags is the only settable bit in the struct on the
 * mq_setattr path and the kernel masks everything but O_NONBLOCK
 * away.  Constraining the random fill to that single bit lets
 * mq_getsetattr's IPC_SET path go through validation instead of
 * bouncing on -EINVAL.
 */
static const struct struct_field mq_attr_fields[] = {
	FIELDX(struct mq_attr, mq_flags, FT_FLAGS,
	       .u.flags.mask = O_NONBLOCK),
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
/* io_uring_register per-opcode variants                                */
/* ------------------------------------------------------------------ */

/*
 * IORING_REGISTER_EVENTFD (opcode 4): arg points at a bare int fd; no
 * enclosing struct.  The variant fields[] still describes the one
 * scalar so CMP attribution and any future schema fill see "fd at
 * offset 0".  sanitise_io_uring_register seeds it from OBJ_FD_EVENTFD
 * regardless.
 */
static const struct struct_field io_uring_register_eventfd_fields[] = {
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
static const struct struct_field io_uring_register_files_update_fields[] = {
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
static const struct struct_field io_uring_register_file_alloc_range_fields[] = {
	FIELDX(struct io_uring_file_index_range, off, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 },
	       .mutate_weight = 80),
	FIELDX(struct io_uring_file_index_range, len, FT_RANGE,
	       .u.range = { .lo = 1, .hi = 16 },
	       .mutate_weight = 80),
	FIELD(struct io_uring_file_index_range, resv),
};

/*
 * Per-opcode variant table.  rec->a2 carries the opcode at sanitise
 * and post time; struct_desc_resolve_variant() picks the matching
 * variant.  Opcodes without an entry fall through to the empty shared
 * prefix (no schema fill, no CMP attribution scope).  Variants land
 * incrementally; see follow-up commits.
 */
static const struct union_variant io_uring_register_variants[] = {
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
 *   - insns + insn_cnt as FT_PTR_ARRAY/FT_LEN_COUNT, with bpf_insn
 *     registered below as the element struct (8 bytes each); cap at
 *     64 instructions so we keep the verifier reachable without
 *     dropping into the very-long-program timeouts.
 *   - log_buf + log_size as FT_PTR_BYTES/FT_LEN_BYTES with the
 *     buffer optional (~80% present per the schema default) so the
 *     NULL-log path also gets reached.
 *
 * license / func_info_* / line_info_* / core_relos / fd_array and
 * the signature/keyring fields stay FT_RAW: sanitise_bpf owns the
 * verifier-passing program assembly today, and a schema-driven
 * random splat in those slots would only feed back to it as noise.
 *
 * The attach_prog_fd / attach_btf_obj_fd anonymous union picks
 * attach_prog_fd as the canonical slot (more common arm); the
 * kernel reads the same bytes either way.
 *
 * Older uapi vintages may lack signature / signature_size /
 * keyring_id; those references are skipped this round rather than
 * gated on #ifdef offsetof which the preprocessor doesn't support.
 */
static const struct struct_field bpf_attr_PROG_LOAD_fields[] = {
	FIELDX(union bpf_attr, prog_type, FT_ENUM,
	       .u.enum_ = { bpf_prog_types, ARRAY_SIZE(bpf_prog_types) },
	       .mutate_weight = 200),
	FIELDX(union bpf_attr, insn_cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_field = "insns" },
	       .mutate_weight = 40),
	FIELDX(union bpf_attr, insns, FT_PTR_ARRAY,
	       .u.ptr_array = { .len_field = "insn_cnt",
				.elem_struct = "bpf_insn",
				.max_count = 64 },
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
 * PROG_ATTACH attach_flags mask.  All eight names are stable in
 * mainline; the four newer-arrival names (REPLACE/BEFORE/AFTER/
 * ID/PREORDER/LINK) all postdate the trinity baseline header
 * vintage but are present in /usr/include/linux/bpf.h.
 */
#define PROG_ATTACH_FLAGS_MASK ( \
	BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI | BPF_F_REPLACE | \
	BPF_F_BEFORE | BPF_F_AFTER | BPF_F_ID | BPF_F_PREORDER | \
	BPF_F_LINK)

/*
 * PROG_ATTACH variant.  The target_fd/target_ifindex and
 * relative_fd/relative_id anonymous unions each get one FT_FD
 * annotation at the shared offset -- picking the broader-semantic
 * arm; the kernel reads the same bytes either way.  expected_revision
 * stays FT_RAW: it's a u64 opaque revision counter that doesn't gate
 * any first-pass validation.
 */
static const struct struct_field bpf_attr_PROG_ATTACH_fields[] = {
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
static const struct struct_field bpf_attr_OBJ_fields[] = {
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
static const struct struct_field bpf_attr_MAP_ELEM_fields[] = {
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
 * fd_by_id_token_fd is an FT_FD slot honoured on the BY_ID arms.
 */
static const struct struct_field bpf_attr_GET_ID_fields[] = {
	FIELD(union bpf_attr, start_id),
	FIELD(union bpf_attr, next_id),
	FIELDX(union bpf_attr, open_flags, FT_FLAGS,
	       .u.flags.mask = (BPF_F_RDONLY | BPF_F_WRONLY)),
	FIELDX(union bpf_attr, fd_by_id_token_fd, FT_FD),
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
 * Skipped this round.
 */
static const struct struct_field bpf_attr_LINK_UPDATE_fields[] = {
	FIELDX(union bpf_attr, link_update.link_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.new_prog_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_REPLACE),
	FIELDX(union bpf_attr, link_update.old_prog_fd, FT_FD),
};

static const struct struct_field bpf_attr_LINK_DETACH_fields[] = {
	FIELDX(union bpf_attr, link_detach.link_fd, FT_FD),
};

static const struct struct_field bpf_attr_ENABLE_STATS_fields[] = {
	/*
	 * enum bpf_stats_type is a tiny set today (RUN_TIME_NS only);
	 * a dedicated enum vocab is overkill -- FT_RANGE keeps the
	 * value bounded near the legal range without committing to
	 * a vocab that turns stale on every uapi bump.
	 */
	FIELDX(union bpf_attr, enable_stats.type, FT_RANGE,
	       .u.range = { 0, 8 }),
};

static const struct struct_field bpf_attr_ITER_CREATE_fields[] = {
	FIELDX(union bpf_attr, iter_create.link_fd, FT_FD),
	FIELD(union bpf_attr, iter_create.flags),
};

static const struct struct_field bpf_attr_PROG_BIND_MAP_fields[] = {
	FIELDX(union bpf_attr, prog_bind_map.prog_fd, FT_FD),
	FIELDX(union bpf_attr, prog_bind_map.map_fd, FT_FD),
	FIELD(union bpf_attr, prog_bind_map.flags),
};

static const struct struct_field bpf_attr_TOKEN_CREATE_fields[] = {
	FIELD(union bpf_attr, token_create.flags),
	FIELDX(union bpf_attr, token_create.bpffs_fd, FT_FD),
};

static const struct struct_field bpf_attr_PROG_STREAM_READ_fields[] = {
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

/*
 * bpf_insn registration -- required so PROG_LOAD's insns
 * FT_PTR_ARRAY can resolve sizeof(struct bpf_insn) (8 bytes) when
 * the pointer pass allocates the sub-buffer.  No field annotations:
 * the kernel verifier rejects the random byte pattern regardless,
 * but the (ptr, cnt) shape sanitise_bpf produces still gets a
 * well-formed schema fallback when the sanitise path is skipped.
 */
static const struct struct_field bpf_insn_fields[] = {
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
static const struct union_variant bpf_attr_variants[] = {
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
		.effective_size	= 16,
	},
	{
		.discrim_value	= BPF_PROG_DETACH,
		.name		= "PROG_DETACH",
		.fields		= bpf_attr_PROG_ATTACH_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_ATTACH_fields),
		.effective_size	= 16,
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
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_MAP_GET_NEXT_ID,
		.name		= "MAP_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_PROG_GET_FD_BY_ID,
		.name		= "PROG_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_MAP_GET_FD_BY_ID,
		.name		= "MAP_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_BTF_GET_FD_BY_ID,
		.name		= "BTF_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_BTF_GET_NEXT_ID,
		.name		= "BTF_GET_NEXT_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
	},
	{
		.discrim_value	= BPF_LINK_GET_FD_BY_ID,
		.name		= "LINK_GET_FD_BY_ID",
		.fields		= bpf_attr_GET_ID_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_GET_ID_fields),
		.effective_size	= 8,
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
	{
		.discrim_value	= BPF_PROG_STREAM_READ_BY_FD,
		.name		= "PROG_STREAM_READ_BY_FD",
		.fields		= bpf_attr_PROG_STREAM_READ_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_STREAM_READ_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->prog_stream_read),
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
	/*
	 * io_uring_register tagged-union infra entry.  Each opcode (in
	 * rec->a2) presents a different per-cmd struct shape at *rec->a3;
	 * the variant table dispatches by opcode.  Shared prefix is empty:
	 * register opcodes are fully self-contained per-cmd structs with
	 * no truly-common fields.  Variants populated incrementally; see
	 * follow-up commits.
	 *
	 * struct_size is set to the largest projected variant
	 * (io_uring_sync_cancel_reg @ 64 bytes) so the buffer fed to the
	 * fill path is never too small for any single-struct opcode.
	 *
	 * Placed BEFORE the USE_BPF block so its struct_catalog[] index is
	 * stable across USE_BPF / non-USE_BPF builds for the
	 * syscall_struct_args[] mapping below; the bpf_attr / bpf_insn /
	 * iovec entries that follow shift by one slot accordingly.
	 *
	 * No live consumer wires this entry today: io_uring_register's
	 * arg slot is ARG_ADDRESS (not ARG_STRUCT_PTR_*) and the existing
	 * sanitise_io_uring_register hand-rolls every opcode's payload.
	 * The entry is forward infra for opcode-scoped CMP attribution
	 * (struct_field_for_cmp pending a cmp_hints caller) and a future
	 * ARG_ADDRESS-mapped fill consumer.  The bpf catalog landed the
	 * same way: variant data first, sanitise caller after.
	 */
	{
		.name			= "io_uring_register_args",
		.struct_size		= 64,
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 2,	/* opcode in rec->a2 */
		.variants		= io_uring_register_variants,
		.num_variants		= ARRAY_SIZE(io_uring_register_variants),
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
	/*
	 * bpf_insn registered for name lookup only -- referenced from
	 * PROG_LOAD's insns FT_PTR_ARRAY.elem_struct so the pointer
	 * pass can size its sub-buffer.  No syscall_struct_args entry.
	 * Sits after bpf_attr to keep the existing struct_catalog[]
	 * indices stable for the syscall_struct_args[] table.
	 */
	{
		.name		= "bpf_insn",
		.struct_size	= sizeof(struct bpf_insn),
		.fields		= bpf_insn_fields,
		.num_fields	= ARRAY_SIZE(bpf_insn_fields),
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
	/* io_uring_register(int fd, unsigned op, void *arg, unsigned nr_args) */
	{ "io_uring_register",	3, &struct_catalog[20] },
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[21] },
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

/*
 * True for the tag set that carries kernel-ABI vocabulary the CMP
 * attribution prefers when it has a same-width match: FT_ENUM /
 * FT_FLAGS / FT_VERSION_MAGIC are the gates the kernel actively
 * compares against the constants KCOV-CMP traps, so attributing a
 * learned constant to one of those slots produces a steerable
 * mutation hint instead of landing on a coincidentally-same-width
 * FT_RAW opaque-id field where future mutations would be wasted.
 */
static bool field_tag_is_gate(enum field_tag tag)
{
	switch (tag) {
	case FT_ENUM:
	case FT_FLAGS:
	case FT_VERSION_MAGIC:
		return true;
	default:
		return false;
	}
}

int struct_field_for_cmp(const struct struct_desc *desc,
			 struct syscallrecord *rec, unsigned long val)
{
	const struct union_variant *variant;
	const struct struct_field *fields;
	unsigned int num_fields;
	unsigned int want = natural_width(val);
	unsigned int i;
	unsigned int gate_seen = 0, exact_seen = 0, fit_seen = 0;
	int gate_pick = -1, exact_pick = -1, fit_pick = -1;

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
	 * Single-pass reservoir sample with three reservoirs:
	 *   gate_pick  — uniform random among same-width gate-tagged
	 *                fields (FT_ENUM / FT_FLAGS / FT_VERSION_MAGIC).
	 *                Preferred over the size-only matches when any
	 *                gate field is a candidate, on the principle
	 *                that the kernel CMP'd a constant against a
	 *                gate field's vocab more often than against a
	 *                same-width opaque field.
	 *   exact_pick — uniform random among same-width fields of any
	 *                tag (the pre-tag fallback).
	 *   fit_pick   — uniform random among fields whose size >= want
	 *                (covers narrow CMP values landing in wider
	 *                slots).
	 */
	for (i = 0; i < num_fields; i++) {
		unsigned int fsize = fields[i].size;
		enum field_tag tag = fields[i].tag;

		if (fsize == want) {
			exact_seen++;
			if (rnd_modulo_u32(exact_seen) == 0)
				exact_pick = (int)i;
			if (field_tag_is_gate(tag)) {
				gate_seen++;
				if (rnd_modulo_u32(gate_seen) == 0)
					gate_pick = (int)i;
			}
		}
		if (fsize >= want) {
			fit_seen++;
			if (rnd_modulo_u32(fit_seen) == 0)
				fit_pick = (int)i;
		}
	}

	if (gate_pick >= 0)
		return gate_pick;
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
