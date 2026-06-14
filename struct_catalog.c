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
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sched.h>
#include <time.h>
#include <utime.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
#include <linux/capability.h>
#include <linux/netfilter.h>
#include <linux/futex.h>
#include <linux/rseq.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>
#include <linux/landlock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <mqueue.h>

#include "compat.h"
#include "config.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_AX25
#include <linux/ax25.h>
#endif
#ifdef USE_ATALK
#include <linux/atalk.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
#endif
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif

#include "argtype-ops.h"
#include "struct_catalog.h"
#include "arch.h"
#ifdef X86
#include <asm/ldt.h>		/* struct user_desc -- modify_ldt arg2 */
#endif
#include "debug.h"
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
/* struct timespec (clock_nanosleep, nanosleep, utimensat)             */
/* ------------------------------------------------------------------ */

/*
 * tv_nsec is rejected by the kernel for values outside [0, 1e9) before
 * the syscall does any real work, so an FT_RAW splat almost never lands
 * on the wait/update path.  Keep tv_sec as an unbounded FT_RANGE so
 * absolute / past / future buckets stay reachable; pin tv_nsec to the
 * legal nanosecond range so the request actually clears the kernel's
 * input check.  Callers that want UTIME_NOW / UTIME_OMIT (utimensat)
 * still construct those values in their own sanitise callback.
 */
static const struct struct_field timespec_fields[] = {
	FIELDX(struct timespec, tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct timespec, tv_nsec, FT_RANGE,
	       .u.range = { 0, 999999999UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct cachestat_range (cachestat)                                  */
/* ------------------------------------------------------------------ */

/*
 * cachestat's input range struct: a (off, len) byte pair the kernel
 * walks across the file's address_space.  cachestat already carries a
 * strong bespoke sanitiser (pick_range() in syscalls/cachestat.c) that
 * picks a file-size-aware off/len -- the registration here is
 * attribution-only: cachestat's argtype slot is not ARG_STRUCT_PTR_*,
 * so the schema-aware fill path never fires and pick_range() continues
 * to own the live values.  FT_RANGE annotations exist so KCOV CMP
 * constants can be attributed to off or len rather than landing on a
 * coincidentally-same-width slot.  Bounds mirror the timespec
 * precedent's u32-fitting ceiling so the catalog stays portable on
 * 32-bit unsigned long builds.
 */
static const struct struct_field cachestat_range_fields[] = {
	FIELDX(struct cachestat_range, off, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct cachestat_range, len, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct mount_attr (mount_setattr, open_tree_attr)                   */
/* ------------------------------------------------------------------ */

/*
 * MOUNT_ATTR_* bit vocabulary.  ifndef-guarded to match the pattern in
 * syscalls/mount.c and syscalls/fsmount.c -- older toolchain headers
 * may pre-date the IDMAP / NOSYMFOLLOW additions.  struct mount_attr
 * itself is presumed available via <linux/mount.h>; if the host header
 * is too old to carry the struct the build already fails in
 * open_tree_attr.c, not here.
 */
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#define MOUNT_ATTR_NOSUID	0x00000002
#define MOUNT_ATTR_NODEV	0x00000004
#define MOUNT_ATTR_NOEXEC	0x00000008
#define MOUNT_ATTR_NOATIME	0x00000010
#define MOUNT_ATTR_STRICTATIME	0x00000020
#define MOUNT_ATTR_NODIRATIME	0x00000080
#define MOUNT_ATTR_IDMAP	0x00100000
#define MOUNT_ATTR_NOSYMFOLLOW	0x00200000
#endif

#define MOUNT_ATTR_ALL_MASK \
	(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | \
	 MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME | \
	 MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSYMFOLLOW)

/*
 * propagation is effectively a 4-valued enum: do_change_type() EINVALs
 * the moment two propagation bits appear together, so FT_FLAGS would
 * be wrong here -- the mutator would happily OR a second bit in and
 * trip the validator.  FT_ENUM over the four MS_* propagation
 * constants keeps the mutator inside the legal one-bit shape.
 */
static const unsigned long mount_attr_propagation_values[] = {
	MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE,
};

/*
 * mount_setattr / open_tree_attr already carry strong bespoke
 * sanitisers (build_mount_attr() in syscalls/open_tree_attr.c, mirrored
 * by sanitise_mount_setattr) that pick coherent attr_set / attr_clr /
 * propagation / userns_fd buckets and respect the kernel's mutually-
 * exclusive ATIME-mode and propagation rules.  Those sanitisers
 * overwrite rec->a4 wholesale after gen_arg_struct_ptr_in's schema-
 * aware fill, so the registration here is attribution-only --
 * struct_field_for_cmp() uses the FT_FLAGS / FT_ENUM / FT_FD tags to
 * steer KCOV-CMP learned constants at the right field rather than at a
 * coincidentally-same-width slot.  The bespoke fill stays live; this
 * entry never displaces it.  Same shape as cachestat_range above and
 * the io_uring_register_args entry below.
 */
static const struct struct_field mount_attr_fields[] = {
	FIELDX(struct mount_attr, attr_set, FT_FLAGS,
	       .u.flags.mask = MOUNT_ATTR_ALL_MASK,
	       .mutate_weight = 100),
	FIELDX(struct mount_attr, attr_clr, FT_FLAGS,
	       .u.flags.mask = MOUNT_ATTR_ALL_MASK,
	       .mutate_weight = 80),
	FIELDX(struct mount_attr, propagation, FT_ENUM,
	       .u.enum_ = { mount_attr_propagation_values,
			    ARRAY_SIZE(mount_attr_propagation_values) },
	       .mutate_weight = 80),
	FIELDX(struct mount_attr, userns_fd, FT_FD,
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct sembuf (semop, semtimedop)                                   */
/* ------------------------------------------------------------------ */

/*
 * sem{,timed}op pass an ARRAY of sembuf at a2 (nsops in a3), not a
 * single struct, and the arg slot is ARG_ADDRESS rather than
 * ARG_STRUCT_PTR_*.  The bespoke fill_sembuf_array() helpers in
 * syscalls/semop.c and syscalls/semtimedop.c allocate the buffer,
 * pick a per-element (sem_num, sem_op, sem_flg) triple respecting
 * the kernel's nsems / IPC_NOWAIT / SEM_UNDO semantics, and overwrite
 * rec->a2 -- the schema-aware fill path never runs for this slot.
 *
 * Registration is attribution-only, mirroring cachestat_range /
 * mount_attr above: struct_field_for_cmp() uses the FT_RANGE /
 * FT_FLAGS tags to steer KCOV-CMP learned constants at sem_num or
 * sem_flg rather than at a coincidentally-same-width slot.  sem_op
 * stays FT_RAW: its kernel semantics are arithmetic
 * (sma->sem_base[].semval + sem_op) rather than a vocab CMP, so no
 * gate-tag lift would help attribution.  sem_num's range upper bound
 * mirrors syscalls/semop.c's pick_sem_num() worst-case
 * (SEMOP_FALLBACK_NSEMS + 63 = 95) so future schema consumers stay
 * inside the same in-range / out-of-range envelope the bespoke
 * sanitiser already explores.
 */
static const struct struct_field sembuf_fields[] = {
	FIELDX(struct sembuf, sem_num, FT_RANGE,
	       .u.range = { 0, 95 },
	       .mutate_weight = 60),
	FIELD(struct sembuf, sem_op),
	FIELDX(struct sembuf, sem_flg, FT_FLAGS,
	       .u.flags.mask = IPC_NOWAIT | SEM_UNDO,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* struct pollfd (poll, ppoll)                                         */
/* ------------------------------------------------------------------ */

/*
 * poll and ppoll pass an ARRAY of pollfd at a1 (nfds in a2), not a
 * single struct, and the arg slot is ARG_ADDRESS rather than
 * ARG_STRUCT_PTR_*.  The bespoke alloc_pollfds() helper in
 * syscalls/poll.c allocates the buffer, picks each entry's
 * (fd, events) tuple from the pollable-fd pool plus a curated event
 * vocabulary, and overwrites rec->a1 -- the schema-aware fill path
 * never runs for this slot.
 *
 * Registration is attribution-only, mirroring sembuf above:
 * struct_field_for_cmp() uses the FT_FD / FT_FLAGS tags to steer
 * KCOV-CMP learned constants at the fd or events slot rather than at
 * a coincidentally-same-width slot.  revents is the kernel-written
 * output half of this value-result buffer and stays FT_RAW: no
 * userspace-side vocab applies, and FT_FLAGS attribution against the
 * kernel-chosen revents bitmask would mislead the heuristic.
 */
#define POLLFD_EVENTS_MASK \
	(POLLIN | POLLOUT | POLLPRI | POLLERR | \
	 POLLHUP | POLLNVAL | POLLRDHUP)

static const struct struct_field pollfd_fields[] = {
	FIELDX(struct pollfd, fd, FT_FD,
	       .mutate_weight = 80),
	FIELDX(struct pollfd, events, FT_FLAGS,
	       .u.flags.mask = POLLFD_EVENTS_MASK,
	       .mutate_weight = 80),
	FIELD(struct pollfd, revents),
};

/* ------------------------------------------------------------------ */
/* struct open_how (openat2)                                           */
/* ------------------------------------------------------------------ */

/*
 * struct open_how / RESOLVE_* may not be present in every host's
 * <linux/openat2.h>; mirror the trinity-local fallback already used
 * by syscalls/open.c so this TU compiles on toolchains that pre-date
 * the openat2 uapi.  The ifndef guard hands off to the host header
 * (or to whichever earlier-included TU has already pulled the symbols
 * in) when it is present.
 */
#ifndef RESOLVE_NO_XDEV
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#define RESOLVE_NO_XDEV		0x01
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#define RESOLVE_IN_ROOT		0x10
#define RESOLVE_CACHED		0x20
#endif

/*
 * openat2 passes struct open_how at a3 with a usize at a4
 * (copy_struct_from_user semantics).  The slot is ARG_ADDRESS rather
 * than ARG_STRUCT_PTR_*, so the schema-aware fill path never runs
 * against it -- the bespoke sanitise_openat2() in syscalls/open.c
 * continues to own the live (flags, mode, resolve) layout, including
 * the O_CREAT / __O_TMPFILE-gated mode write and the curated
 * openat2_resolve_combos[] table that walks the namei RESOLVE_*
 * paths the kernel actually branches on.
 *
 * Registration is attribution-only, mirroring pollfd / sembuf above:
 * struct_field_for_cmp() uses the FT_FLAGS tags to steer KCOV-CMP
 * learned constants at the flags or resolve slot rather than at a
 * coincidentally-same-width slot.  mode stays FT_RAW: the kernel
 * only honours it (masked to S_IALLUGO) when O_CREAT / __O_TMPFILE
 * is set, otherwise a non-zero mode trips the -EINVAL gate before
 * any per-bit CMP fires -- no single-field vocab maps cleanly.
 */
#define OPEN_HOW_FLAGS_MASK						\
	(O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND |	\
	 O_NONBLOCK | O_DSYNC | O_SYNC | O_ASYNC | O_DIRECTORY |	\
	 O_NOFOLLOW | O_CLOEXEC | O_DIRECT | O_NOATIME | O_PATH |	\
	 O_LARGEFILE | O_TMPFILE)

#define OPEN_HOW_RESOLVE_MASK						\
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS |\
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

static const struct struct_field open_how_fields[] = {
	FIELDX(struct open_how, flags, FT_FLAGS,
	       .u.flags.mask = OPEN_HOW_FLAGS_MASK,
	       .mutate_weight = 100),
	FIELD(struct open_how, mode),
	FIELDX(struct open_how, resolve, FT_FLAGS,
	       .u.flags.mask = OPEN_HOW_RESOLVE_MASK,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* struct sigevent (timer_create)                                      */
/* ------------------------------------------------------------------ */

/*
 * timer_create(clockid_t, struct sigevent *, timer_t *) passes the
 * sigevent at a2 with argtype ARG_ADDRESS (not ARG_STRUCT_PTR_*), so
 * the schema-aware fill path never runs against it -- the bespoke
 * timer_create_sanitise() in syscalls/timer_create.c continues to own
 * the live (sigev_value, sigev_signo, sigev_notify, _sigev_un._tid)
 * layout, including the SIGEV_NONE / SIGEV_SIGNAL / SIGEV_THREAD_ID /
 * (SIGEV_SIGNAL | SIGEV_THREAD_ID) notify-mode distribution and the
 * gettid-derived _tid fill on the THREAD_ID arms.
 *
 * Registration is attribution-only, mirroring pollfd / sembuf /
 * open_how above: struct_field_for_cmp() uses the FT_ENUM tag to
 * steer KCOV-CMP learned constants at sigev_notify (a 4-valued
 * discrete vocab the kernel branches on in do_timer_create) and the
 * FT_RANGE tag to attribute small ints at sigev_signo rather than at
 * a coincidentally-same-width slot.  sigev_value and the _sigev_un
 * union stay FT_RAW: sigev_value is an opaque cookie the kernel
 * stores and replays without any per-bit CMP, and the union arms are
 * a tagged-by-sigev_notify payload (a thread tid, or a pair of
 * user-space pointers) with no useful CMP vocab -- no single-field
 * vocab maps cleanly across the arms, so attribution-only with no
 * invented tag is the right call.  sigev_signo upper bound is _NSIG
 * (64 on Linux); the bespoke pick_signo_avoiding_sigint() already
 * draws from rnd_modulo_u32(_NSIG) so the range envelope matches.
 */
static const unsigned long sigevent_notify_values[] = {
	SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID,
};

static const struct struct_field sigevent_fields[] = {
	FIELD(struct sigevent, sigev_value),
	FIELDX(struct sigevent, sigev_signo, FT_RANGE,
	       .u.range = { 1, 64 },
	       .mutate_weight = 60),
	FIELDX(struct sigevent, sigev_notify, FT_ENUM,
	       .u.enum_ = { sigevent_notify_values,
			    ARRAY_SIZE(sigevent_notify_values) },
	       .mutate_weight = 80),
	FIELD(struct sigevent, _sigev_un),
};

/* ------------------------------------------------------------------ */
/* struct robust_list_head (set_robust_list)                           */
/* ------------------------------------------------------------------ */

/*
 * set_robust_list(struct robust_list_head __user *head, size_t len)
 * passes the head pointer at a1 with argtype ARG_ADDRESS (not
 * ARG_STRUCT_PTR_*), so the schema-aware fill path never runs against
 * it -- the bespoke sanitise_set_robust_list() in
 * syscalls/set_robust_list.c continues to own the live (list.next,
 * futex_offset, list_op_pending) layout: it zmalloc_tracked()s a head,
 * self-points list.next, zeros futex_offset, and NULLs list_op_pending
 * before each call.
 *
 * Registration is attribution-only, mirroring pollfd / sembuf /
 * open_how / sigevent above: struct_field_for_cmp() uses the FT_RANGE
 * tag to attribute small-int CMP constants at futex_offset rather than
 * at a coincidentally-same-width slot, and FT_ADDRESS on the embedded
 * list (whose first member is a __user "next" pointer) and on
 * list_op_pending documents the kernel-dereferenced slots for any
 * downstream nested-scrub walker.  futex_offset bounds envelope the
 * page-sized window the kernel walks across the robust list node.
 *
 * get_robust_list's robust_list_head is an OUTPUT (its a2 is a double
 * pointer the kernel writes), so the syscall_struct_args[] mapping
 * below names set_robust_list a1 only.
 */
static const struct struct_field robust_list_head_fields[] = {
	FIELDX(struct robust_list_head, list, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELDX(struct robust_list_head, futex_offset, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct robust_list_head, list_op_pending, FT_ADDRESS,
	       .mutate_weight = 100),
};

/* ------------------------------------------------------------------ */
/* struct rseq (rseq)                                                  */
/* ------------------------------------------------------------------ */

/*
 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
 * passes the rseq pointer at a1.  The bespoke sanitise_rseq() in
 * syscalls/rseq.c continues to own the live fill: it allocates a
 * 32-byte-aligned struct rseq via get_writable_address(),
 * memset()s it to zero, routes a1 through avoid_shared_buffer_inout(),
 * cycles a2 through the rseq_len validation buckets (zero / undersized
 * / current ABI / oversized), and pins a4 to a fixed signature.
 *
 * Registration is attribution-only, mirroring robust_list_head /
 * pollfd / sembuf / open_how / sigevent above: struct_field_for_cmp()
 * uses the FT_RANGE tags to attribute small-int CMP constants at the
 * cpu_id / node_id / mm_cid slots rather than at a coincidentally-
 * same-width slot; FT_FLAGS on flags carries the RSEQ_CS_FLAG_*
 * vocabulary the kernel reads at critical-section abort; FT_ADDRESS
 * on rseq_cs documents the __user pointer slot the kernel
 * dereferences to reach the active struct rseq_cs.  cpu_id_start /
 * cpu_id / node_id / mm_cid are kernel-written outputs whose userspace
 * envelope still benefits from CMP attribution; the bounds mirror the
 * page-sized walk envelopes the kernel uses to validate them.  The
 * abort signature is the syscall's a4 argument, not a struct member,
 * so it has no field here.  The trailing flexible char end[] member
 * has no fixed offset/size and is not registered.
 */
static const struct struct_field rseq_fields[] = {
	FIELDX(struct rseq, cpu_id_start, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, cpu_id, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, rseq_cs, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELDX(struct rseq, flags, FT_FLAGS,
	       .u.flags.mask = RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT |
			       RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL |
			       RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE,
	       .mutate_weight = 80),
	FIELDX(struct rseq, node_id, FT_RANGE,
	       .u.range = { 0, 1024 },
	       .mutate_weight = 60),
	FIELDX(struct rseq, mm_cid, FT_RANGE,
	       .u.range = { 0, 4096 },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct itimerval (setitimer)                                        */
/* ------------------------------------------------------------------ */

/*
 * setitimer(int which, const struct itimerval __user *value,
 *           struct itimerval __user *ovalue) passes the input itimerval
 * at a2.  The bespoke sanitise_setitimer() in syscalls/setitimer.c
 * continues to own the live fill: it get_writable_address()es a struct
 * itimerval, walks both embedded timevals through fill_timeval() (zero
 * / sub-second / small-positive / random tv_sec buckets paired with a
 * legal tv_usec), half the time disarms the timer by zeroing it_value,
 * routes a2 to the writable buffer, and runs a3 through
 * avoid_shared_buffer_out().  setitimer's argtype[1] is not
 * ARG_STRUCT_PTR_*, so the schema-aware fill path never runs against
 * it -- mirrors itimerspec / robust_list_head / rseq / pollfd / sembuf
 * / open_how / sigevent above.
 *
 * Registration is attribution-only: struct_field_for_cmp() uses the
 * FT_RANGE tags to attribute small-int CMP constants at the named
 * tv_sec / tv_usec slots rather than at a coincidentally-same-width
 * slot.  Bounds mirror the timespec_fields[] precedent: tv_sec is left
 * unbounded so absolute / past / future buckets stay reachable; tv_usec
 * is pinned to the legal microsecond range so the request actually
 * clears timeval_valid() inside the kernel's setitimer entry.  Only
 * setitimer's INPUT a2 is mapped below -- a3 (ovalue) is a kernel-
 * written output, and getitimer's a2 is likewise an output, so neither
 * is mapped.
 */
static const struct struct_field itimerval_fields[] = {
	FIELDX(struct itimerval, it_interval.tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_interval.tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_value.tv_sec, FT_RANGE,
	       .u.range = { 0, 4000000000UL },
	       .mutate_weight = 60),
	FIELDX(struct itimerval, it_value.tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct utimbuf (utime)                                              */
/* ------------------------------------------------------------------ */

/*
 * utime(const char *filename, const struct utimbuf __user *times) passes
 * the utimbuf at a2.  utime has no bespoke .sanitise -- argtype[1] was
 * ARG_ADDRESS, so the times buffer was filled as an undifferentiated
 * address slot with no schema path of its own.  Flipping argtype[1] to
 * ARG_STRUCT_PTR_IN routes the slot through the schema-aware fill so it
 * lands on a dedicated sized buffer, and the catalog entry below names
 * the (actime, modtime) layout for CMP attribution.
 *
 * Both members are time_t and currently FT_RAW: the bytes match the
 * historical random splat -- the win is the dedicated sized buffer and
 * letting struct_field_for_cmp attribute KCOV CMP constants at the named
 * actime / modtime fields rather than at a coincidentally-same-width
 * slot.  No FT_TIME tag exists in the catalog vocabulary today; adding
 * one is deferred until a precedent for time_t-shaped semantic tagging
 * lands across the other timespec / timeval consumers.
 */
static const struct struct_field utimbuf_fields[] = {
	FIELD(struct utimbuf, actime),
	FIELD(struct utimbuf, modtime),
};

/* ------------------------------------------------------------------ */
/* struct timeval (settimeofday, select)                               */
/* ------------------------------------------------------------------ */

/*
 * struct timeval is the (tv_sec, tv_usec) pair the kernel takes at
 * settimeofday's a1 (INPUT wall-clock value) and at select's a5
 * (INOUT timeout).  Both syscalls already carry a bespoke .sanitise
 * that owns the live fill via get_writable_address(): settimeofday
 * biases 70% near-now / 30% random with an explicit invalid-tv_usec
 * leg, and select stamps a deterministic short {0, 10us} timeout.
 * Without a catalog entry the slots were filled but had no schema
 * path of their own, so struct_field_for_cmp() had nothing to hang
 * KCOV-CMP attribution against and learned constants fell at a
 * coincidentally-same-width slot rather than at a named field.
 *
 * Registration is attribution-only, mirroring the in-tree timespec /
 * utimensat handling and the landed utimbuf / flock / sigevent
 * commits: the bespoke sanitisers keep owning the fill -- this only
 * feeds the CMP-attribution path.  tv_sec stays FT_RAW so the
 * near-now / random / wraparound bytes the bespoke fills already
 * produce are preserved; tv_usec is pinned to the legal microsecond
 * range so attribution at the named tv_usec slot lines up with the
 * kernel's timeval_valid() check rather than landing on a
 * coincidentally-same-width neighbour.  Bound mirrors the
 * itimerval_fields[] tv_usec precedent (0..999999).
 */
static const struct struct_field timeval_fields[] = {
	FIELD(struct timeval, tv_sec),
	FIELDX(struct timeval, tv_usec, FT_RANGE,
	       .u.range = { 0, 999999UL },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct timezone (settimeofday)                                      */
/* ------------------------------------------------------------------ */

/*
 * struct timezone is the (tz_minuteswest, tz_dsttime) pair settimeofday
 * takes at a2.  The bespoke sanitise_settimeofday() owns the live fill
 * via get_writable_address(): a 50/50 zero-vs-random leg producing
 * tz_minuteswest in [-780, +780] (-13h..+13h in minutes) and tz_dsttime
 * in [0, 3].  Without a catalog entry the slot was filled but had no
 * schema path of its own, so struct_field_for_cmp() had nothing to
 * hang KCOV-CMP attribution against and learned constants fell at a
 * coincidentally-same-width slot rather than at a named field.
 *
 * Registration is attribution-only, mirroring the in-tree timespec /
 * utimensat handling and the landed timeval / utimbuf / flock commits:
 * the bespoke sanitiser keeps owning the fill -- this only feeds the
 * CMP-attribution path.  tz_minuteswest is left FT_RAW: the live fill
 * spans a signed window [-780, +780] and the FT_RANGE union carries
 * unsigned bounds (struct { unsigned long lo, hi; } range), so a
 * literal {-780, 780} would wrap to a garbage upper bound; the signed
 * bytes the bespoke fill produces are preserved verbatim.  tz_dsttime
 * is all-positive [0, 3] and pins cleanly to FT_RANGE so attribution
 * at the named slot lines up with the kernel's narrow legal window.
 */
static const struct struct_field timezone_fields[] = {
	/*
	 * FT_RANGE's bounds are unsigned long, so this signed
	 * [-780, +780] minutes-west window cannot be expressed as a
	 * range; keep FT_RAW and let the bespoke fill own the value.
	 */
	FIELD(struct timezone, tz_minuteswest),
	FIELDX(struct timezone, tz_dsttime, FT_RANGE,
	       .u.range = { 0, 3 },
	       .mutate_weight = 40),
};

/* ------------------------------------------------------------------ */
/* struct flock (fcntl)                                                */
/* ------------------------------------------------------------------ */

/*
 * fcntl's lock-pointer arg (F_GETLK / F_SETLK / F_SETLKW and the
 * F_OFD_* variants) carries a struct flock at a3.  The bespoke
 * sanitise_fcntl() keeps owning the live fill via build_flock(): it
 * picks an l_type / l_whence vocab member, a bounded l_start and
 * l_len, and zeroes l_pid (F_OFD_SETLK requires it).
 *
 * Attribution-only registration, mirroring the mq_notify / sigevent
 * pattern: struct_field_for_cmp() uses the FT_ENUM tags to steer
 * KCOV-CMP learned constants at l_type (a 3-valued vocab the kernel
 * branches on in posix_lock_inode) and l_whence (a 3-valued vocab the
 * kernel uses to resolve the start offset), and FT_RAW on l_start /
 * l_len / l_pid keeps attribution at the named range / pid slots
 * rather than at a coincidentally-same-width slot.  Without the
 * registration the slot fell through with no schema-aware attribution
 * even though the bespoke sanitiser already produced a plausible
 * payload, so per-field CMP steering at l_type / l_whence had nothing
 * to hang against.
 *
 * Resolution to this descriptor is now gated on the F_*LK / F_OFD_*LK
 * / F_CANCELLK cmds via the discriminator-aware syscall_struct_args[]
 * entry below; for non-lock cmds the kernel doesn't read a struct
 * flock at a3 (it reads an fd or an integer flag word that sanitise_
 * fcntl writes through rec->a3), so attribution at the flock fields
 * would be meaningless.
 */
static const unsigned long flock_l_type_values[] = {
	F_RDLCK, F_WRLCK, F_UNLCK,
};

static const unsigned long flock_l_whence_values[] = {
	SEEK_SET, SEEK_CUR, SEEK_END,
};

static const struct struct_field flock_fields[] = {
	FIELDX(struct flock, l_type, FT_ENUM,
	       .u.enum_ = { flock_l_type_values,
			    ARRAY_SIZE(flock_l_type_values) },
	       .mutate_weight = 80),
	FIELDX(struct flock, l_whence, FT_ENUM,
	       .u.enum_ = { flock_l_whence_values,
			    ARRAY_SIZE(flock_l_whence_values) },
	       .mutate_weight = 80),
	FIELD(struct flock, l_start),
	FIELD(struct flock, l_len),
	FIELD(struct flock, l_pid),
};

/* ------------------------------------------------------------------ */
/* struct f_owner_ex (fcntl F_GETOWN_EX / F_SETOWN_EX)                 */
/* ------------------------------------------------------------------ */

/*
 * fcntl's a3 for F_GETOWN_EX / F_SETOWN_EX is a pointer to struct
 * f_owner_ex.  The bespoke sanitise_fcntl() keeps owning the live
 * fill: it allocates the buffer via get_writable_struct(), picks
 * type from {F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP}, and stamps
 * get_pid() into pid before overwriting rec->a3.
 *
 * Attribution-only registration, same shape as the struct flock
 * entry above: struct_field_for_cmp() uses the FT_ENUM tag on type
 * (a 3-valued vocab the kernel branches on in f_setown_ex) to steer
 * KCOV-CMP learned constants at the named slot rather than at a
 * coincidentally-same-width slot.  pid stays FT_RAW: the bespoke
 * sanitiser stamps a getpid()-shaped value and the kernel treats it
 * as an opaque process / thread id with no vocab to attribute
 * against.
 *
 * Resolution to this descriptor is gated on cmd ∈ {F_GETOWN_EX,
 * F_SETOWN_EX} via the discriminator-aware syscall_struct_args[]
 * entry below; this is the first proof of the new mechanism.  Same
 * (name, arg_idx) -> different desc by sibling-arg value -- the
 * existing single-desc table couldn't represent it.
 */
static const unsigned long f_owner_ex_type_values[] = {
	F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP,
};

static const struct struct_field f_owner_ex_fields[] = {
	FIELDX(struct f_owner_ex, type, FT_ENUM,
	       .u.enum_ = { f_owner_ex_type_values,
			    ARRAY_SIZE(f_owner_ex_type_values) },
	       .mutate_weight = 80),
	FIELD(struct f_owner_ex, pid),
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

static const struct struct_field perf_event_attr_fields[] = {
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
 *   TRACEPOINT -> config = runtime tracefs event id (not catalog-able)
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
 * bp_addr's FT_ADDRESS is latent documentation today on two counts:
 * (1) sanitise_perf_event_open() discards the schema-filled buffer
 * and setup_breakpoints() plants its own get_address() value into
 * the csfu buffer; (2) struct_desc_has_address_field() walks only
 * desc->fields[] -- not per-variant fields[] -- so the nested-scrub
 * arg-mask doesn't register perf_event_open's a1 slot from this
 * annotation.  Lifting the walker into variants is out of scope
 * here; for perf the FT_ADDRESS annotation is forward-infra parity
 * with the hand-rolled path.
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
 * PERF_TYPE_TRACEPOINT and PERF_TYPE_RAW: config stays at FT_RAW.
 *
 * TRACEPOINT's config is a runtime-allocated tracepoint id read from
 * /sys/kernel/tracing/events/<subsys>/<event>/id; the legal value
 * set is not enumerable at compile time and varies per running
 * kernel.  The hand-rolled sanitise_perf_event_open() does not
 * enumerate tracepoint ids either -- the gap is identical on both
 * paths and is a known deficiency that would need a tracefs scanner
 * to close, not a static enum table.
 *
 * RAW's config is a vendor-specific PMU counter id (Intel/AMD/ARM
 * /POWER per-uarch raw event encoding).  There is no portable enum;
 * FT_RAW is the right tag.  config1 / config2 may also carry
 * vendor-specific extension bytes -- also FT_RAW.
 *
 * Both variants are declared with NULL fields[] / num_fields=0:
 * struct_fill_passes() short-circuits on n==0 so the shared
 * fields[]' FT_RAW config survives unchanged.  The variant entries
 * exist so the resolver returns a named variant (rather than
 * NULL == "unknown type") for these two PERF_TYPE_*s; future
 * CMP-attribution scoping can then identify the variant by name
 * when the cmp_hints recording-path lift arrives.  Treat the entries
 * as ABI documentation: "yes, TRACEPOINT and RAW were considered
 * and FT_RAW is the right tag for config" -- the comment trail is
 * load-bearing, the array entries are inert.
 */

static const struct union_variant perf_event_attr_variants[] = {
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
		.fields		= NULL,
		.num_fields	= 0,
	},
	{
		.discrim_value	= PERF_TYPE_RAW,
		.name		= "RAW",
		.fields		= NULL,
		.num_fields	= 0,
	},
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
 * Tagged-union on ss_family.  Per-AF sub-variants live below; each
 * variant's fields[] runs against the same sockaddr_storage envelope
 * so offsets are buffer-relative (offsetof on the per-AF struct
 * happens to match offsetof on sockaddr_storage for the shared head).
 *
 * ss_family itself is FT_ENUM over the curated vocab so the scalar
 * pass writes a value the resolver will then match; an FT_RAW splat
 * lands on a known AF roughly 1-in-8 instead of 1-in-32768, which is
 * the difference between "variant fires" and "variant is theoretical".
 *
 * Variants intentionally omit ss_family from their fields[] -- the
 * shared head pass already wrote it.  Each variant declares an
 * effective_size matching the per-AF sizeof(struct sockaddr_XX) so
 * the paired FT_LEN_BYTES (msghdr.msg_namelen) reports the kernel-
 * expected length rather than the full 128-byte envelope.
 *
 * Long-tail families (AF_BLUETOOTH, AF_CAN, AF_RDS, ...) fall
 * through to the shared head pass alone: ss_family lands on a known
 * AF value but the rest of the buffer stays opaque, matching today's
 * pre-variant placeholder behaviour for those families.  AF_BLUETOOTH
 * needs socket-state to disambiguate L2CAP / RFCOMM / HCI / SCO and
 * AF_RDS reuses sockaddr_in / sockaddr_in6 wholesale, so neither
 * fits the single-buffer discriminator the variants table walks.
 */
static const unsigned long sockaddr_storage_af_vocab[] = {
	AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET,
#ifdef USE_VSOCK
	AF_VSOCK,
#endif
#ifdef USE_X25
	AF_X25,
#endif
#ifdef USE_PHONET
	AF_PHONET,
#endif
#ifdef USE_AX25
	AF_AX25,
#endif
#ifdef USE_ATALK
	AF_APPLETALK,
#endif
#ifdef USE_LLC
	AF_LLC,
#endif
#ifdef USE_MCTP
	AF_MCTP,
#endif
#ifdef USE_IF_ALG
	AF_ALG,
#endif
	AF_TIPC,
	AF_QIPCRTR,
	AF_NFC,
#ifdef USE_XDP
	AF_XDP,
#endif
};

/*
 * AF_PACKET curated vocabularies.  Each enum table targets a
 * specific dispatch the kernel does in packet_rcv / af_packet's
 * deliver paths -- protocol decode, ARP hardware type lookup, and
 * the rx-type classifier respectively.  Sets stay small to keep
 * the enum-pick distribution biased toward kernel-visible buckets.
 */
static const unsigned long packet_eth_p_vocab[] = {
	ETH_P_LOOP, ETH_P_ALL, ETH_P_IP, ETH_P_ARP, ETH_P_RARP,
	ETH_P_8021Q, ETH_P_IPV6, ETH_P_MPLS_UC, ETH_P_MPLS_MC,
	ETH_P_LOOPBACK,
};

static const unsigned long packet_arphrd_vocab[] = {
	ARPHRD_ETHER, ARPHRD_PPP, ARPHRD_TUNNEL, ARPHRD_TUNNEL6,
	ARPHRD_LOOPBACK, ARPHRD_SIT, ARPHRD_IPGRE, ARPHRD_VOID,
	ARPHRD_NONE,
};

static const unsigned long packet_pkttype_vocab[] = {
	PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST, PACKET_OTHERHOST,
	PACKET_OUTGOING, PACKET_LOOPBACK, PACKET_USER, PACKET_KERNEL,
};

/* AF_UNIX (sockaddr_un) -- 2-byte family + 108-byte sun_path. */
static const struct struct_field sockaddr_un_variant_fields[] = {
	FIELD(struct sockaddr_un, sun_path),
};

/* AF_INET (sockaddr_in) -- u16 port + 32-bit IPv4 + 8 bytes pad. */
static const struct struct_field sockaddr_in_variant_fields[] = {
	FIELD(struct sockaddr_in, sin_port),
	FIELD(struct sockaddr_in, sin_addr),
};

/*
 * AF_INET6 (sockaddr_in6) -- IPv6 endpoint.  sin6_scope_id is an
 * ifindex; trinity has no live ifindex pool so a coarse range covers
 * the typical machine's interface count without paying for a /proc
 * scan at init.
 */
static const struct struct_field sockaddr_in6_variant_fields[] = {
	FIELD(struct sockaddr_in6, sin6_port),
	FIELD(struct sockaddr_in6, sin6_flowinfo),
	FIELD(struct sockaddr_in6, sin6_addr),
	FIELDX(struct sockaddr_in6, sin6_scope_id, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
};

/*
 * AF_NETLINK (sockaddr_nl) -- nl_groups is a multicast bitmask whose
 * meaning depends on which NETLINK_* family the socket was opened
 * with; that's not discoverable from sockaddr_nl alone so the mask
 * stays generic-full-32.  Family-aware biasing is currently unmodeled.
 */
static const struct struct_field sockaddr_nl_variant_fields[] = {
	FIELD(struct sockaddr_nl, nl_pad),
	FIELD(struct sockaddr_nl, nl_pid),
	FIELDX(struct sockaddr_nl, nl_groups, FT_FLAGS,
	       .u.flags.mask = 0xFFFFFFFFUL),
};

/*
 * AF_PACKET (sockaddr_ll) -- raw socket endpoint.  sll_halen is
 * bounded by the 8-byte sll_addr buffer the variant emits; the
 * kernel reads only the first sll_halen bytes regardless of what
 * landed in the tail, so leaving sll_addr as FT_RAW and sll_halen
 * as FT_RANGE without coupling them is fine.
 */
static const struct struct_field sockaddr_ll_variant_fields[] = {
	FIELDX(struct sockaddr_ll, sll_protocol, FT_ENUM,
	       .u.enum_ = { .vals = packet_eth_p_vocab,
			    .n    = ARRAY_SIZE(packet_eth_p_vocab) }),
	FIELDX(struct sockaddr_ll, sll_ifindex, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
	FIELDX(struct sockaddr_ll, sll_hatype, FT_ENUM,
	       .u.enum_ = { .vals = packet_arphrd_vocab,
			    .n    = ARRAY_SIZE(packet_arphrd_vocab) }),
	FIELDX(struct sockaddr_ll, sll_pkttype, FT_ENUM,
	       .u.enum_ = { .vals = packet_pkttype_vocab,
			    .n    = ARRAY_SIZE(packet_pkttype_vocab) }),
	FIELDX(struct sockaddr_ll, sll_halen, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 8 }),
	FIELD(struct sockaddr_ll, sll_addr),
};

#ifdef USE_VSOCK
/*
 * AF_VSOCK (sockaddr_vm) -- VMware/hypervisor socket endpoint.
 * svm_cid picks from the small set of well-known CIDs the kernel
 * recognises (any/hypervisor/local/host); arbitrary CIDs are rare
 * and bias toward unrouteable.  svm_flags has exactly one defined
 * bit today.  svm_reserved1 and svm_zero stay FT_RAW; the kernel
 * doesn't enforce them but accepts whatever the buffer carries.
 */
static const unsigned long vsock_cid_vocab[] = {
	VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR,
	VMADDR_CID_LOCAL, VMADDR_CID_HOST,
};

static const struct struct_field sockaddr_vm_variant_fields[] = {
	FIELD(struct sockaddr_vm, svm_reserved1),
	FIELD(struct sockaddr_vm, svm_port),
	FIELDX(struct sockaddr_vm, svm_cid, FT_ENUM,
	       .u.enum_ = { .vals = vsock_cid_vocab,
			    .n    = ARRAY_SIZE(vsock_cid_vocab) }),
	FIELDX(struct sockaddr_vm, svm_flags, FT_FLAGS,
	       .u.flags.mask = VMADDR_FLAG_TO_HOST),
};
#endif

#ifdef USE_X25
/*
 * AF_X25 (sockaddr_x25) -- ITU-T X.25 packet-switched endpoint.
 * The only payload member is sx25_addr.x25_addr, a 16-byte buffer
 * carrying an ASCII X.121 address (up to 15 digits plus NUL).  The
 * kernel walks the bytes via strncmp against the bound listener and
 * does not enforce digit-only content at bind, so FT_RAW covers the
 * dispatch surface without a digit vocabulary.  sx25_family is
 * omitted; the shared-head pass already writes ss_family.
 */
static const struct struct_field sockaddr_x25_variant_fields[] = {
	FIELD(struct sockaddr_x25, sx25_addr.x25_addr),
};
#endif

#ifdef USE_PHONET
/*
 * AF_PHONET (sockaddr_pn) -- Nokia Phonet endpoint.  The address tuple
 * is three packed __u8 scalars: spn_obj (object id within the device),
 * spn_dev (device byte; low two bits steal port high-bits via the
 * pn_sockaddr_set_port helper), and spn_resource (the routed-to
 * resource id matched in pn_find_sock_by_res()).  All three reach
 * dispatch as raw bytes, so FT_RAW covers the surface without a
 * curated vocabulary.  struct sockaddr_pn is packed, so offsetof
 * honours the lack of natural alignment.  spn_family and spn_zero[]
 * are omitted; the shared-head pass writes ss_family and the zero
 * padding stays zeroed.
 */
static const struct struct_field sockaddr_pn_variant_fields[] = {
	FIELD(struct sockaddr_pn, spn_obj),
	FIELD(struct sockaddr_pn, spn_dev),
	FIELD(struct sockaddr_pn, spn_resource),
};
#endif

#ifdef USE_AX25
/*
 * AF_AX25 (sockaddr_ax25) -- amateur-radio packet endpoint.  The
 * base struct carries the 7-byte AX.25 callsign (ax25_address, a
 * shifted-ASCII callsign + SSID byte the kernel walks via ax25cmp()
 * in ax25_bind / ax25_connect) and sax25_ndigis, the digipeater
 * count the kernel uses to decide whether to read the trailing
 * fsa_digipeater[] array of full_sockaddr_ax25.  trinity steers the
 * base sockaddr_ax25 only; full_sockaddr_ax25's variable-length
 * digipeater tail is intentionally out of scope here so the variant
 * stays a fixed-size record.  sax25_family is omitted; the shared-
 * head pass already writes ss_family.
 */
static const struct struct_field sockaddr_ax25_variant_fields[] = {
	FIELD(struct sockaddr_ax25, sax25_call),
	FIELD(struct sockaddr_ax25, sax25_ndigis),
};
#endif

#ifdef USE_ATALK
/*
 * AF_APPLETALK (sockaddr_at) -- AppleTalk DDP endpoint.  The address
 * tuple is a __u8 port plus a packed atalk_addr (__be16 net + __u8
 * node) the kernel matches in atalk_bind / atalk_sendmsg against the
 * routed atalk_iface list.  All three reach dispatch as raw bytes so
 * FT_RAW covers the surface without a curated vocabulary.  sat_family
 * is omitted; the shared-head pass writes ss_family.  sat_zero[8] is
 * pad the kernel does not consult and stays zeroed.
 */
static const struct struct_field sockaddr_at_variant_fields[] = {
	FIELD(struct sockaddr_at, sat_port),
	FIELD(struct sockaddr_at, sat_addr.s_net),
	FIELD(struct sockaddr_at, sat_addr.s_node),
};
#endif

#ifdef USE_LLC
/*
 * AF_LLC (sockaddr_llc) -- IEEE 802.2 LLC endpoint.  The 16-byte
 * address is a flat (family, arphrd, test, xid, ua, sap, mac) tuple;
 * no inner tagged union, so this variant stays single-arm.  sllc_arphrd
 * is canonically ARPHRD_ETHER but the kernel does not reject other
 * values at bind, so it stays FT_RAW.  sllc_sap is the LSAP byte the
 * kernel matches in llc_ui_bind() via llc_sap_find(); leaving it
 * FT_RAW keeps the full 0x00-0xFF dispatch surface exposed.  sllc_mac
 * is a 6-byte hardware address the kernel walks via dev_get_by_index
 * / __dev_get_by_index against the bound interface; FT_RAW covers the
 * generic case without a /sys/class/net walk at init.
 */
static const struct struct_field sockaddr_llc_variant_fields[] = {
	FIELD(struct sockaddr_llc, sllc_arphrd),
	FIELD(struct sockaddr_llc, sllc_test),
	FIELD(struct sockaddr_llc, sllc_xid),
	FIELD(struct sockaddr_llc, sllc_ua),
	FIELD(struct sockaddr_llc, sllc_sap),
	FIELD(struct sockaddr_llc, sllc_mac),
};
#endif

#ifdef USE_MCTP
/*
 * AF_MCTP (sockaddr_mctp) -- Management Component Transport Protocol
 * endpoint.  smctp_network / smctp_addr.s_addr / smctp_type carry the
 * raw routing bytes the kernel dispatches on; smctp_tag has one defined
 * owner bit.  smctp_family + the two pad bytes stay zeroed (the shared
 * head pass writes the family).
 */
static const struct struct_field sockaddr_mctp_variant_fields[] = {
	FIELD(struct sockaddr_mctp, smctp_network),
	FIELD(struct sockaddr_mctp, smctp_addr.s_addr),
	FIELD(struct sockaddr_mctp, smctp_type),
	FIELDX(struct sockaddr_mctp, smctp_tag, FT_FLAGS,
	       .u.flags.mask = MCTP_TAG_OWNER),
};
#endif

#ifdef USE_IF_ALG
/*
 * AF_ALG (sockaddr_alg) -- crypto userspace endpoint.  salg_type and
 * salg_name are 14- and 64-byte NUL-padded strings the kernel feeds
 * straight into crypto_find_alg().  FT_VOCAB plants a curated string
 * from a known bucket / algorithm name so the bind path walks past
 * the lookup loop rather than tripping at -ENOENT on random bytes.
 * Per-field draws are independent: a type/name mismatch still drives
 * the full lookup, which is the kernel boundary trinity's proto-alg
 * dictionary documents as worth fuzzing.  salg_feat / salg_mask stay
 * FT_RAW pending a curated CRYPTO_ALG_* mask.
 */
static const char *const salg_type_vocab[] = {
	"hash", "skcipher", "aead", "rng",
	"akcipher", "kpp", "shash", "ahash",
};

static const char *const salg_name_vocab[] = {
	"sha1", "sha256", "sha512", "md5",
	"hmac(sha256)", "hmac(sha512)",
	"aes-cbc-essiv:sha256", "chacha20",
	"poly1305", "gcm(aes)", "ccm(aes)",
	"xts(aes)", "cbc(aes)", "ecb(aes)",
	"rfc4106(gcm(aes))",
};

static const struct struct_field sockaddr_alg_variant_fields[] = {
	FIELDX(struct sockaddr_alg, salg_type, FT_VOCAB,
	       .u.vocab = { .vocab = salg_type_vocab,
			    .vocab_len = ARRAY_SIZE(salg_type_vocab),
			    .element_stride = sizeof(((struct sockaddr_alg *)NULL)->salg_type) }),
	FIELD(struct sockaddr_alg, salg_feat),
	FIELD(struct sockaddr_alg, salg_mask),
	FIELDX(struct sockaddr_alg, salg_name, FT_VOCAB,
	       .u.vocab = { .vocab = salg_name_vocab,
			    .vocab_len = ARRAY_SIZE(salg_name_vocab),
			    .element_stride = sizeof(((struct sockaddr_alg *)NULL)->salg_name) }),
};
#endif

/*
 * AF_TIPC (sockaddr_tipc) -- TIPC endpoint.  The outer variant fills
 * the (family, addrtype, scope) prefix; addrtype is itself a sub-
 * discriminator over the 12-byte inner addr union, so the per-arm
 * member layout is overlaid via nested_variants[].  Each arm leaves
 * its u32 sub-fields FT_RAW so the random splat carries through; the
 * tagged-union plumbing exists to anchor future ENUM/RANGE
 * annotations on type/instance/domain without re-touching the
 * sockaddr_storage entry.  effective_size stays at sizeof(struct
 * sockaddr_tipc) on every arm -- the kernel ABI rejects shorter
 * addrlens regardless of which inner arm is live.
 */
static const unsigned long tipc_addrtype_vocab[] = {
	TIPC_ADDR_NAMESEQ, TIPC_ADDR_NAME, TIPC_ADDR_ID,
};

static const unsigned long tipc_scope_vocab[] = {
	TIPC_ZONE_SCOPE, TIPC_CLUSTER_SCOPE, TIPC_NODE_SCOPE,
};

static const struct struct_field sockaddr_tipc_variant_fields[] = {
	FIELDX(struct sockaddr_tipc, addrtype, FT_ENUM,
	       .u.enum_ = { .vals = tipc_addrtype_vocab,
			    .n    = ARRAY_SIZE(tipc_addrtype_vocab) }),
	FIELDX(struct sockaddr_tipc, scope, FT_ENUM,
	       .u.enum_ = { .vals = tipc_scope_vocab,
			    .n    = ARRAY_SIZE(tipc_scope_vocab) }),
};

static const struct struct_field sockaddr_tipc_id_fields[] = {
	FIELD(struct sockaddr_tipc, addr.id.ref),
	FIELD(struct sockaddr_tipc, addr.id.node),
};

static const struct struct_field sockaddr_tipc_nameseq_fields[] = {
	FIELD(struct sockaddr_tipc, addr.nameseq.type),
	FIELD(struct sockaddr_tipc, addr.nameseq.lower),
	FIELD(struct sockaddr_tipc, addr.nameseq.upper),
};

static const struct struct_field sockaddr_tipc_name_fields[] = {
	FIELD(struct sockaddr_tipc, addr.name.name.type),
	FIELD(struct sockaddr_tipc, addr.name.name.instance),
	FIELD(struct sockaddr_tipc, addr.name.domain),
};

static const struct union_variant sockaddr_tipc_addr_nested[] = {
	{
		.discrim_value	 = TIPC_ADDR_ID,
		.name		 = "TIPC_ADDR_ID",
		.fields		 = sockaddr_tipc_id_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_id_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
	{
		.discrim_value	 = TIPC_ADDR_NAMESEQ,
		.name		 = "TIPC_ADDR_NAMESEQ",
		.fields		 = sockaddr_tipc_nameseq_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_nameseq_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
	{
		.discrim_value	 = TIPC_ADDR_NAME,
		.name		 = "TIPC_ADDR_NAME",
		.fields		 = sockaddr_tipc_name_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_name_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
};

/*
 * AF_QIPCRTR (sockaddr_qrtr) -- Qualcomm IPC Router endpoint.  The
 * 12-byte address is a flat (family, node, port) triple -- no inner
 * tagged union, so this variant stays single-arm.  sq_family is the
 * outer discriminator and is filled by the family ENUM; sq_node and
 * sq_port are u32 routing IDs.
 *
 * Both ID spaces are sparsely populated in practice (a handful of
 * registered nodes, low-numbered well-known ports plus an auto-
 * allocated ephemeral range), so a curated FT_ENUM pool that mixes
 * low integers with the two magic sentinels (QRTR_NODE_BCAST, the
 * broadcast node, and QRTR_PORT_CTRL, the control-channel port the
 * kernel routes to qrtr_ctrl_recv()) drives more useful coverage
 * than a uniform 32-bit splat that almost always misses.  Mirrors
 * the vsock_cid_vocab FT_ENUM shape.
 */
static const unsigned long qrtr_node_vocab[] = {
	0, 1, 2, 3, QRTR_NODE_BCAST,
};

static const unsigned long qrtr_port_vocab[] = {
	0, 1, 2, QRTR_PORT_CTRL,
};

static const struct struct_field sockaddr_qrtr_variant_fields[] = {
	FIELDX(struct sockaddr_qrtr, sq_node, FT_ENUM,
	       .u.enum_ = { .vals = qrtr_node_vocab,
			    .n    = ARRAY_SIZE(qrtr_node_vocab) }),
	FIELDX(struct sockaddr_qrtr, sq_port, FT_ENUM,
	       .u.enum_ = { .vals = qrtr_port_vocab,
			    .n    = ARRAY_SIZE(qrtr_port_vocab) }),
};

/*
 * AF_NFC (sockaddr_nfc) -- NFC raw socket endpoint.  The 16-byte
 * address is a flat (family, dev_idx, target_idx, nfc_protocol)
 * tuple -- no inner tagged union, so this variant stays single-arm
 * (mirrors AF_QIPCRTR).  sockaddr_nfc_llcp is a separate, larger
 * address only valid on NFC_SOCKPROTO_LLCP sockets; modelling it
 * needs a socket-state-aware discriminator the sockaddr_storage
 * envelope does not carry, so it stays out of this variant table.
 *
 * dev_idx / target_idx are the kernel's nfc_dev->idx and nfc_target
 * ->idx; both are densely packed from 0 and rarely exceed a handful
 * on real hardware, so a small FT_RANGE covers the live pool without
 * a /sys/class/nfc walk at init.  nfc_protocol is the per-target
 * protocol selector the kernel matches in rawsock_bind() via
 * nfc_find_target(); a curated FT_ENUM over the seven NFC_PROTO_*
 * values keeps the bind walk hitting registered protocols instead
 * of -EINVAL on a u32 splat.
 */
static const unsigned long nfc_proto_vocab[] = {
	NFC_PROTO_JEWEL, NFC_PROTO_MIFARE, NFC_PROTO_FELICA,
	NFC_PROTO_ISO14443, NFC_PROTO_NFC_DEP, NFC_PROTO_ISO14443_B,
	NFC_PROTO_ISO15693,
};

static const struct struct_field sockaddr_nfc_variant_fields[] = {
	FIELDX(struct sockaddr_nfc, dev_idx, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 }),
	FIELDX(struct sockaddr_nfc, target_idx, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 }),
	FIELDX(struct sockaddr_nfc, nfc_protocol, FT_ENUM,
	       .u.enum_ = { .vals = nfc_proto_vocab,
			    .n    = ARRAY_SIZE(nfc_proto_vocab) }),
};

#ifdef USE_XDP
/*
 * AF_XDP (sockaddr_xdp) -- XSK endpoint.  sxdp_flags drives the
 * UMEM / queue binding semantics; the kernel's xsk_bind() rejects
 * anything outside XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY |
 * XDP_USE_NEED_WAKEUP with -EINVAL before the dispatch lands, so an
 * FT_FLAGS pick over that mask keeps coverage on the registered
 * codepaths.  sxdp_ifindex is a generic 32-bit ifindex -- trinity
 * has no live ifindex pool here, so leave it FT_RAW; bind() mostly
 * fails at the netlink lookup but xsk_bind itself still runs.
 * sxdp_queue_id stays small since real NICs rarely expose many
 * queues, biasing the range toward something xsk_get_pool_from_qid
 * may actually accept.  sxdp_shared_umem_fd is only honoured with
 * XDP_SHARED_UMEM set, but an FT_FD slot biases toward an existing
 * fd in the pool so the rare accept path exercises something other
 * than -EBADF.
 */
#define SOCKADDR_XDP_FLAGS_MASK						\
	(XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)

static const struct struct_field sockaddr_xdp_variant_fields[] = {
	FIELDX(struct sockaddr_xdp, sxdp_flags, FT_FLAGS,
	       .u.flags.mask = SOCKADDR_XDP_FLAGS_MASK),
	FIELD(struct sockaddr_xdp, sxdp_ifindex),
	FIELDX(struct sockaddr_xdp, sxdp_queue_id, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
	FIELDX(struct sockaddr_xdp, sxdp_shared_umem_fd, FT_FD),
};
#endif

static const struct union_variant sockaddr_storage_variants[] = {
	{
		.discrim_value	 = AF_UNIX,
		.name		 = "AF_UNIX",
		.fields		 = sockaddr_un_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_un_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_un),
	},
	{
		.discrim_value	 = AF_INET,
		.name		 = "AF_INET",
		.fields		 = sockaddr_in_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_in_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_in),
	},
	{
		.discrim_value	 = AF_INET6,
		.name		 = "AF_INET6",
		.fields		 = sockaddr_in6_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_in6_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_in6),
	},
	{
		.discrim_value	 = AF_NETLINK,
		.name		 = "AF_NETLINK",
		.fields		 = sockaddr_nl_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_nl_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_nl),
	},
	{
		.discrim_value	 = AF_PACKET,
		.name		 = "AF_PACKET",
		.fields		 = sockaddr_ll_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_ll_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_ll),
	},
#ifdef USE_VSOCK
	{
		.discrim_value	 = AF_VSOCK,
		.name		 = "AF_VSOCK",
		.fields		 = sockaddr_vm_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_vm_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_vm),
	},
#endif
#ifdef USE_X25
	{
		.discrim_value	 = AF_X25,
		.name		 = "AF_X25",
		.fields		 = sockaddr_x25_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_x25_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_x25),
	},
#endif
#ifdef USE_PHONET
	{
		.discrim_value	 = AF_PHONET,
		.name		 = "AF_PHONET",
		.fields		 = sockaddr_pn_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_pn_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_pn),
	},
#endif
#ifdef USE_AX25
	{
		.discrim_value	 = AF_AX25,
		.name		 = "AF_AX25",
		.fields		 = sockaddr_ax25_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_ax25_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_ax25),
	},
#endif
#ifdef USE_ATALK
	{
		.discrim_value	 = AF_APPLETALK,
		.name		 = "AF_APPLETALK",
		.fields		 = sockaddr_at_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_at_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_at),
	},
#endif
#ifdef USE_LLC
	{
		.discrim_value	 = AF_LLC,
		.name		 = "AF_LLC",
		.fields		 = sockaddr_llc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_llc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_llc),
	},
#endif
#ifdef USE_MCTP
	{
		.discrim_value	 = AF_MCTP,
		.name		 = "AF_MCTP",
		.fields		 = sockaddr_mctp_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_mctp_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_mctp),
	},
#endif
#ifdef USE_IF_ALG
	{
		.discrim_value	 = AF_ALG,
		.name		 = "AF_ALG",
		.fields		 = sockaddr_alg_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_alg_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_alg),
	},
#endif
	{
		.discrim_value	 = AF_TIPC,
		.name		 = "AF_TIPC",
		.fields		 = sockaddr_tipc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
		.nested_discrim_offset = offsetof(struct sockaddr_tipc, addrtype),
		.nested_discrim_size   = 1,
		.nested_variants     = sockaddr_tipc_addr_nested,
		.num_nested_variants = ARRAY_SIZE(sockaddr_tipc_addr_nested),
	},
	{
		.discrim_value	 = AF_QIPCRTR,
		.name		 = "AF_QIPCRTR",
		.fields		 = sockaddr_qrtr_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_qrtr_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_qrtr),
	},
	{
		.discrim_value	 = AF_NFC,
		.name		 = "AF_NFC",
		.fields		 = sockaddr_nfc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_nfc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_nfc),
	},
#ifdef USE_XDP
	{
		.discrim_value	 = AF_XDP,
		.name		 = "AF_XDP",
		.fields		 = sockaddr_xdp_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_xdp_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_xdp),
	},
#endif
};

static const struct struct_field sockaddr_storage_fields[] = {
	FIELDX(struct sockaddr_storage, ss_family, FT_ENUM,
	       .u.enum_ = { .vals = sockaddr_storage_af_vocab,
			    .n    = ARRAY_SIZE(sockaddr_storage_af_vocab) },
	       .mutate_weight = 200),
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
/* struct landlock_path_beneath_attr (landlock_add_rule)               */
/* ------------------------------------------------------------------ */

/*
 * landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags) passes
 * the rule_attr struct at a3.  Under LANDLOCK_RULE_PATH_BENEATH the
 * struct is landlock_path_beneath_attr; the bespoke
 * sanitise_landlock_add_rule() in syscalls/landlock_add_rule.c keeps
 * owning the live fill (get_writable_address() allocation, the
 * allowed_access bitmask masked to the low 16 bits, parent_fd drawn
 * from get_random_fd()).  argtype[2] is not declared (the sanitiser
 * unconditionally overwrites rec->a3), so the schema-aware fill path
 * never runs against it -- registration is attribution-only,
 * mirroring sigevent / rseq / landlock_ruleset_attr above.
 *
 * allowed_access carries the LANDLOCK_ACCESS_FS_* vocabulary; reuse
 * the LANDLOCK_ACCESS_FS_MASK defined for landlock_ruleset_attr so a
 * future uapi bit lands in one place.  parent_fd is an open fd the
 * kernel resolves to a path -- no useful per-bit CMP vocab, FT_RAW.
 *
 * The sibling LANDLOCK_RULE_NET_PORT arm passes a different struct
 * (landlock_net_port_attr) at the same a3 slot; that variant is
 * registered separately below and selected by the discriminator-
 * aware syscall_struct_args[] entry on rec->a2 == rule_type.
 */
static const struct struct_field landlock_path_beneath_attr_fields[] = {
	FIELDX(struct landlock_path_beneath_attr, allowed_access, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_FS_MASK,
	       .mutate_weight = 80),
	FIELD(struct landlock_path_beneath_attr, parent_fd),
};

/* ------------------------------------------------------------------ */
/* struct landlock_net_port_attr (landlock_add_rule)                   */
/* ------------------------------------------------------------------ */

/*
 * Sibling variant of landlock_path_beneath_attr above: under
 * LANDLOCK_RULE_NET_PORT the rule_attr at a3 is a
 * struct landlock_net_port_attr instead.  The bespoke
 * sanitise_landlock_add_rule() keeps owning the live fill
 * (get_writable_address() allocation, allowed_access drawn from a
 * 2-bit pool covering LANDLOCK_ACCESS_NET_BIND_TCP and
 * LANDLOCK_ACCESS_NET_CONNECT_TCP, port stratified across the
 * ephemeral / well-known / privileged / unprivileged ranges).
 * argtype[2] is not declared, so the schema-aware fill path never
 * runs against rec->a3; registration is attribution-only and mirrors
 * the landlock_path_beneath_attr entry above.
 *
 * allowed_access carries the LANDLOCK_ACCESS_NET_* vocabulary; reuse
 * the LANDLOCK_ACCESS_NET_MASK defined for landlock_ruleset_attr so
 * a future uapi bit lands in one place.  port is __u64 host-endian
 * and the kernel rejects values > 65535 (build_check_abi() bounds);
 * FT_RANGE {0, 65535} steers KCOV-CMP learned constants at the
 * actually-reachable port space.
 *
 * Resolution to this descriptor is gated on the
 * LANDLOCK_RULE_NET_PORT rule_type via the discriminator-aware
 * syscall_struct_args[] entry below, mirroring the fcntl
 * flock / f_owner_ex registration.  Pre-discriminator the catalog
 * could map only one descriptor per (syscall, arg), so a3 resolved
 * to landlock_path_beneath_attr for every rule_type and
 * struct_field_for_cmp() was attributing CMP-learned constants at
 * allowed_access / parent_fd even on NET_PORT dispatches where the
 * kernel was reading a wholly different struct.
 */
static const struct struct_field landlock_net_port_attr_fields[] = {
	FIELDX(struct landlock_net_port_attr, allowed_access, FT_FLAGS,
	       .u.flags.mask = LANDLOCK_ACCESS_NET_MASK,
	       .mutate_weight = 80),
	FIELDX(struct landlock_net_port_attr, port, FT_RANGE,
	       .u.range = { 0, 65535 },
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct if_dqblk (quotactl Q_SETQUOTA, quotactl_fd Q_SETQUOTA)       */
/* ------------------------------------------------------------------ */

/*
 * quotactl(cmd, special, id, addr) and quotactl_fd(fd, cmd, id, addr)
 * pass a struct if_dqblk at the addr slot (quotactl a4 / quotactl_fd
 * a4) under Q_SETQUOTA -- the SET path is the input arm where the
 * bytes we stamp actually reach disk-quota code.  The bespoke
 * sanitise_quotactl() / sanitise_quotactl_fd() keep owning the live
 * fill (writable allocation, dqb_bhardlimit / dqb_bsoftlimit drawn
 * from rand32(), dqb_ihardlimit / dqb_isoftlimit bounded to 100000,
 * routed through avoid_shared_buffer_inout()); attribution-only
 * registration lets struct_field_for_cmp() steer CMP-learned
 * constants at the named limit / time / valid slots rather than at a
 * coincidentally-same-width slot.
 *
 * dqb_valid carries the QIF_* mask vocabulary; FT_FLAGS over QIF_ALL
 * keeps CMP attribution against the bits the kernel actually
 * switches on (the bespoke arm leaves the field zero today, so this
 * is purely about which slot a learned constant pegs).
 *
 * Q_GETQUOTA / Q_GETNEXTQUOTA also use if_dqblk at the same slot,
 * but they're output-only -- the bytes we stamp on dispatch don't
 * reach the kernel's quota lookup, only the kernel's write-back
 * touches them.  Register only the SET arm so CMP attribution
 * doesn't fire on output bytes that came from the kernel rather
 * than our fill.
 *
 * Resolution to this descriptor is gated on the Q_SETQUOTA subcmd
 * via the discriminator-aware syscall_struct_args[] entry below,
 * which uses the packed-discriminator (shift, mask) extension to
 * unpack QCMD(subcmd, type) -- rec->a<n> >> SUBCMDSHIFT yields the
 * raw subcmd that the kernel switches on, which is what Q_SETQUOTA
 * actually equals.
 */
static const struct struct_field if_dqblk_fields[] = {
	FIELD(struct if_dqblk, dqb_bhardlimit),
	FIELD(struct if_dqblk, dqb_bsoftlimit),
	FIELD(struct if_dqblk, dqb_curspace),
	FIELD(struct if_dqblk, dqb_ihardlimit),
	FIELD(struct if_dqblk, dqb_isoftlimit),
	FIELD(struct if_dqblk, dqb_curinodes),
	FIELD(struct if_dqblk, dqb_btime),
	FIELD(struct if_dqblk, dqb_itime),
	FIELDX(struct if_dqblk, dqb_valid, FT_FLAGS,
	       .u.flags.mask = QIF_ALL,
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct if_dqinfo (quotactl Q_SETINFO, quotactl_fd Q_SETINFO)        */
/* ------------------------------------------------------------------ */

/*
 * Sibling to the if_dqblk registration above: under Q_SETINFO the
 * same addr slot (quotactl a4 / quotactl_fd a4) is a struct
 * if_dqinfo pointer instead.  The bespoke sanitisers keep owning
 * the live fill (writable allocation, dqi_bgrace / dqi_igrace
 * drawn from a deterministic hour-stride picker, routed through
 * avoid_shared_buffer_inout()); attribution-only registration lets
 * struct_field_for_cmp() steer CMP-learned constants at the named
 * grace / flags / valid slots rather than at a coincidentally-same-
 * width slot.
 *
 * dqi_flags carries the DQF_* vocabulary (DQF_ROOT_SQUASH /
 * DQF_SYS_FILE today); dqi_valid carries the IIF_* vocabulary
 * (IIF_BGRACE / IIF_IGRACE / IIF_FLAGS).  FT_FLAGS keeps CMP
 * attribution against the bits the kernel actually switches on.
 *
 * Q_GETINFO also uses if_dqinfo at the same slot but is output-only
 * (kernel writes the grace fields on dispatch); register only the
 * SET arm so CMP attribution doesn't fire on output bytes.
 *
 * Resolution is gated on the Q_SETINFO subcmd via the discriminator-
 * aware syscall_struct_args[] entry below, using the same packed-
 * discriminator (shift=SUBCMDSHIFT, mask=implicit-~0UL) extension
 * the if_dqblk registration uses.
 */
static const struct struct_field if_dqinfo_fields[] = {
	FIELD(struct if_dqinfo, dqi_bgrace),
	FIELD(struct if_dqinfo, dqi_igrace),
	FIELDX(struct if_dqinfo, dqi_flags, FT_FLAGS,
	       .u.flags.mask = DQF_ROOT_SQUASH | DQF_SYS_FILE,
	       .mutate_weight = 60),
	FIELDX(struct if_dqinfo, dqi_valid, FT_FLAGS,
	       .u.flags.mask = IIF_ALL,
	       .mutate_weight = 60),
};

#ifdef X86
/* ------------------------------------------------------------------ */
/* struct user_desc (modify_ldt write_ldt arm, func == 1)              */
/* ------------------------------------------------------------------ */
/*
 * x86-only LDT entry descriptor.  Only the three addressable u32 fields
 * (entry_number / base_addr / limit) get FIELD entries -- the trailing
 * seg_32bit / contents / read_exec_only / limit_in_pages / seg_not_present
 * / useable / lm members are sub-byte bitfields and have no stable
 * offsetof, so they stay outside the schema-aware fill's reach.  The
 * bespoke sanitise_modify_ldt() arm already curates those bits; this
 * registration is attribution-only so struct_field_for_cmp() can steer
 * CMP-learned constants at entry_number / base_addr / limit rather than
 * at a coincidentally-same-width slot.
 *
 * entry_number is FT_RANGE-bounded to [0, LDT_ENTRIES) to match the
 * kernel's switch domain; base_addr / limit stay FT_RAW since the kernel
 * accepts any 32-bit value.
 */
static const struct struct_field user_desc_fields[] = {
	FIELDX(struct user_desc, entry_number, FT_RANGE,
	       .u.range.lo = 0,
	       .u.range.hi = LDT_ENTRIES - 1,
	       .mutate_weight = 60),
	FIELD(struct user_desc, base_addr),
	FIELD(struct user_desc, limit),
};
#endif

/* ------------------------------------------------------------------ */
/* struct sock_filter (sock_fprog.filter array element)                 */
/* ------------------------------------------------------------------ */

/*
 * Classic-BPF instruction word.  Registered so sock_fprog.filter can
 * name it via FT_PTR_ARRAY.elem_struct and the pointer pass knows
 * sizeof(struct sock_filter) for sub-array allocation.  No syscall_
 * struct_args entry: sock_filter is never passed directly as an
 * ARG_STRUCT_PTR slot -- it only appears as the element type of the
 * len-counted array hung off sock_fprog.filter.
 *
 * All four members stay FT_RAW: the live fill is owned by the
 * bespoke bpf_gen_filter() / bpf_gen_seccomp() Markov-chain BPF
 * generators in net/bpf.c, which build well-formed cBPF programs
 * the kernel verifier will actually load.  A flat random splat per
 * field would produce instruction words the verifier rejects on the
 * first opcode read.  These FIELD entries exist so struct_field_for_
 * cmp() can attribute CMP-learned constants at named code / jt / jf
 * / k slots rather than at coincidentally-same-width slots.
 */
static const struct struct_field sock_filter_fields[] = {
	FIELD(struct sock_filter, code),
	FIELD(struct sock_filter, jt),
	FIELD(struct sock_filter, jf),
	FIELD(struct sock_filter, k),
};

/* ------------------------------------------------------------------ */
/* struct sock_fprog (seccomp SET_MODE_FILTER, SO_ATTACH_FILTER, ...)   */
/* ------------------------------------------------------------------ */

/*
 * Embedded-pointer struct: { u16 len; struct sock_filter *filter; }.
 * filter points at a len-counted array of struct sock_filter -- the
 * kernel reads len first, then dereferences filter for (len *
 * sizeof(sock_filter)) bytes, so a flat memcpy registration would
 * leave the embedded pointer as a garbage value the kernel would
 * dereference.  The catalog already expresses this exact shape via
 * the FT_PTR_ARRAY (elem_struct + len_field) + FT_LEN_COUNT pair
 * used by msghdr.msg_iov / msg_iovlen; the pointer-fill pass
 * allocates a sock_filter[len] sub-buffer, points filter at it, and
 * the length pass writes the coupled count into len.
 *
 * Attribution-only registration: the live fill for the seccomp /
 * setsockopt(SO_ATTACH_FILTER) / prctl(PR_SET_SECCOMP) call sites
 * is owned by the bespoke bpf_gen_seccomp() / bpf_gen_filter()
 * Markov generators in net/bpf.c -- those produce well-formed
 * cBPF the kernel verifier accepts, which a schema-aware FT_RAW
 * splat across sock_filter[] words cannot.  The descriptor still
 * earns its keep by giving struct_field_for_cmp() named len /
 * filter slots and a cataloged elem_struct so CMP-learned
 * constants attribute at the right field rather than at a
 * coincidentally-same-width slot.
 *
 * max_count caps the sub-array to 64 elements -- the speculative
 * allocator path only fires when no bespoke sanitiser has already
 * stamped (a, len) at the slot (i.e. never for the existing
 * seccomp / setsockopt / prctl users), so the bound is purely a
 * safety ceiling on future schema-only callers.  BPF_MAXINSNS is
 * 4096 in the kernel; 64 is well under that and keeps catalog-
 * speculative allocations small.
 */
static const struct struct_field sock_fprog_fields[] = {
	FIELDX(struct sock_fprog, len, FT_LEN_COUNT,
	       .u.len_of = { .buf_field = "filter" }),
	FIELDX(struct sock_fprog, filter, FT_PTR_ARRAY,
	       .u.ptr_array = { .len_field = "len",
				.elem_struct = "sock_filter",
				.max_count = 64 }),
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
/* struct ns_id_req (listns)                                           */
/* ------------------------------------------------------------------ */

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.  Defined locally
 * under the same #ifndef guard the listns sanitiser uses so the
 * translation unit builds against kernel headers that predate the
 * struct.  The shape MUST match the one in syscalls/listns.c -- a
 * future header bump that grows the struct needs both copies updated.
 *
 * ns_type carries a single CLONE_NEW* namespace selector.  An out-of-
 * vocab bit makes listns return -EINVAL before any iterator runs, so
 * an FT_RAW splat almost never reaches the namespace lookup paths;
 * mask the field to the eight defined CLONE_NEW* bits so CMP-learned
 * constants attribute against a real selector.  CLONE_NEWCGROUP /
 * CLONE_NEWTIME are shimmed because older kernel headers may omit
 * them; mirror the listns sanitiser's shim values verbatim.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 ns_type;
	__u64 ns_id;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	24
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME		0x00000080
#endif

#define NS_ID_REQ_NS_TYPE_MASK \
	(CLONE_NEWNS   | CLONE_NEWUTS  | CLONE_NEWIPC     | CLONE_NEWUSER | \
	 CLONE_NEWPID  | CLONE_NEWNET  | CLONE_NEWCGROUP  | CLONE_NEWTIME)

static const struct struct_field ns_id_req_fields[] = {
	FIELD(struct ns_id_req, size),
	FIELDX(struct ns_id_req, ns_type, FT_FLAGS,
	       .u.flags.mask = NS_ID_REQ_NS_TYPE_MASK),
	FIELD(struct ns_id_req, ns_id),
	FIELD(struct ns_id_req, user_ns_id),
};

/* ------------------------------------------------------------------ */
/* struct xattr_args (setxattrat, getxattrat)                          */
/* ------------------------------------------------------------------ */

/*
 * struct xattr_args from include/uapi/linux/xattr.h.  Gated on
 * USE_XATTR_ARGS because the build host's uapi headers may predate
 * the addition; mirror the syscalls/{set,get}xattrat.c guard so the
 * translation unit still builds on older headers.  The bespoke
 * sanitisers in those syscall files own the live fill --
 * build_csfu_struct(&desc_{set,get}xattrat) stamps the size word
 * envelope and the in-line picker populates value / size / flags
 * plus the value sub-buffer; this registration layers per-field
 * CMP attribution on top.
 *
 * value is an embedded __aligned_u64 carrying a userspace pointer --
 * FT_ADDRESS mirrors the rseq_cs / robust_list_head treatment so
 * KCOV-CMP learned address constants attribute against it.  size is
 * a free __u32 the kernel reads as the value-buffer bound (FT_RAW).
 * flags carries the XATTR_CREATE / XATTR_REPLACE vocabulary --
 * anything outside the mask is rejected by the VFS before any
 * sub-buffer read, so the mask is the entire useful CMP vocabulary.
 */
#ifdef USE_XATTR_ARGS
static const struct struct_field xattr_args_fields[] = {
	FIELDX(struct xattr_args, value, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELD(struct xattr_args, size),
	FIELDX(struct xattr_args, flags, FT_FLAGS,
	       .u.flags.mask = (XATTR_CREATE | XATTR_REPLACE),
	       .mutate_weight = 80),
};
#endif

/* ------------------------------------------------------------------ */
/* struct file_attr (file_setattr)                                     */
/* ------------------------------------------------------------------ */

/*
 * struct file_attr from <linux/fs.h> (shimmed in include/compat.h when
 * the system uapi headers predate the file_getattr/file_setattr
 * addition).  The bespoke sanitise_file_setattr() owns the live fill --
 * build_csfu_struct(&desc_file_setattr) stamps the size word envelope
 * and the in-line xflag picker draws fa_xflags from a curated
 * FS_XFLAG_* pool with an occasional outside-mask leg; this
 * registration layers per-field CMP attribution on top.
 *
 * fa_xflags carries the FS_XFLAG_* vocabulary -- anything outside the
 * mask is bounced by vfs_fileattr_set() on -EINVAL before the kernel
 * reaches the real setattr arms, so the mask is the entire useful CMP
 * vocabulary.  fa_extsize / fa_nextents / fa_projid / fa_cowextsize are
 * free u32 slots the kernel reads as raw values.  Mirrors the
 * attribution-only treatment of timer_create's sigevent, rseq, and
 * the just-landed xattr_args entries.
 */
#define FILE_ATTR_XFLAGS_MASK						\
	(FS_XFLAG_REALTIME    | FS_XFLAG_PREALLOC    | FS_XFLAG_IMMUTABLE | \
	 FS_XFLAG_APPEND      | FS_XFLAG_SYNC        | FS_XFLAG_NOATIME  | \
	 FS_XFLAG_NODUMP      | FS_XFLAG_RTINHERIT   | FS_XFLAG_PROJINHERIT | \
	 FS_XFLAG_NOSYMLINKS  | FS_XFLAG_EXTSIZE     | FS_XFLAG_EXTSZINHERIT | \
	 FS_XFLAG_NODEFRAG    | FS_XFLAG_FILESTREAM  | FS_XFLAG_DAX      | \
	 FS_XFLAG_COWEXTSIZE  | FS_XFLAG_HASATTR)

static const struct struct_field file_attr_fields[] = {
	FIELDX(struct file_attr, fa_xflags, FT_FLAGS,
	       .u.flags.mask = FILE_ATTR_XFLAGS_MASK,
	       .mutate_weight = 80),
	FIELD(struct file_attr, fa_extsize),
	FIELD(struct file_attr, fa_nextents),
	FIELD(struct file_attr, fa_projid),
	FIELD(struct file_attr, fa_cowextsize),
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
/* siginfo_t (rt_sigqueueinfo, rt_tgsigqueueinfo)                       */
/* ------------------------------------------------------------------ */

/*
 * siginfo_t is a si_code-discriminated union.  si_signo / si_errno /
 * si_code form the fixed header; the union body's active arm is
 * selected primarily by si_code (with si_signo refining the positive-
 * si_code receiver-side arms).  Trinity's rt_sigqueueinfo /
 * rt_tgsigqueueinfo sanitisers own the live fill -- both hand-build
 * the buffer and pin si_code to SI_USER / SI_QUEUE / SI_TKILL (plus
 * an "intentionally invalid" bucket on rt_sigqueueinfo for the EPERM
 * gate).  This registration is attribution-only: schema-aware fill
 * never runs at the slot (argtype[*] is not ARG_STRUCT_PTR_*), but
 * struct_field_for_cmp() now steers CMP-learned constants at the
 * named si_signo / si_code / si_pid / si_uid / si_value slots rather
 * than at coincidentally-same-width slots.
 *
 * Variants resolve via the in-buffer si_code discriminator, mirroring
 * sockaddr_storage's buffer-relative ss_family and perf_event_attr's
 * buffer-relative type.  Only the negative-si_code arms userland
 * actually supplies on the SET path are modeled here: SI_QUEUE picks
 * the _rt arm (si_pid + si_uid + si_value), SI_USER / SI_TKILL pick
 * the _kill arm (si_pid + si_uid).  Positive si_code (SI_KERNEL /
 * SEGV_MAPERR / ...) is kernel-origin and rejected on the unprivileged
 * SET path with EPERM, so no variant is registered for those values
 * -- the resolver falls through to the shared head alone.  The
 * signal-specific receiver-side arms (_sigchld on SIGCHLD,
 * _sigfault on SIGSEGV/SIGBUS/..., _sigpoll on SIGIO/SIGPOLL,
 * _sigsys on SIGSYS) need a two-axis (si_signo, si_code) discriminator
 * the catalog does not express; they are deliberately left unmodeled
 * here (the SET-path consumers never reach them).
 *
 * Width / sign note: si_code is `int` (4 bytes signed).  The width-4
 * buffer_discrim reader (read_discrim) returns zero-extended, so the
 * negative SI_* constants live as their uint32_t cast in
 * discrim_value (0xFFFFFFFFUL for SI_QUEUE etc.), not as the sign-
 * extended unsigned long form.
 *
 * Not mapped here on purpose: waitid's a3 is a kernel-written OUTPUT
 * buffer with no input fill to attribute against (same shape as the
 * gettimeofday / get_robust_list / cachestat-output skips above);
 * pidfd_send_signal's a3 is also struct siginfo_t but is intentionally
 * not in this commit's scope.
 */
static const unsigned long siginfo_t_si_code_vocab[] = {
	(unsigned long)(uint32_t) SI_USER,
	(unsigned long)(uint32_t) SI_QUEUE,
	(unsigned long)(uint32_t) SI_TKILL,
	(unsigned long)(uint32_t) SI_TIMER,
	(unsigned long)(uint32_t) SI_ASYNCIO,
	(unsigned long)(uint32_t) SI_KERNEL,
};

static const struct struct_field siginfo_t_fields[] = {
	FIELDX(siginfo_t, si_signo, FT_RANGE,
	       .u.range = { 1, 64 }),
	FIELD(siginfo_t, si_errno),
	FIELDX(siginfo_t, si_code, FT_ENUM,
	       .u.enum_ = { .vals = siginfo_t_si_code_vocab,
			    .n    = ARRAY_SIZE(siginfo_t_si_code_vocab) }),
};

/* SI_QUEUE -- _rt arm (sigqueue() origin: pid + uid + sigval payload). */
static const struct struct_field siginfo_t_rt_variant_fields[] = {
	FIELD(siginfo_t, si_pid),
	FIELD(siginfo_t, si_uid),
	FIELD(siginfo_t, si_value),
};

/* SI_USER / SI_TKILL -- _kill arm (kill() / tkill() origin: pid + uid). */
static const struct struct_field siginfo_t_kill_variant_fields[] = {
	FIELD(siginfo_t, si_pid),
	FIELD(siginfo_t, si_uid),
};

static const unsigned long siginfo_t_kill_discrim_values[] = {
	(unsigned long)(uint32_t) SI_USER,
	(unsigned long)(uint32_t) SI_TKILL,
};

static const struct union_variant siginfo_t_variants[] = {
	{
		.discrim_value	= (unsigned long)(uint32_t) SI_QUEUE,
		.name		= "SI_QUEUE",
		.fields		= siginfo_t_rt_variant_fields,
		.num_fields	= ARRAY_SIZE(siginfo_t_rt_variant_fields),
	},
	{
		.discrim_values		= siginfo_t_kill_discrim_values,
		.num_discrim_values	= ARRAY_SIZE(siginfo_t_kill_discrim_values),
		.name			= "SI_USER/SI_TKILL",
		.fields			= siginfo_t_kill_variant_fields,
		.num_fields		= ARRAY_SIZE(siginfo_t_kill_variant_fields),
	},
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
/* struct shmid_ds (shmctl IPC_SET path)                                */
/* ------------------------------------------------------------------ */

static const struct struct_field shmid_ds_fields[] = {
	FIELD(struct shmid_ds, shm_perm.uid),
	FIELD(struct shmid_ds, shm_perm.gid),
	FIELD(struct shmid_ds, shm_perm.mode),
};

/* ------------------------------------------------------------------ */
/* struct iocb (io_cancel)                                              */
/* ------------------------------------------------------------------ */

/*
 * IOCB_CMD_* opcode vocabulary for aio_lio_opcode.  The kernel rejects
 * anything outside this set up-front (aio_read_events_ring -> -EINVAL)
 * before any iocb body is consumed, so FT_RAW would burn most splats
 * on the reject path.
 */
static const unsigned long iocb_opcode_values[] = {
	IOCB_CMD_PREAD, IOCB_CMD_PWRITE, IOCB_CMD_FSYNC, IOCB_CMD_FDSYNC,
	IOCB_CMD_POLL,  IOCB_CMD_NOOP,   IOCB_CMD_PREADV, IOCB_CMD_PWRITEV,
};

#define IOCB_FLAGS_MASK \
	(IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO)

/*
 * RWF_* vocabulary for aio_rw_flags.  Host uapi headers vary on the
 * newer additions (NOAPPEND, ATOMIC, DONTCACHE) so the per-bit guards
 * keep the mask portable -- bits absent at build time are simply
 * omitted from the OR.
 */
#ifndef RWF_HIPRI
#define RWF_HIPRI	0x00000001
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC	0x00000002
#endif
#ifndef RWF_SYNC
#define RWF_SYNC	0x00000004
#endif
#ifndef RWF_NOWAIT
#define RWF_NOWAIT	0x00000008
#endif
#ifndef RWF_APPEND
#define RWF_APPEND	0x00000010
#endif
#ifndef RWF_NOAPPEND
#define RWF_NOAPPEND	0x00000020
#endif
#ifndef RWF_ATOMIC
#define RWF_ATOMIC	0x00000040
#endif
#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE	0x00000080
#endif

#define IOCB_RWF_MASK \
	(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | \
	 RWF_NOAPPEND | RWF_ATOMIC | RWF_DONTCACHE)

/*
 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
 *           struct io_event __user *result)
 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns the
 * live fill (memset, aio_lio_opcode = IOCB_CMD_PREAD, fd from
 * get_random_fd(), aio_buf via get_writable_address, optional pool
 * pin from OBJ_AIO_IOCB).  Attribution-only registration lets
 * struct_field_for_cmp steer KCOV-CMP learned constants at the named
 * opcode / flags / fd slots rather than at a coincidentally-same-width
 * slot.  Same shape as the timespec / siginfo_t entries above.
 *
 * Signed fields stay FT_RAW: FT_RANGE only carries an unsigned [lo, hi]
 * range, so aio_reqprio (__s16) and aio_offset (__s64) keep the
 * historical per-field random splat to preserve negative-value coverage.
 *
 * aio_key is documented as kernel-written ("the kernel sets aio_key to
 * the req #"), so FT_RAW avoids attributing CMP constants to bytes we
 * stamp but the kernel overwrites.
 */
static const struct struct_field iocb_fields[] = {
	FIELD(struct iocb, aio_data),
	FIELD(struct iocb, aio_key),
	FIELDX(struct iocb, aio_rw_flags, FT_FLAGS,
	       .u.flags.mask = IOCB_RWF_MASK,
	       .mutate_weight = 80),
	FIELDX(struct iocb, aio_lio_opcode, FT_ENUM,
	       .u.enum_ = { iocb_opcode_values,
			    ARRAY_SIZE(iocb_opcode_values) },
	       .mutate_weight = 100),
	FIELD(struct iocb, aio_reqprio),
	FIELDX(struct iocb, aio_fildes, FT_FD,
	       .mutate_weight = 80),
	FIELD(struct iocb, aio_buf),
	FIELD(struct iocb, aio_nbytes),
	FIELD(struct iocb, aio_offset),
	FIELD(struct iocb, aio_reserved2),
	FIELDX(struct iocb, aio_flags, FT_FLAGS,
	       .u.flags.mask = IOCB_FLAGS_MASK,
	       .mutate_weight = 80),
	FIELDX(struct iocb, aio_resfd, FT_FD,
	       .mutate_weight = 60),
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

static const struct struct_field io_uring_register_pbuf_ring_fields[] = {
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

static const struct struct_field io_uring_register_sync_cancel_fields[] = {
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
static const unsigned long io_uring_restriction_opcodes[] = {
	IORING_RESTRICTION_REGISTER_OP,
	IORING_RESTRICTION_SQE_OP,
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
};

static const struct struct_field io_uring_register_restriction_fields[] = {
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
static const unsigned long io_uring_napi_opcodes[] = {
	IO_URING_NAPI_REGISTER_OP,
	IO_URING_NAPI_STATIC_ADD_ID,
	IO_URING_NAPI_STATIC_DEL_ID,
};

static const unsigned long io_uring_napi_tracking_strategies[] = {
	IO_URING_NAPI_TRACKING_DYNAMIC,
	IO_URING_NAPI_TRACKING_STATIC,
	IO_URING_NAPI_TRACKING_INACTIVE,
};

static const struct struct_field io_uring_register_napi_fields[] = {
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
static const unsigned long io_uring_clock_ids[] = {
	CLOCK_MONOTONIC,
	CLOCK_BOOTTIME,
};

static const struct struct_field io_uring_register_clock_fields[] = {
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

static const struct struct_field io_uring_register_clone_buffers_fields[] = {
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
static const struct struct_field io_uring_register_pbuf_status_fields[] = {
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

static const struct struct_field io_uring_register_rsrc_register_fields[] = {
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
static const struct struct_field io_uring_register_rsrc_update2_fields[] = {
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
static const struct struct_field io_uring_register_probe_fields[] = {
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
_Static_assert(sizeof(struct io_uring_rsrc_update) <= 64,
	"io_uring_register variant FILES_UPDATE exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_file_index_range) <= 64,
	"io_uring_register variant FILE_ALLOC_RANGE exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_buf_reg) <= 64,
	"io_uring_register variant PBUF_RING exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_buf_reg) <= 64,
	"io_uring_register variant UNREGISTER_PBUF_RING exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_sync_cancel_reg) <= 64,
	"io_uring_register variant SYNC_CANCEL exceeds struct_size 64");
_Static_assert(sizeof(struct iovec) <= 64,
	"io_uring_register variant BUFFERS exceeds struct_size 64");
_Static_assert(sizeof(struct iovec) <= 64,
	"io_uring_register variant UNREGISTER_BUFFERS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_restriction) <= 64,
	"io_uring_register variant RESTRICTIONS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_update) <= 64,
	"io_uring_register variant RING_FDS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_update) <= 64,
	"io_uring_register variant UNREGISTER_RING_FDS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_napi) <= 64,
	"io_uring_register variant NAPI exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_napi) <= 64,
	"io_uring_register variant UNREGISTER_NAPI exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_clock_register) <= 64,
	"io_uring_register variant CLOCK exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_clone_buffers) <= 64,
	"io_uring_register variant CLONE_BUFFERS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_buf_status) <= 64,
	"io_uring_register variant PBUF_STATUS exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_register) <= 64,
	"io_uring_register variant FILES2 exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_register) <= 64,
	"io_uring_register variant BUFFERS2 exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_update2) <= 64,
	"io_uring_register variant FILES_UPDATE2 exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_rsrc_update2) <= 64,
	"io_uring_register variant BUFFERS_UPDATE exceeds struct_size 64");
_Static_assert(sizeof(struct io_uring_probe) <= 64,
	"io_uring_register variant PROBE exceeds struct_size 64");

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
 * excl_prog_hash_size) are intentionally not annotated; adding
 * offsetof references against a union member the header doesn't
 * declare would break the build on older distros, and the kernel
 * still accepts a zero-fill in those bytes.
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
 *   - insns + insn_cnt as FT_BPF_PROGRAM/FT_LEN_COUNT.  Fill delegates
 *     to net/ebpf.c's three-tier generator (~50% valid, 25% boundary,
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
static const struct struct_field bpf_attr_PROG_LOAD_fields[] = {
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
 * Intentionally skipped.
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
static const char *const bpf_attr_query_arrays[] = {
	"query.prog_ids",
	"query.prog_attach_flags",
	"query.link_ids",
	"query.link_attach_flags",
};

static const struct struct_field bpf_attr_QUERY_fields[] = {
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
static const struct struct_field bpf_attr_TASK_FD_QUERY_fields[] = {
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
static const struct struct_field bpf_attr_BTF_LOAD_fields[] = {
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
static const char *const bpf_attr_batch_arrays[] = {
	"batch.keys",
	"batch.values",
};

#define BATCH_ELEM_FLAGS_MASK \
	(BPF_ANY | BPF_NOEXIST | BPF_EXIST | BPF_F_LOCK)

static const struct struct_field bpf_attr_BATCH_fields[] = {
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

static const struct struct_field bpf_attr_TEST_fields[] = {
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
static const struct struct_field bpf_attr_INFO_fields[] = {
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
static const struct struct_field bpf_attr_RAW_TRACEPOINT_fields[] = {
	FIELDX(union bpf_attr, raw_tracepoint.name, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.max_bytes = 64 }),
	FIELDX(union bpf_attr, raw_tracepoint.prog_fd, FT_FD),
	FIELD(union bpf_attr, raw_tracepoint.cookie),
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
static const struct struct_field bpf_attr_LINK_CREATE_fields[] = {
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
static const struct struct_field bpf_attr_LINK_CREATE_BASE_fields[] = {
	FIELD(union bpf_attr, link_create.target_btf_id),
};

static const struct union_variant bpf_attr_LINK_CREATE_base = {
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

static const unsigned long bpf_attach_types_tracing[] = {
	BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN,
	BPF_LSM_MAC, BPF_LSM_CGROUP, BPF_TRACE_RAW_TP,
	BPF_TRACE_FSESSION,
};

/*
 * ITER sub-variant: iter_info is a user pointer to a bpf_iter_link_info
 * blob the verifier walks; the schema fill plants random bytes so the
 * kernel's first-pass copy_from_user succeeds and the iter-type
 * dispatch runs.  iter_info_len pairs back via FT_LEN_BYTES.
 */
static const struct struct_field bpf_attr_LINK_CREATE_ITER_fields[] = {
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
static const struct struct_field bpf_attr_LINK_CREATE_PERF_EVENT_fields[] = {
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
static const struct struct_field bpf_attr_LINK_CREATE_TRACING_fields[] = {
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
static const unsigned long netfilter_pfs[] = {
	NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6,
	NFPROTO_ARP, NFPROTO_NETDEV, NFPROTO_BRIDGE,
};

static const struct struct_field bpf_attr_LINK_CREATE_NETFILTER_fields[] = {
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
static const struct struct_field bpf_attr_LINK_CREATE_TCX_fields[] = {
	FIELDX(union bpf_attr, link_create.tcx.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.tcx.expected_revision),
};

static const struct struct_field bpf_attr_LINK_CREATE_NETKIT_fields[] = {
	FIELDX(union bpf_attr, link_create.netkit.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.netkit.expected_revision),
};

static const struct struct_field bpf_attr_LINK_CREATE_CGROUP_fields[] = {
	FIELDX(union bpf_attr, link_create.cgroup.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.cgroup.expected_revision),
};

static const unsigned long bpf_attach_types_tcx[] = {
	BPF_TCX_INGRESS, BPF_TCX_EGRESS,
};

static const unsigned long bpf_attach_types_netkit[] = {
	BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
};

/*
 * CGROUP_MULTI claims every BPF_CGROUP_* attach type.  The cgroup
 * arm's inner struct is shared across all of them; per-attach
 * semantics live in kernel/bpf/cgroup.c and don't affect the wire
 * shape sanitise produces.
 */
static const unsigned long bpf_attach_types_cgroup[] = {
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
static const unsigned long bpf_attach_types_kprobe_multi[] = {
	BPF_TRACE_KPROBE_MULTI, BPF_TRACE_KPROBE_SESSION,
};

static const char *const bpf_attr_link_create_kprobe_multi_arrays[] = {
	"link_create.kprobe_multi.syms",
	"link_create.kprobe_multi.addrs",
	"link_create.kprobe_multi.cookies",
};

static const struct struct_field bpf_attr_LINK_CREATE_KPROBE_MULTI_fields[] = {
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

static const unsigned long bpf_attach_types_uprobe_multi[] = {
	BPF_TRACE_UPROBE_MULTI, BPF_TRACE_UPROBE_SESSION,
};

static const char *const bpf_attr_link_create_uprobe_multi_arrays[] = {
	"link_create.uprobe_multi.offsets",
	"link_create.uprobe_multi.ref_ctr_offsets",
	"link_create.uprobe_multi.cookies",
};

static const struct struct_field bpf_attr_LINK_CREATE_UPROBE_MULTI_fields[] = {
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
static const struct union_variant bpf_attr_LINK_CREATE_nested[] = {
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
};

/*
 * bpf_insn registration -- retained as an 8-byte CMP-attribution shape
 * so a learned KCOV-compare constant on code / off / imm can be
 * attributed back to the right field by struct_field_for_cmp().
 * PROG_LOAD's insns FILL now flows through FT_BPF_PROGRAM (which calls
 * net/ebpf.c's generator) rather than splatting random bpf_insn
 * elements via FT_PTR_ARRAY, but the per-field shape is still the
 * vocabulary the CMP-hint path reasons over.
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
		.effective_size	= offsetof(union bpf_attr, fd_by_id_token_fd) +
				  sizeof(((union bpf_attr *)NULL)->fd_by_id_token_fd),
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
	{
		.discrim_value	= BPF_PROG_STREAM_READ_BY_FD,
		.name		= "PROG_STREAM_READ_BY_FD",
		.fields		= bpf_attr_PROG_STREAM_READ_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_PROG_STREAM_READ_fields),
		.effective_size	= sizeof(((union bpf_attr *)NULL)->prog_stream_read),
	},
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
#endif

/* ------------------------------------------------------------------ */
/* setsockopt optval shapes -- proof batch for the two-key             */
/* (level, optname) discriminator.  Five shapes already owned by       */
/* bespoke build_*() functions in syscalls/setsockopt.c, registered    */
/* here so apply_sockopt_entry()'s explicit-key lookup resolves them   */
/* and struct_field_fill_schema_aware() takes over the fill.  Bespoke  */
/* builders stay in code as the miss-fallback for the int / bool /    */
/* string scalar entries (no struct shape to catalog) and for the     */
/* higher-leverage shapes that have not been migrated yet (sctp /     */
/* mptcp / tcp_repair / can_filter[] etc.); coverage on those paths   */
/* is byte-identical to before until their rows land.                 */
/* ------------------------------------------------------------------ */

/*
 * struct linger -- SOL_SOCKET / SO_LINGER.  l_onoff is a boolean
 * (kernel masks to 0/1); l_linger is a small positive lingertime in
 * seconds (bespoke build_linger() drew 0..59).  Both pin cleanly to
 * FT_RANGE so the schema fill produces values inside the legal window
 * the bespoke builder did, and struct_field_for_cmp() can attribute
 * KCOV-CMP constants at the named slots rather than at a
 * coincidentally-same-width neighbour.
 */
static const struct struct_field linger_fields[] = {
	FIELDX(struct linger, l_onoff, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct linger, l_linger, FT_RANGE,
	       .u.range = { 0, 60 },
	       .mutate_weight = 60),
};

/*
 * struct ip_mreqn -- IPPROTO_IP / IP_{ADD,DROP}_MEMBERSHIP and
 * IP_MULTICAST_IF.  Bespoke build_ip_mreqn() seeded imr_multiaddr in
 * the 224.0.0.0/4 multicast range and zeroed imr_address / imr_ifindex
 * (kernel-default interface).  The three fields stay FT_RAW for the
 * proof: imr_multiaddr is __be32, so schema fill in host byte order
 * produces a multicast address only ~1/16 of the time vs the bespoke
 * builder's 100%, and FT_MAGIC -- the natural tag for curated
 * be32 vocab -- still falls through to FT_RAW in the fill switch
 * today.  The miss-fallback option is GONE for
 * the cataloged (level, optname) tuples once this row registers, so
 * the multicast-bias regression is the price of the proof; a follow-up
 * implementing FT_MAGIC (or a be32-aware range tag) restores it
 * without touching this entry.
 */
static const struct struct_field ip_mreqn_fields[] = {
	FIELD(struct ip_mreqn, imr_multiaddr),
	FIELD(struct ip_mreqn, imr_address),
	FIELD(struct ip_mreqn, imr_ifindex),
};

/*
 * struct ipv6_mreq -- IPPROTO_IPV6 / IPV6_{ADD,DROP}_MEMBERSHIP.
 * Bespoke build_ipv6_mreq() set ipv6mr_multiaddr to a link-local
 * solicited-node address (ff02::xx) and zeroed ipv6mr_interface.
 * ipv6mr_multiaddr is struct in6_addr (16 bytes); fill_field_raw
 * leaves wider-than-4-byte fields at the buffer's initial fill, which
 * is zero from zmalloc, so the schema fill produces the IPv6 "any"
 * address rather than a link-local multicast group.  Same FT_MAGIC
 * follow-up applies; for the proof the row registers and we accept
 * that 16-byte multicast biasing is on the schema-fill TODO list.
 */
static const struct struct_field ipv6_mreq_fields[] = {
	FIELD(struct ipv6_mreq, ipv6mr_multiaddr),
	FIELD(struct ipv6_mreq, ipv6mr_interface),
};

/*
 * struct packet_mreq -- SOL_PACKET / PACKET_{ADD,DROP}_MEMBERSHIP.
 * Bespoke build_packet_mreq() set mr_ifindex=1 (default-ish), mr_type
 * in [1..4] (which over-shoots PACKET_MR_UNICAST=3 and under-shoots
 * PACKET_MR_MULTICAST=0), mr_alen=6 (ethernet), and random bytes in
 * mr_address[8].  FT_ENUM on mr_type pins it to the four actually-
 * valid PACKET_MR_* values -- a strict improvement over the bespoke
 * draw.  mr_ifindex / mr_alen go FT_RANGE so the schema fill stays
 * close to the bespoke window.  mr_address[8] keeps FT_RAW and falls
 * to "left at initial fill" (zero) the same way ipv6_mreq's 16-byte
 * addr does; bespoke set random bytes there, so this is a regression
 * for that field specifically and the same FT_MAGIC follow-up applies.
 */
static const unsigned long packet_mreq_type_values[] = {
	PACKET_MR_MULTICAST,
	PACKET_MR_PROMISC,
	PACKET_MR_ALLMULTI,
	PACKET_MR_UNICAST,
};

static const struct struct_field packet_mreq_fields[] = {
	FIELDX(struct packet_mreq, mr_ifindex, FT_RANGE,
	       .u.range = { 0, 4 },
	       .mutate_weight = 60),
	FIELDX(struct packet_mreq, mr_type, FT_ENUM,
	       .u.enum_ = { packet_mreq_type_values,
			    ARRAY_SIZE(packet_mreq_type_values) },
	       .mutate_weight = 80),
	FIELDX(struct packet_mreq, mr_alen, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 40),
	FIELD(struct packet_mreq, mr_address),
};

#ifdef USE_SCTP
/*
 * struct sctp_initmsg -- IPPROTO_SCTP / SCTP_INITMSG.  Four __u16 fields
 * controlling SCTP association init params.  Stream counts bound to
 * [0, 128] (the kernel caps max_instreams/num_ostreams well below this in
 * practice), max_attempts bounded to a sane small INIT retry count, and
 * max_init_timeo bounded to a millisecond window matching the SCTP RTO
 * envelope.  Bespoke build_sctp_initmsg() zero-fills as a miss-fallback;
 * the schema fill above produces values inside the kernel's accept window
 * and lets struct_field_for_cmp() attribute KCOV-CMP constants at the
 * named slots.
 */
static const struct struct_field sctp_initmsg_fields[] = {
	FIELDX(struct sctp_initmsg, sinit_num_ostreams, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_initmsg, sinit_max_instreams, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_initmsg, sinit_max_attempts, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 40),
	FIELDX(struct sctp_initmsg, sinit_max_init_timeo, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 40),
};

/*
 * struct sctp_rtoinfo -- IPPROTO_SCTP / SCTP_RTOINFO.  Carries the SCTP
 * RTO (retransmission timeout) envelope for an association: assoc_id
 * picks the target association (FT_RAW lets KCOV-CMP attribution catch
 * the kernel's lookup constant) and three __u32 millisecond fields
 * (initial / max / min) bounded to [0, 60000] -- a window wide enough to
 * exercise the kernel's clamp logic without flooding it with absurd
 * values.  Bespoke build_sctp_rtoinfo() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_rtoinfo_fields[] = {
	FIELDX(struct sctp_rtoinfo, srto_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_initial, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_max, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_rtoinfo, srto_min, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_assocparams -- IPPROTO_SCTP / SCTP_ASSOCINFO.  Examines
 * and sets various per-association and endpoint parameters.  sasoc_assoc_id
 * picks the target association (FT_RAW so the per-field splat continues to
 * drive the association lookup and struct_field_for_cmp() can attribute
 * KCOV-CMP constants).  sasoc_asocmaxrxt is the association-level max
 * retransmit (FT_RANGE [0, 16] keeps it within plausible retry budgets).
 * sasoc_number_peer_destinations / sasoc_peer_rwnd / sasoc_local_rwnd
 * are FT_RAW (peer-count and window-byte counters with no useful clamp).
 * sasoc_cookie_life is the cookie lifetime in milliseconds, FT_RANGE
 * [0, 60000] to exercise the kernel's clamp without flooding the input
 * validator.  Bespoke build_sctp_assocparams() zero-fills as a
 * miss-fallback.
 */
static const struct struct_field sctp_assocparams_fields[] = {
	FIELDX(struct sctp_assocparams, sasoc_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_assocparams, sasoc_asocmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_assocparams, sasoc_number_peer_destinations, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_peer_rwnd, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_local_rwnd, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_assocparams, sasoc_cookie_life, FT_RANGE,
	       .u.range = { 0, 60000 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_setadaptation -- IPPROTO_SCTP / SCTP_ADAPTATION_LAYER.
 * RFC 5061 / RFC 5062 indication value advertised to the peer at
 * association setup; the kernel stores it verbatim and echoes it back
 * in the ADAPTATION-INDICATION parameter.  Single member
 * ssb_adaptation_ind (__u32) is FT_RAW -- arbitrary peer-visible
 * cookie with no useful clamp.  Bespoke build_sctp_setadaptation()
 * zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_setadaptation_fields[] = {
	FIELDX(struct sctp_setadaptation, ssb_adaptation_ind, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_assoc_value -- IPPROTO_SCTP / { SCTP_CONTEXT, SCTP_MAXSEG,
 * SCTP_MAX_BURST, SCTP_STREAM_SCHEDULER }.  Two-field carrier shared by
 * several sockopts that take an (assoc_id, value) pair: assoc_id picks
 * the target association (FT_RAW so the per-field splat continues to
 * drive the association lookup and struct_field_for_cmp() can attribute
 * KCOV-CMP constants), assoc_value is the per-optname payload (FT_RAW --
 * value semantics differ per optname: SCTP_CONTEXT is an opaque cookie,
 * SCTP_MAXSEG / SCTP_MAX_BURST / SCTP_STREAM_SCHEDULER are small integers
 * with kernel-side clamping, so a single FT_RANGE wouldn't fit all four).
 * Bespoke build_sctp_assoc_value() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_assoc_value_fields[] = {
	FIELDX(struct sctp_assoc_value, assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_assoc_value, assoc_value, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sndinfo -- IPPROTO_SCTP / SCTP_DEFAULT_SNDINFO.  RFC 6458
 * default per-stream send parameters: snd_sid picks the target stream
 * (FT_RANGE [0, 128] matches the SCTP_INITMSG stream-count envelope and
 * keeps the value inside the kernel's accept window).  snd_flags is a
 * bitfield drawn from the SCTP send-flag set (UNORDERED / ADDR_OVER /
 * ABORT / SACK_IMMEDIATELY / SENDALL / EOF), masked so the splat lands
 * on plausible combinations rather than random 16-bit noise.  snd_ppid
 * (peer-visible payload protocol id), snd_context (opaque per-message
 * cookie), and snd_assoc_id (association lookup key) are FT_RAW -- each
 * is either peer-visible / opaque or a lookup constant that
 * struct_field_for_cmp() can attribute against KCOV-CMP.  Bespoke
 * build_sctp_sndinfo() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_sndinfo_fields[] = {
	FIELDX(struct sctp_sndinfo, snd_sid, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndinfo, snd_flags, FT_FLAGS,
	       .u.flags.mask = (SCTP_UNORDERED | SCTP_ADDR_OVER |
				SCTP_ABORT | SCTP_SACK_IMMEDIATELY |
				SCTP_SENDALL | SCTP_EOF),
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndinfo, snd_ppid, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndinfo, snd_context, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndinfo, snd_assoc_id, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sndrcvinfo -- IPPROTO_SCTP / SCTP_DEFAULT_SEND_PARAM.  The
 * legacy default-send-parameters struct (RFC 6458's older sndrcvinfo);
 * sinfo_stream picks the target stream (FT_RANGE [0, 128] matches the
 * SCTP_INITMSG stream-count envelope and keeps the value inside the
 * kernel's accept window).  sinfo_flags is a bitfield drawn from the
 * SCTP send-flag set (UNORDERED / ADDR_OVER / ABORT / SACK_IMMEDIATELY
 * / SENDALL / EOF), masked so the splat lands on plausible combinations
 * rather than random 16-bit noise.  sinfo_ssn / sinfo_ppid /
 * sinfo_context / sinfo_timetolive / sinfo_tsn / sinfo_cumtsn /
 * sinfo_assoc_id are FT_RAW -- each is either peer-visible / opaque or
 * a lookup constant that struct_field_for_cmp() can attribute against
 * KCOV-CMP.  Bespoke build_sctp_sndrcvinfo() zero-fills as a
 * miss-fallback.
 */
static const struct struct_field sctp_sndrcvinfo_fields[] = {
	FIELDX(struct sctp_sndrcvinfo, sinfo_stream, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndrcvinfo, sinfo_ssn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_flags, FT_FLAGS,
	       .u.flags.mask = (SCTP_UNORDERED | SCTP_ADDR_OVER |
				SCTP_ABORT | SCTP_SACK_IMMEDIATELY |
				SCTP_SENDALL | SCTP_EOF),
	       .mutate_weight = 60),
	FIELDX(struct sctp_sndrcvinfo, sinfo_ppid, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_context, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_timetolive, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_tsn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_cumtsn, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_sndrcvinfo, sinfo_assoc_id, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_event_subscribe -- IPPROTO_SCTP / SCTP_EVENTS.  Legacy
 * notification-subscription bitmap (RFC 6458's older event-subscribe
 * predecessor to SCTP_EVENT) consisting of one __u8 boolean per
 * notification type.  Each field is FT_RANGE [0, 1] so the per-field
 * splat lands on the in-spec 0/1 values rather than random byte noise;
 * the kernel's setsockopt parser tolerates any non-zero byte as "on",
 * but staying inside [0, 1] keeps the request realistic and gives
 * struct_field_for_cmp() a clean constant to attribute against
 * KCOV-CMP.  Bespoke build_sctp_events() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_event_subscribe_fields[] = {
	FIELDX(struct sctp_event_subscribe, sctp_data_io_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_association_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_address_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_send_failure_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_peer_error_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_shutdown_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_partial_delivery_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_adaptation_layer_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_authentication_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_sender_dry_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_stream_reset_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_assoc_reset_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_stream_change_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
	FIELDX(struct sctp_event_subscribe, sctp_send_failure_event_event, FT_RANGE,
	       .u.range = { 0, 1 }, .mutate_weight = 50),
};

/*
 * struct sctp_authchunk -- IPPROTO_SCTP / SCTP_AUTH_CHUNK.  RFC 4895
 * AUTH extension: register a chunk type whose receipt the local
 * endpoint requires to be carried inside an AUTH chunk.  Single
 * member sauth_chunk (__u8) is FT_RAW -- arbitrary chunk-type id; the
 * kernel validates against its own chunk-type table at sockopt time
 * and ignores anything it does not recognise, so no useful clamp.
 * Bespoke build_sctp_authchunk() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_authchunk_fields[] = {
	FIELDX(struct sctp_authchunk, sauth_chunk, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_sack_info -- IPPROTO_SCTP / SCTP_DELAYED_SACK (the canonical
 * spelling; SCTP_DELAYED_ACK / SCTP_DELAYED_ACK_TIME alias the same
 * optname value 16).  RFC 6458 delayed-SACK tuning: sack_assoc_id picks
 * the target association (FT_RAW so the kernel's per-assoc lookup
 * constant shows up to KCOV-CMP), sack_delay is the delayed-ack timer
 * in ms bounded to [0, 500] -- the kernel rejects values above
 * SCTP_MAX_DELAY_VALUE (500ms) outright, so staying inside the window
 * exercises the timer-arm path rather than the EINVAL early-out, and
 * sack_freq is the every-Nth-packet ack frequency bounded to [0, 16]
 * which keeps the kernel's freq counter inside a realistic envelope
 * without flooding the SACK-immediate path.  Bespoke build_sctp_sackinfo()
 * zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_sack_info_fields[] = {
	FIELDX(struct sctp_sack_info, sack_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_sack_info, sack_delay, FT_RANGE,
	       .u.range = { 0, 500 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_sack_info, sack_freq, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_authkeyid -- IPPROTO_SCTP / SCTP_AUTH_{ACTIVE,DELETE,
 * DEACTIVATE}_KEY.  RFC 4895 AUTH key management: scact_assoc_id picks
 * the target association (FT_RAW so the kernel's per-assoc lookup
 * constant shows up to KCOV-CMP), scact_keynumber is the shared-key
 * identifier bounded to [0, 8] -- realistic for the small set of keys an
 * endpoint typically provisions while still exercising the lookup path.
 * Bespoke build_sctp_authkeyid() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_authkeyid_fields[] = {
	FIELDX(struct sctp_authkeyid, scact_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_authkeyid, scact_keynumber, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_default_prinfo -- IPPROTO_SCTP / SCTP_DEFAULT_PRINFO.
 * RFC 7496 PR-SCTP default policy carrier: pr_assoc_id selects the
 * target association (FT_RAW so the per-assoc lookup constant shows
 * up to KCOV-CMP), pr_value is the policy-specific lifetime / retx
 * limit / priority cookie (FT_RAW -- semantics differ per policy and
 * the kernel does not clamp), and pr_policy is the small 4-valued
 * vocab the kernel branches on in sctp_set_default_prinfo() (FT_ENUM
 * over SCTP_PR_SCTP_{NONE,TTL,RTX,PRIO} keeps the mutator inside the
 * legal shape -- any other value is rejected with -EINVAL).  Bespoke
 * build_sctp_default_prinfo() zero-fills as a miss-fallback.
 */
static const unsigned long sctp_default_prinfo_policy_values[] = {
	SCTP_PR_SCTP_NONE, SCTP_PR_SCTP_TTL,
	SCTP_PR_SCTP_RTX,  SCTP_PR_SCTP_PRIO,
};

static const struct struct_field sctp_default_prinfo_fields[] = {
	FIELDX(struct sctp_default_prinfo, pr_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_default_prinfo, pr_value, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_default_prinfo, pr_policy, FT_ENUM,
	       .u.enum_ = { sctp_default_prinfo_policy_values,
			    ARRAY_SIZE(sctp_default_prinfo_policy_values) },
	       .mutate_weight = 80),
};

/*
 * struct sctp_add_streams -- IPPROTO_SCTP / SCTP_ADD_STREAMS.  RFC 6525
 * dynamic stream reconfiguration: sas_assoc_id picks the target
 * association (FT_RAW so the kernel's per-assoc lookup constant shows
 * up to KCOV-CMP) while sas_instrms / sas_outstrms request how many
 * additional inbound / outbound streams to negotiate, bounded to
 * [0, 128] -- the kernel branches on (current + requested) overflowing
 * 16 bits and on the peer's RECONF capability, so staying inside a
 * realistic envelope exercises the negotiation path rather than the
 * EINVAL early-out.  Bespoke build_sctp_add_streams() zero-fills as a
 * miss-fallback.
 */
static const struct struct_field sctp_add_streams_fields[] = {
	FIELDX(struct sctp_add_streams, sas_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_add_streams, sas_instrms, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_add_streams, sas_outstrms, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_stream_value -- IPPROTO_SCTP / SCTP_STREAM_SCHEDULER_VALUE.
 * Per-stream scheduler parameter carrier: assoc_id selects the
 * association (FT_RAW so the kernel's per-assoc lookup constant shows
 * up to KCOV-CMP), stream_id picks the target stream bounded to
 * [0, 128] matching the SCTP_INITMSG stream-count envelope, and
 * stream_value is the scheduler-specific opaque cookie (FT_RAW; the
 * kernel's interpretation varies by active scheduler so no useful
 * clamp).  Bespoke build_sctp_stream_value() zero-fills as a
 * miss-fallback.
 */
static const struct struct_field sctp_stream_value_fields[] = {
	FIELDX(struct sctp_stream_value, assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_stream_value, stream_id, FT_RANGE,
	       .u.range = { 0, 128 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_stream_value, stream_value, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_event -- IPPROTO_SCTP / SCTP_EVENT.  RFC 6458 generic
 * notification-subscription opt (the modern per-event toggle that
 * superseded the legacy SCTP_EVENTS / sctp_event_subscribe bitmap):
 * se_assoc_id selects the target association (FT_RAW so the kernel's
 * per-assoc lookup constant shows up to KCOV-CMP), se_type names the
 * sctp_sn_type notification (FT_RAW -- the value list lives in the
 * SCTP_SN_TYPE_BASE = (1<<15) range rather than a contiguous small
 * enum, so the byte-noise default still hits the live span often
 * enough), and se_on is the on/off toggle clamped to [0, 1] so the
 * splat lands on the in-spec boolean rather than random noise.
 * Bespoke build_sctp_event() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_event_fields[] = {
	FIELDX(struct sctp_event, se_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_event, se_type, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_event, se_on, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 50),
};

/*
 * struct sctp_paddrthlds -- IPPROTO_SCTP / SCTP_PEER_ADDR_THLDS.  Per-
 * peer-address retransmit / partial-failure threshold opt (RFC 5062 +
 * the peer-failure draft).  spt_assoc_id picks the target association
 * (FT_RAW so the per-assoc lookup constant shows up to KCOV-CMP);
 * spt_address embeds a struct sockaddr_storage and is treated as a
 * single opaque FT_RAW blob spanning sizeof(struct sockaddr_storage)
 * -- the kernel matches it against the live peer address list rather
 * than parsing it field-wise, so the per-byte splat is the right
 * shape and field-splitting it would just give KCOV-CMP misleading
 * sub-field offsets for a value that is logically atomic.
 * spt_pathmaxrxt is the per-path max retransmit (__u16, FT_RANGE
 * [0, 16] -- keeps it inside plausible retry budgets) and
 * spt_pathpfthld is the partial-failure threshold (__u16, FT_RANGE
 * [0, 16] -- same envelope).  Bespoke build_sctp_paddrthlds()
 * zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_paddrthlds_fields[] = {
	FIELDX(struct sctp_paddrthlds, spt_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds, spt_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrthlds, spt_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds, spt_pathpfthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_paddrthlds_v2 -- IPPROTO_SCTP / SCTP_PEER_ADDR_THLDS_V2.
 * Back-compat extension of struct sctp_paddrthlds adding a trailing
 * spt_pathcpthld (__u16, FT_RANGE [0, 16]) -- the per-path
 * consecutive-retransmit threshold the v2 optname carries on top of
 * the v1 layout.  Everything else mirrors v1: spt_assoc_id is FT_RAW
 * so the per-assoc lookup constant shows up to KCOV-CMP, spt_address
 * is a single opaque FT_RAW blob spanning sizeof(struct
 * sockaddr_storage), and spt_pathmaxrxt / spt_pathpfthld stay in the
 * [0, 16] envelope.  Bespoke build_sctp_paddrthlds_v2() zero-fills
 * as a miss-fallback.
 */
static const struct struct_field sctp_paddrthlds_v2_fields[] = {
	FIELDX(struct sctp_paddrthlds_v2, spt_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathpfthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrthlds_v2, spt_pathcpthld, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
};

/*
 * struct sctp_udpencaps -- IPPROTO_SCTP / SCTP_REMOTE_UDP_ENCAPS_PORT.
 * Per-peer UDP encapsulation port for SCTP-over-UDP (RFC 6951).
 * sue_assoc_id picks the target association (sctp_assoc_t / __u32,
 * FT_RAW so the per-assoc lookup constant shows up to KCOV-CMP).
 * sue_address embeds a struct sockaddr_storage and is treated as a
 * single opaque FT_RAW blob spanning sizeof(struct sockaddr_storage)
 * -- the kernel matches it against the live peer address list rather
 * than parsing it field-wise, so the per-byte splat is the right
 * shape and field-splitting it would just give KCOV-CMP misleading
 * sub-field offsets for a value that is logically atomic.  sue_port
 * is the UDP encapsulation port (__u16, network/big-endian; FT_RAW
 * to let the per-byte splat exercise both bytes without anchoring
 * KCOV-CMP at a single canonical value).  Bespoke
 * build_sctp_udpencaps() zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_udpencaps_fields[] = {
	FIELDX(struct sctp_udpencaps, sue_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_udpencaps, sue_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_udpencaps, sue_port, FT_RAW,
	       .mutate_weight = 60),
};

/*
 * struct sctp_paddrparams -- IPPROTO_SCTP / SCTP_PEER_ADDR_PARAMS.
 * Per-peer-address heartbeat / PMTU / SACK-delay parameter block
 * (RFC 6458 7.1.13).  spp_assoc_id picks the target association
 * (sctp_assoc_t / __u32, FT_RAW so the per-assoc lookup constant
 * shows up to KCOV-CMP); spp_address embeds a struct sockaddr_storage
 * and is treated as a single opaque FT_RAW blob spanning
 * sizeof(struct sockaddr_storage) -- the kernel matches it against
 * the live peer address list rather than parsing it field-wise, so
 * the per-byte splat is the right shape and field-splitting it would
 * just give KCOV-CMP misleading sub-field offsets for a value that
 * is logically atomic.  spp_hbinterval / spp_pathmtu / spp_sackdelay
 * are __u32 timer/MTU/delay knobs (FT_RAW -- letting the per-byte
 * splat exercise the full range without anchoring KCOV-CMP at a
 * single canonical value); spp_pathmaxrxt is __u16, FT_RANGE
 * [0, 16] -- keeps it inside plausible retry budgets matching the
 * paddrthlds rows.  spp_flags is the SPP_* bitset and is masked to
 * the documented bit set (SPP_HB_{ENABLE,DISABLE,DEMAND},
 * SPP_PMTUD_{ENABLE,DISABLE}, SPP_SACKDELAY_{ENABLE,DISABLE},
 * SPP_HB_TIME_IS_ZERO, SPP_IPV6_FLOWLABEL, SPP_DSCP).
 * spp_ipv6_flowlabel (__u32) and spp_dscp (__u8) are RAW.  The
 * struct is packed,aligned(4) -- compiler-derived offsetof() in
 * FIELDX honors the packing.  Bespoke build_sctp_paddrparams()
 * zero-fills as a miss-fallback.
 */
static const struct struct_field sctp_paddrparams_fields[] = {
	FIELDX(struct sctp_paddrparams, spp_assoc_id, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_address, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrparams, spp_hbinterval, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_pathmaxrxt, FT_RANGE,
	       .u.range = { 0, 16 },
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_pathmtu, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_sackdelay, FT_RAW,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_flags, FT_FLAGS,
	       .u.flags.mask = SPP_HB_ENABLE | SPP_HB_DISABLE |
			       SPP_HB_DEMAND |
			       SPP_PMTUD_ENABLE | SPP_PMTUD_DISABLE |
			       SPP_SACKDELAY_ENABLE | SPP_SACKDELAY_DISABLE |
			       SPP_HB_TIME_IS_ZERO |
			       SPP_IPV6_FLOWLABEL | SPP_DSCP,
	       .mutate_weight = 60),
	FIELDX(struct sctp_paddrparams, spp_ipv6_flowlabel, FT_RAW,
	       .mutate_weight = 40),
	FIELDX(struct sctp_paddrparams, spp_dscp, FT_RAW,
	       .mutate_weight = 40),
};
#endif

/* ------------------------------------------------------------------ */
/* The catalog itself                                                   */
/* ------------------------------------------------------------------ */

const struct struct_desc struct_catalog[] = {
	/* Slot order is immaterial -- refs use SC_X. */
	[SC_TIMEX] = {
		.name		= "timex",
		.struct_size	= sizeof(struct timex),
		.fields		= timex_fields,
		.num_fields	= ARRAY_SIZE(timex_fields),
	},
	[SC_SCHED_ATTR] = {
		.name		= "sched_attr",
		.struct_size	= sizeof(struct sched_attr),
		.fields		= sched_attr_fields,
		.num_fields	= ARRAY_SIZE(sched_attr_fields),
	},
	[SC_CLONE_ARGS] = {
		.name		= "clone_args",
		.struct_size	= sizeof(struct clone_args),
		.fields		= clone_args_fields,
		.num_fields	= ARRAY_SIZE(clone_args_fields),
	},
	[SC_IO_URING_PARAMS] = {
		.name		= "io_uring_params",
		.struct_size	= sizeof(struct io_uring_params),
		.fields		= io_uring_params_fields,
		.num_fields	= ARRAY_SIZE(io_uring_params_fields),
	},
	[SC_RLIMIT] = {
		.name		= "rlimit",
		.struct_size	= sizeof(struct rlimit),
		.fields		= rlimit_fields,
		.num_fields	= ARRAY_SIZE(rlimit_fields),
	},
	[SC_ITIMERSPEC] = {
		.name		= "itimerspec",
		.struct_size	= sizeof(struct itimerspec),
		.fields		= itimerspec_fields,
		.num_fields	= ARRAY_SIZE(itimerspec_fields),
	},
	[SC_EPOLL_EVENT] = {
		.name		= "epoll_event",
		.struct_size	= sizeof(struct epoll_event),
		.fields		= epoll_event_fields,
		.num_fields	= ARRAY_SIZE(epoll_event_fields),
	},
	[SC_PERF_EVENT_ATTR] = {
		.name			= "perf_event_attr",
		.struct_size		= sizeof(struct perf_event_attr),
		.fields			= perf_event_attr_fields,
		.num_fields		= ARRAY_SIZE(perf_event_attr_fields),
		.variants		= perf_event_attr_variants,
		.num_variants		= ARRAY_SIZE(perf_event_attr_variants),
		.buffer_discrim_offset	= offsetof(struct perf_event_attr, type),
		.buffer_discrim_size	= sizeof(((struct perf_event_attr *) 0)->
						 type),
	},
	[SC_SIGACTION] = {
		.name		= "sigaction",
		.struct_size	= sizeof(struct sigaction),
		.fields		= sigaction_fields,
		.num_fields	= ARRAY_SIZE(sigaction_fields),
	},
	[SC_MSGHDR] = {
		.name		= "msghdr",
		.struct_size	= sizeof(struct msghdr),
		.fields		= msghdr_fields,
		.num_fields	= ARRAY_SIZE(msghdr_fields),
	},
	[SC_SOCKADDR_STORAGE] = {
		.name			= "sockaddr_storage",
		.struct_size		= sizeof(struct sockaddr_storage),
		.fields			= sockaddr_storage_fields,
		.num_fields		= ARRAY_SIZE(sockaddr_storage_fields),
		.variants		= sockaddr_storage_variants,
		.num_variants		= ARRAY_SIZE(sockaddr_storage_variants),
		.buffer_discrim_offset	= offsetof(struct sockaddr_storage,
						   ss_family),
		.buffer_discrim_size	= sizeof(((struct sockaddr_storage *) 0)->
						 ss_family),
	},
	[SC_LANDLOCK_RULESET_ATTR] = {
		.name		= "landlock_ruleset_attr",
		.struct_size	= sizeof(struct landlock_ruleset_attr),
		.fields		= landlock_ruleset_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_ruleset_attr_fields),
	},
	[SC_MNT_ID_REQ] = {
		.name		= "mnt_id_req",
		.struct_size	= sizeof(struct mnt_id_req),
		.fields		= mnt_id_req_fields,
		.num_fields	= ARRAY_SIZE(mnt_id_req_fields),
	},
	[SC_USER_CAP_HEADER] = {
		.name		= "user_cap_header",
		.struct_size	= sizeof(struct __user_cap_header_struct),
		.fields		= user_cap_header_fields,
		.num_fields	= ARRAY_SIZE(user_cap_header_fields),
	},
	[SC_USER_CAP_DATA] = {
		.name		= "user_cap_data",
		.struct_size	= sizeof(struct __user_cap_data_struct),
		.fields		= user_cap_data_fields,
		.num_fields	= ARRAY_SIZE(user_cap_data_fields),
	},
	[SC_FUTEX_WAITV] = {
		.name		= "futex_waitv",
		.struct_size	= sizeof(struct futex_waitv),
		.fields		= futex_waitv_fields,
		.num_fields	= ARRAY_SIZE(futex_waitv_fields),
	},
	[SC_STACK_T] = {
		.name		= "stack_t",
		.struct_size	= sizeof(stack_t),
		.fields		= stack_t_fields,
		.num_fields	= ARRAY_SIZE(stack_t_fields),
	},
	[SC_SIGINFO_T] = {
		.name			= "siginfo_t",
		.struct_size		= sizeof(siginfo_t),
		.fields			= siginfo_t_fields,
		.num_fields		= ARRAY_SIZE(siginfo_t_fields),
		.variants		= siginfo_t_variants,
		.num_variants		= ARRAY_SIZE(siginfo_t_variants),
		.buffer_discrim_offset	= offsetof(siginfo_t, si_code),
		.buffer_discrim_size	= sizeof(((siginfo_t *) 0)->si_code),
	},
	[SC_MQ_ATTR] = {
		.name		= "mq_attr",
		.struct_size	= sizeof(struct mq_attr),
		.fields		= mq_attr_fields,
		.num_fields	= ARRAY_SIZE(mq_attr_fields),
	},
	[SC_MSQID_DS] = {
		.name		= "msqid_ds",
		.struct_size	= sizeof(struct msqid_ds),
		.fields		= msqid_ds_fields,
		.num_fields	= ARRAY_SIZE(msqid_ds_fields),
	},
	[SC_SCHED_PARAM] = {
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
	 * no truly-common fields.  Variants are populated per-opcode; not
	 * all opcodes are covered yet.
	 *
	 * struct_size is set to the largest projected variant
	 * (io_uring_sync_cancel_reg @ 64 bytes) so the buffer fed to the
	 * fill path is never too small for any single-struct opcode.
	 *
	 * No live consumer wires this entry today: io_uring_register's
	 * arg slot is ARG_ADDRESS (not ARG_STRUCT_PTR_*) and the existing
	 * sanitise_io_uring_register hand-rolls every opcode's payload.
	 * The entry is forward infra for opcode-scoped CMP attribution
	 * (struct_field_for_cmp pending a cmp_hints caller) and a future
	 * ARG_ADDRESS-mapped fill consumer.  The bpf catalog landed the
	 * same way: variant data first, sanitise caller after.
	 */
	[SC_IO_URING_REGISTER_ARGS] = {
		.name			= "io_uring_register_args",
		.struct_size		= 64,
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 2,	/* opcode in rec->a2 */
		.variants		= io_uring_register_variants,
		.num_variants		= ARRAY_SIZE(io_uring_register_variants),
	},
#ifdef USE_BPF
	[SC_BPF_ATTR] = {
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
	 * bpf_insn registered for name lookup only -- kept as a CMP-
	 * attribution shape (code / off / imm) so KCOV-compare learned
	 * constants can be attributed to the right field.  No
	 * syscall_struct_args entry; PROG_LOAD's insns now flows through
	 * FT_BPF_PROGRAM rather than FT_PTR_ARRAY.elem_struct.
	 */
	[SC_BPF_INSN] = {
		.name		= "bpf_insn",
		.struct_size	= sizeof(struct bpf_insn),
		.fields		= bpf_insn_fields,
		.num_fields	= ARRAY_SIZE(bpf_insn_fields),
	},
#endif
	/*
	 * iovec: referenced by msghdr.msg_iov's FT_PTR_ARRAY.elem_struct
	 * so the pointer pass can resolve sizeof(struct iovec) for
	 * allocation, and also named at the iovec-array slot of the
	 * readv / writev / preadv{,2} / pwritev{,2} / vmsplice /
	 * process_madvise / process_vm_{readv,writev} syscalls via
	 * syscall_struct_args[] below.  Those slots are ARG_IOVEC /
	 * ARG_IOVEC_IN (not ARG_STRUCT_PTR_*), so the schema-aware fill
	 * path never runs against them -- the bespoke alloc_iovec()
	 * generator owns the live (iov_base, iov_len) layout.  The
	 * mapping is attribution-only: it lets struct_field_for_cmp()
	 * steer CMP-learned constants at the named iov_base / iov_len
	 * slots rather than at a coincidentally-same-width slot.
	 */
	[SC_IOVEC] = {
		.name		= "iovec",
		.struct_size	= sizeof(struct iovec),
		.fields		= iovec_fields,
		.num_fields	= ARRAY_SIZE(iovec_fields),
	},
	[SC_TIMESPEC] = {
		.name		= "timespec",
		.struct_size	= sizeof(struct timespec),
		.fields		= timespec_fields,
		.num_fields	= ARRAY_SIZE(timespec_fields),
	},
	[SC_CACHESTAT_RANGE] = {
		.name		= "cachestat_range",
		.struct_size	= sizeof(struct cachestat_range),
		.fields		= cachestat_range_fields,
		.num_fields	= ARRAY_SIZE(cachestat_range_fields),
	},
	[SC_MOUNT_ATTR] = {
		.name		= "mount_attr",
		.struct_size	= sizeof(struct mount_attr),
		.fields		= mount_attr_fields,
		.num_fields	= ARRAY_SIZE(mount_attr_fields),
	},
	[SC_SEMBUF] = {
		.name		= "sembuf",
		.struct_size	= sizeof(struct sembuf),
		.fields		= sembuf_fields,
		.num_fields	= ARRAY_SIZE(sembuf_fields),
	},
	[SC_POLLFD] = {
		.name		= "pollfd",
		.struct_size	= sizeof(struct pollfd),
		.fields		= pollfd_fields,
		.num_fields	= ARRAY_SIZE(pollfd_fields),
	},
	[SC_OPEN_HOW] = {
		.name		= "open_how",
		.struct_size	= sizeof(struct open_how),
		.fields		= open_how_fields,
		.num_fields	= ARRAY_SIZE(open_how_fields),
	},
	[SC_SIGEVENT] = {
		.name		= "sigevent",
		.struct_size	= sizeof(struct sigevent),
		.fields		= sigevent_fields,
		.num_fields	= ARRAY_SIZE(sigevent_fields),
	},
	[SC_ROBUST_LIST_HEAD] = {
		.name		= "robust_list_head",
		.struct_size	= sizeof(struct robust_list_head),
		.fields		= robust_list_head_fields,
		.num_fields	= ARRAY_SIZE(robust_list_head_fields),
	},
	[SC_RSEQ] = {
		.name		= "rseq",
		.struct_size	= sizeof(struct rseq),
		.fields		= rseq_fields,
		.num_fields	= ARRAY_SIZE(rseq_fields),
	},
	[SC_ITIMERVAL] = {
		.name		= "itimerval",
		.struct_size	= sizeof(struct itimerval),
		.fields		= itimerval_fields,
		.num_fields	= ARRAY_SIZE(itimerval_fields),
	},
	[SC_UTIMBUF] = {
		.name		= "utimbuf",
		.struct_size	= sizeof(struct utimbuf),
		.fields		= utimbuf_fields,
		.num_fields	= ARRAY_SIZE(utimbuf_fields),
	},
	[SC_FLOCK] = {
		.name		= "flock",
		.struct_size	= sizeof(struct flock),
		.fields		= flock_fields,
		.num_fields	= ARRAY_SIZE(flock_fields),
	},
	[SC_TIMEVAL] = {
		.name		= "timeval",
		.struct_size	= sizeof(struct timeval),
		.fields		= timeval_fields,
		.num_fields	= ARRAY_SIZE(timeval_fields),
	},
	[SC_TIMEZONE] = {
		.name		= "timezone",
		.struct_size	= sizeof(struct timezone),
		.fields		= timezone_fields,
		.num_fields	= ARRAY_SIZE(timezone_fields),
	},
	[SC_NS_ID_REQ] = {
		.name		= "ns_id_req",
		.struct_size	= sizeof(struct ns_id_req),
		.fields		= ns_id_req_fields,
		.num_fields	= ARRAY_SIZE(ns_id_req_fields),
	},
#ifdef USE_XATTR_ARGS
	[SC_XATTR_ARGS] = {
		.name		= "xattr_args",
		.struct_size	= sizeof(struct xattr_args),
		.fields		= xattr_args_fields,
		.num_fields	= ARRAY_SIZE(xattr_args_fields),
	},
#endif
	[SC_FILE_ATTR] = {
		.name		= "file_attr",
		.struct_size	= sizeof(struct file_attr),
		.fields		= file_attr_fields,
		.num_fields	= ARRAY_SIZE(file_attr_fields),
	},
	[SC_LANDLOCK_PATH_BENEATH_ATTR] = {
		.name		= "landlock_path_beneath_attr",
		.struct_size	= sizeof(struct landlock_path_beneath_attr),
		.fields		= landlock_path_beneath_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_path_beneath_attr_fields),
	},
	[SC_F_OWNER_EX] = {
		.name		= "f_owner_ex",
		.struct_size	= sizeof(struct f_owner_ex),
		.fields		= f_owner_ex_fields,
		.num_fields	= ARRAY_SIZE(f_owner_ex_fields),
	},
	[SC_LANDLOCK_NET_PORT_ATTR] = {
		.name		= "landlock_net_port_attr",
		.struct_size	= sizeof(struct landlock_net_port_attr),
		.fields		= landlock_net_port_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_net_port_attr_fields),
	},
	[SC_IF_DQBLK] = {
		.name		= "if_dqblk",
		.struct_size	= sizeof(struct if_dqblk),
		.fields		= if_dqblk_fields,
		.num_fields	= ARRAY_SIZE(if_dqblk_fields),
	},
	[SC_IF_DQINFO] = {
		.name		= "if_dqinfo",
		.struct_size	= sizeof(struct if_dqinfo),
		.fields		= if_dqinfo_fields,
		.num_fields	= ARRAY_SIZE(if_dqinfo_fields),
	},
#ifdef X86
	[SC_USER_DESC] = {
		.name		= "user_desc",
		.struct_size	= sizeof(struct user_desc),
		.fields		= user_desc_fields,
		.num_fields	= ARRAY_SIZE(user_desc_fields),
	},
#endif
	[SC_SOCK_FILTER] = {
		.name		= "sock_filter",
		.struct_size	= sizeof(struct sock_filter),
		.fields		= sock_filter_fields,
		.num_fields	= ARRAY_SIZE(sock_filter_fields),
	},
	[SC_SOCK_FPROG] = {
		.name		= "sock_fprog",
		.struct_size	= sizeof(struct sock_fprog),
		.fields		= sock_fprog_fields,
		.num_fields	= ARRAY_SIZE(sock_fprog_fields),
	},
	[SC_SHMID_DS] = {
		.name		= "shmid_ds",
		.struct_size	= sizeof(struct shmid_ds),
		.fields		= shmid_ds_fields,
		.num_fields	= ARRAY_SIZE(shmid_ds_fields),
	},
	[SC_IOCB] = {
		.name		= "iocb",
		.struct_size	= sizeof(struct iocb),
		.fields		= iocb_fields,
		.num_fields	= ARRAY_SIZE(iocb_fields),
	},
	[SC_LINGER] = {
		.name		= "linger",
		.struct_size	= sizeof(struct linger),
		.fields		= linger_fields,
		.num_fields	= ARRAY_SIZE(linger_fields),
	},
	[SC_IP_MREQN] = {
		.name		= "ip_mreqn",
		.struct_size	= sizeof(struct ip_mreqn),
		.fields		= ip_mreqn_fields,
		.num_fields	= ARRAY_SIZE(ip_mreqn_fields),
	},
	[SC_IPV6_MREQ] = {
		.name		= "ipv6_mreq",
		.struct_size	= sizeof(struct ipv6_mreq),
		.fields		= ipv6_mreq_fields,
		.num_fields	= ARRAY_SIZE(ipv6_mreq_fields),
	},
	[SC_PACKET_MREQ] = {
		.name		= "packet_mreq",
		.struct_size	= sizeof(struct packet_mreq),
		.fields		= packet_mreq_fields,
		.num_fields	= ARRAY_SIZE(packet_mreq_fields),
	},
#ifdef USE_SCTP
	[SC_SCTP_INITMSG] = {
		.name		= "sctp_initmsg",
		.struct_size	= sizeof(struct sctp_initmsg),
		.fields		= sctp_initmsg_fields,
		.num_fields	= ARRAY_SIZE(sctp_initmsg_fields),
	},
	[SC_SCTP_RTOINFO] = {
		.name		= "sctp_rtoinfo",
		.struct_size	= sizeof(struct sctp_rtoinfo),
		.fields		= sctp_rtoinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_rtoinfo_fields),
	},
	[SC_SCTP_ASSOCPARAMS] = {
		.name		= "sctp_assocparams",
		.struct_size	= sizeof(struct sctp_assocparams),
		.fields		= sctp_assocparams_fields,
		.num_fields	= ARRAY_SIZE(sctp_assocparams_fields),
	},
	[SC_SCTP_SETADAPTATION] = {
		.name		= "sctp_setadaptation",
		.struct_size	= sizeof(struct sctp_setadaptation),
		.fields		= sctp_setadaptation_fields,
		.num_fields	= ARRAY_SIZE(sctp_setadaptation_fields),
	},
	[SC_SCTP_ASSOC_VALUE] = {
		.name		= "sctp_assoc_value",
		.struct_size	= sizeof(struct sctp_assoc_value),
		.fields		= sctp_assoc_value_fields,
		.num_fields	= ARRAY_SIZE(sctp_assoc_value_fields),
	},
	[SC_SCTP_SNDINFO] = {
		.name		= "sctp_sndinfo",
		.struct_size	= sizeof(struct sctp_sndinfo),
		.fields		= sctp_sndinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_sndinfo_fields),
	},
	[SC_SCTP_SNDRCVINFO] = {
		.name		= "sctp_sndrcvinfo",
		.struct_size	= sizeof(struct sctp_sndrcvinfo),
		.fields		= sctp_sndrcvinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_sndrcvinfo_fields),
	},
	[SC_SCTP_EVENT_SUBSCRIBE] = {
		.name		= "sctp_event_subscribe",
		.struct_size	= sizeof(struct sctp_event_subscribe),
		.fields		= sctp_event_subscribe_fields,
		.num_fields	= ARRAY_SIZE(sctp_event_subscribe_fields),
	},
	[SC_SCTP_AUTHCHUNK] = {
		.name		= "sctp_authchunk",
		.struct_size	= sizeof(struct sctp_authchunk),
		.fields		= sctp_authchunk_fields,
		.num_fields	= ARRAY_SIZE(sctp_authchunk_fields),
	},
	[SC_SCTP_SACK_INFO] = {
		.name		= "sctp_sack_info",
		.struct_size	= sizeof(struct sctp_sack_info),
		.fields		= sctp_sack_info_fields,
		.num_fields	= ARRAY_SIZE(sctp_sack_info_fields),
	},
	[SC_SCTP_AUTHKEYID] = {
		.name		= "sctp_authkeyid",
		.struct_size	= sizeof(struct sctp_authkeyid),
		.fields		= sctp_authkeyid_fields,
		.num_fields	= ARRAY_SIZE(sctp_authkeyid_fields),
	},
	[SC_SCTP_DEFAULT_PRINFO] = {
		.name		= "sctp_default_prinfo",
		.struct_size	= sizeof(struct sctp_default_prinfo),
		.fields		= sctp_default_prinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_default_prinfo_fields),
	},
	[SC_SCTP_ADD_STREAMS] = {
		.name		= "sctp_add_streams",
		.struct_size	= sizeof(struct sctp_add_streams),
		.fields		= sctp_add_streams_fields,
		.num_fields	= ARRAY_SIZE(sctp_add_streams_fields),
	},
	[SC_SCTP_STREAM_VALUE] = {
		.name		= "sctp_stream_value",
		.struct_size	= sizeof(struct sctp_stream_value),
		.fields		= sctp_stream_value_fields,
		.num_fields	= ARRAY_SIZE(sctp_stream_value_fields),
	},
	[SC_SCTP_EVENT] = {
		.name		= "sctp_event",
		.struct_size	= sizeof(struct sctp_event),
		.fields		= sctp_event_fields,
		.num_fields	= ARRAY_SIZE(sctp_event_fields),
	},
	[SC_SCTP_PADDRTHLDS] = {
		.name		= "sctp_paddrthlds",
		.struct_size	= sizeof(struct sctp_paddrthlds),
		.fields		= sctp_paddrthlds_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrthlds_fields),
	},
	[SC_SCTP_PADDRTHLDS_V2] = {
		.name		= "sctp_paddrthlds_v2",
		.struct_size	= sizeof(struct sctp_paddrthlds_v2),
		.fields		= sctp_paddrthlds_v2_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrthlds_v2_fields),
	},
	[SC_SCTP_UDPENCAPS] = {
		.name		= "sctp_udpencaps",
		.struct_size	= sizeof(struct sctp_udpencaps),
		.fields		= sctp_udpencaps_fields,
		.num_fields	= ARRAY_SIZE(sctp_udpencaps_fields),
	},
	[SC_SCTP_PADDRPARAMS] = {
		.name		= "sctp_paddrparams",
		.struct_size	= sizeof(struct sctp_paddrparams),
		.fields		= sctp_paddrparams_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrparams_fields),
	},
#endif
};

/*
 * Lock the enum and the array in lockstep at compile time.  A missing
 * [SC_X] = {...} slot would let ARRAY_SIZE diverge from SC_NR_ENTRIES;
 * catching it here is sharper than the runtime hole-check below.
 */
_Static_assert(ARRAY_SIZE(struct_catalog) == SC_NR_ENTRIES,
	       "struct_catalog[] and enum struct_catalog_idx must stay in lockstep");

/* ------------------------------------------------------------------ */
/* Discriminator value lists                                            */
/* ------------------------------------------------------------------ */

/*
 * fcntl arg3 cmd discriminator pools.  Sibling arg a2 (cmd) selects
 * which struct backs the a3 pointer; the discriminator-aware lookup
 * resolves these lists against rec->a2 to pick the right descriptor.
 *
 * fcntl_flock_cmds: every cmd where the kernel reads a struct flock
 * at a3 -- POSIX (F_GETLK / F_SETLK / F_SETLKW), OFD (F_OFD_*) and
 * F_CANCELLK.  The LK64 variants are folded in via the
 * F_GETLK64 != F_GETLK preprocessor gate so 64-bit-clean toolchains
 * (where the LK64 cmd values collapse onto their non-LK64 siblings)
 * don't waste a duplicate-match slot.
 *
 * fcntl_f_owner_ex_cmds: the two cmds where a3 is a struct
 * f_owner_ex pointer.
 */
static const unsigned long fcntl_flock_cmds[] = {
	F_GETLK, F_SETLK, F_SETLKW,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_CANCELLK,
#if F_GETLK64 != F_GETLK
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
};

static const unsigned long fcntl_f_owner_ex_cmds[] = {
	F_GETOWN_EX, F_SETOWN_EX,
};

/*
 * landlock_add_rule arg3 rule_type discriminator pools.  Sibling arg
 * a2 (rule_type) selects which struct backs the a3 pointer; the
 * discriminator-aware lookup resolves these lists against rec->a2 to
 * pick the right descriptor.
 *
 * landlock_add_rule_path_beneath_rule_types: just
 * LANDLOCK_RULE_PATH_BENEATH (a3 is a struct landlock_path_beneath_attr).
 *
 * landlock_add_rule_net_port_rule_types: just LANDLOCK_RULE_NET_PORT
 * (a3 is a struct landlock_net_port_attr).
 *
 * One-element pools so the registration shape matches the fcntl
 * cmd-discriminator above; new landlock rule_types will land here as
 * additional entries with their own descriptor + pool.
 */
static const unsigned long landlock_add_rule_path_beneath_rule_types[] = {
	LANDLOCK_RULE_PATH_BENEATH,
};

static const unsigned long landlock_add_rule_net_port_rule_types[] = {
	LANDLOCK_RULE_NET_PORT,
};

/*
 * quotactl / quotactl_fd cmd discriminator pools.  Both syscalls pack
 * the cmd into a single arg as QCMD(subcmd, type) (subcmd in the high
 * bits, USRQUOTA / GRPQUOTA / PRJQUOTA / ... type in the low byte),
 * so the discriminator-aware lookup unpacks via the (shift, mask)
 * extension: discrim_shift = SUBCMDSHIFT strips the type byte and
 * leaves the raw subcmd that the kernel switches on, which is what
 * Q_SETQUOTA / Q_SETINFO actually equal.
 *
 * quotactl_if_dqblk_subcmds: just Q_SETQUOTA (a4 / a3 is a struct
 * if_dqblk pointer the kernel reads on dispatch).  Q_GETQUOTA /
 * Q_GETNEXTQUOTA also use if_dqblk at the same slot but they're
 * output-only -- registering them would attribute CMP-learned
 * constants against bytes the kernel wrote rather than bytes we
 * stamped.
 */
static const unsigned long quotactl_if_dqblk_subcmds[] = {
	Q_SETQUOTA,
};

/*
 * quotactl_if_dqinfo_subcmds: just Q_SETINFO (a4 / a3 is a struct
 * if_dqinfo pointer the kernel reads on dispatch).  Q_GETINFO also
 * uses if_dqinfo at the same slot but is output-only -- registering
 * it would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_if_dqinfo_subcmds[] = {
	Q_SETINFO,
};

/*
 * seccomp(op, flags, args) op-discriminator pool.  Sibling arg a1 (op)
 * selects which struct backs the a3 pointer; the discriminator-aware
 * lookup resolves this list against rec->a1 to pick the right descriptor.
 *
 * seccomp_set_mode_filter_ops: just SECCOMP_SET_MODE_FILTER (a3 is a
 * struct sock_fprog pointer the kernel reads for cBPF install).  The
 * other three ops (SECCOMP_SET_MODE_STRICT, SECCOMP_GET_ACTION_AVAIL,
 * SECCOMP_GET_NOTIF_SIZES) point a3 at a different shape (or NULL) and
 * are not registered -- attributing CMP-learned constants against
 * sock_fprog fields on those dispatches would steer them at bytes the
 * kernel never reads as filter program.
 *
 * SECCOMP_SET_MODE_FILTER fallback mirrors the shims in
 * childops/recipe-runner.c and fds/seccomp_notif.c so the descriptor
 * registers even on toolchain headers that predate linux/seccomp.h
 * carrying the enum.
 */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER		1
#endif

static const unsigned long seccomp_set_mode_filter_ops[] = {
	SECCOMP_SET_MODE_FILTER,
};

/*
 * setsockopt (level, optname) discriminator vocab -- proof batch for
 * the two-key extension.  Each list enumerates the optnames inside a
 * single level that share an optval struct shape, so one
 * syscall_struct_args[] row covers every (level, this-vocab) tuple
 * without cloning the entry.  Same pattern as cgroup link_create's
 * 20-attach-type discrim_values list.
 *
 * Symbol comes from setsockopt.c's sockopt_table[] vocabulary; the
 * lookup matches on the raw integer value, not the symbolic name.
 */
static const unsigned long setsockopt_timeval_optnames[] = {
	SO_RCVTIMEO,
	SO_SNDTIMEO,
};

static const unsigned long setsockopt_ip_mreqn_optnames[] = {
	IP_ADD_MEMBERSHIP,
	IP_DROP_MEMBERSHIP,
	IP_MULTICAST_IF,
};

static const unsigned long setsockopt_ipv6_mreq_optnames[] = {
	IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP,
};

static const unsigned long setsockopt_packet_mreq_optnames[] = {
	PACKET_ADD_MEMBERSHIP,
	PACKET_DROP_MEMBERSHIP,
};

#ifdef USE_SCTP
static const unsigned long setsockopt_sctp_assoc_value_optnames[] = {
	SCTP_CONTEXT,
	SCTP_MAXSEG,
	SCTP_MAX_BURST,
	SCTP_STREAM_SCHEDULER,
};

static const unsigned long setsockopt_sctp_authkeyid_optnames[] = {
	SCTP_AUTH_ACTIVE_KEY,
	SCTP_AUTH_DELETE_KEY,
	SCTP_AUTH_DEACTIVATE_KEY,
};
#endif

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
	{ "adjtimex",		1, &struct_catalog[SC_TIMEX] },
	/* clock_adjtime(clockid_t, struct timex *) */
	{ "clock_adjtime",	2, &struct_catalog[SC_TIMEX] },
	/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
	{ "sched_setattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[SC_CLONE_ARGS] },
	/* io_uring_setup(u32, struct io_uring_params *) */
	{ "io_uring_setup",	2, &struct_catalog[SC_IO_URING_PARAMS] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[SC_RLIMIT] },
	{ "prlimit64",		4, &struct_catalog[SC_RLIMIT] },
	/* timer_settime(timer_t, int, struct itimerspec *, struct itimerspec *) */
	{ "timer_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* timerfd_settime(int, int, struct itimerspec *, struct itimerspec *) */
	{ "timerfd_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[SC_EPOLL_EVENT] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[SC_PERF_EVENT_ATTR] },
	/* rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t) */
	{ "rt_sigaction",	2, &struct_catalog[SC_SIGACTION] },
	{ "rt_sigaction",	3, &struct_catalog[SC_SIGACTION] },
	/* sigaction(int, const struct old_sigaction *, struct old_sigaction *) */
	{ "sigaction",		2, &struct_catalog[SC_SIGACTION] },
	{ "sigaction",		3, &struct_catalog[SC_SIGACTION] },
	/* sendmsg(int, const struct msghdr *, int) */
	{ "sendmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* recvmsg(int, struct msghdr *, int) */
	{ "recvmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* bind(int, struct sockaddr *, socklen_t) */
	{ "bind",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* connect(int, struct sockaddr *, socklen_t) */
	{ "connect",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* sendto(int, const void *, size_t, int, struct sockaddr *, socklen_t) */
	{ "sendto",		5, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t, u32) */
	{ "landlock_create_ruleset",	1, &struct_catalog[SC_LANDLOCK_RULESET_ATTR] },
	/* statmount(const struct mnt_id_req *, struct statmount *, size_t, u32) */
	{ "statmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* listmount(const struct mnt_id_req *, u64 *, size_t, u32) */
	{ "listmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* capset(cap_user_header_t hdr, const cap_user_data_t data) */
	{ "capset",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	{ "capset",		2, &struct_catalog[SC_USER_CAP_DATA] },
	/* capget(cap_user_header_t hdr, cap_user_data_t data) */
	{ "capget",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	/* futex_waitv(struct futex_waitv *waiters, unsigned int nr, unsigned int flags, struct timespec *timo, clockid_t clockid) */
	{ "futex_waitv",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* sigaltstack(const stack_t *ss, stack_t *old_ss) */
	{ "sigaltstack",	1, &struct_catalog[SC_STACK_T] },
	/*
	 * rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo)
	 * rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
	 *                   siginfo_t __user *uinfo)
	 *
	 * Attribution-only registration -- argtype[*] for the siginfo
	 * slot is not ARG_STRUCT_PTR_*, so the schema-aware fill never
	 * runs against rec->a3 (rt_sigqueueinfo) / rec->a4
	 * (rt_tgsigqueueinfo).  The bespoke sanitisers keep owning the
	 * live fill (fill_siginfo_by_class on rt_sigqueueinfo, a fixed
	 * SI_QUEUE shape on rt_tgsigqueueinfo), and this entry lets
	 * struct_field_for_cmp() steer CMP-learned constants at the
	 * named si_signo / si_code / si_pid / si_uid / si_value slots
	 * rather than at coincidentally-same-width slots.  Variants in
	 * the descriptor scope the candidate field pool to the live
	 * _kill / _rt arm whenever struct_desc_resolve_variant is
	 * called with the post-fill buf (CMP-time callers that pass
	 * buf == NULL fall through to the shared head).
	 *
	 * Not mapped here on purpose: waitid's a3 is a kernel-written
	 * OUTPUT (mirrors the gettimeofday / get_robust_list /
	 * cachestat-output skips above) and registering it would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  pidfd_send_signal's a3
	 * is also struct siginfo_t but is intentionally out of scope
	 * for this commit.
	 */
	{ "rt_sigqueueinfo",	3, &struct_catalog[SC_SIGINFO_T] },
	{ "rt_tgsigqueueinfo",	4, &struct_catalog[SC_SIGINFO_T] },
	/* mq_open(const char *, int, mode_t, struct mq_attr *) */
	{ "mq_open",		4, &struct_catalog[SC_MQ_ATTR] },
	/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
	{ "mq_getsetattr",	2, &struct_catalog[SC_MQ_ATTR] },
	{ "mq_getsetattr",	3, &struct_catalog[SC_MQ_ATTR] },
	/* msgctl(int msqid, int cmd, struct msqid_ds *buf) — IPC_SET path */
	{ "msgctl",		3, &struct_catalog[SC_MSQID_DS] },
	/* shmctl(int shmid, int cmd, struct shmid_ds *buf) — IPC_SET path */
	{ "shmctl",		3, &struct_catalog[SC_SHMID_DS] },
	/* sched_setparam(pid_t, struct sched_param *) */
	{ "sched_setparam",	2, &struct_catalog[SC_SCHED_PARAM] },
	/* sched_setscheduler(pid_t, int, struct sched_param *) */
	{ "sched_setscheduler",	3, &struct_catalog[SC_SCHED_PARAM] },
	/* io_uring_register(int fd, unsigned op, void *arg, unsigned nr_args) */
	{ "io_uring_register",	3, &struct_catalog[SC_IO_URING_REGISTER_ARGS] },
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[SC_BPF_ATTR] },
#endif
	/* clock_nanosleep(clockid_t, int, struct timespec *, struct timespec *) */
	{ "clock_nanosleep",	3, &struct_catalog[SC_TIMESPEC] },
	/* nanosleep(struct timespec *, struct timespec *) */
	{ "nanosleep",		1, &struct_catalog[SC_TIMESPEC] },
	/*
	 * utimensat(int, const char *, struct timespec[2], int)
	 * utimensat's `utimes` arg is a 2-element timespec array -- the
	 * mapping table has no array semantics, so the entry below names
	 * the single-struct desc and the existing sanitise_utimensat
	 * callback continues to own the 2-element layout.
	 */
	{ "utimensat",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * ppoll(struct pollfd *, nfds_t, struct timespec *tsp, const sigset_t *, size_t)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_ppoll / ppoll_post_state in syscalls/poll.c continues to
	 * own the live fill; this row only lets schema-aware CMP attribution
	 * name the tv_sec / tv_nsec fields.  ppoll's a1 (pollfd array) is
	 * mapped to SC_POLLFD above and is unaffected.
	 */
	{ "ppoll",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
	 *                 const struct timespec *uts, size_t sigsetsize)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitiser (build_timeout stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (uthese,
	 * sigset_t) and a2 (uinfo, siginfo_t) are not timespecs and are
	 * intentionally unregistered here.
	 */
	{ "rt_sigtimedwait",	3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp,
	 *          struct timespec *tsp, void *sig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_pselect6 (allocs the timespec via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a6 (sig, a
	 * packed { sigset_t *, size_t } pointer) is not a timespec and is
	 * intentionally unregistered here.
	 */
	{ "pselect6",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * semtimedop(int semid, struct sembuf *sops, unsigned nsops,
	 *            const struct timespec *timeout)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_semtimedop (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a2 (sops, the
	 * sembuf array) is mapped to SC_SEMBUF below and is unaffected.
	 */
	{ "semtimedop",		4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * clock_settime(clockid_t which_clock, const struct timespec *tp)
	 * a2 is the INPUT timespec.  Attribution-only: the bespoke
	 * sanitise_clock_settime (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "clock_settime",	2, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	 *              unsigned int msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedsend (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedsend",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	 *                 unsigned int *msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedreceive (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedreceive",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_getevents(aio_context_t ctx_id, long min_nr, long nr,
	 *              struct io_event *events, struct timespec *timeout)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_getevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_getevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex_wait(void *uaddr, unsigned long val, unsigned long mask,
	 *            unsigned int flags, struct timespec *timeout,
	 *            clockid_t clockid)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_wait (stamps the slot via get_writable_struct)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  Plain futex()
	 * is intentionally NOT registered: its a4 is op-multiplexed and is
	 * a timespec* only for FUTEX_WAIT-family ops, val2 otherwise.
	 */
	{ "futex_wait",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
	 *             unsigned int flags, struct timespec *timeout,
	 *             clockid_t clockid)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_waitv (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (waiters)
	 * is mapped to SC_FUTEX_WAITV above and is unaffected.
	 */
	{ "futex_waitv",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
	 *              struct timespec *timeout, const sigset_t *sigmask,
	 *              size_t sigsetsize)
	 * a4 is the INPUT timeout timespec (epoll_pwait2 takes a timespec*
	 * where epoll_pwait took an int ms).  Attribution-only: the bespoke
	 * sanitise_epoll_pwait2 / pick_timespec (stamps the slot via
	 * get_writable_struct) continues to own the live fill; this row only
	 * lets schema-aware CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "epoll_pwait2",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
	 *               struct io_event *events, struct timespec *timeout,
	 *               const struct __aio_sigset *usig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_pgetevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_pgetevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * cachestat(unsigned int fd, struct cachestat_range *cstat_range,
	 *           struct cachestat *cstat, unsigned int flags)
	 * Maps the INPUT cstat_range arg only; cstat is the kernel-written
	 * output and is intentionally not registered.  Attribution-only:
	 * sanitise_cachestat / pick_range continues to own the live fill.
	 */
	{ "cachestat",		2, &struct_catalog[SC_CACHESTAT_RANGE] },
	/*
	 * mount_setattr(int dfd, const char *path, unsigned int flags,
	 *               struct mount_attr *uattr, size_t usize)
	 * open_tree_attr(int dfd, const char *filename, unsigned int flags,
	 *                struct mount_attr *uattr, size_t usize)
	 * Both a4 slots are ARG_STRUCT_PTR_IN, but the bespoke sanitisers
	 * (build_mount_attr / sanitise_mount_setattr) overwrite rec->a4
	 * after the schema-aware fill -- attribution-only registration so
	 * struct_field_for_cmp can steer CMP-learned constants at the
	 * named fields.  The curated bespoke fill stays live.
	 */
	{ "mount_setattr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	{ "open_tree_attr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	/*
	 * sembuf is an array slot on ARG_ADDRESS at a2 of both semop and
	 * semtimedop; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * fill_sembuf_array() owns the live (nsops, sem_*) layout.
	 */
	{ "semop",		2, &struct_catalog[SC_SEMBUF] },
	{ "semtimedop",		2, &struct_catalog[SC_SEMBUF] },
	/*
	 * pollfd is an array slot on ARG_ADDRESS at a1 of both poll and
	 * ppoll; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * alloc_pollfds() owns the live (nfds, fd, events) layout.
	 */
	{ "poll",		1, &struct_catalog[SC_POLLFD] },
	{ "ppoll",		1, &struct_catalog[SC_POLLFD] },
	/*
	 * openat2(int dfd, const char *filename, struct open_how *how,
	 *         size_t usize)
	 * a3 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_openat2 / build_csfu_struct path keeps owning the
	 * live (flags, mode, resolve) layout and the usize bucket
	 * distribution.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * flags / resolve slot.
	 */
	{ "openat2",		3, &struct_catalog[SC_OPEN_HOW] },
	/*
	 * timer_create(clockid_t, struct sigevent *, timer_t *)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * timer_create_sanitise() keeps owning the live (sigev_value,
	 * sigev_signo, sigev_notify, _sigev_un._tid) layout and the
	 * SIGEV_* notify-mode distribution.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at sigev_notify / sigev_signo rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "timer_create",	2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * mq_notify(mqd_t, const struct sigevent *)
	 * a2 carries the same struct sigevent that timer_create's a2
	 * carries; the bespoke sanitise_mq_notify() keeps owning the
	 * live fill (NULL-deregister half the time, otherwise SIGEV_NONE
	 * / SIGEV_SIGNAL / SIGEV_THREAD with sigev_signo populated).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at sigev_notify / sigev_signo rather
	 * than at a coincidentally-same-width slot.
	 */
	{ "mq_notify",		2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * set_robust_list(struct robust_list_head __user *head, size_t len)
	 * a1 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_set_robust_list() keeps owning the live (list.next,
	 * futex_offset, list_op_pending) layout.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned constants
	 * at the named fields.  get_robust_list's robust_list_head is an
	 * output (a2 is a double pointer the kernel writes), so only
	 * set_robust_list's a1 is mapped.
	 */
	{ "set_robust_list",	1, &struct_catalog[SC_ROBUST_LIST_HEAD] },
	/*
	 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
	 * a1 is the INPUT struct rseq pointer; the bespoke sanitise_rseq()
	 * keeps owning the live fill (32-byte-aligned allocation, zero-
	 * init, a2 length-bucket distribution, a4 signature pin).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at the named fields rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "rseq",		1, &struct_catalog[SC_RSEQ] },
	/*
	 * setitimer(int which, const struct itimerval __user *value,
	 *           struct itimerval __user *ovalue)
	 * a2 is the INPUT struct itimerval pointer; the bespoke
	 * sanitise_setitimer() keeps owning the live fill (writable
	 * allocation, per-timeval bucket distribution via fill_timeval(),
	 * half-the-time disarm of it_value, a3 routed through
	 * avoid_shared_buffer_out()).  a3 (ovalue) is a kernel-written
	 * output and is intentionally not mapped; getitimer's a2 is
	 * likewise an output and is not mapped either.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named tv_sec / tv_usec slots rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "setitimer",		2, &struct_catalog[SC_ITIMERVAL] },
	/*
	 * utime(const char *filename, const struct utimbuf __user *times)
	 * a2 is the INPUT struct utimbuf pointer.  utime has no bespoke
	 * .sanitise -- the slot previously fell through ARG_ADDRESS with no
	 * schema-aware fill.  argtype[1] is now ARG_STRUCT_PTR_IN so the
	 * times buffer lands on a dedicated sized buffer; the catalog entry
	 * also lets struct_field_for_cmp steer CMP-learned constants at the
	 * named actime / modtime slots rather than at a coincidentally-
	 * same-width slot.
	 */
	{ "utime",		2, &struct_catalog[SC_UTIMBUF] },
	/*
	 * fcntl(int fd, int cmd, ... arg)
	 * a3's type depends on the cmd in a2 -- the first proof of the
	 * discriminator-aware syscall_struct_args[] mechanism.  Two
	 * variants, both attribution-only (the bespoke sanitise_fcntl()
	 * keeps owning the live fill):
	 *
	 *   - struct flock for F_GETLK / F_SETLK / F_SETLKW, the F_OFD_*
	 *     variants, F_CANCELLK (and the LK64 variants on archs where
	 *     F_GETLK64 != F_GETLK).  build_flock() picks an l_type /
	 *     l_whence vocab member, a bounded l_start and l_len, and
	 *     zeroes l_pid.  struct_field_for_cmp() steers CMP-learned
	 *     constants at the named l_type / l_whence slots.
	 *
	 *   - struct f_owner_ex for F_GETOWN_EX / F_SETOWN_EX.  The
	 *     bespoke arm picks type from {F_OWNER_TID, F_OWNER_PID,
	 *     F_OWNER_PGRP} and stamps get_pid() into pid;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named type slot.
	 *
	 * cmds that don't carry a struct at a3 (F_DUPFD, F_GETFD,
	 * F_SETFL, F_*OWN, F_*SIG, F_*LEASE, F_*PIPE_SZ, F_ADD_SEALS,
	 * F_NOTIFY, F_DUPFD_QUERY, ...) match no variant and resolve to
	 * NULL -- gen_arg_struct_ptr_inout falls through to a zeroed
	 * fallback buffer that sanitise_fcntl overwrites with an fd or
	 * integer flag word, same as before.
	 */
	{
		"fcntl", 3, &struct_catalog[SC_FLOCK],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_flock_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_flock_cmds),
	},
	{
		"fcntl", 3, &struct_catalog[SC_F_OWNER_EX],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_f_owner_ex_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_f_owner_ex_cmds),
	},
	/*
	 * settimeofday(struct timeval __user *tv, struct timezone __user *tz)
	 * a1 is the INPUT struct timeval pointer.  The bespoke
	 * sanitise_settimeofday() keeps owning the live fill (70% near-now
	 * via clock_gettime() + bounded tv_usec, 30% random with an
	 * explicit invalid-tv_usec leg).  Attribution-only registration
	 * lets struct_field_for_cmp steer CMP-learned constants at the
	 * named tv_sec / tv_usec slots rather than at a coincidentally-
	 * same-width slot.
	 *
	 * select(int n, fd_set *, fd_set *, fd_set *, struct timeval *tvp)
	 * a5 is the INOUT timeout pointer.  sanitise_select() stamps a
	 * deterministic {0, 10us} short timeout in the writable buffer it
	 * allocates; the kernel may write back the remaining time, so the
	 * slot is INOUT.  Attribution-only registration again -- the
	 * bespoke fill remains the sole writer; the catalog entry just
	 * lets CMP-learned constants attribute at tv_sec / tv_usec rather
	 * than at a coincidentally-same-width slot.
	 *
	 * futimesat(int dfd, const char __user *filename,
	 *           struct timeval __user *utimes)
	 * a3 is the INPUT struct timeval[2] pointer.  The bespoke
	 * sanitise_futimesat() owns the live fill via a bucketed picker
	 * (NULL leg, near-now / far-past / far-future valid, deliberately
	 * invalid tv_usec, mixed, fully random) writing both array
	 * elements into a get_writable_address(sizeof(*tv) * 2) slab.
	 * Attribution-only registration describes utimes[0] only -- the
	 * single-struct descriptor cannot span the [2] array, but covering
	 * the first element is enough to let struct_field_for_cmp steer
	 * CMP-learned constants at the named tv_sec / tv_usec slots
	 * rather than at a coincidentally-same-width slot.  The bespoke
	 * fill remains the sole writer of both elements.
	 *
	 * utimes(char __user *filename, struct __kernel_old_timeval __user *utimes)
	 * a2 is the INPUT struct timeval[2] pointer.  Attribution-only
	 * registration describes utimes[0] only -- the single-struct
	 * descriptor cannot span the [2] array, but covering the first
	 * element is enough to let struct_field_for_cmp steer CMP-learned
	 * constants at the named tv_sec / tv_usec slots rather than at a
	 * coincidentally-same-width slot.  The live fill remains the sole
	 * writer of both elements.
	 *
	 * Not mapped here on purpose: gettimeofday's a1 is a kernel-written
	 * OUTPUT buffer with no input fill to attribute against.
	 */
	{ "settimeofday",	1, &struct_catalog[SC_TIMEVAL] },
	{ "select",		5, &struct_catalog[SC_TIMEVAL] },
	{ "futimesat",		3, &struct_catalog[SC_TIMEVAL] },
	{ "utimes",		2, &struct_catalog[SC_TIMEVAL] },
	/*
	 * settimeofday(struct timeval __user *tv, struct timezone __user *tz)
	 * a2 is the INPUT struct timezone pointer.  The bespoke
	 * sanitise_settimeofday() keeps owning the live fill via a
	 * RAND_BOOL() gate over get_writable_address(): a 50/50 zero-leg vs
	 * random-leg producing tz_minuteswest in [-780, +780] and tz_dsttime
	 * in [0, 3].  Attribution-only registration lets struct_field_for_cmp
	 * steer CMP-learned constants at the named tz_minuteswest /
	 * tz_dsttime slots rather than at a coincidentally-same-width slot.
	 *
	 * Not mapped here on purpose: gettimeofday's a2 is a kernel-written
	 * OUTPUT buffer with no input fill to attribute against.
	 */
	{ "settimeofday",	2, &struct_catalog[SC_TIMEZONE] },
	/*
	 * listns(const struct ns_id_req __user *req, u64 __user *ns_ids,
	 *        size_t nr_ns_ids, unsigned int flags)
	 * a1 is the INPUT struct ns_id_req pointer.  sanitise_listns()
	 * keeps owning the live fill via build_csfu_struct(&desc_listns)
	 * -- the csfu path stamps the versioned size word and the
	 * subsequent ns_type / ns_id / user_ns_id pickers populate the
	 * remaining slots.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * size / ns_type / ns_id / user_ns_id slots, with ns_type masked
	 * to the eight defined CLONE_NEW* selector bits.
	 */
	{ "listns",		1, &struct_catalog[SC_NS_ID_REQ] },
#ifdef USE_XATTR_ARGS
	/*
	 * setxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            const struct xattr_args __user *uargs, size_t usize)
	 * getxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            struct xattr_args __user *uargs, size_t usize)
	 * a5 is the INPUT struct xattr_args pointer in both cases (the
	 * kernel reads value / size / flags before any sub-buffer access
	 * even for getxattrat).  sanitise_{set,get}xattrat() keep owning
	 * the live fill via build_csfu_struct(&desc_{set,get}xattrat) and
	 * the in-line value/size/flags picker; attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named value / size / flags slots, with flags
	 * masked to XATTR_CREATE | XATTR_REPLACE.
	 */
	{ "setxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
	{ "getxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
#endif
	/*
	 * file_setattr(int dfd, const char __user *filename,
	 *              struct file_attr __user *ufattr, size_t usize,
	 *              unsigned int at_flags)
	 * a3 is the INPUT struct file_attr pointer.  The bespoke
	 * sanitise_file_setattr() keeps owning the live fill via
	 * build_csfu_struct(&desc_file_setattr) and the curated
	 * FS_XFLAG_* pool picker; this registration is attribution-only
	 * so struct_field_for_cmp can steer CMP-learned constants at
	 * the named fa_xflags / fa_extsize / fa_nextents / fa_projid /
	 * fa_cowextsize slots rather than at a coincidentally-same-
	 * width slot.
	 *
	 * Not mapped here on purpose: file_getattr's a2 buffer is a
	 * kernel-written OUTPUT and has no input fill to attribute
	 * against.
	 */
	{ "file_setattr",	3, &struct_catalog[SC_FILE_ATTR] },
	/*
	 * landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
	 *                   const void __user *rule_attr, __u32 flags)
	 * a3's type depends on the rule_type in a2, mirroring fcntl's
	 * cmd-discriminated a3 above.  Two variants, both attribution-only
	 * (the bespoke sanitise_landlock_add_rule() keeps owning the live
	 * fill -- argtype[2] is not declared, so the schema-aware fill
	 * path never runs against rec->a3):
	 *
	 *   - struct landlock_path_beneath_attr for
	 *     LANDLOCK_RULE_PATH_BENEATH.  The bespoke arm masks
	 *     allowed_access to the low 16 bits (LANDLOCK_ACCESS_FS_*) and
	 *     stamps get_random_fd() into parent_fd;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named allowed_access / parent_fd slots.
	 *
	 *   - struct landlock_net_port_attr for LANDLOCK_RULE_NET_PORT.
	 *     The bespoke arm picks allowed_access from the 2-bit
	 *     LANDLOCK_ACCESS_NET_* pool and stratifies port across
	 *     ephemeral / well-known / privileged / unprivileged ranges;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named allowed_access / port slots.
	 *
	 * rule_types outside both lists match no variant and resolve to
	 * NULL -- gen_arg_struct_ptr_inout falls through to a zeroed
	 * fallback buffer that sanitise_landlock_add_rule's switch
	 * default leaves untouched (rec->a3 keeps whatever the generic
	 * arg-gen wrote), same as before.
	 *
	 * Pre-discriminator the catalog could map only one descriptor per
	 * (syscall, arg), so a3 resolved to landlock_path_beneath_attr
	 * for every rule_type and struct_field_for_cmp() was attributing
	 * CMP-learned constants at allowed_access / parent_fd even on
	 * NET_PORT dispatches where the kernel was reading a wholly
	 * different struct.
	 */
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_PATH_BENEATH_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_path_beneath_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_path_beneath_rule_types),
	},
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_NET_PORT_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_net_port_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_net_port_rule_types),
	},
	/*
	 * quotactl(unsigned int cmd, const char *special, qid_t id,
	 *          void *addr)
	 * quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id,
	 *             void *addr)
	 * The addr slot (quotactl a4 / quotactl_fd a4) is a struct
	 * if_dqblk pointer under Q_SETQUOTA -- the SET path is the
	 * input arm where the bytes we stamp actually reach the
	 * kernel's quota lookup.  Both sanitisers keep owning the live
	 * fill (writable allocation, dqb_*hardlimit / dqb_*softlimit
	 * pickers, routed through avoid_shared_buffer_inout()); this
	 * registration is attribution-only so struct_field_for_cmp()
	 * can steer CMP-learned constants at the named limit / time /
	 * valid slots rather than at a coincidentally-same-width slot.
	 *
	 * The cmd discriminator is packed: rec->a1 (quotactl) /
	 * rec->a2 (quotactl_fd) is QCMD(subcmd, type) ==
	 * (subcmd << SUBCMDSHIFT) | (type & SUBCMDMASK), so the
	 * pre-extension exact-match discriminator could never resolve
	 * (Q_SETQUOTA would have had to land in the low byte to
	 * compare equal to the raw arg).  discrim_shift = SUBCMDSHIFT
	 * strips the type byte before the match; discrim_mask defaults
	 * to zero (i.e. ~0UL, all bits after the shift), which suffices
	 * because the kernel-side subcmd values are disjoint scalars.
	 *
	 * Q_GETQUOTA / Q_GETNEXTQUOTA also use if_dqblk at the same
	 * slot but they're output-only -- registering them would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  Subcmds outside the
	 * Q_SETQUOTA pool match no variant and resolve to NULL --
	 * gen_arg_struct_ptr_inout falls through to a zeroed fallback
	 * buffer that the bespoke sanitiser overwrites for the
	 * remaining cmds, same as before.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * if_dqinfo sibling of the if_dqblk registration above: the same
	 * addr slot (quotactl a4 / quotactl_fd a4) is a struct if_dqinfo
	 * pointer under Q_SETINFO.  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk pair -- the bespoke sanitisers own the live
	 * dqi_bgrace / dqi_igrace fill; this entry only steers
	 * struct_field_for_cmp().  Q_GETINFO uses if_dqinfo at the same
	 * slot but is output-only, so the pool stays at just Q_SETINFO.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
#ifdef X86
	/*
	 * modify_ldt(int func, void __user *ptr, unsigned long bytecount)
	 * a2 is a struct user_desc pointer only on the write_ldt arm
	 * (func == 1); the read arm (func == 0) hands the kernel a
	 * plain user buffer to splat the live LDT into.  The bespoke
	 * sanitise_modify_ldt() arm keeps owning the live fill (per-bit
	 * RAND_BOOL pickers for the seg_32bit / contents / read_exec_only
	 * / limit_in_pages / seg_not_present / useable / lm bitfields,
	 * rec->a3 pinned to sizeof(struct user_desc));  attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named entry_number / base_addr / limit slots
	 * rather than at a coincidentally-same-width slot.
	 *
	 * Discriminator pool is the single value {1}; func == 0 / 2 fall
	 * through to NULL and the bespoke arm continues to own them.
	 */
	{
		"modify_ldt", 2, &struct_catalog[SC_USER_DESC],
		.discrim_arg_idx	= 1,
		.discrim_value		= 1,
	},
#endif
	/*
	 * seccomp(unsigned int op, unsigned int flags, void __user *args)
	 * a3 is a struct sock_fprog pointer only on SECCOMP_SET_MODE_FILTER
	 * (the cBPF install arm); the other ops point a3 at different
	 * shapes (uint32_t * for SECCOMP_GET_ACTION_AVAIL, a seccomp_notif_
	 * sizes-sized scratch buffer for SECCOMP_GET_NOTIF_SIZES) or leave
	 * it unused (SECCOMP_SET_MODE_STRICT).  The bespoke sanitise_seccomp()
	 * keeps owning the live fill via bpf_gen_seccomp(), which builds a
	 * Markov-chain cBPF program the kernel verifier will load; an
	 * FT_RAW splat across sock_filter[] insn words could not.
	 * Attribution-only registration so struct_field_for_cmp() can steer
	 * CMP-learned constants at the named len / filter slots (and at
	 * the cataloged sock_filter elem_struct's code / jt / jf / k
	 * slots) rather than at a coincidentally-same-width slot.
	 *
	 * argtype[2] is ARG_ADDRESS, not ARG_STRUCT_PTR_*, so the schema-
	 * aware fill path never overwrites rec->a3 -- the bespoke fill
	 * stays the sole writer.  Ops outside the SET_MODE_FILTER pool
	 * match no variant and resolve to NULL, matching the iovec /
	 * sembuf / pollfd attribution-only pattern.
	 *
	 * Not registered here on purpose: prctl(PR_SET_SECCOMP, mode, ...)
	 * also reads a sock_fprog at a3, but only when a2 ==
	 * SECCOMP_MODE_FILTER -- a two-arg discriminator that the catalog
	 * now expresses via (discrim_arg_idx=1, discrim_value=PR_SET_SECCOMP,
	 * discrim2_arg_idx=2, discrim2_value=SECCOMP_MODE_FILTER).  Left
	 * unregistered in this batch by scope -- the proof targets the
	 * setsockopt optval shapes; prctl/seccomp two-key rows follow.
	 * setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...) is similarly
	 * the SO_ATTACH_FILTER arm of the (level, optname) two-key family
	 * the proof batch below exercises -- the BPF arms stay bespoke
	 * because they REPLACE the optval allocation wholesale rather than
	 * fill it (see socket_setsockopt() SO_ATTACH_FILTER branch), so a
	 * schema-fill row would race the bpf_gen_filter() replacement.
	 */
	{
		"seccomp", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_values		= seccomp_set_mode_filter_ops,
		.num_discrim_values	= ARRAY_SIZE(seccomp_set_mode_filter_ops),
	},
	/*
	 * ----------------------------------------------------------------
	 * setsockopt(fd, level, optname, optval, optlen) optval -- a4.
	 *
	 * Two-key proof batch: five (level, optname) shapes already owned
	 * by bespoke build_*() functions in syscalls/setsockopt.c, now
	 * resolved through struct_arg_lookup_two_key() from
	 * apply_sockopt_entry().  discrim_arg_idx=2 is level (a2) and
	 * discrim2_arg_idx=3 is optname (a3); the explicit-key consumer
	 * passes them directly off the picked sockopt_table[] row so the
	 * lookup runs against the authoritative pre-commit values, not
	 * the post-mangle rec->a2/a3 the kernel would see.
	 *
	 * argtype[3] is not ARG_STRUCT_PTR_*, so the rec-based
	 * struct_arg_lookup() never resolves these rows -- which is the
	 * point: the bespoke driver owns selection / optlen / BPF-arm
	 * replacement / per-fd pairing, and routes only the fill through
	 * the catalog when a row matches.  Bespoke builders remain in
	 * code as the miss-fallback for the int / bool / string scalar
	 * sockopt_table[] entries (no struct shape, no row to register)
	 * and for the higher-leverage shapes (sctp / mptcp / tcp_repair /
	 * can_filter[] etc.) that follow this proof.
	 * ----------------------------------------------------------------
	 */
	{
		"setsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQN],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreqn_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreqn_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IPV6_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IPV6,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ipv6_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ipv6_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_PACKET_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_PACKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_packet_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_packet_mreq_optnames),
	},
#ifdef USE_SCTP
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_INITMSG],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_INITMSG,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_RTOINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_RTOINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOCPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ASSOCINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SETADAPTATION],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADAPTATION_LAYER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOC_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_assoc_value_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_assoc_value_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SNDINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDRCVINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SEND_PARAM,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT_SUBSCRIBE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENTS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHCHUNK],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_AUTH_CHUNK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SACK_INFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DELAYED_SACK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHKEYID],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_authkeyid_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_authkeyid_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_DEFAULT_PRINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_PRINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ADD_STREAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADD_STREAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_STREAM_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_STREAM_SCHEDULER_VALUE,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS_V2],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS_V2,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_UDPENCAPS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_REMOTE_UDP_ENCAPS_PORT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_PARAMS,
	},
#endif
	/*
	 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
	 *           struct io_event __user *result)
	 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns
	 * the live fill (memset, opcode = IOCB_CMD_PREAD, fd from
	 * get_random_fd(), aio_buf via get_writable_address, optional pool
	 * pin from OBJ_AIO_IOCB) and overwrites rec->a2 wholesale.
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * KCOV-CMP learned constants at the named opcode / flags / fd
	 * slots rather than at a coincidentally-same-width slot.
	 *
	 * Not registered here on purpose: io_submit's a3 is
	 * `struct iocb __user * __user *` -- an array-of-pointers, the
	 * wrong indirection for a flat single-struct descriptor.  The
	 * io_cancel a2 slot is the real `struct iocb *`.
	 */
	{ "io_cancel",		2, &struct_catalog[SC_IOCB] },
	/*
	 * iovec is an array slot on ARG_IOVEC / ARG_IOVEC_IN at the
	 * vec / iov argument of every iovec-shaped syscall; the per-
	 * element type is named here so future schema consumers and
	 * struct_field_for_cmp() can resolve it.  The bespoke
	 * alloc_iovec() generator owns the live (iov_base, iov_len)
	 * layout, so all rows below are attribution-only.
	 *
	 * readv(int fd, const struct iovec *vec, int vlen)
	 * writev(int fd, const struct iovec *vec, int vlen)
	 * preadv(unsigned long fd, const struct iovec *vec,
	 *        unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * preadv2(..., int flags)
	 * pwritev(unsigned long fd, const struct iovec *vec,
	 *         unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * pwritev2(..., int flags)
	 * vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
	 *          unsigned int flags)
	 * process_madvise(int pidfd, const struct iovec *vec, size_t vlen,
	 *                 int behavior, unsigned int flags)
	 */
	{ "readv",		2, &struct_catalog[SC_IOVEC] },
	{ "writev",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv2",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev2",		2, &struct_catalog[SC_IOVEC] },
	{ "vmsplice",		2, &struct_catalog[SC_IOVEC] },
	{ "process_madvise",	2, &struct_catalog[SC_IOVEC] },
	/*
	 * process_vm_readv(pid_t pid, const struct iovec *lvec,
	 *                  unsigned long liovcnt, const struct iovec *rvec,
	 *                  unsigned long riovcnt, unsigned long flags)
	 * process_vm_writev(pid_t pid, const struct iovec *lvec,
	 *                   unsigned long liovcnt, const struct iovec *rvec,
	 *                   unsigned long riovcnt, unsigned long flags)
	 * Both lvec (a2) and rvec (a4) are iovec arrays; map each
	 * separately so attribution covers both slots.
	 */
	{ "process_vm_readv",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_readv",	4, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	4, &struct_catalog[SC_IOVEC] },
	/* sentinel */
	{ NULL, 0, NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr_64[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * desc_by_nr_32[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * Populated at init time by scanning the active syscall table.
 * Split to avoid collisions when biarch builds have different syscall
 * numbers for 32-bit and 64-bit that happen to overlap.
 *
 * Each non-NULL cell points into slot_pool[] and groups every
 * registration for that (nr, arg_idx): one optional default entry plus
 * any discriminator variants.  struct_arg_lookup() walks the variants
 * (rec required) first and falls back to the default; a slot with
 * neither a default nor a matching variant returns NULL.
 */
/*
 * Per-slot discriminated variant cap.  Bumped 8 -> 32 ahead of the
 * setsockopt (level, optname) two-key rows: arg4 will accrete one
 * binding per cataloged optval shape, and even the proof batch
 * (linger / timeval / ip_mreqn / ipv6_mreq / packet_mreq) consumes
 * five slots before any of the higher-leverage shapes (sctp / mptcp /
 * tcp_repair) land.  Init BUG()s on overflow, so the cap MUST be raised
 * before any setsockopt rows -- a deferred bump turns the first
 * registration past 8 into a hard boot failure.
 */
#define DISCRIM_VARIANTS_PER_SLOT_MAX	32

struct slot_binding {
	const struct struct_desc	*default_desc;
	const struct syscall_struct_arg	*discrim[DISCRIM_VARIANTS_PER_SLOT_MAX];
	unsigned int			 num_discrim;
};

/*
 * Slot-binding pool.  Sized for every registered (nr, arg) cell across
 * both arch tables -- syscall_struct_args[] is ~60 entries today, so 256
 * leaves growth headroom and stays comfortably under any reasonable
 * static budget.  struct_catalog_init() BUG()s if a registration
 * overflows either the pool or the per-slot variant cap rather than
 * silently dropping mappings.
 */
#define SLOT_POOL_MAX			256

static struct slot_binding slot_pool[SLOT_POOL_MAX];
static unsigned int slot_pool_used;

static const struct slot_binding *desc_by_nr_64[MAX_NR_SYSCALL][6];
static const struct slot_binding *desc_by_nr_32[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}

/*
 * Read rec->a<arg_idx> (1-based) into *out.  Returns false when arg_idx
 * is out of range so the caller can skip the variant cleanly.  Folded
 * out so the two key paths (key1 and key2) share the dispatch instead
 * of cloning the six-way switch.
 */
static bool read_rec_arg(const struct syscallrecord *rec,
			 unsigned int arg_idx, unsigned long *out)
{
	if (arg_idx == 0 || arg_idx > 6)
		return false;
	switch (arg_idx) {
	case 1: *out = rec->a1; return true;
	case 2: *out = rec->a2; return true;
	case 3: *out = rec->a3; return true;
	case 4: *out = rec->a4; return true;
	case 5: *out = rec->a5; return true;
	case 6: *out = rec->a6; return true;
	}
	return false;
}

/*
 * Match one discriminator key against a raw input value.  Applies the
 * packed-discriminator extraction (shift then mask, both zero-default
 * to the identity transform), then matches against value or values[].
 * Folded out so key1 and key2 share the extract+match block.
 */
static bool discrim_key_matches(unsigned long raw,
				unsigned int shift,
				unsigned long mask,
				unsigned long value,
				const unsigned long *values,
				unsigned int num_values)
{
	unsigned long effective_mask = mask ? mask : ~0UL;
	unsigned long extracted = (raw >> shift) & effective_mask;
	unsigned int j;

	if (values != NULL) {
		for (j = 0; j < num_values; j++) {
			if (values[j] == extracted)
				return true;
		}
		return false;
	}
	return value == extracted;
}

/*
 * Pull the entry's key2 value off rec and AND-match it against key1.
 * Returns true when discrim2_arg_idx == 0 (single-key entry: key2 is a
 * no-op) so the caller's single-key AND stays trivially true.  An
 * unreadable second arg (out-of-range) returns false rather than
 * silently passing -- a misconfigured row should not match anything.
 */
static bool discrim_key2_matches(const struct syscall_struct_arg *sa,
				 const struct syscallrecord *rec)
{
	unsigned long raw;

	if (sa->discrim2_arg_idx == 0)
		return true;
	if (!read_rec_arg(rec, sa->discrim2_arg_idx, &raw))
		return false;
	return discrim_key_matches(raw, sa->discrim2_shift, sa->discrim2_mask,
				   sa->discrim2_value, sa->discrim2_values,
				   sa->num_discrim2_values);
}

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec)
{
	const struct slot_binding *b;
	unsigned int i;

	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	b = do32bit ? desc_by_nr_32[nr][arg_idx - 1]
		    : desc_by_nr_64[nr][arg_idx - 1];
	if (b == NULL)
		return NULL;

	/*
	 * Discriminated variants are consulted only when the caller has a
	 * live syscall record to read sibling args off.  No rec, or no
	 * discriminated entries registered, falls straight through to the
	 * default desc -- the byte-identical pre-discriminator path.
	 */
	if (rec != NULL && b->num_discrim != 0) {
		for (i = 0; i < b->num_discrim; i++) {
			const struct syscall_struct_arg *sa = b->discrim[i];
			unsigned long raw;

			if (!read_rec_arg(rec, sa->discrim_arg_idx, &raw))
				continue;
			if (!discrim_key_matches(raw, sa->discrim_shift,
						 sa->discrim_mask,
						 sa->discrim_value,
						 sa->discrim_values,
						 sa->num_discrim_values))
				continue;
			/*
			 * Key2 only participates when the entry declares one
			 * (discrim2_arg_idx != 0); single-key rows leave
			 * key2 a no-op and stay byte-identical to the
			 * pre-extension path.  Both keys must match.
			 */
			if (!discrim_key2_matches(sa, rec))
				continue;
			return sa->desc;
		}
	}
	return b->default_desc;
}

const struct struct_desc *struct_arg_lookup_two_key(const char *name,
						    unsigned int arg_idx,
						    unsigned long k1,
						    unsigned long k2)
{
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;

	/*
	 * Linear scan keeps the cost identical to struct_arg_lookup_by_name
	 * and avoids a second nr-indexed table just for explicit-key
	 * callers.  syscall_struct_args[] is small (~70 entries today); the
	 * scan runs once per apply_sockopt_entry call which already does
	 * O(table) work picking a random row.
	 *
	 * Skip rows with no second key registered: this entry point is for
	 * genuine two-key resolution -- a single-key row would resolve to
	 * different semantics on its own and a caller wanting that should
	 * use struct_arg_lookup() (rec-path) or struct_arg_lookup_by_name
	 * (discriminator-blind) instead.
	 */
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (sa->discrim_arg_idx == 0 || sa->discrim2_arg_idx == 0)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (!discrim_key_matches(k1, sa->discrim_shift, sa->discrim_mask,
					 sa->discrim_value, sa->discrim_values,
					 sa->num_discrim_values))
			continue;
		if (!discrim_key_matches(k2, sa->discrim2_shift,
					 sa->discrim2_mask,
					 sa->discrim2_value,
					 sa->discrim2_values,
					 sa->num_discrim2_values))
			continue;
		return sa->desc;
	}
	return NULL;
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

/*
 * Read a discriminator of the given width out of buf at off and widen to
 * unsigned long.  Caller must validate width to {1,2,4,8} and that the
 * read stays within the surrounding buffer.
 */
static unsigned long read_discrim(const unsigned char *buf,
				  unsigned int off, unsigned int width)
{
	switch (width) {
	case 1:
		return buf[off];
	case 2: {
		uint16_t v;
		memcpy(&v, buf + off, sizeof(v));
		return v;
	}
	case 4: {
		uint32_t v;
		memcpy(&v, buf + off, sizeof(v));
		return v;
	}
	case 8: {
		uint64_t v;
		memcpy(&v, buf + off, sizeof(v));
		return (unsigned long) v;
	}
	}
	return 0;
}

const struct union_variant *
struct_desc_resolve_variant(const struct struct_desc *desc,
			    struct syscallrecord *rec,
			    const unsigned char *buf)
{
	unsigned long discrim;
	unsigned int idx;
	unsigned int i;

	if (desc == NULL)
		return NULL;
	if (desc->variants == NULL || desc->num_variants == 0)
		return NULL;

	idx = desc->discrim_arg_idx;
	if (idx != 0) {
		if (rec == NULL || idx > 6)
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
	} else if (desc->buffer_discrim_size != 0) {
		/*
		 * Buffer-relative discriminator: the just-filled buffer
		 * carries the discriminator value at a fixed offset.  CMP
		 * and other pre-fill callers pass buf == NULL and short-
		 * circuit here.
		 */
		if (buf == NULL)
			return NULL;
		if (desc->buffer_discrim_offset + desc->buffer_discrim_size >
		    desc->struct_size)
			return NULL;
		/*
		 * Accept widths 1/2/4/8 -- matches the nested reader so the
		 * two callers of read_discrim() stay identical.  Today's
		 * buffer-discrim users are width 2 and 4 only; the width-8
		 * branch is intentionally reachable for future users.
		 */
		if (desc->buffer_discrim_size != 1 &&
		    desc->buffer_discrim_size != 2 &&
		    desc->buffer_discrim_size != 4 &&
		    desc->buffer_discrim_size != 8)
			return NULL;
		discrim = read_discrim(buf, desc->buffer_discrim_offset,
				       desc->buffer_discrim_size);
	} else {
		return NULL;
	}

	for (i = 0; i < desc->num_variants; i++) {
		const struct union_variant *v = &desc->variants[i];

		if (v->discrim_values != NULL) {
			unsigned int j;

			for (j = 0; j < v->num_discrim_values; j++) {
				if (v->discrim_values[j] == discrim)
					return v;
			}
			continue;
		}
		if (v->discrim_value == discrim)
			return v;
	}
	return NULL;
}

const struct union_variant *
struct_desc_resolve_nested_variant(const struct union_variant *outer,
				   const unsigned char *buf,
				   unsigned int size)
{
	unsigned long discrim = 0;
	unsigned int off, width;
	unsigned int i;

	if (outer == NULL || buf == NULL)
		return NULL;
	if (outer->nested_variants == NULL || outer->num_nested_variants == 0)
		return NULL;

	off = outer->nested_discrim_offset;
	width = outer->nested_discrim_size;
	if (width != 1 && width != 2 && width != 4 && width != 8)
		return NULL;
	if (off + width > size)
		return NULL;

	discrim = read_discrim(buf, off, width);

	for (i = 0; i < outer->num_nested_variants; i++) {
		const struct union_variant *v = &outer->nested_variants[i];

		/*
		 * Nested-of-nested is rejected here defensively -- the fill
		 * path also caps recursion, but refusing the entry up-front
		 * keeps the API contract explicit.
		 */
		if (v->nested_variants != NULL)
			continue;

		if (v->discrim_values != NULL) {
			unsigned int j;

			for (j = 0; j < v->num_discrim_values; j++) {
				if (v->discrim_values[j] == discrim)
					return v;
			}
			continue;
		}
		if (v->discrim_value == discrim)
			return v;
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
	/*
	 * CMP runs before the next fill so there's no buffer to consult
	 * for buffer-discriminator structs; passing buf == NULL makes the
	 * resolver short-circuit and attribution lands on the flat field
	 * list (typically the shared head field carrying the discriminator
	 * itself, which is the high-value CMP target anyway).
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
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
	const struct struct_desc *first = NULL;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	/*
	 * Prefer the slot's default (non-discriminated) entry; fall back to
	 * the first discriminated variant when no default is registered.
	 * Callers that need OR-across-all-variants semantics (e.g. the
	 * nested-address-scrub mask) use struct_arg_any_has_address_field()
	 * below -- single-desc returns can't represent that question.
	 */
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (sa->discrim_arg_idx == 0)
			return sa->desc;
		if (first == NULL)
			first = sa->desc;
	}
	return first;
}

bool struct_arg_any_has_address_field(const char *name, unsigned int arg_idx)
{
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return false;
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (struct_desc_has_address_field(sa->desc))
			return true;
	}
	return false;
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

/*
 * Allocate (or fetch) the slot_binding cell at table[nr][arg_idx-1].
 * Pool growth is bounded by SLOT_POOL_MAX; running out is a hard
 * configuration error (caller forgot to bump the cap when extending
 * the registration table), not a runtime degradation, so BUG() rather
 * than silently dropping mappings.
 */
static struct slot_binding *
slot_binding_get(const struct slot_binding *table[MAX_NR_SYSCALL][6],
		 unsigned int nr, unsigned int arg_idx)
{
	struct slot_binding *b;

	if (table[nr][arg_idx - 1] != NULL)
		return (struct slot_binding *) table[nr][arg_idx - 1];

	if (slot_pool_used >= SLOT_POOL_MAX) {
		output(0, "struct_catalog: SLOT_POOL_MAX (%u) exhausted at "
		       "(nr=%u, arg=%u) -- raise SLOT_POOL_MAX or trim "
		       "syscall_struct_args[]\n",
		       (unsigned int) SLOT_POOL_MAX, nr, arg_idx);
		BUG("struct_catalog: SLOT_POOL_MAX exhausted");
	}
	b = &slot_pool[slot_pool_used++];
	b->default_desc = NULL;
	b->num_discrim = 0;
	table[nr][arg_idx - 1] = b;
	return b;
}

/*
 * Attach one syscall_struct_args[] entry to its (nr, arg_idx) binding.
 * Default entries write through to slot_binding::default_desc;
 * discriminated entries push into the variant list in registration
 * order so the lookup walk's first-match semantic matches the source
 * declaration order.  Multiple defaults for the same slot are a
 * registration bug; BUG() so the conflict surfaces at init rather than
 * silently leaking the later-registered desc into the lookup.
 */
static void slot_binding_attach(const struct slot_binding *table[MAX_NR_SYSCALL][6],
				unsigned int nr,
				const struct syscall_struct_arg *sa)
{
	struct slot_binding *b = slot_binding_get(table, nr, sa->arg_idx);

	if (sa->discrim_arg_idx == 0) {
		if (b->default_desc != NULL) {
			output(0, "struct_catalog: duplicate default "
			       "registration for (%s, arg %u)\n",
			       sa->syscall_name, sa->arg_idx);
			BUG("struct_catalog: duplicate default registration");
		}
		b->default_desc = sa->desc;
		return;
	}
	if (b->num_discrim >= DISCRIM_VARIANTS_PER_SLOT_MAX) {
		output(0, "struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX (%u) "
		       "exhausted for (%s, arg %u) -- raise the cap or "
		       "collapse variants\n",
		       (unsigned int) DISCRIM_VARIANTS_PER_SLOT_MAX,
		       sa->syscall_name, sa->arg_idx);
		BUG("struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX exhausted");
	}
	b->discrim[b->num_discrim++] = sa;
}

/*
 * Slot-shape guard for syscall_struct_args[] rows.
 *
 * argtype[] is 0-indexed; syscall_struct_args::arg_idx is 1-indexed.  The
 * off-by-one was caught in the 2026-06-11 audit when six of eight new rows
 * were silently mapping their struct_desc onto the wrong slot -- the
 * dispatcher tolerates the mismatch (the desc fires against whatever
 * argtype actually sits at argidx-1, typically ARG_PATHNAME or a scalar
 * length / fd) so nothing aborted at build or runtime.  This guard turns
 * that silent mis-map into an init-time BUG by demanding that the slot
 * named by (argidx - 1) is a pointer-bearing argtype that can plausibly
 * carry the registered struct:
 *
 *   - ARG_STRUCT_PTR_IN / OUT / INOUT  (schema-aware fill, primary user)
 *   - ARG_ADDRESS / ARG_NON_NULL_ADDRESS  (bespoke .sanitise owns the
 *     live fill, attribution-only catalog row for CMP steering)
 *   - ARG_IOVEC / ARG_IOVEC_IN  (alloc_iovec() owns the live fill;
 *     catalog row is attribution-only for the iov_base / iov_len CMP
 *     names, see the SC_IOVEC comment above the catalog slot)
 *   - ARG_SOCKADDR  (bespoke sockaddr generator owns the live fill;
 *     attribution-only catalog row for sa_family / port CMP names)
 *   - ARG_UNDEFINED  (the syscall has not fully classified its
 *     argtypes -- the bespoke .sanitise owns the fill regardless;
 *     this case is permissive on purpose so the guard does not block
 *     the long tail of legacy syscallentries that still leave argtype
 *     unset.  Migrating those to concrete argtypes tightens the guard
 *     for free.)
 *
 * The rejected set is what the off-by-one bug actually lands on:
 * ARG_PATHNAME (filename slot), ARG_LEN, ARG_FD and all typed-fd
 * argtypes, ARG_MODE_T, ARG_PID, ARG_KEY_SERIAL, ARG_RANGE, ARG_OP,
 * ARG_LIST, ARG_CPU, ARG_NUMA_NODE, ARG_MMAP, ARG_SOCKETINFO, the
 * paired-length helpers (ARG_IOVECLEN, ARG_SOCKADDRLEN, ARG_STRUCT_SIZE),
 * etc. -- every scalar or string slot whose contents are not a struct
 * the kernel will dereference as the desc named here.
 */
static bool is_struct_slot_argtype(enum argtype t)
{
	switch (t) {
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_UNDEFINED:
		return true;
	default:
		return false;
	}
}

static const char *argtype_name(enum argtype t)
{
	if ((unsigned int) t < argtype_table_size && argtype_table[t].name != NULL)
		return argtype_table[t].name;
	return "<unknown>";
}

static void validate_one_against_table(const struct syscalltable *table,
				       unsigned int nr_syscalls,
				       const char *tablename,
				       const struct syscall_struct_arg *sa,
				       unsigned int *violations)
{
	struct syscallentry *entry;
	enum argtype t;
	int nr;

	nr = search_syscall_table(table, nr_syscalls, sa->syscall_name);
	if (nr < 0)
		return;		/* not present on this arch table -- not an error */
	if ((unsigned int) nr >= MAX_NR_SYSCALL)
		return;
	entry = table[nr].entry;
	if (entry == NULL)
		return;

	if (sa->arg_idx < 1 || sa->arg_idx > entry->num_args) {
		outputerr("struct_catalog: %s arg_idx %u out of range for "
			  "syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, entry->name,
			  entry->num_args, tablename);
		(*violations)++;
		return;
	}

	t = entry->argtype[sa->arg_idx - 1];
	if (!is_struct_slot_argtype(t)) {
		outputerr("struct_catalog: %s arg %u maps struct_desc \"%s\" "
			  "onto non-struct slot (argtype[%u]=%s, num_args=%u) "
			  "in %s -- argidx is 1-based, argtype[] is 0-based; "
			  "off-by-one?\n",
			  sa->syscall_name, sa->arg_idx,
			  sa->desc != NULL ? sa->desc->name : "<null>",
			  sa->arg_idx - 1, argtype_name(t),
			  entry->num_args, tablename);
		(*violations)++;
	}

	if (sa->discrim_arg_idx != 0 &&
	    (sa->discrim_arg_idx < 1 || sa->discrim_arg_idx > entry->num_args)) {
		outputerr("struct_catalog: %s arg %u discrim_arg_idx %u out of "
			  "range for syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, sa->discrim_arg_idx,
			  entry->name, entry->num_args, tablename);
		(*violations)++;
	}
}

static void validate_syscall_struct_args(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int violations = 0;

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (biarch) {
			validate_one_against_table(syscalls_64bit,
						   max_nr_64bit_syscalls,
						   "64bit table", sa,
						   &violations);
			validate_one_against_table(syscalls_32bit,
						   max_nr_32bit_syscalls,
						   "32bit table", sa,
						   &violations);
		} else {
			validate_one_against_table(syscalls,
						   max_nr_syscalls,
						   "syscall table", sa,
						   &violations);
		}
	}

	if (violations != 0) {
		outputerr("struct_catalog: %u syscall_struct_args[] entr%s "
			  "failed slot-shape validation -- see lines above\n",
			  violations, violations == 1 ? "y" : "ies");
		BUG("struct_catalog: syscall_struct_args[] slot-shape violation");
	}
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	/*
	 * Holes are zero-init struct_desc slots with .name == NULL --
	 * a sign of a typo'd [SC_X] designator above the slot, or of an
	 * SC_X enum constant added without a matching catalog entry.
	 * Catch it on first init rather than letting the dispatch path
	 * deref a half-zeroed struct_desc.
	 */
	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (struct_catalog[i].name == NULL) {
			outputerr("struct_catalog: hole at slot %u "
				  "(missing [SC_X] designator)\n", i);
			BUG("struct_catalog: hole in catalog array");
		}
	}

	validate_syscall_struct_args();

	memset(desc_by_nr_64, 0, sizeof(desc_by_nr_64));
	memset(desc_by_nr_32, 0, sizeof(desc_by_nr_32));
	slot_pool_used = 0;

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL) {
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
			}
		}
	}

	for (i = 0; i < SC_NR_ENTRIES; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
