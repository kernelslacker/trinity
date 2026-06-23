#pragma once

#include <time.h>
#include <sys/types.h>
#include "locks.h"
#include "object-types.h"
#include "types.h"
#include "utils.h"

#define PREBUFFER_LEN	4096
#define POSTBUFFER_LEN	128

#define MAX_NR_SYSCALL 1024

enum syscallstate {
	UNKNOWN,	/* new child */
	PREP,		/* doing sanitize */
	BEFORE,		/* about to do syscall */
	GOING_AWAY,	/* used when we don't expect to come back (execve for eg) */
	AFTER,		/* returned from doing syscall. */
};

enum arg_ptr_dir {
	ARG_DIR_NONE = 0,
	ARG_DIR_IN,
	ARG_DIR_OUT,
	ARG_DIR_INOUT,
	ARG_DIR_OPTIONAL_IN,
	ARG_DIR_OPTIONAL_OUT,
	ARG_DIR_OPAQUE,
};

enum arg_ptr_owner {
	ARG_OWNER_NONE = 0,
	ARG_OWNER_GENERIC,
	ARG_OWNER_SANITISER,
	ARG_OWNER_POST_STATE,
	ARG_OWNER_EXTERNAL,
};

/*
 * arg_slot_meta.flags bits.  Descriptive only in this row -- the live
 * inject/scrub/cleanup paths do not consult any of them.
 */
#define ARG_META_FLAG_CURATED			(1u << 0)
#define ARG_META_FLAG_ALLOW_NULL		(1u << 1)
#define ARG_META_FLAG_MAY_ALIAS_USER		(1u << 2)
#define ARG_META_FLAG_NEEDS_CLEANUP		(1u << 3)
#define ARG_META_FLAG_POST_HANDLER_CONSUMES	(1u << 4)
#define ARG_META_FLAG_MINICORPUS_REPLAY_SAFE	(1u << 5)
#define ARG_META_FLAG_SKIP_BLANKET_SCRUB	(1u << 6)

struct arg_slot_meta {
	void		*alloc_base;
	size_t		len;
	size_t		alloc_len;
	uint32_t	flags;
	uint32_t	struct_tag;
	uint32_t	generation;
	uint8_t		dir;		/* enum arg_ptr_dir */
	uint8_t		owner;		/* enum arg_ptr_owner */
};

struct syscallrecord {
	unsigned int nr;

	/*
	 * Pointer to the resolved syscallentry for this call.  Stamped once
	 * at the top of dispatch_step() (the only path that drives a real
	 * syscall through this rec) so the .sanitise / .post handlers and
	 * their helpers (this_syscallname() and the per-discriminator flag
	 * tests built on top of it) can read the entry directly instead of
	 * re-running get_syscall_entry(nr, do32bit) -- which is a table
	 * lookup plus a biarch branch -- on every probe.  NULL outside an
	 * in-flight dispatch; this_syscallname() treats NULL as "not me".
	 */
	struct syscallentry *entry;

	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long retval;

	/*
	 * Per-syscall scratch slot owned by .post handlers.  Sanitise stashes
	 * a pointer or value here (typically a copy of an argN that needs to
	 * outlive .post) so the post path is immune to the argN slot being
	 * scribbled by sibling syscalls between BEFORE and AFTER.
	 */
	unsigned long post_state;

	/* timestamp (written before the syscall, and updated afterwards. */
	struct timespec tp;

	int errno_post;	/* what errno was after the syscall. */
	int rettype;	/* per-call return type (copied from entry, may be overridden by sanitise) */

	bool do32bit;
	/*
	 * Set true by do_syscall() when validate_arg_coupling() rejects the
	 * call before the kernel is entered.  Read by dispatch_step() to skip
	 * kcov_collect() -- a userspace pre-validation reject did not exercise
	 * any kernel code, so bumping total_calls / per_syscall_calls[nr] for
	 * it would poison kcov_syscall_cold_skip_pct() on syscalls whose
	 * validators are strict.  Cleared per-call at the top of
	 * dispatch_step() alongside rec->entry.
	 */
	bool validator_rejected;
	lock_t lock;
	enum syscallstate state;
	char prebuffer[PREBUFFER_LEN];
	char postbuffer[POSTBUFFER_LEN];

	/*
	 * Wholesale-stomp detector.  Stamped with REC_CANARY_MAGIC just
	 * before the syscall is dispatched; checked on entry to
	 * handle_syscall_ret().  The snapshot pattern (post_state, plus
	 * per-handler argN shadows) defends against scribbles of individual
	 * pointer slots, but an aliased value-result write from a sibling
	 * syscall can clobber the entire syscallrecord including bookkeeping
	 * fields the snapshot pattern can't shadow.  An unchanged canary at
	 * post-handler entry rules that class out for the call; a mismatch
	 * tells us the rec was rewritten under us between BEFORE and AFTER.
	 *
	 * Trailing the postbuffer (cold tail) is deliberate: a wholesale
	 * stomp typically covers many hundreds of bytes, so a canary near
	 * the end has the highest probability of being inside the clobber
	 * region while staying off every hot cacheline.
	 */
	uint64_t _canary;

	/*
	 * Per-arg shadow of integer slots the post handler will read to
	 * validate rec->retval.  Populated in __do_syscall() after the
	 * second blanket_address_scrub from the local a1..a6 values that
	 * are about to be passed to the kernel, gated on
	 * entry->arg_snapshot_mask.  Opted-in post handlers read via
	 * get_arg_snapshot(rec, N) instead of rec->aN directly; the
	 * accessor verifies shadow vs. live and bumps arg_shadow_stomp on
	 * mismatch.  Defends the small set of handlers that compare an
	 * integer arg against retval (epoll_wait family's maxevents,
	 * getsid's pid gate) from sibling-stomp scribbles of rec->aN
	 * between dispatch and the post handler -- a stomp that leaves the
	 * canary intact is invisible to the wholesale detector above.
	 * Capturing from the dispatch-time locals rather than rec->aN
	 * means the tripwire only fires for a stomp that lands AFTER the
	 * kernel saw its args, which is the bug class arg_shadow_stomp is
	 * meant to surface; an earlier sanitise/dispatch-window stomp is
	 * already covered by the kernel seeing the stomped value directly.
	 * arg_snapshot_mask mirrors entry->arg_snapshot_mask at snapshot
	 * time so the accessor can confirm "this slot was actually
	 * shadowed" without re-resolving the entry per read.  Placed after
	 * _canary (cold tail) so a single stomp pattern aliased onto the
	 * aN slots will not also hit the shadow at the matching offset.
	 */
	unsigned long arg_shadow[6];
	uint8_t arg_snapshot_mask;

	/*
	 * Always-populated, non-tripwire snapshot of the six syscall args
	 * captured in __do_syscall() from the dispatch-time locals a1..a6
	 * right after the second blanket_address_scrub() and before kernel
	 * entry.  Read by cmp_hints_collect()'s RedQueen attribution scan
	 * so attribution runs against the values the kernel actually saw,
	 * rather than against live rec->aN which a sibling stomp can
	 * rewrite between dispatch and the consumer.
	 *
	 * Distinct from arg_shadow[] above: that array is opt-in per
	 * syscall (gated by entry->arg_snapshot_mask) and carries the
	 * post-handler tripwire / corruption-counter contract enforced by
	 * get_arg_snapshot().  The CMP/RedQueen path is not a per-syscall
	 * result oracle -- it sweeps every dispatched call -- so it wants
	 * an always-on snapshot with no per-slot opt-in and no per-read
	 * tripwire bump.  dispatch_args_valid is set true alongside the
	 * populate; consumers gate the read on it so a fresh rec that
	 * never went through __do_syscall() (zero-init) returns no
	 * attribution rather than reading a zeroed array.
	 */
	unsigned long dispatch_args[6];
	bool dispatch_args_valid;

	/*
	 * Publish sequence counter for lock-free diagnostic readers.
	 * Mutated by srec_publish_begin / srec_publish_end (see
	 * syscall_record.h) which writers bracket around coherent field
	 * writes: odd during in-progress mutations, even on completion.
	 * The brackets are self-sufficient ordering anchors, so writers
	 * are free to drop rec->lock around them.  Readers spin on
	 * SREC_SNAPSHOT() against this field for a coherent multi-field
	 * view without taking rec->lock.  Placed at the end of the
	 * struct so existing field offsets stay put; the whole
	 * syscallrecord is already pushed into the cold tail of struct
	 * childdata, so seq lands far outside any hot cacheline.
	 */
	uint32_t seq;

	/*
	 * Per-rec owned-pointer list.  A small fixed-size carrier any
	 * pre-dispatch phase (sanitise, fill_arg generators, nested
	 * struct fills) appends to via rec_own(); the dispatcher's
	 * cleanup phase drains it via rec_owned_drain() exactly once
	 * per dispatched call, unconditionally -- on success, on
	 * failure, on the validator_rejected early-EINVAL skip, on the
	 * --dry-run synthesised ENOSYS path, and on the EXTRA_FORK
	 * grandchild that died before AFTER.  Lets a sanitiser register
	 * ownership of a heap buffer at allocation time without having
	 * to enqueue it onto the deferred-free ring before the kernel
	 * has read it (the lifetime-inversion shape that motivated this
	 * carrier in the first place: a pre-dispatch enqueue survives
	 * today only because the ring TTL outlasts the in-flight
	 * syscall, and any early-drain path -- ENOMEM dispose, full-
	 * ring eviction -- can free a buffer the kernel is still
	 * reading).
	 *
	 * Sized to cover every in-tree sanitiser with headroom: the
	 * heaviest planned callers (execve, io_uring_setup, setsockopt)
	 * own <= 3 buffers; nested cataloged-struct fills (Phase 5) are
	 * the only path that can plausibly approach the bound, and a
	 * static_assert there can grow the limit if a future addition
	 * pushes past it.  Overflow degrades to deferred_free_enqueue()
	 * (with a stat bump) rather than leaking; see rec_own() for the
	 * fallback rationale.
	 *
	 * Memory cost: REC_OWNED_MAX * sizeof(void *) + sizeof(unsigned
	 * int) ~= 68 bytes per rec, in the cold tail of the rec which
	 * is itself in the cold tail of struct childdata -- no hot-
	 * cacheline impact.  Reset to empty (owned_count = 0) at the
	 * top of generate_syscall_args() alongside the rec->post_state
	 * reset hoist, so a sanitise-less minicorpus-replay step cannot
	 * inherit a stale entry from the previous dispatch.
	 *
	 * Placed after seq so the seq field's offset (and every
	 * existing field offset above it) stay put.
	 */
#define REC_OWNED_MAX	8
	void		*owned[REC_OWNED_MAX];
	unsigned int	owned_count;

	/*
	 * SHADOW per-arg-slot ownership/direction descriptor.  Seeded from
	 * the slot's argtype at the tail of generate_syscall_args() before
	 * blanket_address_scrub runs.  Telemetry only: no consumer reads
	 * dir/owner/flags/len to decide injection, scheduling, or scrub
	 * policy.  Lives in the cold tail of the rec (after owned[]) so
	 * the offset of every existing field stays put.  arg_meta_gen is
	 * the per-rec dispatch sequence the seed stamps into each slot's
	 * generation field so a stale sidecar inherited from a prior
	 * dispatch (missed reset path) is detectable.
	 */
	struct arg_slot_meta arg_meta[6];
	uint32_t	arg_meta_gen;
};

#define REC_CANARY_MAGIC	0xdeadbeefcafebabeULL

enum argtype {
	ARG_UNDEFINED,
	ARG_FD,
	ARG_LEN,
	ARG_ADDRESS,
	ARG_MODE_T,
	ARG_NON_NULL_ADDRESS,
	ARG_PID,
	ARG_KEY_SERIAL,	/* kernel keyring key_serial_t (signed 32-bit) */
	ARG_TIMERID,	/* POSIX per-process timer_t */
	ARG_AIO_CTX,	/* Linux AIO aio_context_t (opaque kernel u64) */
	ARG_SEM_ID,	/* SysV semaphore set id from semget (signed int) */
	ARG_MSG_ID,	/* SysV message queue id from msgget (signed int) */
	ARG_SYSV_SHM,	/* SysV shared memory id from shmget (signed int) */
	ARG_RANGE,
	ARG_OP,
	ARG_LIST,
	ARG_CPU,
	ARG_NUMA_NODE,
	ARG_PATHNAME,
	ARG_XATTR_NAME,	/* writable pool buffer filled with a namespace-shaped xattr name */
	ARG_FSTYPE_NAME,	/* writable pool buffer filled with a filesystem-type name */
	ARG_TIMESPEC,	/* writable pool buffer filled with a bucketed struct timespec */
	ARG_ITIMERVAL,	/* writable pool buffer filled with a bucketed struct itimerval (setitimer) */
	ARG_ITIMERSPEC,	/* writable pool buffer filled with a bucketed struct itimerspec (timer_settime) */
	ARG_TIMEVAL,	/* writable pool buffer filled with a bucketed struct timeval (settimeofday/adjtime) */
	ARG_NODEMASK,	/* writable pool buffer filled with a valid-ish NUMA nodemask bitmap */
	ARG_CPUMASK,	/* writable pool buffer filled with a valid-ish CPU affinity mask (cpu_set_t) */
	ARG_BUF_SIZED,	/* writable pool buffer + coherent paired byte length */
	ARG_BUF_LEN,	/* paired byte-length sibling of ARG_BUF_SIZED */
	ARG_IOVEC,
	ARG_IOVEC_IN,
	ARG_IOVECLEN,
	ARG_SOCKADDR,
	ARG_SOCKADDRLEN,
	ARG_MMAP,
	ARG_SOCKETINFO,
	ARG_STRUCT_PTR_IN,
	ARG_STRUCT_PTR_OUT,
	ARG_STRUCT_PTR_INOUT,
	ARG_STRUCT_SIZE,
	ARG_FD_BPF_BTF,
	ARG_FD_BPF_LINK,
	ARG_FD_BPF_MAP,
	ARG_FD_BPF_PROG,
	ARG_FD_EPOLL,
	ARG_FD_EVENTFD,
	ARG_FD_FANOTIFY,
	ARG_FD_FS_CTX,
	ARG_FD_INOTIFY,
	ARG_FD_IO_URING,
	ARG_FD_LANDLOCK,
	ARG_FD_MEMFD,
	ARG_FD_MOUNT,
	ARG_FD_MQ,
	ARG_FD_PERF,
	ARG_FD_PIDFD,
	ARG_FD_PIPE,
	ARG_FD_SIGNALFD,
	ARG_FD_SOCKET,
	ARG_FD_TIMERFD,
};

static inline bool is_typed_fdarg(enum argtype type)
{
	return type >= ARG_FD_BPF_BTF && type <= ARG_FD_TIMERFD;
}

static inline bool is_fdarg(enum argtype type)
{
	return type == ARG_FD || is_typed_fdarg(type);
}

struct arglist {
	unsigned int num;
	unsigned long *values;
	/* OR of values[0..num).  Populated once at table init by
	 * populate_arglist_all_bits() from copy_syscall_table(); zero
	 * before that pass runs and zero on arg slots whose argtype is
	 * not ARG_OP/ARG_LIST (those slots use the .range union member
	 * and never read this field). */
	unsigned long all_bits;
};

#define ARGLIST(vals)		\
{				\
	.num = ARRAY_SIZE(vals),\
	.values = vals,		\
}

#define NR_ERRNOS 133	// Number in /usr/include/asm-generic/errno.h

/* Per-(syscall,argnum) scoreboard of low-numbered fds (0..255) that have
 * survived a successful call.  Inline 32-byte bitmap so the whole struct
 * stays POD and lives in alloc_shared() memory -- no per-process pointers
 * (see commit e065bf1241a1 for why pointers do not work here). */
#define SUCCESS_FD_SCOREBOARD_BITS	256
#define SUCCESS_FD_SCOREBOARD_BYTES	(SUCCESS_FD_SCOREBOARD_BITS / 8)

/* Packed views of the ARG_LEN scoreboard (min, max) and the failed-fd
 * run-length tracker (fd, count).  Both are updated lock-free via CAS
 * loops on the raw word -- len_score by store_successful_len(), fail_run
 * by store_failed_fd() (bump) and store_successful_fd() (clear). */
union len_score_u {
	uint64_t raw;
	struct {
		uint32_t min;
		uint32_t max;
	} u;
};
union fail_run_u {
	uint32_t raw;
	struct {
		uint8_t fd;
		uint8_t count;
		uint16_t pad;
	} u;
};

struct results {
	/* Lockless: all scoreboard updates use atomic ops -- the fd bitmaps
	 * are set/cleared via __atomic on the byte, len_score is RMW'd via
	 * CAS on the packed 64-bit word, and fail_run is RMW'd via CAS on
	 * the packed 32-bit word.  No mutex is taken on any update path. */
	/* ARG_FD / typed-fd: bit `fd` set if get_random_fd / get_typed_fd
	 * returned that low fd for this slot and the call succeeded. */
	unsigned char success_fds[SUCCESS_FD_SCOREBOARD_BYTES];
	/* ARG_FD / typed-fd: bit `fd` set after the same fd has failed
	 * FAIL_RUN_THRESHOLD times in a row on this slot.  fill_arg() uses
	 * it to bias re-rolls away from (slot, fd) pairs the kernel keeps
	 * rejecting (EBADF/EINVAL/etc).  Cleared by store_successful_fd(). */
	unsigned char failed_fds[SUCCESS_FD_SCOREBOARD_BYTES];
	/* ARG_LEN: range of successful length values, folded into one
	 * 64-bit word so store_successful_len() can RMW it with a single
	 * CAS.  min == UINT32_MAX && max == 0 is the not-seen sentinel
	 * (stamped by results_init_one() in results.h); readers should
	 * check len_score_is_seen() before consuming min/max. */
	union len_score_u len_score;
	/* Run-length tracking for the failed_fds bitmap.  Only the most
	 * recently-failing fd is tracked (full per-fd counters would cost
	 * 256 bytes per slot); good enough since we only care about long
	 * consecutive runs against a single fd, which is the actual symptom
	 * of a permanently-broken (slot, fd) pair.  count == 0 means no
	 * run in flight (so static-zero init "just works").  Mutated
	 * lock-free via CAS on fail_run.raw. */
	union fail_run_u fail_run;
};

#define FAIL_RUN_THRESHOLD	3
#define FAILED_FD_REROLL_LIMIT	16

struct syscallentry {
	void (*sanitise)(struct syscallrecord *rec);
	void (*post)(struct syscallrecord *rec);
	/*
	 * Unconditional per-syscall teardown hook.  Runs exactly once per
	 * dispatched call, from the tail of handle_syscall_ret(), AFTER
	 * .post and BEFORE generic_free_arg() recycles the argtype-owned
	 * buffers.  Unlike .post, .cleanup does NOT gate on state == AFTER
	 * or on the retfd / rzs rejection flags: it fires on success, on
	 * failure, on the validator_rejected early-EINVAL skip, on the
	 * --dry-run synthesised ENOSYS path, and on the EXTRA_FORK
	 * grandchild that died before reaching AFTER.  This is the home for
	 * sanitiser-owned frees -- buffers the sanitiser allocated and
	 * stashed in rec (typically via rec->post_state, which is private
	 * to the post / cleanup pair and less stomp-prone than the rec->aN
	 * syscall slots).  Moving these frees out of pre-dispatch
	 * deferred_free_enqueue_or_leak() and out of .post lets .post stay
	 * a pure successful-result inspector (close the returned fd,
	 * publish_resource(), mq_unlink the named queue, ...) while
	 * .cleanup owns the deterministic teardown.
	 *
	 * Implementation pattern: stash the canonical pointer in
	 * rec->post_state at sanitise time, defend the cleanup-time deref
	 * with looks_like_corrupted_ptr() (or a *_POST_STATE_MAGIC cookie
	 * compare for snap structs), and call tracked_free_now() rather
	 * than raw free() for zmalloc_tracked() pointers so the alloc-track
	 * side-set stays in lock-step with the heap.
	 */
	void (*cleanup)(struct syscallrecord *rec);
	int (*init)(void);
	char * (*decode)(struct syscallrecord *rec, unsigned int argnum);

	unsigned int number;
	unsigned int active_number;
	const char *name;
	const unsigned int num_args;
	unsigned int flags;

	enum argtype argtype[6];

	const char *argname[6];

	struct results results[6];

	unsigned int successes, failures, attempted;
	unsigned int errnos[NR_ERRNOS + 1];

	/*
	 * Per-argument type-specific parameters, indexed [0..5] for args 1..6.
	 * ARG_RANGE uses .range.{low,hi}; ARG_OP/ARG_LIST uses .list.
	 * An argument can only ever be one type, so these are unioned.
	 */
	struct arg_param {
		union {
			struct { unsigned int low, hi; } range;
			struct arglist list;
		};
	} arg_params[6];

	const unsigned int group;
	const int rettype;

	/*
	 * Object type for the fd this syscall returns, or OBJ_NONE if
	 * the syscall does not return a trackable fd.  Set once in the
	 * syscallentry; the generic post-hook in handle_syscall_ret()
	 * uses it to register the returned fd into the per-type pool
	 * automatically, without each new fd-creating syscall having
	 * to write its own .post handler.
	 */
	enum objecttype ret_objtype;

	/*
	 * Post-derived secondary-object registrar.  ret_objtype covers
	 * the single-fd case where the syscall's primary retval IS the
	 * trackable object (open, socket, accept, ...).  Some syscalls
	 * instead return their object(s) out of band: through a user
	 * out-pointer (io_setup's ctxp, timer_create's created_timer_id,
	 * name_to_handle_at's handle/mnt_id) or as a multi-fd pair
	 * written into a user int[2] (pipe, pipe2, socketpair).  The
	 * static enum slot above cannot express "two pipe fds at
	 * fildes[0..1]" or "an aio_context_t dereferenced from rec->aN",
	 * so the registration logic for those syscalls lives in a
	 * per-syscall hook that reads the relevant scratch slot
	 * (rec->post_state, rec->aN) and calls the appropriate
	 * register_*()/publish_*() helper.  Invoked from
	 * handle_syscall_ret() ahead of entry->post(); .post may clear
	 * rec->post_state during its cleanup pass, and reading the
	 * scratch slot from the hook after that point would see zero.
	 * The hook is responsible for its own retval check and shape
	 * validation -- success criteria differ per syscall (== 0 for
	 * pipe/socketpair/io_setup, >= 0 for timer_create) and the
	 * dispatcher cannot uniformly gate the call.
	 */
	void (*ret_objtype_via_post)(struct syscallrecord *rec);

	/*
	 * Cached coarse syscall category (enum syscall_category, fits in a
	 * byte).  Resolved once from .name at table-init time in
	 * copy_syscall_table() so the dispatch path can index
	 * syscall_category_count[] directly instead of re-running the
	 * ~70-entry strncmp prefix scan in stats_syscall_category() on
	 * every call.
	 */
	unsigned char syscall_category;

	/*
	 * Cached "is this the close(2) syscall?" flag.  Resolved once from
	 * .name at table-init time in copy_syscall_table() so the dispatch
	 * fd-leak accounting in random-syscall.c can branch on a single
	 * byte load instead of running strcmp(entry->name, "close") on
	 * every syscall invocation.
	 */
	bool is_close_syscall;

	/*
	 * Cached per-discriminator flags for the handful of shared
	 * .sanitise / .post hooks that serve two syscallentries and need
	 * to tell which variant they were called for (mmap vs mmap2,
	 * sync_file_range vs sync_file_range2, inotify_init vs
	 * inotify_init1, epoll_create vs epoll_create1, execve vs
	 * execveat).  Resolved once from .name at table-init time in
	 * copy_syscall_table() so the discriminator collapses to a single
	 * byte load instead of the lookup-and-strcmp shape this_syscallname
	 * costs on every probe.  Packed adjacent to is_close_syscall so the
	 * whole cluster fits in the existing alignment hole in front of
	 * bound_arg without growing the struct.
	 */
	bool is_mmap2;
	bool is_sync_file_range2;
	bool is_inotify_init1;
	bool is_epoll_create1;
	bool is_execve;

	/*
	 * Cached membership flag for the epoll_wait family
	 * (epoll_wait / epoll_pwait / epoll_pwait2), set at table init
	 * so validate_arg_coupling() can short-circuit non-members with
	 * a single byte load instead of three strcmps per dispatch.
	 */
	bool is_epoll_wait_family;

	/*
	 * Cached bitmap of arg slots (1..6) whose argtype legitimately
	 * accepts a numeric substitute -- bit k set means slot (k+1) is a
	 * legal target for the sequence-chain executor's retval-substitute
	 * stomp.  Resolved once from .argtype[] at table-init time in
	 * copy_syscall_table() via compute_numeric_substitute_mask() so
	 * apply_chain_substitution() in random-syscall.c can dispatch via a
	 * single masked-rand + __builtin_ctz instead of re-walking the
	 * argtype array and re-running the 23-case
	 * argtype_accepts_numeric_substitute() switch on every chain step.
	 * 6 bits used; upper 2 bits always zero.
	 */
	uint8_t numeric_substitute_mask;

	/*
	 * Cached bitmaps of arg slots (1..6) that participate in the per-call
	 * hot loops that used to walk the full argtype[] table for every
	 * dispatch.  Bit k (k=0..5) set means slot (k+1) qualifies:
	 *
	 *   address_scrub_mask  -- argtype_get_ops()->default_address_scrub
	 *                          eligible slot (blanket_address_scrub() in
	 *                          generate-args.c).
	 *   cleanup_arg_mask    -- argtype_get_ops()->cleanup is non-NULL
	 *                          (generic_free_arg() in generate-args.c).
	 *   fd_arg_mask         -- is_fdarg(argtype) -- ARG_FD or any typed-fd
	 *                          argtype (handle_success/handle_failure in
	 *                          results.c).
	 *   len_arg_mask        -- argtype == ARG_LEN (handle_success in
	 *                          results.c).
	 *
	 * Resolved once at table-init time in copy_syscall_table() via the
	 * matching compute_*_mask() helpers so the hot loops can early-return
	 * on a zero mask and dispatch via __builtin_ctz instead of walking
	 * the argtype array and re-running argtype_get_ops() / is_fdarg() per
	 * slot.  6 bits used per mask; upper 2 bits always zero.
	 */
	uint8_t address_scrub_mask;
	uint8_t cleanup_arg_mask;
	uint8_t fd_arg_mask;
	uint8_t len_arg_mask;

	/*
	 * Bitmap of arg slots whose argtype is ARG_STRUCT_PTR_IN/OUT/INOUT
	 * AND whose cataloged struct reaches an FT_ADDRESS field via the
	 * pointer chain (direct, FT_PTR_STRUCT target, or FT_PTR_ARRAY
	 * element struct).  blanket_address_scrub() walks the struct buffer
	 * for these slots and applies avoid_shared_buffer_out() to every
	 * FT_ADDRESS field discovered, so address-like fields nested inside
	 * cataloged structs get the same wild-write defense as top-level
	 * ARG_ADDRESS slots.  Zero for the bulk of syscalls -- the dispatch
	 * short-circuits on the cached zero without a struct walk.
	 */
	uint8_t nested_address_scrub_mask;

	/*
	 * Trinity 1-based index (1..6) of the syscall argument whose value
	 * upper-bounds rec->retval -- typically the "count" / "size" / "len"
	 * argument of read/write/recv/send-class syscalls.  Consumed at the
	 * do_syscall layer by enforce_count_bound() in syscall.c, which logs
	 * any retval > rec->aN as structural ABI corruption (sign-extension
	 * tear in the return path, sibling-stomp of rec->retval, -errno
	 * leaking through the success slot, kernel write past the user
	 * bound).  Default 0 means "no bound" -- the helper short-circuits.
	 * Only annotate syscalls whose retval semantics are exactly
	 * "bytes/items processed in [0, aN] || -1" with no zero-as-query
	 * exception; iov-sum and zero-as-query syscalls stay per-syscall.
	 */
	int bound_arg;

	/*
	 * Per-syscall opt-in bitmap of arg slots (1..6) whose value the
	 * post handler reads to validate rec->retval.  Bit k (k=0..5) set
	 * means slot (k+1) gets snapshotted into rec->arg_shadow[k] at the
	 * tail of generate_syscall_args() and must be consumed via
	 * get_arg_snapshot(rec, k+1) from the post handler.  Tripwire-armed:
	 * a mismatch between shadow and live rec->aN at read time bumps
	 * parent_stats.arg_shadow_stomp via the per-child stats_ring,
	 * surfacing sibling stomps that the canary check misses because
	 * they only scribble a single integer slot.  Default 0 -- the
	 * snapshot hook short-circuits on a zero mask; the accessor falls
	 * back to the live rec->aN read for non-opted-in slots.  Mirror of
	 * the address_scrub_mask convention: bit i corresponds to slot (i+1).
	 */
	uint8_t arg_snapshot_mask;
};

#define RET_BORING		-1
#define RET_NONE		0
#define RET_ZERO_SUCCESS	1
#define RET_FD			2
#define RET_KEY_SERIAL_T	3
#define RET_PID_T		4
#define RET_PATH		5
#define RET_NUM_BYTES		6
#define RET_GID_T		7
#define RET_UID_T		8
#define RET_ADDRESS		9
/* Highest defined RET_* tag.  Used to size the ret_bounds[] table in
 * syscall.c that drives the table-driven generic return-bound validator;
 * keep in sync when adding a new RET_* above. */
#define RET_LAST		RET_ADDRESS

#define GROUP_NONE	0
#define GROUP_VM	1
#define GROUP_VFS	2
#define GROUP_NET	3
#define GROUP_IPC	4
#define GROUP_PROCESS	5
#define GROUP_SIGNAL	6
#define GROUP_IO_URING	7
#define GROUP_BPF	8
#define GROUP_SCHED	9
#define GROUP_TIME	10
#define GROUP_XATTR	11
#define NR_GROUPS	12

struct syscalltable {
	struct syscallentry *entry;
};

#define AVOID_SYSCALL		(1<<0)
#define NI_SYSCALL		(1<<1)
#define BORING			(1<<2)
#define ACTIVE			(1<<3)
#define TO_BE_DEACTIVATED	(1<<4)
#define NEED_ALARM		(1<<5)
#define EXTRA_FORK		(1<<6)
#define IGNORE_ENOSYS		(1<<7)
#define EXPENSIVE		(1<<8)
#define NEEDS_ROOT		(1<<9)
/*
 * KCOV_REMOTE_HEAVY: this syscall does most of its interesting kernel
 * work via deferred contexts (kthreads, workqueues, softirqs, io_uring
 * SQ workers, netlink async delivery, mount/cgroup workqueues, namespace
 * setup helpers) that are only visible through KCOV_REMOTE_ENABLE.  When
 * the random-syscall dispatcher decides whether to enter remote mode for
 * the upcoming call it picks the heavier 1-in-KCOV_REMOTE_RATIO_HEAVY
 * sample rate for syscalls flagged here, instead of the default
 * 1-in-KCOV_REMOTE_RATIO trickle that's calibrated for synchronous,
 * caller-thread-only syscalls.  Used by PC-mode children only;
 * CMP-mode children never enter remote mode.
 */
#define KCOV_REMOTE_HEAVY	(1<<10)
/*
 * SKIP_BLANKET_SCRUB: opt this syscall out of blanket_address_scrub() in
 * generate-args.c.  The blanket walks every default_address_scrub slot
 * after the per-syscall sanitiser has run and redirects pointers that
 * overlap shared_regions[] or the libc heap arena to a fresh
 * get_writable_address() page.  That is the correct defense-in-depth
 * default for the bulk of syscalls, where any aliasing into trinity's
 * own bookkeeping is incidental and the kernel-side write/read at the
 * pointer carries no curated payload.
 *
 * A handful of syscalls invert this contract: the sanitiser deliberately
 * places a pointer at an address whose bytes the kernel must observe
 * unchanged, and whose VA must remain stable across the dispatch.  For
 * those the blanket scrub silently substitutes an unrelated writable
 * page underneath the kernel, dropping the comparison / hashing semantics
 * the sanitiser carefully set up.  Setting this bit at the entry zeroes
 * address_scrub_mask at table-init time in copy_syscall_table(), so the
 * hot-path early-return in blanket_address_scrub() short-circuits with
 * zero per-dispatch cost.
 */
#define SKIP_BLANKET_SCRUB	(1<<11)
/*
 * AVOID_REEXEC: opt this syscall out of the CMP RedQueen greedy re-exec
 * step in dispatch_step's tail (redqueen_reexec_step).  The re-exec gate
 * already excludes every sanitise-bearing syscall (same gate
 * replay_syscall_step uses, for the same reason -- generic_sanitise
 * re-runs would either resurrect freed pointer slots or stomp the
 * captured slot pin); AVOID_REEXEC is the auditable layer on top for the
 * handful of sanitise-free syscalls whose effects are still destructive
 * to the calling child (process termination, irreversible global state).
 * Today's denylist is the exit family -- belt-and-braces alongside the
 * pre-existing AVOID_SYSCALL on those entries, so a future flag rework
 * that drops AVOID_SYSCALL doesn't silently expose them to re-exec --
 * with headroom for future sanitise-free additions discovered by the
 * reexec_skipped_destructive counter.
 */
#define AVOID_REEXEC		(1<<12)
/*
 * REEXEC_SANITISE_OK: opt this entry IN to the CMP RedQueen re-exec step
 * even though it carries a .sanitise.  The blanket destructive-syscall
 * gate in redqueen_reexec_step() excludes every sanitise-bearing entry
 * because a generic .sanitise re-run can resurrect freed pointer slots
 * or stomp the captured slot pin; this flag is the auditable opt-in for
 * the small set of sanitisers whose ownership is well-understood --
 * sanitisers that populate ONLY fixed-size input structs (or strings)
 * with no nested pointer chains, no INOUT / output buffers, no shared-
 * buffer relocation, and no bespoke deferred-free / post_state oracle.
 *
 * The re-exec contract for a flagged entry is unchanged from the
 * sanitise-free path: generate_syscall_args() runs in full so the
 * re-exec gets FRESH OWNED pointers, the parent's a1..a6 pointer values
 * are NEVER reused in the child record, the RedQueen pin (slot or field)
 * is applied AFTER sanitise so the pin lands on known input fields, and
 * the inner dispatch_step's cleanup path owns the re-exec'd args (no
 * manual free here).  The parent-record restore from the snapshot at the
 * tail of redqueen_reexec_step() runs unchanged.
 */
#define REEXEC_SANITISE_OK	(1<<13)
/*
 * EXPLICITLY_EXCLUDED: this entry was named in -x at parse time and the
 * exclusion must outlive deactivate_disabled_syscalls(), which clears
 * ACTIVE|TO_BE_DEACTIVATED off the entry once it has been removed from
 * the active table.  syscall_nr_is_excluded() (tables.c) consults this
 * bit at every trinity_raw_syscall(__NR_X) site to honor -x even when a
 * targeting selector (-c / -r / -g) is also active -- under those modes
 * a non-targeted entry is "inactive" because it was never enabled, so
 * the old ACTIVE-bit inference treated unrelated syscalls as excluded
 * (false positive) and the explicitly -x'd one as not (false negative,
 * the bug this flag fixes -- the targeting/exclusion interaction).
 * Set in toggle_syscall_n() / toggle_syscall_biarch_n() alongside TO_BE_DEACTIVATED, and
 * never cleared -- the deactivate paths in tables-{uni,bi}arch.c mask
 * only ACTIVE|TO_BE_DEACTIVATED so this bit survives.
 */
#define EXPLICITLY_EXCLUDED	(1<<14)

struct kcov_child;
struct childdata;

void do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		struct kcov_child *kc, struct childdata *child);

/*
 * Uniform-random syscall picker.  Public so any future strategy with a
 * "no usable signal here" branch can delegate to the canonical
 * uniform-pick + correctness-gate implementation rather than
 * re-implementing it.
 */
bool set_syscall_nr_random(struct syscallrecord *rec, struct childdata *child);

/*
 * Per-call arch picker for biarch builds.  Returns do32 and stamps the
 * child's active_syscalls pointer / nr_syscalls slot so the caller's
 * subsequent loop indexes the correct table.  *nr_syscalls_out is the
 * current shm->nr_active_*bit_syscalls snapshot — the picker samples
 * the compact active prefix, not the max table.  Uniarch callers
 * should not call this.
 */
bool choose_syscall_table(struct childdata *child, unsigned int *nr_syscalls_out);
void handle_syscall_ret(struct syscallrecord *rec, struct syscallentry *entry);
void generic_post_close_fd(struct syscallrecord *rec);
void post_mount_fd(struct syscallrecord *rec);
void post_fs_ctx_fd(struct syscallrecord *rec);
uint8_t compute_numeric_substitute_mask(const struct syscallentry *entry);
uint8_t compute_address_scrub_mask(const struct syscallentry *entry);
uint8_t compute_cleanup_arg_mask(const struct syscallentry *entry);
uint8_t compute_fd_arg_mask(const struct syscallentry *entry);
uint8_t compute_len_arg_mask(const struct syscallentry *entry);
uint8_t compute_nested_address_scrub_mask(const struct syscallentry *entry);
void populate_arglist_all_bits(struct syscallentry *entry);

/*
 * Seed rec->arg_meta[] from entry->argtype[] just before
 * blanket_address_scrub().  SHADOW telemetry: writes the per-slot
 * dir/owner/flags/generation descriptor but does not feed any decision.
 */
void arg_meta_init(struct syscallentry *entry, struct syscallrecord *rec);

/*
 * Tripwire bump for get_arg_snapshot() mismatches.  Out-of-line so the
 * accessor stays a small inline on the common path (mask cleared or
 * shadow == live).  Defined in utils.c.
 */
void arg_shadow_stomp_bump(struct syscallrecord *rec, unsigned int argnum,
			   unsigned long shadow, unsigned long current);

/*
 * Verify-and-read accessor for arg-shadow snapshotted slots.  Opted-in
 * post handlers call this in place of reading rec->aN directly.  If the
 * slot is not in this rec's snapshot mask (defensive -- a non-opted call
 * site should not be reaching for the accessor), returns the live slot
 * value unchanged so the handler still sees something usable.  When the
 * slot IS shadowed, compares shadow vs live, bumps the tripwire on
 * mismatch (sibling stomp landing after the dispatch-time snapshot in
 * __do_syscall() and before the post handler runs), and returns the
 * stable shadow value so the handler's retval-vs-bound check operates
 * on the value the kernel actually saw rather than the post-stomp value.
 */
static inline unsigned long get_arg_snapshot(struct syscallrecord *rec,
					     unsigned int argnum)
{
	unsigned long *slot;
	unsigned long shadow, current;

	switch (argnum) {
	case 1: slot = &rec->a1; break;
	case 2: slot = &rec->a2; break;
	case 3: slot = &rec->a3; break;
	case 4: slot = &rec->a4; break;
	case 5: slot = &rec->a5; break;
	case 6: slot = &rec->a6; break;
	default: return 0;
	}

	current = *slot;
	if ((rec->arg_snapshot_mask & (uint8_t)(1u << (argnum - 1))) == 0)
		return current;

	shadow = rec->arg_shadow[argnum - 1];
	if (shadow != current)
		arg_shadow_stomp_bump(rec, argnum, shadow, current);
	return shadow;
}

#define for_each_arg(_e, _i) \
	for (_i = 1; _i <= (_e)->num_args; _i++)

