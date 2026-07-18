#pragma once

#include <sys/resource.h>

#include "child-api.h"
#include "list.h"
#include "object-types.h"
#include "syscall.h"
#include "trinity.h"
#include "types.h"

struct epollobj;

bool open_fds(void);

void process_fds_param(char *optarg, bool enable);

struct fd_provider {
        struct list_head list;
	const char *name;
	enum objecttype objtype;
        int (*init)(void);
        int (*get)(void);
	/*
	 * Optional per-child post-fork init hook.  Invoked once per child
	 * from init_child_rendezvous_parent() after the OBJ_LOCAL pool is
	 * brought up, so implementations can freely populate OBJ_LOCAL
	 * objhead entries in the child's own mm.  Providers whose kernel-
	 * side resource lifecycle is tied to the creating task's mm (KVM
	 * vCPU / VM fds -- vcpu->kvm->mm is stamped at KVM_CREATE_VM time
	 * and every subsequent vCPU ioctl compares vcpu->kvm->mm against
	 * current->mm; io_uring rings whose SQE user_data + registered
	 * buffers reference addresses valid only in the creating mm; ...)
	 * MUST create their kernel objects here rather than in .init,
	 * otherwise every child inherits a parent-context object that
	 * -EIOs from any child-side ioctl.
	 *
	 * Runs after init_object_lists(OBJ_LOCAL, ...) and before the
	 * child touches any fd from the pool, so the hook may unconditionally
	 * add_object(..., OBJ_LOCAL, ...) without an ordering worry.
	 */
	void (*child_init)(struct childdata *child);
	void (*child_ops)(void);	/* optional: called periodically in child context */
	/*
	 * Optional per-provider top-up hook, called periodically from the
	 * child tick via run_fd_provider_replenish().  Providers that back a
	 * small OBJ_GLOBAL pool (epoll, eventfd, fanotify, ...) drain over
	 * the child's lifetime as inherited slots get closed by fuzz-driven
	 * close / dup2 / close_range hits; the empty pool then surfaces as
	 * fd_random_exhausted bumps and EBADF-retry burn in gen_arg_fd.
	 *
	 * The hook is invited to open at most @budget new fds and publish
	 * them into a place the child's own arg-generation can reach.  A
	 * post-fork add_object(OBJ_GLOBAL) is a no-op by the mainpid guard
	 * in objects/registry.c, so implementations push new fds into
	 * this_child()->live_fds via child_fd_ring_push(), which feeds the
	 * 70% live-fd branch of gen_arg_fd() directly.
	 *
	 * Rate-limit contract: the dispatcher also gates how often the walk
	 * runs and caps how many providers get called per tick, but each
	 * implementation MUST additionally self-cap -- do not refill-to-full
	 * every call, only top up while below the init target and only up to
	 * @budget per invocation.  Replenish issues create syscalls that
	 * compete with the fuzz budget; the whole path is a small bounded
	 * bleed-off, not a maintenance loop.
	 */
	void (*try_replenish)(unsigned int budget);
	bool enabled;
	bool initialized;
	/*
	 * Set by providers whose fds back a kernel ->poll handler that can
	 * block indefinitely waiting on an external actor (FUSE userspace
	 * daemon, userfaultfd consumer, KVM vCPU thread, io_uring CQ
	 * producer, exiting task referenced by pidfd).  arm_epoll() and the
	 * epoll_ctl/poll/ppoll/select sanitisers refuse to populate watch
	 * sets with these fds: ep_item_poll runs the target ->poll
	 * synchronously inside EPOLL_CTL_ADD/MOD, ep_send_events, and
	 * __ep_eventpoll_poll, and a blocked ->poll wedges the calling task
	 * into TASK_UNINTERRUPTIBLE — SIGKILL and the watchdog cannot
	 * recover it, defer-slot-reuse pins the slot, and throughput
	 * collapses across the fleet.  The tagged fds remain available for
	 * direct read/write/recv/ioctl fuzzing — they are only barred from
	 * watch-set membership.  Defaults to false; providers opt in
	 * explicitly.
	 */
	bool poll_can_block;
};

void register_fd_provider(const struct fd_provider *prov);
void dump_fd_provider_names(void);
void run_fd_provider_child_ops(void);

/*
 * Walk every initialised fd_provider with a non-NULL child_init and
 * invoke it exactly once against @child.  Called from init_child()
 * after the OBJ_LOCAL pool has been brought up.  Provider order matches
 * fd_providers registration order; that order is only observable to a
 * provider that mutates state shared with a peer provider, and no
 * current provider does.
 */
void run_fd_provider_child_init(struct childdata *child);

/*
 * Walk registered fd_providers with a non-NULL ->try_replenish and give
 * each up to @per_provider_budget new fds to publish this tick.  Internally
 * rate-limited (roughly one in four calls does any work) and dispatcher-
 * capped at a small number of providers per tick so a burst of
 * create-syscalls cannot swamp the child's fuzz budget.  Safe to call
 * from child context only; parent calls fall through without work.
 */
void run_fd_provider_replenish(unsigned int per_provider_budget);

/*
 * Reason categories an fd-provider init() can report when it returns
 * false, so the open_fds() dispatcher can log WHY a provider failed
 * rather than just THAT it failed.  Without this, the bare
 * "Error during initialization of <name>" line forced a
 * post-hoc audit to tell a build-time CONFIG miss (kernel without
 * CONFIG_IOMMUFD) from a runtime capability gap (no CAP_SYS_ADMIN
 * for perf_event_open) from a transient resource shortage
 * (alloc_object failed, no pagecache-backed files in the index).
 * Per-provider syscall logs already carry the strerror() text, but
 * a provider whose init returns false from a non-syscall path
 * (alloc, empty pool, fileindex without eligible files) had no
 * structured signal at all.
 *
 * Providers report via fd_provider_init_fail() at each return-false
 * site; the dispatcher resets the slot before calling init() and
 * reads it after init() returns false.  The LAST reported reason on
 * the path that returned false wins, which matches what callers want
 * to know.
 */
enum fd_init_reason {
	FD_INIT_REASON_NONE = 0,
	FD_INIT_REASON_ERRNO,		/* captured_errno is the underlying cause */
	FD_INIT_REASON_CONFIG_ABSENT,	/* feature missing at kernel build time / no /dev node */
	FD_INIT_REASON_CAP_MISSING,	/* lacks capability or permission to use the feature */
	FD_INIT_REASON_RESOURCE,	/* in-process resource shortage (alloc/pool/eligible-input) */
};

/*
 * Record the structured reason for the current fd_provider init()
 * failure.  Call immediately before "return false" in init().  Safe
 * to call from any provider; the dispatcher in open_fds() resets the
 * slot before each init() and consumes it after a false return.
 * @captured_errno may be 0 when the reason is not errno-derived
 * (e.g. CONFIG_ABSENT determined at build time, RESOURCE for an
 * empty input pool).  @detail is a short tag string (e.g. the
 * syscall or pool name); NULL is accepted.
 */
void fd_provider_init_fail(enum fd_init_reason reason, int captured_errno,
			   const char *detail);

const char *fd_init_reason_name(enum fd_init_reason r);

/*
 * Return the name of the registered fd_provider whose objtype matches
 * the supplied enum value, or NULL when no provider claims that type.
 * Used by dump_stats() to label the per-provider outstanding-fd gauge
 * (shm->stats.fd.provider_outstanding[]) without exposing the provider
 * list itself.
 */
const char *fd_provider_name(enum objecttype type);

/*
 * Walk every fd-bearing arg slot in entry's argtype[].  args[0..5] holds
 * the per-slot syscall argument values (a1..a6).  cb(fd, ctx) is invoked
 * once per slot whose argtype is is_fdarg(), plus argtype[0] == ARG_SOCKETINFO
 * (post-sanitise slot 0 holds the resulting fd, not the socketinfo struct;
 * is_fdarg() does not cover that case so we mirror it explicitly here).
 * Values whose raw arg exceeds max_files_rlimit.rlim_cur are skipped.
 * No locking: caller owns rec->lock or a stable snapshot of args[].
 */
typedef void (*fd_arg_cb)(int fd, void *ctx);

static inline void for_each_fd_arg(const struct syscallentry *entry,
				   const unsigned long args[6],
				   fd_arg_cb cb, void *ctx)
{
	uint8_t mask;

	if (entry == NULL)
		return;

	mask = entry->fd_arg_mask;
	if (entry->argtype[0] == ARG_SOCKETINFO)
		mask |= 0x01;

	while (mask != 0) {
		unsigned int slot = (unsigned int)__builtin_ctz(mask);
		unsigned long fd = args[slot];

		mask &= (uint8_t)(mask - 1);

		if (fd > max_files_rlimit.rlim_cur)
			continue;

		cb((int) fd, ctx);
	}
}

/*
 * Return true if fd belongs to a registered fd_provider whose
 * poll_can_block tag is set.  Used by the epoll/select/poll sanitisers
 * (and arm_epoll) to refuse blocking-poll fds in watch sets.  Returns
 * false for untracked fds (no entry in the fd hash) and for fds whose
 * provider did not opt in.
 */
bool fd_poll_can_block(int fd);

int get_random_fd(void);
int get_new_random_fd(void);
int get_typed_fd(enum argtype type);

/*
 * Protected-fd registry consulted by close / dup2 / dup3 / close_range
 * argument generators, the size-changing fd-arg sanitisers (see
 * reroll_protected_fd_arg() below), and the random-syscall chain-
 * substitution path to keep fds whose lifetime trinity depends on for
 * its own correctness or diagnostics OUT of the picker pool.  Currently
 * covers:
 *
 *   - the calling child's per-task kcov PC fd and cmp fd (see kcov.h);
 *     a fuzz-induced close/dup2 over either slot silently disables
 *     coverage for the rest of that child's life.
 *   - STDERR_FILENO and the stderr capture memfd installed by
 *     init_stderr_memfd() (see signals.h); the SIGABRT-handler drain
 *     that surfaces glibc malloc_printerr / __fortify_fail text into
 *     the per-pid bug log writes via fd 2 and reads from the memfd,
 *     so either being clobbered before the handler runs loses the
 *     pre-crash explanation.
 *
 * Parent-context callers (this_child() == NULL) still get STDERR_FILENO
 * protected -- the constant is process-wide -- but neither the kcov
 * slots nor the memfd are live in the parent, so those checks naturally
 * fall through.
 */
bool fd_is_protected(int fd);

/*
 * Returns the lowest protected fd inside [lo, hi] (inclusive), or -1
 * if no protected fd lies in the range.  close_range trims its upper
 * bound to (this value - 1) so the kernel-side walk stops short of
 * the first protected slot rather than skipping it.
 *
 * lo / hi are unsigned int to match the kernel ABI for close_range
 * (SYSCALL_DEFINE3(close_range, unsigned int, unsigned int, unsigned)).
 * Signed int here lets a sanitiser pass through rec->a1/a2 == (unsigned
 * long)-1 -- the gen_arg_fd exhaustion fallback -- as int -1.  The
 * inner `hi < lo` guard then returns -1 (no protected fd "in range")
 * even though the kernel, casting to u32, walks [a1, 0xFFFFFFFF] and
 * closes the kcov fd at KCOV_FD_HIGH_BASE.  Unsigned int matches the
 * kernel's view and closes the gap.
 */
int lowest_protected_fd_in_range(unsigned int lo, unsigned int hi);

/*
 * Belt-and-suspenders gate consulted by the size-changing fd-arg
 * sanitisers (ftruncate / ftruncate64, fallocate, lseek / llseek,
 * write / writev / pwrite64 / pwritev / pwritev2): if *slot names a
 * protected fd, reroll via get_random_fd() up to FAILED_FD_REROLL_LIMIT
 * times, then stamp the slot with (unsigned long)-1 on exhaustion so
 * the kernel returns EBADF.  Defends the stderr capture memfd against
 * a fuzz-induced grow to multi-GB sparse size, which the SIGABRT-
 * handler bug-log drain would otherwise materialise into the on-disk
 * log.  See the block comment above fd_is_protected() in fds.c.
 */
void reroll_protected_fd_arg(unsigned long *slot);

/*
 * Pick from the fd_types whose ->poll handlers park the caller on a
 * real wait queue (pipe / eventfd / timerfd / signalfd / inotify /
 * fanotify / socket).  Used by poll(2)/ppoll(2)/select(2)/pselect6(2)
 * to bias the watch set toward fds the kernel actually has to wait on.
 */
int get_pollable_random_fd(void);
int get_child_live_fd(struct childdata *child);

/* Defined in fds/epoll.c — child-side lazy arm.  See block comment
 * above arm_epoll() for why arming must not run in parent context. */
void arm_epoll_if_needed(struct epollobj *eo);

#define REG_FD_PROV(_struct) \
	static void __attribute__((constructor)) register_##_struct(void) { \
		register_fd_provider(&_struct); \
	}

/*
 * Full-buffer fd I/O loops shared by every persistence format trinity
 * emits.  Both restart on EINTR.  write_all() returns @len on success
 * or -1 on error (including a short-write of 0).  read_all() returns
 * the number of bytes successfully read, which may be less than @len
 * at EOF; -1 on error.
 */
ssize_t write_all(int fd, const void *buf, size_t len);
ssize_t read_all(int fd, void *buf, size_t len);
