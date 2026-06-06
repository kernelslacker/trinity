#pragma once

#include <sys/resource.h>

#include "child.h"
#include "list.h"
#include "object-types.h"
#include "syscall.h"
#include "trinity.h"
#include "types.h"

struct epollobj;

void setup_fd_providers(void);

bool open_fds(void);

void process_fds_param(char *optarg, bool enable);

struct fd_provider {
        struct list_head list;
	const char *name;
	enum objecttype objtype;
        int (*init)(void);
        int (*get)(void);
	void (*child_ops)(void);	/* optional: called periodically in child context */
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
 * Return the name of the registered fd_provider whose objtype matches
 * the supplied enum value, or NULL when no provider claims that type.
 * Used by dump_stats() to label the per-provider outstanding-fd gauge
 * (shm->stats.fd_provider_outstanding[]) without exposing the provider
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
 * argument generators (and the random-syscall chain-substitution path) to
 * keep fds whose lifetime trinity depends on for its own correctness or
 * diagnostics OUT of the picker pool.  Currently covers:
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
 */
int lowest_protected_fd_in_range(int lo, int hi);

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
