#ifndef _CHILDOPS_RECIPE_RUNNER_INTERNAL_H
#define _CHILDOPS_RECIPE_RUNNER_INTERNAL_H

/*
 * Shared declarations for the recipe_runner translation units.
 *
 * The recipe catalogue was a single 4000-line .c file; building it
 * serialised the parallel make at one slow compile.  The recipes are
 * now grouped into per-concern modules (simple lifecycles, network,
 * close-race, deadline-race, supervisor) that compile concurrently;
 * recipe-runner.c holds only the dispatcher table.
 *
 * Each recipe_<name>() function used to be file-local static; it is
 * declared here because the recipes[] table in recipe-runner.c now
 * lives in a different translation unit from the implementations.  No
 * other caller exists -- treat these prototypes as the catalogue's
 * cross-unit boundary, not as a general public API.
 */

#include <stdbool.h>


#include "kernel/io_uring.h"
#include "kernel/memfd.h"
#include "kernel/unistd.h"
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING	0x0002U
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING	0x8000000ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES		0x10000000ULL
#endif

/*
 * Bound on racer-side blocking syscalls in 2nd-thread recipes.  Long
 * enough that a close() consistently lands while the racer is mid-
 * syscall, short enough that pthread_join() returns in well under one
 * alarm tick.  Mirrors close-racer.c's RACER_TIMEOUT_MS.
 */
#define RECIPE_RACER_TIMEOUT_MS		100

/*
 * Latch threshold: if pthread_create fails this many times back-to-back
 * inside a single recipe invocation, stop trying for the rest of it.
 * Mirrors close-racer.c's THREAD_SPAWN_LATCH.  fork_storm or cgroup_churn
 * can push us into EAGAIN territory on nproc/thread limits, and there is
 * no point hammering a limit that won't lift mid-op.
 */
#define RECIPE_THREAD_SPAWN_LATCH	3

bool recipe_timerfd(bool *unsupported);
bool recipe_eventfd(bool *unsupported);
bool recipe_pipe(bool *unsupported);
bool recipe_epoll(bool *unsupported);
bool recipe_signalfd(bool *unsupported);
bool recipe_memfd_seal(bool *unsupported);
bool recipe_tcp_server(bool *unsupported);
bool recipe_inotify(bool *unsupported);
bool recipe_shmget(bool *unsupported);
bool recipe_msgget(bool *unsupported);
bool recipe_semget(bool *unsupported);
bool recipe_posix_timer(bool *unsupported);
bool recipe_mq_open(bool *unsupported);
bool recipe_futex(bool *unsupported);
bool recipe_fanotify(bool *unsupported);
bool recipe_userfaultfd(bool *unsupported);
bool recipe_vfs_leases(bool *unsupported);
bool recipe_mm_vma(bool *unsupported);
bool recipe_mm_memfd(bool *unsupported);
bool recipe_net_unix_gc(bool *unsupported);
bool recipe_net_tcp(bool *unsupported);
bool recipe_uffd_wp(bool *unsupported);
bool recipe_fsnotify_xwatch(bool *unsupported);
bool recipe_net_raw(bool *unsupported);
bool recipe_net_unix_oob(bool *unsupported);
bool recipe_timerfd_xclose(bool *unsupported);
bool recipe_signalfd_delivery(bool *unsupported);
bool recipe_epoll_xclose(bool *unsupported);
bool recipe_iouring_fixed_uaf(bool *unsupported);
bool recipe_bpf_htab_iter_del(bool *unsupported);
bool recipe_perf_mmap_close(bool *unsupported);
bool recipe_keys_revoke_race(bool *unsupported);
bool recipe_ptrace_seize_exitkill(bool *unsupported);
bool recipe_mount_userns_dance(bool *unsupported);
bool recipe_seccomp_listener_exec(bool *unsupported);
bool recipe_cgroup_kill_events(bool *unsupported);

#endif /* _CHILDOPS_RECIPE_RUNNER_INTERNAL_H */
