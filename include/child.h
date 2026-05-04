#pragma once

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "types.h"
#include "edgepair.h"
#include "kcov.h"
#include "objects.h"
#include "pre_crash_ring.h"
#include "syscall.h"

struct fd_event_ring;

/*
 * Circular ring of file descriptors returned by recent fd-creating syscalls.
 * Used to bias ARG_FD generation toward fds that are known to be open.
 */
#define CHILD_FD_RING_SIZE 16

struct child_fd_ring {
	int fds[CHILD_FD_RING_SIZE];
	unsigned int head;
};

/*
 * Per-child ring of recently completed syscall records.  The owning child
 * is the sole producer; the parent reads the ring in post-mortem context
 * to assemble a chronological fleet-wide trace of what was running just
 * before the kernel taint flag flipped.  Lock-free SPSC: producer issues
 * a release-store of head after writing the slot; consumer issues an
 * acquire-load of head before reading slots.  Size must be a power of 2.
 *
 * Each slot holds only the structured fields the post-mortem reader needs
 * to reconstruct a one-line summary (syscall name, args, return value,
 * errno, timestamp) — not the 4 KiB pre-rendered prebuffer/postbuffer
 * that the live -v output uses.  Keeps the per-syscall push to a
 * field-by-field copy of ~80 bytes instead of a 4 KiB struct copy that
 * trashed L1/L2 on every call.
 */
#define CHILD_SYSCALL_RING_SIZE 16

struct chronicle_slot {
	struct timespec tp;		/* CLOCK_MONOTONIC at syscall return. */
	unsigned long a1, a2, a3, a4, a5, a6;	/* arg values as the kernel saw them. */
	unsigned long retval;		/* return value the kernel reported. */
	unsigned int nr;		/* index into the syscall table. */
	int errno_post;			/* errno after return. */
	bool do32bit;			/* selects which table nr indexes. */
	bool valid;			/* false in zero-init slots; the post-mortem
					 * reader uses this to skip slots a freshly
					 * spawned child has not yet filled. */
};

struct child_syscall_ring {
	struct chronicle_slot recent[CHILD_SYSCALL_RING_SIZE];
	_Atomic uint32_t head;
};

enum child_op_type {
	CHILD_OP_SYSCALL = 0,	/* default: fuzz random syscalls */
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SCHED_CYCLER,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_FAULT_INJECTOR,
	CHILD_OP_RECIPE_RUNNER,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_FD_STRESS,
	CHILD_OP_REFCOUNT_AUDITOR,
	CHILD_OP_FS_LIFECYCLE,
	CHILD_OP_SIGNAL_STORM,
	CHILD_OP_FUTEX_STORM,
	CHILD_OP_PIPE_THRASH,
	CHILD_OP_FORK_STORM,
	CHILD_OP_FLOCK_THRASH,
	CHILD_OP_CGROUP_CHURN,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_IOURING_FLOOD,
	CHILD_OP_CLOSE_RACER,
	CHILD_OP_SOCKET_FAMILY_CHAIN,
	CHILD_OP_XATTR_THRASH,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_MADVISE_CYCLER,
	CHILD_OP_EPOLL_VOLATILITY,
	CHILD_OP_KEYRING_SPAM,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	NR_CHILD_OP_TYPES,
};

/*
 * Layout note — the leading 64 bytes are the per-syscall hot block.
 *
 * Every field in the leading cacheline is read or written on (almost)
 * every syscall by the dispatch_step / __do_syscall / kcov_collect path
 * or the random-syscall picker.  Keeping them packed in one line saves
 * the 1-3 cacheline misses per call the previous layout incurred when
 * the giant 4 KiB syscallrecord (with PREBUFFER_LEN=4096) sat at the
 * front of the struct and pushed every other hot field out into
 * cachelines that had to be re-fetched on each call.
 *
 * The static_assert in child.c pins op_nr (the last hot field) to an
 * offset under 64 so a future field reorder that breaks this property
 * fails the build instead of silently regressing the hot path.
 *
 * struct childdata itself is aligned to 64 bytes so each per-child
 * allocation starts on a fresh cacheline; without this, alloc_shared
 * could hand out a struct whose first 8 bytes share a line with the
 * preceding allocation's tail.
 */
struct childdata {
	/* ---- Hot leading cacheline (64 bytes) ---- */

	/* Per-child KCOV state (fd + trace buffer + active/cmp/remote flags).
	 * Touched on every syscall: dispatch_step gates cmp_mode/remote_mode
	 * off kcov.active and kcov.remote_capable, __do_syscall hands &kcov
	 * to the kcov_enable_X / kcov_disable wrappers, and kcov_collect
	 * mutates dedup + current_generation per call. */
	struct kcov_child kcov;

	/* Last syscall number executed, for edge-pair tracking.
	 * Read every call (edgepair_is_cold gate) and written every call
	 * (post-dispatch update). */
	unsigned int last_syscall_nr;

	/* Last syscall group executed, for group biasing.
	 * Read every call (group_bias gate) and conditionally written. */
	unsigned int last_group;

	/* Per-iteration child-op counter, written every loop iteration in
	 * child_process and consulted by the stall detector. */
	unsigned long op_nr;

	/* Per-child syscall counter, batch-flushed to shm->stats.op_count
	 * every LOCAL_OP_FLUSH_BATCH ops to avoid contending one cache line
	 * across all children.  Incremented inside __do_syscall on every
	 * call.  Aggregated by the parent when an exact total is needed. */
	unsigned long local_op_count;

	/* ---- End of hot leading cacheline ---- */

	/* Warm fields: read or written per call but not in inner retry
	 * loops.  Kept adjacent so the second cacheline absorbs whatever
	 * the first one missed. */

	/* Pointer to the active-syscall lookup table for this child's
	 * current pick.  Uniarch: set once at child init to
	 * shm->active_syscalls and never written again.  Biarch: refreshed
	 * by choose_syscall_table on every pick (the do32 dice picks one
	 * of shm->active_syscalls{32,64}).  Per-child storage so the
	 * biarch update doesn't need an atomic store on a process-global. */
	int *active_syscalls;

	/* last time the child made progress. */
	struct timespec tp;

	enum child_op_type op_type;

	/* per-child fd caching to avoid cross-child races */
	int current_fd;
	unsigned int fd_lifetime;
	/* Per-slot generation snapshot from current_fd's fd_hash entry,
	 * taken when the fd was fetched.  A mismatch on the next iteration
	 * indicates the slot was emptied or the fd number was recycled
	 * onto a fresh object; either way the cached fd is no longer
	 * trustworthy. */
	uint32_t cached_fd_generation;

	/* fd to /proc/self/fail-nth, opened once per child.  -1 means
	 * fault injection is unavailable on this kernel/config.  Read on
	 * every call by maybe_inject_fault. */
	int fail_nth_fd;

	unsigned int seed;

	unsigned int num;

	/* Snapshot of shm->sibling_freeze_gen taken when we last ran the
	 * sibling-childdata mprotect sweep.  Read at the top of every
	 * child_process loop iteration; on mismatch we re-run the sweep so
	 * any sibling spawned since our last pass joins our PROT_READ set.
	 * See the comment on shm_s::sibling_freeze_gen for the race this
	 * closes. */
	unsigned int last_seen_freeze_gen;

	/* Stall detection state: consecutive alarm timeouts without progress. */
	unsigned int stall_count;
	unsigned int stall_last;

	unsigned char xcpu_count;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	bool dropped_privs;

	/* FD leak instrumentation: count fds created and closed by
	 * this child's syscalls, with per-group breakdown.
	 * On child exit, if fd_created - fd_closed > threshold,
	 * we log which syscall groups are responsible. */
	unsigned long fd_created;
	unsigned long fd_closed;
	unsigned long fd_created_by_group[NR_GROUPS];

	/* Ring buffer for reporting fd events to the parent.
	 * Allocated in shared memory, one per child. */
	struct fd_event_ring *fd_event_ring;

	/* Name of the recipe currently executing inside recipe_runner(),
	 * or NULL when no recipe is in flight.  Read by post-mortem to
	 * attribute a kernel taint to a specific multi-syscall sequence. */
	const char *current_recipe_name;

	/* Set by __BUG() in the child immediately before _exit() so the
	 * parent's reap path can attribute a "child gone" event to a self-
	 * inflicted assertion failure rather than a kernel zombie or wild
	 * SIGKILL.  bug_text is a string-literal pointer (the bugtxt arg
	 * passed to __BUG, which is always a literal at the call site).
	 * bug_lineno + bug_func let the parent print the call site too. */
	bool hit_bug;
	const char *bug_text;
	const char *bug_func;
	unsigned int bug_lineno;

	/* ---- Cold tail: large rings and the per-call syscallrecord with
	 * its 4 KiB prebuffer.  Pushed past every hot/warm field so reads
	 * of any field above land in the leading cacheline(s) instead of
	 * dragging the prebuffer's lines into L1. ---- */

	/* Ring of fds returned by recent fd-creating syscalls.
	 * Consulted preferentially when generating ARG_FD arguments. */
	struct child_fd_ring live_fds;

	struct objhead objects[MAX_OBJECT_TYPES];

	/* Ring of recently completed syscall records, drained by the parent
	 * during post-mortem to reconstruct a fleet-wide chronology. */
	struct child_syscall_ring syscall_ring;

	/* Compact rolling history of recently completed syscalls, drained
	 * on __BUG() to recover what this child was doing just before an
	 * assertion failure (most often a parent-side list/fd-event drain
	 * crash caused by a child wild write hundreds of syscalls back). */
	struct pre_crash_ring pre_crash;

	/* The actual syscall records each child uses.  Dominated by a 4 KiB
	 * prebuffer + 128 B postbuffer used by -v rendering — only nr / a1..a6
	 * / retval / lock / state are touched on the hot path, and those are
	 * already in the rec's own first cacheline. */
	struct syscallrecord syscall;
} __attribute__((aligned(64)));

extern unsigned int max_children;

/*
 * Compute the adaptive iteration count for an opt-in childop.  Reads
 * the per-op multiplier (Q8.8 fixed point) maintained by adapt_budget()
 * out of shm->stats.childop_budget_mult[op] and scales `base` by it.
 *
 * If the slot is zero (uninitialised, or wild-write zeroed), fall back
 * to `base` so the loop never collapses to zero iterations — preserves
 * the pre-CV.13 behaviour as the safe default.
 *
 * Caller must have shm.h in scope (childop .c files already do).  The
 * macro evaluates `op` and `base` exactly once each via statement-
 * expression locals, which matters because callers sometimes pass
 * expressions with side effects for `base` (none today, but cheap to
 * future-proof).
 */
#define BUDGETED(op, base) ({						\
	uint16_t _m = shm->stats.childop_budget_mult[(op)];		\
	unsigned int _b = (unsigned int)(base);				\
	_m ? ((_b * (unsigned int)_m) >> 8) : _b;			\
})

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void child_fd_ring_push(struct child_fd_ring *ring, int fd);

void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec);

void init_child_mappings(void);

void child_process(struct childdata *child, int childno);

/* Dedicated alt-op children: when --alt-op-children=N is set, the first
 * N child slots run a fixed alt op for life (round-robin from a static
 * rotation table) instead of the default 95%-syscall / 5%-altop mix.
 * Lets slow VMA / inode / mlock / fork-storm paths get continuous
 * exercise without slowing the throughput-optimised default children.
 *
 * assign_dedicated_alt_op() runs in the parent right before fork(),
 * stamping child->op_type so the freshly-spawned child reads its
 * assigned op out of shared memory before it enters the dispatch loop.
 *
 * log_alt_op_config() prints the reservation count and the start of the
 * rotation under -v.  No-op when --alt-op-children is 0.
 */
void assign_dedicated_alt_op(struct childdata *child, int childno);
void log_alt_op_config(void);

void set_dontkillme(struct childdata *child, bool state);

void reap_child(struct childdata *child, int childno);

/* Childops */
bool random_syscall(struct childdata *child);
bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
struct chain_step;
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new);
bool drop_privs(struct childdata *child);
bool mmap_lifecycle(struct childdata *child);
bool mprotect_split(struct childdata *child);
bool mlock_pressure(struct childdata *child);
bool inode_spewer(struct childdata *child);
void inode_spewer_cleanup(void);
void inode_spewer_reap(pid_t pid);
bool procfs_writer(struct childdata *child);
void procfs_writer_init(void);
bool memory_pressure(struct childdata *child);
bool userns_fuzzer(struct childdata *child);
bool sched_cycler(struct childdata *child);
bool barrier_racer(struct childdata *child);
bool genetlink_fuzzer(struct childdata *child);
bool perf_event_chains(struct childdata *child);
bool tracefs_fuzzer(struct childdata *child);
bool bpf_lifecycle(struct childdata *child);
bool fault_injector(struct childdata *child);
bool recipe_runner(struct childdata *child);
bool iouring_recipes(struct childdata *child);
bool fd_stress(struct childdata *child);
bool refcount_auditor(struct childdata *child);
bool fs_lifecycle(struct childdata *child);
bool signal_storm(struct childdata *child);
bool futex_storm(struct childdata *child);
bool pipe_thrash(struct childdata *child);
bool fork_storm(struct childdata *child);
bool flock_thrash(struct childdata *child);
bool cgroup_churn(struct childdata *child);
bool mount_churn(struct childdata *child);
bool uffd_churn(struct childdata *child);
bool iouring_flood(struct childdata *child);
bool close_racer(struct childdata *child);
bool socket_family_chain(struct childdata *child);
bool xattr_thrash(struct childdata *child);
bool pidfd_storm(struct childdata *child);
bool madvise_cycler(struct childdata *child);
bool epoll_volatility(struct childdata *child);
bool keyring_spam(struct childdata *child);
bool vdso_mremap_race(struct childdata *child);
bool numa_migration_churn(struct childdata *child);
bool cpu_hotplug_rider(struct childdata *child);
