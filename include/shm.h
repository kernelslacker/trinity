#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "arch.h"
#include "child-api.h"
#include "efault_cache.h"
#include "exit.h"
#include "files.h"
#include "locks.h"
#include "net.h"
#include "object-types.h"
#include "scratch_block.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"
#include "types.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
struct io_uringobj;

void create_shm(void);
void init_shm(void);

/*
 * Concurrent in-flight cap for unshare(CLONE_NEWNET) and the matching
 * clone()/clone3() flag.  Trinity children fuzzing fork()/clone()/clone3()
 * spawn untracked grandchildren; each grandchild that calls unshare with
 * CLONE_NEWNET feeds the kernel's netns cleanup workqueue, and the
 * per-call cost grows with the queue's backlog.  Past a few in-flight
 * unshares per host the workqueue can't keep up — copy_net_ns() begins
 * blocking in D-state, the untracked grandchild population grows
 * unbounded, and the box turns into a forkbomb.  A small fleet-wide
 * cap on in-flight CLONE_NEWNET callers caps the backlog the kernel
 * side has to drain.  See shm->newnet_in_flight and the
 * unshare_newnet_throttled stat counter.
 */
#define MAX_CONCURRENT_NEWNET 4

struct shm_s {
	char __padding[4096];

	/* Frequently updated by all children — own cache line. */
	struct stats_s stats __attribute__((aligned(64)));

	/* Wall-clock time init_shm() ran.  Read-only after init; used by
	 * dump_stats() to log absolute runtime alongside iters/s, which lets
	 * crash post-mortem correlate trinity output to external logs.
	 * Do NOT subtract from time(NULL) to compute elapsed -- an NTP
	 * backward step would flip the delta negative.  Elapsed is computed
	 * from start_mono_ns below. */
	time_t start_time;

	/* CLOCK_MONOTONIC anchor for the run, stamped in init_shm() alongside
	 * start_time.  Read-only after init.  Elapsed-runtime computations
	 * (dump_stats runtime header) subtract mono_ns() from this so an
	 * NTP wall-clock step -- forward or backward -- cannot skew the
	 * displayed uptime or (worse) drive a would-be duration negative. */
	uint64_t start_mono_ns;

	/*
	 * Identity of trinity's own binary, captured once in init_shm() via
	 * stat("/proc/self/exe", ...).  Read-only after init; written exactly
	 * once before any child forks, so children inherit the populated cache
	 * via shared mapping and the execve sanitiser can fstatat() the target
	 * of a fuzzed execve / execveat and refuse the syscall if the resolved
	 * (dev, ino) matches.  Catches every path that resolves to the trinity
	 * binary regardless of name -- /proc/self/exe, /proc/<pid>/exe,
	 * hardlinks, bind-mounted aliases, the literal path the operator
	 * launched with, and execveat(fd, "", AT_EMPTY_PATH) where fd is
	 * inherited from the parent.  valid == false means the startup stat
	 * failed (very unlikely; /proc not mounted or similar) and the guard
	 * short-circuits to "no protection" -- degraded behaviour matches the
	 * pre-guard baseline.  See sanitise_execve() in syscalls/execve.c.
	 */
	struct {
		dev_t dev;
		ino_t ino;
		bool valid;
	} trinity_self_exe;

	/*
	 * Monotonic generation counter bumped by each new child after it
	 * completes its sibling-childdata freeze in init_child.  Each child
	 * caches the last value it saw and re-checks it at the top of the
	 * child_process loop; a mismatch triggers a catch-up refreeze that
	 * pulls any newly-spawned sibling into our PROT_READ set.
	 *
	 * Closes the startup race where a sibling that was mid-syscall when
	 * a fresh child was forked still has the new child's childdata at
	 * PROT_READWRITE in its view.  In that window a value-result kernel
	 * write triggered by the busy sibling can land inside the new
	 * child's not-yet-frozen region (childdata is alloc_shared and so
	 * occupies a discrete 4 KiB-aligned mmap slot per child — random
	 * pointer args from the busy sibling can fall there).  The window
	 * closes once each existing sibling reaches its next loop top
	 * check — typically one syscall worth of latency.
	 *
	 * Lives next to start_time deliberately: that slot was padding
	 * before the 64-byte-aligned fd_hash cacheline, so adding the
	 * counter doesn't introduce false sharing with anything hot.  Only
	 * written on spawn (rare); reads are RELAXED-equivalent loads on
	 * the loop top — one pulled cacheline shared across all readers.
	 */
	unsigned int sibling_freeze_gen;

	/* Written by main process — own cache line to avoid
	 * false sharing with child-written stats above. */
	unsigned int running_childs __attribute__((aligned(64)));

	/* rng related state */
	unsigned int seed;

	/* Indices of syscall in syscall table that are active.
	 * All indices shifted by +1. Empty index equals to 0.
	 *
	 * 'active_syscalls' is only used on uniarch. The other two
	 * are only used on biarch. */
	int active_syscalls32[MAX_NR_SYSCALL];
	int active_syscalls64[MAX_NR_SYSCALL];
	int active_syscalls[MAX_NR_SYSCALL];
	unsigned int nr_active_syscalls;
	unsigned int nr_active_32bit_syscalls;
	unsigned int nr_active_64bit_syscalls;

	/*
	 * Cost-partitioned active pools maintained BESIDE the flat
	 * active_syscalls*[] arrays above.  Every syscall live in a flat
	 * array is also live in exactly one of these two pools, split by
	 * whether syscall_is_expensive() returns true for its table
	 * index -- the authoritative source of truth is the read-only
	 * EXPENSIVE bitmap that select_syscall_tables() builds once at
	 * init from entry->flags & EXPENSIVE, so a scribbled
	 * entry->flags cannot mis-classify.
	 *
	 * Same +1 index encoding as the flat arrays (val = calln + 1,
	 * val == 0 is the empty slot), same swap-with-last mutation
	 * discipline, same shm->syscalltable_lock coverage as the flat
	 * arrays' mutations in deactivate_syscall_locked().  The
	 * per-entry back-index for pool-side swap-with-last is
	 * syscallentry->pool_number (see include/syscall.h), mirroring
	 * active_number's role for the flat array.
	 *
	 * Partition invariant, checked from within the activate /
	 * deactivate paths under the lock:
	 *   nr_active_cheap + nr_active_exp == nr_active_syscalls
	 *   nr_active_cheap_32bit + nr_active_exp_32bit == nr_active_32bit_syscalls
	 *   nr_active_cheap_64bit + nr_active_exp_64bit == nr_active_64bit_syscalls
	 *
	 * BEHAVIOUR-NEUTRAL storage: the live picker still draws from
	 * the flat active_syscalls*[] + expensive_accept.  These pools
	 * are maintained but NOT read by random-syscall.c -- they are
	 * the foundation for the later O(1) cost-selector phases.
	 *
	 * Uniarch builds only touch the un-suffixed pair; biarch builds
	 * only touch the _32bit / _64bit pairs, mirroring the flat
	 * arrays' arch-only-touches convention.
	 */
	int active_cheap[MAX_NR_SYSCALL];
	int active_expensive[MAX_NR_SYSCALL];
	int active_cheap32[MAX_NR_SYSCALL];
	int active_expensive32[MAX_NR_SYSCALL];
	int active_cheap64[MAX_NR_SYSCALL];
	int active_expensive64[MAX_NR_SYSCALL];
	unsigned int nr_active_cheap;
	unsigned int nr_active_exp;
	unsigned int nr_active_cheap_32bit;
	unsigned int nr_active_exp_32bit;
	unsigned int nr_active_cheap_64bit;
	unsigned int nr_active_exp_64bit;

	/*
	 * Cached "table has at least one active syscall" booleans for the
	 * biarch picker.  Maintained by validate_syscall_table_{32,64}() at
	 * startup and invalidated by the deactivate_syscall{32,64}() paths
	 * (and the 32-on-64 emulation auto-disable) when the corresponding
	 * nr_active_*bit_syscalls counter falls to zero.  Lets
	 * choose_syscall_table() short-circuit the per-pick walk through
	 * validate_syscall_table_{32,64}() with two single-byte loads.
	 *
	 * Only meaningful on biarch builds; uniarch never reads them.
	 */
	bool valid_syscall_table_32;
	bool valid_syscall_table_64;

	/*
	 * Per-syscall consecutive validation-failure counter.  Bumped by
	 * the pickers when validate_specific_syscall_silent() returns
	 * false; reset to 0 when validation passes.  Deactivation only
	 * triggers once the count hits VALIDATE_FAIL_THRESHOLD, so a
	 * transient flap (e.g. a probe that EAGAIN'd once) no longer
	 * permanently kills the entry on the first failure.  u8 is plenty:
	 * we only compare against the small threshold and reset on
	 * success.  All accesses are relaxed atomic so concurrent pickers
	 * across children can race the same slot without a lock.
	 *
	 * Dimensioned [2][MAX_NR_SYSCALL] so biarch builds keep the 32-bit
	 * and 64-bit tables' failure counters separate -- slot N in one
	 * table is usually a different syscall than slot N in the other,
	 * and a single-dimension array let resets and threshold trips on
	 * one arch silently overwrite or be driven by observations from
	 * the sibling.  Uniarch builds only ever touch index [0], matching
	 * the existing do32 ? 1 : 0 convention used elsewhere (see
	 * cmp_hints_strip).
	 */
	unsigned char syscall_validation_failures[2][MAX_NR_SYSCALL];

#ifdef ARCH_IS_BIARCH
	/* Check that 32bit emulation is available. */
	unsigned int syscalls32_succeeded;
	unsigned int syscalls32_attempted;
#endif
	/* io_uring ring with valid mappings, shared across children.
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless).
	 * Destructor nulls this. */
	struct io_uringobj *mapped_ring;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t buglock;

	/*
	 * Sibling cursor for the shared string heap (see
	 * alloc_shared_str() in utils.c).
	 */
	size_t shared_str_heap_used __attribute__((aligned(64)));

	/*
	 * Per-bucket freelist head for the shared string heap.
	 * NUM_SHM_FREELIST_BUCKETS fixed-size slots (8..1024 bytes, powers of
	 * two); allocations above 1024 bytes bypass the freelist and use the
	 * bump allocator directly.  Each head is a 64-bit (version, token)
	 * tuple: the low 32 bits carry a heap-offset token (slot offset + 1;
	 * 0 == empty list) and the high 32 bits carry a monotonic version
	 * counter that defeats the ABA race in freelist_pop (see the long
	 * comment above the freelist primitives in utils.c).  The link to the
	 * next free slot is stored as a token in the slot's own first
	 * uint32_t (safe because the slot is, by definition, not live when
	 * the link is written).  The offset encoding is arch-portable — it
	 * survives processes mapping the shared heap at different base
	 * addresses and makes no assumption about pointer width or canonical
	 * VA layout.  Manipulated by lock-free CAS in freelist_push/pop in
	 * utils.c.
	 */
#define NUM_SHM_FREELIST_BUCKETS 8
	uint64_t shared_str_freelist[NUM_SHM_FREELIST_BUCKETS];

	/* various flags. */
	enum exit_reasons exit_reason;
	/* set by check_uid alongside panic(EXIT_UID_CHANGED) so main can
	 * include the offending uid in the bail message. */
	uid_t uid_at_exit;
	bool dont_make_it_fail;

	/* Set to true once we detect that /proc/self/fail-nth can't be
	 * opened (kernel built without CONFIG_FAULT_INJECTION, etc.).
	 * Lives in shm so the flag propagates across fork(). */
	bool no_fail_nth;
	bool spawn_no_more;
	bool ready;
	bool postmortem_in_progress;

	/* global debug flag.
	 * This is in the shm so we can do things like gdb to the main pid,
	 * and have the children automatically take notice.
	 * This can be useful if for some reason we don't want to gdb to the child.
	 */
	bool debug;

	/* set to true if a child hits an EPERM/EINVAL trying to
	 * unshare(CLONE_NEWPID). Stored in shm so the flag propagates
	 * across fork() — a process-local static would be duplicated
	 * into each child's address space. */
	bool no_pidns;

	/* set to true if a child fails the MS_REC|MS_PRIVATE remount
	 * after unshare(CLONE_NEWNS). Stored in shm so the flag
	 * propagates across fork() — a process-local static would be
	 * duplicated into each child's address space. Used to suppress
	 * log spam over long fuzz runs and to skip the unshare+remount
	 * dance once we know it can't be made private. */
	bool no_private_ns;

	/*
	 * Parent-provisioned startup-isolation latches.  Written once by
	 * setup_startup_isolation() in the parent's pre-fork window;
	 * children read RELAXED in init_child_setup_sandbox to decide
	 * whether to do the per-child net/mount unshare or inherit the
	 * parent's provisioned ns.  Either latch false degrades to the
	 * per-child unshare path with zero behaviour change.  Design
	 * rationale (independent latching, degrade ladder, memory
	 * ordering, why netns_fd is stashed here):
	 * Documentation/shm-state.md
	 *
	 *   net_ready:   parent's private-netns provisioning succeeded.
	 *   mnt_ready:   parent's private-mount-ns unshare AND
	 *                MS_REC|MS_PRIVATE remount of '/' both succeeded.
	 *   netns_fd:    dup'd /proc/self/ns/net handle to the provisioned
	 *                netns; -1 sentinel means "not published".
	 *                Initialised to -1 by create_shm() over the
	 *                memset-zero so the sentinel is honest even before
	 *                setup runs.
	 */
	struct {
		bool net_ready;
		bool mnt_ready;
		int netns_fd;

		/*
		 * Scratch block-device pool, populated by fds/scratch_block.c
		 * during open_fds() when mnt_ready is latched.  The provider
		 * runs in the parent's brief root window, calls
		 * /dev/loop-control -> LOOP_CTL_GET_FREE -> LOOP_CONFIGURE
		 * over scratch image files and (best-effort) formats one with
		 * mkfs.ext4 then mounts it inside the parent's private mount
		 * ns.  A tmpfs slot is added unconditionally (default:
		 * tmpfs always; ext4 when the loop side + mkfs.ext4 both
		 * succeed).
		 *
		 * This pool is the BOX-SAFETY CHOKEPOINT for fuzzed block
		 * I/O: it is the ONLY source of loop fds + device paths that
		 * a child can draw, by construction.  A host disk node can
		 * never enter the pool because every entry's loop number
		 * came from the kernel's own LOOP_CTL_GET_FREE allocation
		 * and the parent retains the loop fd for the run's lifetime
		 * (children inherit it via fork; a child close drops only
		 * that child's ref).  Childops needing /dev/loopN draw
		 * their loop number from this pool rather than reaching
		 * for arbitrary host block devices, so the node is always
		 * a fuzz-safe parent-owned entry, never a host disk node.
		 *
		 * Children consult scratch_block_ready before reading any
		 * other field; when false (non-root, mnt_ready degraded, or
		 * provider init failed), childops fall back to today's
		 * per-child tmpfs/ramfs path.  loop_fd / loop_num are -1
		 * for the tmpfs slot, so an entry with loop_num >= 0 is the
		 * only kind a block-fd consumer should pick.
		 *
		 * Parent teardown via atexit (mirror self_cgroup_cleanup):
		 * unmount + LOOP_CLR_FD on every published entry, close the
		 * parent-held loop fd, unlink the backing image, rmdir the
		 * scratch subtree.  Idempotent against partial teardown.
		 */
		bool scratch_block_ready;
		unsigned int scratch_block_count;
		struct scratch_block_entry scratch_block[SCRATCH_BLOCK_MAX];
	} isolation;

	/*
	 * Fleet-wide in-flight count of unshare(CLONE_NEWNET) and the
	 * matching clone()/clone3() flag.  The sanitise hooks for those
	 * three syscalls bump this on admission and the matching post
	 * hooks drop it; calls that find the count already at
	 * MAX_CONCURRENT_NEWNET strip CLONE_NEWNET from the flag arg
	 * instead of admitting another in-flight caller and bump
	 * the unshare_newnet_throttled aggregate counter.  See the long comment on
	 * MAX_CONCURRENT_NEWNET above for the kernel-side reason this
	 * cap exists.  Stored in shm so all children plus any untracked
	 * grandchildren they fork share one counter — a process-local
	 * static would be duplicated across the COW fork tree and let
	 * each subtree run its own unbounded admission rate.
	 */
	int newnet_in_flight;

	/* recipe_runner discovery latches: a recipe whose first invocation
	 * detects an absent kernel feature (ENOSYS, missing config) flips
	 * its slot here so siblings stop probing.  Indexed by the recipe's
	 * slot in the static catalog inside recipe-runner.c. */
	bool recipe_disabled[MAX_RECIPES];

	/* iouring_recipes discovery latches: mirrors recipe_disabled but
	 * scoped to the iouring-recipes childop catalog. */
	bool iouring_recipe_disabled[MAX_IOURING_RECIPES];

	/* Set to true once we confirm io_uring_setup returns ENOSYS.
	 * Avoids repeated failed probes from every child. */
	bool iouring_enosys;

	/* socket_family_chain childop unsupported latch.  Set to true after
	 * an invocation hits a burst of ESRCH/EPERM/ENOPROTOOPT errors,
	 * indicating the kernel was built without CRYPTO_USER_API or AF_ALG
	 * is otherwise locked down.  Siblings then skip the chain entirely. */
	bool socket_family_chain_unsupported;

	/* Per-family latch for the socket-family-grammar dispatcher
	 * (net/socket-family-grammar.c).  sfg_unsupported[family] is set
	 * when can_run() probes fail or when run_grammar_chain() exhausts
	 * its ERR_BURST_LIMIT for that family — siblings then skip the
	 * grammar entry on subsequent picks.  No auto-clear; module load
	 * mid-run takes the hit, same recovery story as the AF_ALG latch
	 * above. */
	bool sfg_unsupported[TRINITY_PF_MAX];

	/* Per-kind feature-absent latches for the vxlan_encap_churn
	 * childop (childops/net/vxlan-encap.c).  Indexed by the file-local
	 * enum tun_kind (0 = vxlan, 1 = gre, 2 = geneve); the indices
	 * are stable and pinned by a _Static_assert in vxlan-encap.c.
	 * Set when RTM_NEWLINK rejects the kind with rtnl_link_ops-not-
	 * registered errno (absent module / CONFIG); subsequent picks
	 * skip the kind so the unsupported attempt is paid once per
	 * fleet rather than once per grandchild invocation.
	 *
	 * Must live in shm: the rejection is observed inside the
	 * transient grandchild forked by userns_run_in_ns(), which
	 * _exit()s after the body returns.  A process-local static
	 * would die with the grandchild and the next invocation would
	 * re-attempt the same unsupported kind every single time
	 * (latch-in-grandchild bug).  No auto-clear; an absent kernel
	 * CONFIG does not appear mid-run, same recovery story as the
	 * sfg_unsupported gates above.  RELAXED atomic load/store from
	 * multiple grandchildren is safe — the only transition is
	 * false -> true and the write is idempotent. */
#define VXLAN_ENCAP_NR_KINDS 3
	bool vxlan_encap_kind_unsupported[VXLAN_ENCAP_NR_KINDS];

	/* Feature-absent latch for the ip_gre_churn childop
	 * (childops/net/ip_gre-churn.c).  Set when RTM_NEWLINK type=gretap
	 * rejects with the rtnl_link_ops-not-registered errno set (absent
	 * CONFIG_NET_IPGRE / module).  Same shm-vs-static rationale as the
	 * vxlan_encap_kind_unsupported[] block above: the rejection is
	 * observed inside a transient userns_run_in_ns grandchild that
	 * _exit()s after the body returns, so a process-local static would
	 * die with the grandchild and every subsequent invocation would
	 * re-attempt the unsupported create.  RELAXED atomic load/store
	 * from multiple grandchildren is safe -- only false -> true, and
	 * the write is idempotent. */
	bool ip_gre_kind_unsupported;

	/* Feature-absent latch for the sctp_chunk_rx childop
	 * (childops/net/sctp-chunk-rx.c).  Set when socket(IPPROTO_SCTP)
	 * rejects with EPROTONOSUPPORT / ESOCKTNOSUPPORT / EAFNOSUPPORT /
	 * EACCES inside the transient userns_run_in_ns grandchild
	 * (missing CONFIG_IP_SCTP / hardening policy blocking raw SCTP
	 * sockets in the child's userns).  Same shm-vs-static rationale
	 * as the ip_gre_kind_unsupported gate above: the rejection is
	 * observed inside a transient grandchild that _exit()s after the
	 * body returns, so a process-local static would die with the
	 * grandchild and every subsequent invocation would re-attempt
	 * the missing kind forever.  RELAXED atomic load/store from
	 * multiple grandchildren is safe -- only false -> true, and the
	 * write is idempotent. */
	bool sctp_chunk_rx_kind_unsupported;

	/* Feature-absent latch for the esp_crafted_rx childop
	 * (childops/net/esp-crafted-rx.c).  Set when NETLINK_XFRM open
	 * or XFRM_MSG_NEWSA installing a null-cipher/null-auth ESP SA
	 * rejects with the CONFIG_XFRM / CONFIG_INET_ESP / CONFIG_INET6_ESP
	 * absent errno set (EOPNOTSUPP / EPROTONOSUPPORT / EAFNOSUPPORT /
	 * ENOPROTOOPT / ENOENT) inside the transient userns_run_in_ns
	 * grandchild.  Same shm-vs-static rationale as the two gates above:
	 * the rejection is observed inside a transient grandchild that
	 * _exit()s after the body returns, so a process-local static would
	 * die with the grandchild and every subsequent invocation would
	 * re-attempt the missing kind forever.  RELAXED atomic load/store
	 * from multiple grandchildren is safe -- only false -> true, and
	 * the write is idempotent. */
	bool esp_crafted_rx_kind_unsupported;

	/* Feature-absent latch for the fou_gue_mcast_rx childop
	 * (childops/net/fou-gue-mcast-rx.c).  Set when genl_open("fou")
	 * or FOU_CMD_ADD installing a FOU/GUE receive port rejects with
	 * the CONFIG_NET_FOU / CONFIG_IPV6_FOU absent errno set (ENOENT /
	 * EPROTONOSUPPORT / EAFNOSUPPORT / EOPNOTSUPP / ENOPROTOOPT /
	 * EPERM) inside the transient userns_run_in_ns grandchild.  Same
	 * shm-vs-static rationale as the sibling latches above: the
	 * rejection is observed inside a transient grandchild that
	 * _exit()s after the body returns, so a process-local static
	 * would die with the grandchild and every subsequent invocation
	 * would re-attempt the missing kind forever.  RELAXED atomic
	 * load/store from multiple grandchildren is safe -- only
	 * false -> true, and the write is idempotent. */
	bool fou_gue_mcast_rx_kind_unsupported;

	/* Feature-absent latch for the geneve_rx childop
	 * (childops/net/geneve-rx.c).  Set when RTM_NEWLINK kind="geneve"
	 * installing a geneve tunnel dev rejects with the CONFIG_GENEVE
	 * / module-absent errno set (EAFNOSUPPORT / EOPNOTSUPP / ENOTSUP
	 * / ENOENT / EPROTONOSUPPORT) inside the transient
	 * userns_run_in_ns grandchild.  Same shm-vs-static rationale as
	 * the sibling latches above: the rejection is observed inside a
	 * transient grandchild that _exit()s after the body returns, so
	 * a process-local static would die with the grandchild and every
	 * subsequent invocation would re-attempt the missing kind
	 * forever.  RELAXED atomic load/store from multiple grandchildren
	 * is safe -- only false -> true, and the write is idempotent. */
	bool geneve_rx_kind_unsupported;

	/* Feature-absent latch for the bareudp_rx childop
	 * (childops/net/bareudp-rx.c).  Set when RTM_NEWLINK kind="bareudp"
	 * installing a bareudp tunnel dev rejects with the CONFIG_BAREUDP
	 * / module-absent errno set (EAFNOSUPPORT / EOPNOTSUPP / ENOTSUP
	 * / ENOENT / EPROTONOSUPPORT) inside the transient
	 * userns_run_in_ns grandchild.  Same shm-vs-static rationale as
	 * the sibling latches above: the rejection is observed inside a
	 * transient grandchild that _exit()s after the body returns, so
	 * a process-local static would die with the grandchild and every
	 * subsequent invocation would re-attempt the missing kind
	 * forever.  RELAXED atomic load/store from multiple grandchildren
	 * is safe -- only false -> true, and the write is idempotent. */
	bool bareudp_rx_kind_unsupported;

	/* Feature-absent latch for the mpls_label_stack_rx childop
	 * (childops/net/mpls-label-stack-rx.c).  Set when
	 * /proc/sys/net/mpls/platform_labels open returns ENOENT (missing
	 * CONFIG_MPLS_ROUTING / mpls_router module) inside the transient
	 * userns_run_in_ns grandchild.  Same shm-vs-static rationale as
	 * the sibling latches above: the rejection is observed inside a
	 * transient grandchild that _exit()s after the body returns, so
	 * a process-local static would die with the grandchild and every
	 * subsequent invocation would re-attempt the missing kind
	 * forever.  RELAXED atomic load/store from multiple grandchildren
	 * is safe -- only false -> true, and the write is idempotent. */
	bool mpls_label_stack_rx_kind_unsupported;

	/* Feature-absent latch for the espintcp_coalesce_churn childop
	 * (childops/net/espintcp-coalesce-churn.c).  Set when
	 * setsockopt(TCP_ULP, "espintcp") rejects with the
	 * CONFIG_INET_ESPINTCP absent errno set (ENOPROTOOPT /
	 * EOPNOTSUPP / EAFNOSUPPORT / EPERM) inside the transient
	 * userns_run_in_ns grandchild.  Same shm-vs-static rationale as
	 * the sibling latches above: the rejection is observed inside a
	 * transient grandchild that _exit()s after the body returns, so
	 * a process-local static would die with the grandchild and every
	 * subsequent invocation would re-attempt the missing kind
	 * forever.  RELAXED atomic load/store from multiple grandchildren
	 * is safe -- only false -> true, and the write is idempotent. */
	bool espintcp_coalesce_kind_unsupported;

	/*
	 * Distinct-sequence-hash ring for run_grammar_chain's per-walk
	 * phase ordering.  Each walk computes an FNV-1a hash over the
	 * step-IDs it actually executed and calls sfg_seq_record()
	 * to fold it into this ring.  The ring's population is surfaced
	 * as stats.socket_family_grammar_distinct_seq — a value greater
	 * than one proves the phase-order table is live.
	 *
	 * Fixed capacity keeps the memory footprint small (128 * 4 =
	 * 512 bytes) and the counter saturates when the ring fills — the
	 * metric is a variety signal, not a full inventory.  Multiple
	 * children write concurrently; a compare-exchange on sfg_seq_count
	 * makes the append race-free without a lock.  Losers of the CAS
	 * re-scan the ring (the winner just wrote a slot that may match
	 * their hash), so a duplicate under a lost race is possible only
	 * if two children race with the same NEW hash simultaneously —
	 * an over-count of one is acceptable for a variety metric.
	 */
#define SFG_SEQ_HASH_CAP 128
	uint32_t sfg_seq_hashes[SFG_SEQ_HASH_CAP];
	unsigned int sfg_seq_count;

	/*
	 * P4 feedback-scheduler reward arms, parallel to sfg_seq_hashes[]
	 * and keyed by the same slot index (returned by sfg_seq_record).
	 * A legal grammar walk credits the slot for its executed sequence
	 * with the new-edge count harvested over the walk; the picker
	 * rolls these up per (family, order-index) arm to tilt selection
	 * toward productive orderings.  sfg_seq_arm holds the arm id that
	 * owns each slot (stamped on first credit).  Zero-initialised with
	 * the rest of shm; an uncredited slot has attempts == 0 and is
	 * skipped by the rollup.  No second unbounded structure — this is
	 * a fixed extension of the existing ring (128 * 12 = 1536 bytes).
	 */
	uint32_t sfg_seq_attempts[SFG_SEQ_HASH_CAP];
	uint32_t sfg_seq_reward[SFG_SEQ_HASH_CAP];
	uint32_t sfg_seq_arm[SFG_SEQ_HASH_CAP];

	/*
	 * Multi-strategy syscall picker — see include/strategy.h.
	 *
	 * current_strategy: fleet-wide active strategy enum.  Children read
	 *   it on every syscall pick (relaxed atomic, single int read — cheap).
	 *   Updated only by the CAS-winning child at a rotation boundary.
	 *
	 * syscalls_at_last_switch: shm_published->fleet_op_count at the most
	 *   recent rotation.  Doubles as the CAS guard — a child computes
	 *   (op_count - syscalls_at_last_switch); if that crosses
	 *   STRATEGY_WINDOW it tries to CAS this field forward to op_count.
	 *   The CAS winner performs the strategy switch and emits the stats
	 *   line; losers just continue with the new strategy on their next
	 *   pick.
	 *
	 * pc_edge_calls_at_window_start / pc_edge_count_at_window_start:
	 *   snapshots of pc_edge_calls_by_strategy[prev] and
	 *   pc_edge_count_by_strategy[prev] taken at the previous switch.
	 *   Let the next switch compute the per-window deltas as
	 *   pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start
	 *   (call-count delta), and similarly for the bucket-count series.
	 *   Written only by the CAS-winning child during a switch and read
	 *   back by the next CAS-winning child; accesses are RELAXED-atomic
	 *   so the cross-arch shared-memory discipline stays uniform with
	 *   the surrounding per-strategy counter fields rather than relying
	 *   on the CAS for ordering.
	 *
	 * pc_edge_calls_by_strategy[]: cumulative count of SYSCALL CALLS
	 *   attributed to each strategy whose post-call kcov_collect()
	 *   flipped at least one never-seen bucket bit.  Bumped by +1 per
	 *   such call, NOT by the number of distinct edges that call
	 *   uncovered: a syscall that exposes 50 fresh edges in one shot
	 *   still bumps the call-count series by 1.  This series counts
	 *   calls-with-≥1-new-edge (not the edge count itself) and feeds
	 *   the UCB1 learner via bandit_reward_calls[] below.
	 *
	 * pc_edge_count_by_strategy[]: cumulative count of REAL bucket-edge
	 *   bits flipped by syscalls attributed to each strategy — the
	 *   per-call new_edge_count from kcov_collect(), summed across all
	 *   contributing calls.  Strictly >= the call-count series, often
	 *   far larger when individual calls uncover deep paths.  Added
	 *   alongside the call-count series so both signals are visible
	 *   without changing the learner's behaviour; a future commit may
	 *   switch UCB1 to consume this series instead, or fold a transform
	 *   of it (e.g. log2(1 + count)) into the reward.
	 *
	 * Cmp-mode runs do not produce a new-edge signal and are not
	 * attributed to either series.
	 */
	int current_strategy;

	/*
	 * current_selection_reason: enum strategy_selection_reason for the
	 *   current_strategy above -- why select_next_strategy() returned
	 *   that arm for this window.  Stored alongside current_strategy
	 *   so the rotation site can read it back at window close and
	 *   decide whether to feed the just-finished window into the UCB
	 *   learner.  Forced-intervention windows (SR_PLATEAU_FORCE) skip
	 *   the learner update so policy-chosen RANDOM windows and
	 *   intervention RANDOM windows do not get conflated in
	 *   bandit_pulls[]/bandit_reward_calls[].  Held as int rather than
	 *   the enum type so the shm layout stays language-stable across
	 *   any future enum reorder.
	 */
	int current_selection_reason;
	unsigned long syscalls_at_last_switch;
	unsigned long pc_edge_calls_at_window_start;
	unsigned long pc_edge_count_at_window_start;
	unsigned long pc_edge_calls_by_strategy[NR_STRATEGIES];
	unsigned long pc_edge_count_by_strategy[NR_STRATEGIES];

	/*
	 * UCB1 bandit picker (Phase 2) — see include/strategy.h.
	 *
	 * picker_mode: arm-selection policy (PICKER_ROUND_ROBIN or
	 *   PICKER_BANDIT_UCB1).  Set once at init_shm time from
	 *   picker_mode_arg, never mutated thereafter.  Read by the
	 *   CAS-winning child on the rotation path.
	 *
	 * bandit_pulls[]: number of windows each arm was selected for.
	 *   Bumped by bandit_record_pull() during the rotation switch,
	 *   which is serialised by the syscalls_at_last_switch CAS, so
	 *   plain integer writes are safe (no concurrent writers).
	 *
	 * bandit_reward_calls[]: cumulative reward attributed to each arm,
	 *   in CALL-COUNT units — sum of per-window
	 *   (pc_edge_calls_by_strategy delta + cmp_term).  The PC
	 *   component counts CALLS that produced at least one new edge,
	 *   not real bucket edges (see the pc_edge_calls_by_strategy
	 *   comment above).  This is the signal the UCB1 picker scores
	 *   against.  The learner may later switch to consuming
	 *   bandit_reward_pc_edge_count[] below (real bucket count) or a
	 *   transform of it; both signals are exposed so that choice can
	 *   be made later.
	 *
	 * bandit_reward_pc_edge_count[]: cumulative PC-edge BUCKET COUNT
	 *   attributed to each arm — sum of per-window
	 *   pc_edge_count_by_strategy deltas, no cmp term folded in.
	 *   Diagnostic-only today: visible alongside the call-count series
	 *   in dump_strategy_stats() so the operator can see how the two
	 *   signals would score the same set of windows differently before
	 *   we commit to flipping the learner.
	 *
	 * Both reward series are written under the same CAS-serialised
	 * rotation path as bandit_pulls[].
	 */
	int picker_mode;
	unsigned long bandit_pulls[NR_STRATEGIES];
	unsigned long bandit_reward_calls[NR_STRATEGIES];
	unsigned long bandit_reward_pc_edge_count[NR_STRATEGIES];

	/*
	 * Per-arm x chaos-state cohort accumulators -- chaos-mode V2
	 * observation-only attribution.  Each completed window is bucketed
	 * into [arm][chaos_state] in bandit_record_pull, where chaos_state
	 * is the cmp_hints_chaos_active flag sampled at window close
	 * (chaos_off=0 / chaos_on=1).  The cohort split lets the operator
	 * compare per-arm reward and kernel-diagnostic-fire rates between
	 * windows where cmp_hints suppression was active and windows where
	 * it was not, without re-running the fuzzer with chaos disabled.
	 *
	 * Three parallel matrices mirror the existing lifetime series with
	 * a chaos-state dimension:
	 *
	 *   bandit_pulls_by_chaos[a][c]              -- window count for arm
	 *     a with chaos state c.  Bumped on every non-SR_PLATEAU_FORCE
	 *     window the learner accepts; the per-cohort sum across c
	 *     equals bandit_pulls[a].
	 *   bandit_reward_calls_by_chaos[a][c]       -- combined reward
	 *     (pc_edge_calls + cmp_term), same units as
	 *     bandit_reward_calls[a].  Sum across c equals bandit_reward_
	 *     calls[a].
	 *   bandit_warn_fires_by_chaos[a][c]         -- per-window delta
	 *     of kmsg_warn_fires bucketed into the matching cohort.  Brand
	 *     new V2 counter; no companion lifetime series because the
	 *     headline V2 question is "does chaos correlate with WARNs?"
	 *     and a per-arm-flat WARN total without the cohort split would
	 *     not answer it.
	 *
	 * Observation-only -- nothing in select_next_strategy / ucb1_score
	 * / pick_next_strategy reads these arrays.  The learner's reward
	 * formula in bandit_record_pull is unchanged.  Action mode (V3)
	 * will fold the chaos cohort signal back into the picker once the
	 * statistical-significance gate from the design doc clears.
	 *
	 * Single-writer protocol matches the existing bandit_pulls[] path
	 * (CAS-serialised rotation), dump-side reads are RELAXED.
	 * NR_STRATEGIES * 2 * 3 series * 8 bytes = 192 bytes today.
	 */
	unsigned long bandit_pulls_by_chaos[NR_STRATEGIES][2];
	unsigned long bandit_reward_calls_by_chaos[NR_STRATEGIES][2];
	unsigned long bandit_warn_fires_by_chaos[NR_STRATEGIES][2];

	/*
	 * Per-arm syscall-level exposure counters -- the denominators the
	 * bandit reward series (bandit_pulls[], pc_edge_calls_by_strategy[],
	 * bandit_reward_calls[]) leave implicit.  Multi-producer, RELAXED
	 * fetch_add on the hot path; RELAXED loads in dump_strategy_stats()
	 * at end of run.  Design rationale (why explicit denominators, how
	 * A/B tuning uses these) in Documentation/shm-state.md.
	 *
	 *   strategy_picks[]:             every syscall pick credited to an
	 *     arm, bumped in set_syscall_nr() after arm resolution.  Widest
	 *     population -- all dispatched syscalls (explorer + bandit).
	 *   strategy_bandit_pool_ops[]:   strict subset of strategy_picks
	 *     bumped only on the bandit-pool path.  Pairs cleanly with
	 *     pc_edge_calls_by_strategy[] (both exclude explorer).
	 *   strategy_completed_calls[]:   bumped at end of dispatch_step
	 *     after the syscall returned.  Excludes set_syscall_nr() FAIL
	 *     returns, so completed/picks is the per-arm dispatch success
	 *     rate.
	 */
	unsigned long strategy_picks[NR_STRATEGIES];
	unsigned long strategy_bandit_pool_ops[NR_STRATEGIES];
	unsigned long strategy_completed_calls[NR_STRATEGIES];

	/*
	 * Per-arm-per-selection-reason reward attribution.  Each window's
	 * outcome is bucketed into [arm][reason] independent of the
	 * learner-facing bandit_pulls[]/bandit_reward_calls[] series above
	 * so the operator and the future intervention classifier can see
	 * how each arm's exposure splits across selection paths:
	 *
	 *   bandit_pulls_by_reason[a][SR_NORMAL_UCB]    -- arm a was
	 *     chosen by the UCB1 scorer (the bandit's policy decision).
	 *   bandit_pulls_by_reason[a][SR_COLD_START]    -- arm a was
	 *     chosen because UCB1 had not seen it pulled yet.
	 *   bandit_pulls_by_reason[a][SR_ROUND_ROBIN]   -- arm a's slot
	 *     in the fixed cycle (round-robin mode only).
	 *   bandit_pulls_by_reason[a][SR_PLATEAU_FORCE] -- arm a (always
	 *     STRATEGY_RANDOM today) was forced by the intervention
	 *     orchestrator over the top of the bandit's pick.  These
	 *     windows are deliberately EXCLUDED from bandit_pulls[] and
	 *     the recent_*_x1000 EMA so the learner's view of RANDOM
	 *     stays uncontaminated, but they ARE recorded here so the
	 *     operator can see the intervention cohort's reward
	 *     separately and a future plateau-rescue classifier can
	 *     read pulls_by_reason[*][SR_PLATEAU_FORCE] +
	 *     pc_edge_calls_by_strategy[*] to decide which arm to force
	 *     next time.
	 *
	 * Three parallel matrices mirror the lifetime series:
	 *
	 *   bandit_pulls_by_reason[a][r]              -- window count
	 *   bandit_reward_calls_by_reason[a][r]       -- combined reward
	 *     (pc_edge_calls + cmp_term), same units as
	 *     bandit_reward_calls[].
	 *   bandit_reward_pc_edge_count_by_reason[a][r] -- real bucket-
	 *     edge count, same units as bandit_reward_pc_edge_count[].
	 *
	 * Same single-writer protocol as bandit_pulls[] (CAS-serialised
	 * rotation path).  dump_strategy_stats() uses RELAXED loads.
	 * 3 strategies * 4 reasons * 3 series * 8 bytes = 288 bytes,
	 * trivial against existing shm consumers.
	 */
	unsigned long bandit_pulls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_calls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_pc_edge_count_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];

	/*
	 * Random-rescue classifier counters -- see classify_random_rescue
	 * in include/strategy.h.  Each new-edge syscall completed during a
	 * SR_PLATEAU_FORCE window is classified into one of the
	 * RRC_* buckets and the corresponding slot here is bumped.  The
	 * cumulative distribution is what the next plateau intervention
	 * reads to decide whether plain RANDOM is still the right rescue
	 * arm or whether the classifier has accumulated enough evidence to
	 * point at a more targeted intervention (cold-skip disable,
	 * cmp-hint boost, etc.).
	 *
	 * Multi-producer (every child that completes a rescue increments
	 * its class slot); RELAXED fetch_add on the write side, RELAXED
	 * loads on the orchestrator-side reads in select_next_strategy and
	 * dump_strategy_stats.  Per-class cacheline contention is
	 * acceptable: the writer set is small (only children whose syscall
	 * landed in a forced-intervention window and produced new edges)
	 * and the readers consult these counts at rotation boundaries and
	 * at end-of-run, not on the hot pick path.
	 */
	unsigned long random_rescue_class_count[RRC_NR_CLASSES];

	/*
	 * Currently-amplified random-rescue class, published by the
	 * orchestrator (select_next_strategy) at every rotation boundary.
	 * RRC_NR_CLASSES is the "no amplification" sentinel -- either the
	 * fleet is not in a plateau intervention or no class has cleared
	 * the dominance threshold against its peers.  Held as int rather
	 * than the enum so the shm layout stays language-stable across any
	 * future enum reorder.
	 *
	 * Read by children on the hot pick / arg-generation path to
	 * conditionally relax structured filters that the classifier
	 * blamed for the recent rescue cohort:
	 *
	 *   RRC_COLD_SKIP    -> set_syscall_nr_heuristic skips its
	 *                       kcov_syscall_cold_skip_pct retry, so
	 *                       cold syscalls flow through the heuristic
	 *                       arm during the intervention.
	 *   RRC_CMP_DERIVED  -> generate-args.c's 1-in-16
	 *                       cmp_hints_try_get rolls flip to 1-in-4
	 *                       so the learned constants the classifier
	 *                       credited the rescues to fire more often.
	 *
	 * Gated on (shm->plateau_active && current_selection_reason ==
	 * SR_PLATEAU_FORCE) at every read site so the relaxation applies
	 * only inside the intervention window, never as a permanent
	 * change to the structured pickers.
	 */
	int plateau_rescue_amplified_class;

	/*
	 * Plateau intervention mode rotation state.  Inside an
	 * SR_PLATEAU_FORCE window the orchestrator round-robins
	 * PIM_UNIFORM_RANDOM / PIM_ANTI_PRIOR / PIM_RRC_BIASED /
	 * PIM_COVERAGE_FRONTIER at each rotation.  Design rationale
	 * (rotation dispatch, anti-prior fast path, visibility hand-off):
	 * Documentation/shm-state.md
	 *
	 *   plateau_intervention_mode_current: latched mode for the current
	 *     intervention window; published by select_next_strategy at
	 *     rotation.  Held as int so the shm layout stays language-stable
	 *     across enum reorders.  Reset to PIM_UNIFORM_RANDOM on every
	 *     non-intervention rotation so a stale mode cannot keep the
	 *     anti-prior gate latched on after the plateau lifts.
	 *   plateau_anti_prior_baseline_calls: cached mean of
	 *     kcov_shm->per_syscall.per_syscall_calls across the active syscall set,
	 *     refreshed at every PIM_ANTI_PRIOR rotation.  Zero == "no
	 *     baseline yet"; the accept gate short-circuits to "pass" in
	 *     that state so cold-start picks degenerate to uniform.
	 *   plateau_anti_prior_accept_weight[MAX_NR_SYSCALL]: per-syscall
	 *     pre-computed acceptance numerator in [1,
	 *     ANTI_PRIOR_THRESHOLD_SCALE] (= 64).  uint8_t suffices because
	 *     no per-syscall weight can exceed SCALE by construction.
	 *     Visibility hand-off piggybacks on the RELEASE store of
	 *     current_strategy that publishes the mode.
	 *   plateau_intervention_rotation_counter: monotonic per-intervention
	 *     counter, fetch_add on every plateau-window rotation; the
	 *     selected mode is the post-increment modulo NR_PIM_MODES.
	 *     Only ticks while plateau_active is set so each intervention
	 *     resumes where the previous one left off.
	 *   plateau_intervention_mode_windows[NR_PIM_MODES]: per-mode
	 *     window count, bumped at the same rotation site as the mode
	 *     selection so end-of-run analysis has an exact denominator per
	 *     mode.
	 */
	int plateau_intervention_mode_current;
	unsigned long plateau_anti_prior_baseline_calls;
	uint8_t plateau_anti_prior_accept_weight[MAX_NR_SYSCALL];
	unsigned long plateau_intervention_rotation_counter;
	unsigned long plateau_intervention_mode_windows[NR_PIM_MODES];

	/*
	 * Wall-lever shadow gate.  Identifies high-call zero-yield
	 * syscalls during a warm-plateau window so a future live variant can
	 * reclaim their pick budget for productive / cold syscalls.  Held in
	 * shm next to the anti-prior cache because the publish ordering and
	 * the rotation-boundary refresh discipline are identical.
	 *
	 * wall_lever_baseline_calls: cached mean of kcov_shm->per_syscall_
	 *   calls across the active syscall count (biarch ? nr_active_32 +
	 *   nr_active_64 : nr_active_syscalls; mirrors no_syscalls_enabled).
	 *   Refreshed by wall_lever_refresh_baseline() on every rotation
	 *   where plateau_active is set, BEFORE the mode-specific arm
	 *   dispatch.  Zero means "no baseline yet" (no plateau-active
	 *   rotation has fired, or no syscalls are active) and the shadow
	 *   predicate short-circuits to "not suppressed" in that state so
	 *   warm-up runs and the cold-start window degrade to today's pure
	 *   picker.
	 *
	 * wall_lever_suppress[MAX_NR_SYSCALL]: per-syscall pre-computed
	 *   suppression decision in {0, 1}, populated alongside the baseline
	 *   at every plateau-active rotation.  Picker-side shadow gate reads
	 *   a single relaxed byte per candidate -- the clamp / multiply /
	 *   compare math lives in the refresh path so the per-pick cost is
	 *   one load and one branch.  uint8_t suffices because the field is
	 *   a boolean carrier.  Visibility hand-off rides on the same
	 *   RELEASE store of current_strategy that publishes plateau_
	 *   intervention_mode_current -- mirrors plateau_anti_prior_accept_
	 *   weight's publish ordering.
	 */
	unsigned long wall_lever_baseline_calls;
	uint8_t wall_lever_suppress[MAX_NR_SYSCALL];

	/*
	 * Phase 2 plateau intervention: shm mirror of strategy.c's
	 * parent-private hypothesis_current.  Published by
	 * strategy_plateau_hypothesis_tick() (parent only) at every stats
	 * tick; read RELAXED by select_next_strategy() on every rotation
	 * to gate the targeted intervention selection.
	 *
	 * PLATEAU_HYPOTHESIS_NONE means "no rule matched" or "no plateau
	 * active" -- both cases revert to the round-robin intervention
	 * path.  Held as int (not the enum) so the shm layout stays
	 * language-stable across any future enum reorder, same convention
	 * as plateau_rescue_amplified_class.
	 *
	 * The gate is a derived predicate over this field, not a latched
	 * flag: when plateau_active falls and the tick driver writes NONE
	 * here, the next select_next_strategy rotation reverts to round-
	 * robin automatically.  No standalone activation/deactivation
	 * state to keep in sync.
	 */
	int plateau_current_hypothesis;

	/*
	 * Discounted "recent" counters the UCB1 picker scores against
	 * instead of the lifetime bandit_pulls[]/bandit_reward_calls[]
	 * series.  Fixed-point parts-per-thousand (suffix _x1000) so the
	 * EMA arithmetic stays in integer math; SR_PLATEAU_FORCE windows
	 * skip both decay and increment.  Same CAS-serialised single-writer
	 * protocol as bandit_pulls[]; RELAXED reads.  Design rationale
	 * (non-stationarity, why every arm decays every window, plateau
	 * skip, fixed-point encoding): Documentation/shm-state.md
	 *
	 *   recent_pulls_x1000[]:  discounted effective sample count.  Each
	 *     non-intervention window decays every arm by (1 - alpha) and
	 *     adds BANDIT_EMA_SCALE to the active arm.  Asymptote for an
	 *     always-picked arm is SCALE/alpha.
	 *   recent_reward_x1000[]: discounted total reward in the same
	 *     fixed-point.  Mean per-window reward is
	 *     recent_reward_x1000[i] / recent_pulls_x1000[i] (x1000 cancels)
	 *     so the UCB1 exploit term works without an explicit rescale.
	 */
	unsigned long recent_pulls_x1000[NR_STRATEGIES];
	unsigned long recent_reward_x1000[NR_STRATEGIES];

	/*
	 * Monotonic rotation counter, bumped by the CAS-winning child in
	 * maybe_rotate_strategy() once per completed window.  Used as the
	 * generation tag for the cmp_novelty[] bloom decay below: a bloom
	 * entry with window_tag more than CMP_NOVELTY_DECAY_WINDOWS behind
	 * this counter is considered stale and gets cleared on next access.
	 * Stays plain unsigned long with explicit __atomic_* accessors to
	 * match the existing bandit_pulls[]/bandit_reward_calls[] convention.
	 */
	unsigned long bandit_window_count;

	/*
	 * Per-syscall comparison-constant novelty bloom — see include/strategy.h
	 * (bandit_cmp_observe).  Each entry holds a 1024-bit bloom filter over
	 * the comparison constants observed for that syscall in the recent
	 * past, plus a generation tag (the rotation count at which the bloom
	 * was last cleared).  When a child observing a fresh CMP record finds
	 * the entry's tag more than CMP_NOVELTY_DECAY_WINDOWS rotations old it
	 * lazily zeroes the bloom and republishes the tag, so a constant that
	 * stops appearing for K windows is forgotten and counts as novel
	 * again.  Sized 132 bytes per syscall * MAX_NR_SYSCALL ≈ 132 KiB inside
	 * shm — well below other arrays already living here (per_syscall_*).
	 *
	 * bandit_cmp_new_constants[]: per-arm cumulative count of CMP records
	 *   that missed the bloom at observation time.  Bumped by every child
	 *   inside bandit_cmp_observe() (atomic add, multiple producers).  The
	 *   rotation hook turns the per-window delta into a secondary reward
	 *   term inside bandit_record_pull().
	 */
	/*
	 * Indexed by [syscall_nr][do32 ? 1 : 0].  Biarch builds split the
	 * novelty bloom per arch so 32-bit nr=N and 64-bit nr=N (which
	 * may be unrelated calls) do not poison each other's per-syscall
	 * constant-novelty signal.  Uniarch builds only touch [*][0].
	 */
	struct cmp_novelty_entry {
		uint32_t window_tag;
		uint8_t bloom[128];
	} cmp_novelty[MAX_NR_SYSCALL][2];
	unsigned long bandit_cmp_new_constants[NR_STRATEGIES];

	/*
	 * Snapshot of bandit_cmp_new_constants[active_arm] at the start of
	 * the current window, by symmetry with pc_edge_calls_at_window_start.
	 * The
	 * rotation hook reads bandit_cmp_new_constants[prev] and subtracts
	 * this snapshot to compute the cmp-novelty delta the just-finished
	 * window produced, then reseeds the snapshot from the next arm's
	 * counter.  Single field rather than per-arm because only one arm
	 * is active per window.  Written only by the CAS-winning child and
	 * read back by the next; accesses are RELAXED-atomic to keep the
	 * shared-memory discipline uniform with the companion *_at_window_start
	 * fields rather than relying on the CAS for cross-arch ordering.
	 */
	unsigned long bandit_cmp_at_window_start;

	/*
	 * Snapshot of kcov_shm->kmsg.kmsg_warn_fires at the start of the current
	 * bandit window.  Single global field (mirrors bandit_cmp_at_window_
	 * start) because kmsg_warn_fires is global rather than per-arm --
	 * the chaos-cohort attribution that consumes the delta needs only
	 * "how many WARNs fired in this window", not "how many WARNs fired
	 * while strategy X was active".  Reseeded from the
	 * live counter at every rotation regardless of selection reason, so
	 * the delta the cohort split sees represents only events the kernel
	 * emitted inside the just-finished window.  Written only by the
	 * CAS-winning child on the rotation path; RELAXED accesses match the
	 * other *_at_window_start fields.
	 */
	unsigned long kmsg_warn_fires_at_window_start;

	/*
	 * Per-arm cumulative sum of (cmp_term * 1000 / total_reward) across
	 * windows where cmp_term > 0.  Divided by bandit_pulls[arm] at end
	 * of run to print the average per-window CMP contribution share, so
	 * the operator can tune CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL on real
	 * run data.  Written only by the CAS-winning child, same path as
	 * bandit_pulls/bandit_reward_calls.
	 */
	unsigned long bandit_cmp_share_sum_x1000[NR_STRATEGIES];

	/*
	 * Per-syscall frontier-edge ring -- see include/strategy.h.
	 *
	 * frontier_history[nr][slot] counts NEW edges syscall nr produced
	 * during the rotation window mapped to slot.  Slot is an index in
	 * [0, FRONTIER_DECAY_WINDOWS); the slot currently being filled is
	 * (frontier_slot & mask), advanced once per rotation by the
	 * CAS-winning child via frontier_window_advance().  Sum across all
	 * slots is the syscall's "recent frontier-edge count" -- the weight
	 * the coverage-frontier picker biases its uniform pick toward.
	 *
	 * Bumped on the kcov_collect new-edge branch by every child
	 * (multi-producer, atomic add).  Slot rotation zeroes the new slot
	 * before publishing the new index, so a producer racing the rotation
	 * either bumps the previous (still-valid) slot or the freshly cleared
	 * new slot -- both attribute correctly within the K-window decay.
	 *
	 * Sized MAX_NR_SYSCALL * FRONTIER_DECAY_WINDOWS * 4 = 32 KiB, a
	 * rounding error against the cmp_novelty[] block above.
	 */
	uint32_t frontier_history[MAX_NR_SYSCALL][FRONTIER_DECAY_WINDOWS];
	uint32_t frontier_slot;

	/*
	 * Per-syscall cached recent-edge count -- running sum of
	 * frontier_history[nr][*] across the live ring, maintained
	 * incrementally so frontier_recent_count(nr) is a single RELAXED
	 * load instead of an O(FRONTIER_DECAY_WINDOWS) walk.  Producers
	 * fetch_add 1 here in lockstep with the per-slot bump; the window
	 * rotator subtracts the just-zeroed slot's contribution from this
	 * counter in the same pass that clears the slot.  Same RELAXED
	 * race envelope as frontier_history -- a producer add that
	 * interleaves with the rotation's exchange-then-subtract can leave
	 * cached one bump above the live sum, bounded by one window and
	 * folded back in by the next rotation.
	 */
	uint32_t frontier_recent_count_cached[MAX_NR_SYSCALL];

	/*
	 * Cached max of frontier_recent_count() across all syscalls --
	 * the rejection-sampling acceptance ratio in the coverage-frontier
	 * picker uses this as the bias-mass denominator.  Recomputed
	 * authoritatively on each window rotation, and ratcheted upward
	 * on new-edge bumps, so the picker reads it with a single
	 * RELAXED load instead of walking ~MAX_NR_SYSCALL frontier rings
	 * (8 RELAXED loads each) per pick.  Torn / stale values are
	 * acceptable: a slightly low cached max biases the picker toward
	 * heavier-weighted syscalls (under-rejecting cold ones); a
	 * slightly high one biases it toward uniform.  Both errors are
	 * bounded by one window rotation.
	 */
	unsigned int frontier_max_weight_cached;

	/*
	 * EFAULT-probe cache for ioctl arg classification.  Open-addressing
	 * hashmap keyed on (group_idx, request); see ioctls/efault_cache.c
	 * for the slot encoding and the probing protocol.  Lives in shm so
	 * a verdict reached by one child is reused by all the others — the
	 * kernel's ioctl tables are global and the probe has side effects
	 * we want to amortise.  Zero-initialised by create_shm(); packed ==
	 * 0 is the empty-slot sentinel.
	 */
	uint64_t ioctl_efault_cache[IOCTL_EFAULT_CACHE_SIZE];
};
extern struct shm_s *shm;
extern unsigned int shm_size;

/*
 * Low-bit ticket the CLONE_NEWNET throttle stamps onto rec->post_state
 * after a successful admission.  clone3 packs the args pointer in the
 * high bits of post_state; zmalloc returns >=8-byte-aligned pointers,
 * so bit 0 is free.  unshare and clone leave the rest of post_state as
 * zero, so the same bit overlays cleanly there too.
 */
#define NEWNET_INFLIGHT_TICKET	0x1UL

/*
 * Single-CAS admission for the CLONE_NEWNET throttle.  Returns true if
 * the caller now owns one ticket against shm->newnet_in_flight; the
 * caller MUST stamp NEWNET_INFLIGHT_TICKET onto rec->post_state and
 * release with release_newnet_ticket() from the post hook.  Returns
 * false if the cap is full -- caller strips CLONE_NEWNET and bumps the
 * throttled stat.
 *
 * A relaxed load followed by a separate __atomic_fetch_add() (the
 * shape these three call sites used to share) lets several callers
 * all observe the counter below the cap then all increment, over-
 * admitting by an entire wave.  CAS closes that window: the
 * increment only commits if the value we tested against is still
 * what we read.
 *
 * Unconditional fetch-add + rollback is not equivalent -- the
 * transient over-admission still feeds copy_net_ns() and is the whole
 * thing the cap exists to prevent.
 */
static inline bool try_admit_newnet(void)
{
	int old = __atomic_load_n(&shm->newnet_in_flight, __ATOMIC_RELAXED);

	while (old < MAX_CONCURRENT_NEWNET) {
		if (__atomic_compare_exchange_n(&shm->newnet_in_flight,
						&old, old + 1,
						false,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return true;
		/* CAS failure refreshed `old` with the witnessed value;
		 * loop re-checks the cap against the fresh observation. */
	}
	return false;
}

/*
 * Single-RMW ticket release.  Atomically clears NEWNET_INFLIGHT_TICKET
 * on rec->post_state and decrements shm->newnet_in_flight iff the bit
 * was set on entry.  Idempotent: a second caller racing in observes
 * the bit already cleared and skips the decrement.
 *
 * The race this guards against is raw clone()/clone3(): the kernel
 * returns in both the calling task and the newly created one, the
 * syscallrecord lives in shared memory (children[] -> alloc_shared),
 * and both branches run the post hook against the same post_state.
 * A plain check-then-clear-then-decrement lets both branches decrement
 * for one admission, drifting the counter toward negative and
 * permanently disabling the cap.
 *
 * post_state for clone3 carries the args pointer in the high bits;
 * fetch_and(~NEWNET_INFLIGHT_TICKET) clears only bit 0 and leaves
 * the pointer intact for the post handler's downstream
 * deferred_freeptr().
 */
static inline void release_newnet_ticket(struct syscallrecord *rec)
{
	unsigned long old = __atomic_fetch_and(&rec->post_state,
					       ~NEWNET_INFLIGHT_TICKET,
					       __ATOMIC_RELAXED);

	if (old & NEWNET_INFLIGHT_TICKET)
		__atomic_fetch_sub(&shm->newnet_in_flight, 1,
				   __ATOMIC_RELAXED);
}

/*
 * Global pointer to the children array.  Lives in normal data segment
 * (NOT in shm), so each forked process gets its own COW copy.  A stray
 * child write to this pointer corrupts only that one child's copy and
 * cannot zero out the pointer for parent or siblings.  The pointed-to
 * array is mprotected PROT_READ in init_shm() so its contents are
 * also protected.
 */
extern struct childdata **children;

/*
 * Length of each per-child childdata mapping in bytes.  Set once by
 * init_shm_per_child_rings() to sizeof(struct childdata) rounded up
 * to a page multiple, so freeze_sibling_childdata's mprotect() call
 * covers exactly the span the mapping owns.  Kept in the parent's
 * data segment (inherited COW-per-child) so a wild write to the
 * variable in one child cannot perturb another child's freeze length.
 */
extern size_t childdata_mapping_len;

/*
 * Canary copy of each child's fd_event_ring pointer, taken at init time
 * so wild-write damage to the per-child ring pointer can be detected.
 * fd_event_drain_all() compares the live pointer against this array;
 * a mismatch means the pointer was overwritten after init, and we use
 * the known-good value to keep draining while logging the incident.
 */
extern struct fd_event_ring **expected_fd_event_rings;

/*
 * Canary copy of each child's stats_ring pointer, taken at init time so
 * wild-write damage to the per-child ring pointer can be detected.
 * stats_ring_drain_all() compares the live pointer against this array;
 * a mismatch means the pointer was overwritten after init, and we use
 * the known-good value to keep draining while logging the incident.
 */
extern struct stats_ring **expected_stats_rings;
