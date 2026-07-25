/*
 * Per-child freeze phase: mprotect the shared regions this child must
 * not scribble (sibling childdata + pids[] + stats mirror), then
 * rendezvous with the parent, seed the child PRNG, bring up per-child
 * object pools (OBJ_LOCAL list, cloned OBJ_GLOBAL snapshot, mappings,
 * futexes, dirty mapping), and optionally pin the child to a CPU.
 * Split out of child-init.c so make -j can compile the freeze /
 * rendezvous path concurrently with the sandbox / runtime setup
 * helpers.
 *
 * bind_child_to_cpu stays static -- only init_child_rendezvous_parent
 * calls it and both live here.  freeze_sibling_childdata was already
 * exposed via include/child-internal.h (the loop-top catch-up sweep
 * in child.c calls across the TU boundary).  init_child_freeze_shared
 * and init_child_rendezvous_parent shed their static linkage so
 * init_child (in child-init-core.c) can call them; declarations
 * added to include/child-internal.h.
 */

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "child-internal.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "rnd.h"
#include "self_cgroup.h"
#include "shm.h"
#include "signals.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "trinity.h"	// ARRAY_SIZE
#include "writer-watch.h"
#include "uid.h"
#include "utils.h"	// zmalloc

#include "kernel/sched.h"

static void bind_child_to_cpu(struct childdata *child, int childno)
{
	cpu_set_t set;
	unsigned int cpudest;
	pid_t pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	if (no_bind_to_cpu == true)
		return;

	if (sched_getaffinity(pid, sizeof(set), &set) != 0)
		return;

	if (child->num >= num_online_cpus)
		cpudest = child->num % num_online_cpus;
	else
		cpudest = child->num;

	CPU_ZERO(&set);
	CPU_SET(cpudest, &set);
	sched_setaffinity(pid, sizeof(set), &set);
}

/*
 * Mprotect every sibling's childdata to PROT_READ in our address space.
 *
 * Called from init_child for the initial sweep, and from the top of the
 * child_process loop as a catch-up sweep when shm->sibling_freeze_gen
 * has bumped (a new sibling joined since we last ran).  Idempotent:
 * mprotect on an already-PROT_READ region is a cheap no-op for slots
 * that haven't changed protection.
 *
 * Uses my_childno (caller's stack value) rather than child->num so a
 * sibling's stray write that corrupted our own num field can't trick
 * us into mprotecting our own region and then SIGSEGV'ing on the next
 * write.
 *
 * mprotect can return -ENOMEM if the kernel runs out of VMA slots
 * splitting the mapping that covers a sibling's childdata.  Best-effort
 * hardening — count the failure and keep going rather than aborting,
 * which would turn a transient kernel limit into a fleet-wide outage.
 */
void freeze_sibling_childdata(int my_childno)
{
	unsigned int i;
	size_t len = childdata_mapping_len;

	/*
	 * childdata_mapping_len is stamped by init_shm_per_child_rings()
	 * during parent init, before any child forks -- a zero here means
	 * a caller reached this site before init_shm ran, which is a
	 * setup bug rather than a runtime condition.  Refuse to mprotect
	 * a zero span: the kernel would round it up to the containing
	 * page, but mprotect(len=0) is a documented no-op that would
	 * silently leave the freeze off (the same failure mode the
	 * end-aligned pointer bug had) instead of loudly flagging it.
	 */
	if (len == 0) {
		outputerr("freeze_sibling_childdata: childdata_mapping_len uninitialised\n");
		__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	for_each_child(i) {
		if ((unsigned int)my_childno == i)
			continue;
		if (children[i] == NULL)
			continue;
#ifdef CONFIG_GUARD_SHARED
		/*
		 * Investigation hook: warn if this internal protect's
		 * range happens to overlap a registered kcov buffer.  An
		 * internal-mprotect path that strips a kcov buffer's
		 * PROT_WRITE is a distinct mechanism for the trace_buf
		 * reset-fault from the externally-fuzzed mm-sanitiser
		 * route, and the spec calls this site out explicitly.
		 */
		internal_mprotect_audit_kcov("freeze_sibling_childdata",
			(unsigned long)children[i],
			len, PROT_READ);
#endif
		if (mprotect(children[i], len, PROT_READ) != 0) {
			int saved_errno = errno;

			/*
			 * Route through the shared mprotect-failure logger so
			 * the resolved caller PC lands in the same format as
			 * every other internal mprotect failure -- the prior
			 * bare-outputerr line was too easy to lose in the
			 * fleet log stream and hid the persistent EINVAL
			 * cluster that came from the end-aligned childdata
			 * pointer.  Keep the counter bump for the stats view
			 * that surfaces the failure rate over time.
			 */
			log_mprotect_failure(children[i], len, PROT_READ,
					     __builtin_return_address(0),
					     saved_errno);
			outputerr("freeze_sibling_childdata: mprotect(sibling %u childdata, %zu) failed: %s\n",
				  i, len, strerror(saved_errno));
			__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

/*
 * Freeze the shared-memory regions this child relies on so that a
 * sibling's stray kernel-side write can't scribble them mid-run.
 * Four PROT_READ pulls, each independently justified by its
 * inline comment:
 *
 *   - the per-sibling childdata regions (initial sweep + freeze_gen
 *     bump so existing siblings re-sweep on their next loop top
 *     check),
 *   - the shared pids[] array (a single allocation that doesn't
 *     grow, hence the one-shot mprotect here rather than the
 *     per-loop catch-up),
 *   - the stats published mirror.
 *
 * Also re-publishes child->num from the stack-based childno before
 * the freeze so the freeze itself observes a known-good num field.
 */
void init_child_freeze_shared(struct childdata *child, int childno)
{
	unsigned int new_gen;

	/* Re-set num from the stack-based childno in case shared memory
	 * was corrupted by a sibling's stray write. */
	child->num = childno;

	/* Initial sibling-childdata freeze.  See freeze_sibling_childdata
	 * for the per-mprotect rationale.  After it returns we publish a
	 * fresh sibling_freeze_gen so existing siblings refreeze on their
	 * next loop top check and pull our own region into PROT_READ —
	 * closing the startup-race window where a faster sibling's value-
	 * result kernel write could land in our not-yet-frozen childdata.
	 *
	 * RELEASE on the bump pairs with the ACQUIRE load on the loop top
	 * check so any sibling that observes the new gen also observes the
	 * children[] entries this child relies on.  Cache last_seen with
	 * the just-bumped value so we don't immediately self-trigger a
	 * refreeze on our first loop iteration. */
	freeze_sibling_childdata(childno);
	new_gen = __atomic_add_fetch(&shm->sibling_freeze_gen, 1, __ATOMIC_RELEASE);
	child->last_seen_freeze_gen = new_gen;

	/* Same rationale for the shared pids[] array: a stray sibling write
	 * into pids[] could spoof a child's pid, breaking pid_alive() / the
	 * watchdog reaper.  Done here (not in freeze_sibling_childdata)
	 * because pids[] is a single allocation that doesn't grow — one
	 * mprotect at init time is enough; the per-loop refreeze path only
	 * needs to chase newly-spawned childdata regions. */
#ifdef CONFIG_GUARD_SHARED
	internal_mprotect_audit_kcov("init_child:pids",
		(unsigned long)pids, max_children * sizeof(*pids), PROT_READ);
#endif
	if (mprotect(pids, max_children * sizeof(*pids), PROT_READ) != 0) {
		int saved_errno = errno;

		log_mprotect_failure(pids, max_children * sizeof(*pids), PROT_READ,
				     __builtin_return_address(0), saved_errno);
		outputerr("init_child: mprotect(pids[]) failed: %s\n", strerror(saved_errno));
		__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
				   __ATOMIC_RELAXED);
	}

	/* Same shape for the shm_published stats mirror: children read
	 * fleet_op_count off it on the cold path (maybe_rotate_strategy()'s
	 * rotation clock, syscalls_todo termination); the parent's
	 * stats_publish_locked() inside stats_ring_drain_all() is the
	 * sole writer.  The integrity check in shm_is_corrupt() already
	 * documents the PROT_READ contract, but the matching mprotect()
	 * call was missing -- a wild kernel write through a fuzzed syscall
	 * arg pointer could scribble fleet_op_count between publishes and
	 * perturb rotation / termination behavior. */
	stats_published_freeze();
}

/*
 * Synchronise with the parent and bring up this child's private
 * per-process state.  Two phases bundled here because they share
 * the same precondition (the parent must have published our pid in
 * pids[childno]) and the same liveness requirement (no
 * outputerr-able path -- stderr is already /dev/null at this
 * point):
 *
 *   - Block until the parent stamps pids[childno] = our pid,
 *     panicking via the shm survivor counter if the parent dies
 *     under us.
 *   - Once the rendezvous resolves, cache our (childno, pid, child)
 *     in the this_child fast path, seed the child PRNG, and bring
 *     up the per-child object pools (OBJ_LOCAL list, cloned
 *     OBJ_GLOBAL snapshot, mappings, futexes, dirty mapping,
 *     optional CPU pin).
 *
 * The local pid migrates into this helper -- it has no consumer
 * outside this section, and getpid() is invariant within a
 * process lifetime, so the call-site move is semantically a no-op.
 */
void init_child_rendezvous_parent(struct childdata *child, int childno)
{
	pid_t pid = getpid();

	/* Wait for parent to set our childno */
	while (__atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE) != pid) {
		sched_yield();
		/* Make sure parent is actually alive to wait for us.
		 * stderr was redirected to /dev/null at the top of this
		 * function, so an outputerr here would be lost -- bump a
		 * survivor counter in shm instead so a post-mortem reader
		 * can tell this path actually fired. */
		if (pid_alive(mainpid) == false) {
			__atomic_add_fetch(&shm->stats.diag.child_dead_parent_observed,
					   1, __ATOMIC_RELAXED);
			panic(EXIT_SHM_CORRUPTION);
			_exit(EXIT_SHM_CORRUPTION);
		}
	}

	/* Cache our childno/pid for O(1) lookups in this_child()/find_childno().
	 * Pass the child pointer directly — don't re-derive it from
	 * children[] which sits in mprotected shared memory but accessing
	 * via the cached argument avoids the indirection on the hot path. */
	set_child_cache(childno, pid, child);

	set_seed(child);

	init_object_lists(OBJ_LOCAL, child);

	/*
	 * Take the fork-time snapshot of the parent's OBJ_GLOBAL pool into
	 * this child's private heap before any caller below resolves an
	 * OBJ_GLOBAL objhead (init_child_mappings walks OBJ_MMAP_ANON,
	 * init_child_futexes walks OBJ_FUTEX).  Subsequent get_objhead()
	 * calls in this child return the local copy.
	 */
	clone_global_objects_to_child(child);

	init_child_mappings();
	init_child_futexes();

	dirty_random_mapping();

	if (RAND_BOOL())
		bind_child_to_cpu(child, childno);
}
