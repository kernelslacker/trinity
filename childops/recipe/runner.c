/*
 * recipe_runner - resource-threaded multi-syscall sequences.
 *
 * Trinity picks syscalls independently, so deep kernel object states
 * (a socket in LISTEN with sockopts applied; a memfd written, ftruncated,
 * mmap'd, and sealed; a timerfd configured then read) are unreachable
 * via random isolated calls.  Most of the interesting UAF and refcount
 * bugs sit on the teardown path of an object that's been driven through
 * a specific construction sequence first; random independent calls never
 * reach the precondition.
 *
 * Each recipe is a small DAG: a syscall produces a resource (fd, key,
 * timer id), subsequent syscalls in the recipe consume it, and a
 * teardown step releases it.  Every code path — success, intermediate
 * failure, structural failure — converges on a single goto-cleanup
 * exit so we never leak fds and undo the FD-exhaustion fix.
 *
 * Recipe arg construction is intentionally inline and simple (NULL
 * pointers, page_size for buffers, sensible flags) rather than feeding
 * through trinity's sanitise/random_syscall machinery.  The point of a
 * recipe is the sequence, not argument fuzz; mixing the two would
 * pollute state and trigger errors before we ever reach the
 * interesting transitions.  Argument fuzzing remains the job of the
 * default CHILD_OP_SYSCALL path.
 */

#include <stdbool.h>
#include <stdint.h>

#include "child.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "childops/recipe/internal.h"

/*
 * A discoverable recipe sets *unsupported = true on its first failed
 * probe to indicate the kernel lacks the relevant feature (ENOSYS,
 * missing CONFIG_*, etc.).  The dispatcher latches the recipe off in
 * shm so siblings stop probing.  Non-discoverable recipes leave the
 * pointer NULL.
 */
struct recipe {
	const char *name;
	bool (*run)(bool *unsupported);
};

static const struct recipe recipes[] = {
	{ "timerfd",      recipe_timerfd      },
	{ "eventfd",      recipe_eventfd      },
	{ "pipe",         recipe_pipe         },
	{ "epoll",        recipe_epoll        },
	{ "signalfd",     recipe_signalfd     },
	{ "memfd_seal",   recipe_memfd_seal   },
	{ "tcp_server",   recipe_tcp_server   },
	{ "inotify",      recipe_inotify      },
	{ "shmget",       recipe_shmget       },
	{ "msgget",       recipe_msgget       },
	{ "semget",       recipe_semget       },
	{ "posix_timer",  recipe_posix_timer  },
	{ "mq_open",      recipe_mq_open      },
	{ "futex",        recipe_futex        },
	{ "fanotify",     recipe_fanotify     },
	{ "userfaultfd",  recipe_userfaultfd  },
	{ "vfs_leases",   recipe_vfs_leases   },
	{ "mm_vma",       recipe_mm_vma       },
	{ "mm_memfd",     recipe_mm_memfd     },
	{ "net_unix_gc",  recipe_net_unix_gc  },
	{ "net_tcp",      recipe_net_tcp      },
	{ "net_unix_oob", recipe_net_unix_oob },
	{ "net_raw",      recipe_net_raw      },
	{ "fsnotify_xwatch", recipe_fsnotify_xwatch },
	{ "uffd_wp",      recipe_uffd_wp      },
	{ "timerfd_xclose", recipe_timerfd_xclose },
	{ "signalfd_delivery", recipe_signalfd_delivery },
	{ "epoll_xclose", recipe_epoll_xclose },
	{ "iouring_fixed_uaf", recipe_iouring_fixed_uaf },
	{ "bpf_htab_iter_del", recipe_bpf_htab_iter_del },
	{ "perf_mmap_close", recipe_perf_mmap_close },
	{ "keys_revoke_race", recipe_keys_revoke_race },
	{ "ptrace_seize_exitkill", recipe_ptrace_seize_exitkill },
	{ "mount_userns_dance", recipe_mount_userns_dance },
	{ "seccomp_listener_exec", recipe_seccomp_listener_exec },
	{ "cgroup_kill_events", recipe_cgroup_kill_events },
};

/*
 * Build-time guarantee that the catalog fits in the shm bookkeeping
 * arrays sized via MAX_RECIPES in stats.h.  Bumping the catalog past
 * MAX_RECIPES without growing the arrays would silently overflow
 * shm->recipe_disabled and shm->stats.recipe.completed_per.
 */
_Static_assert(ARRAY_SIZE(recipes) <= MAX_RECIPES,
	       "recipe catalog outgrew MAX_RECIPES; bump it in stats.h");

bool recipe_runner(struct childdata *child)
{
	const struct recipe *r;
	unsigned int idx;
	unsigned int tries;
	bool unsupported = false;
	bool ok;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.recipe.runs, 1, __ATOMIC_RELAXED);

	/* Pick a recipe that hasn't been latched off.  A few retries are
	 * enough — even if every discovery-probe recipe is disabled, at
	 * worst one in four picks will land on a non-discoverable one. */
	for (tries = 0; tries < 8; tries++) {
		idx = rnd_modulo_u32((unsigned int)ARRAY_SIZE(recipes));
		if (!__atomic_load_n(&shm->recipe_disabled[idx],
				     __ATOMIC_RELAXED))
			break;
	}
	if (tries == 8)
		return true;	/* nothing runnable on this kernel */

	r = &recipes[idx];

	/* Setup gate passed: a runnable recipe was selected and the
	 * dispatcher is committed to invoking it.  Bump setup_accepted
	 * before data_path so the invariant data_path <= setup_accepted
	 * holds at every observation point; no bail path runs between
	 * the two bumps here. */
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* Publish the active recipe name so post-mortem can attribute a
	 * kernel taint to the sequence in flight.  Cleared on completion
	 * regardless of success/failure so a stale name never lingers. */
	child->current_recipe_name = r->name;
	ok = r->run(&unsupported);
	child->current_recipe_name = NULL;

	if (unsupported)
		__atomic_store_n(&shm->recipe_disabled[idx], true,
				 __ATOMIC_RELAXED);

	if (ok) {
		__atomic_add_fetch(&shm->stats.recipe.completed, 1,
				   __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.recipe.completed_per[idx], 1,
				   __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.recipe.partial, 1,
				   __ATOMIC_RELAXED);
	}

	return true;
}

/*
 * Emit per-recipe completion counts and, where applicable, the
 * latched-disabled state.  Called from dump_stats() so the catalog
 * layout stays private to this file.
 */
void __cold recipe_runner_dump_stats(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(recipes); i++) {
		unsigned long n = __atomic_load_n(
			&shm->stats.recipe.completed_per[i],
			__ATOMIC_RELAXED);
		bool disabled = __atomic_load_n(
			&shm->recipe_disabled[i],
			__ATOMIC_RELAXED);

		if (n == 0 && !disabled)
			continue;

		output(0, "  %-14s %lu%s\n", /* check-static: child-output-ok */
			recipes[i].name, n,
			disabled ? " (disabled — kernel feature absent)" : "");
	}
}
