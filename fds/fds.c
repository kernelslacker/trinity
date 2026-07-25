#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "fd.h"
#include "fd-event.h"
#include "fds-internal.h"
#include "list.h"
#include "net.h"
#include "object-types.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"
#include "utils.h"

/*
 * Map fd → owning fd_provider.  Consults the fork-time OBJ_GLOBAL
 * fd_hash first, then the calling child's OBJ_LOCAL pools so fds
 * created post-fork by providers that publish into OBJ_LOCAL
 * (kvm-vcpu, kvm-vm, io_uring, userfaultfd, pidfd, seccomp-notif, ...)
 * resolve to their provider — those never enter fd_hash, and
 * fd_poll_can_block() used to answer false for their poll-blocking
 * fds, letting the epoll/poll/select sanitisers admit them into
 * watch sets.  Returns NULL for untracked fds and for tracked fds
 * whose objtype does not match any registered provider.
 */
static struct fd_provider *fd_lookup_provider(int fd)
{
	struct fd_hash_entry *e;
	struct list_head *node;
	enum objecttype type;

	e = fd_hash_lookup(fd);
	if (e != NULL) {
		type = e->type;
	} else {
		struct object *lobj = local_fd_find_by_fd(fd);

		if (lobj == NULL)
			return NULL;
		type = lobj->obj_type;
	}

	if (fd_providers == NULL)
		return NULL;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (provider->objtype == type)
			return provider;
	}
	return NULL;
}

bool fd_poll_can_block(int fd)
{
	struct fd_provider *provider;

	if (fd < 0)
		return false;

	provider = fd_lookup_provider(fd);
	if (provider == NULL)
		return false;
	return provider->poll_can_block;
}

/*
 * Call child_ops for all initialized fd providers that have one.
 * Invoked periodically from the child process to exercise fd-level
 * operations (bind/listen/accept etc.) as fuzzing actions.
 *
 * After the child_ops walk, invite ->try_replenish opt-ins to top up
 * their pools.  Keeping the two dispatchers coupled avoids adding a
 * second periodic-work callsite in child.c -- the replenish walk is
 * cheaper than the child_ops walk (self-gated on rate and per-provider
 * pool depth) and is fine to piggyback here.
 */
void run_fd_provider_child_ops(void)
{
	struct list_head *node;

	if (fd_providers == NULL)
		return;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (provider->initialized && provider->child_ops != NULL)
			provider->child_ops();
	}

	run_fd_provider_replenish(2);
}

void run_fd_provider_child_init(struct childdata *child)
{
	struct list_head *node;

	if (fd_providers == NULL)
		return;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (provider->initialized && provider->child_init != NULL)
			provider->child_init(child);
	}
}

/*
 * Dispatcher cap: the maximum number of providers touched per replenish
 * tick.  Each provider issues create-syscalls to open the new fds, so a
 * larger cap trades fuzz-budget cycles for pool depth.  Three lets the
 * (currently ~4) opted-in providers all get service every couple of
 * dispatcher ticks without ever bursting more than ~6 create-syscalls
 * (3 providers * 2 budget) in a single periodic-work pass.
 */
#define REPLENISH_MAX_PROVIDERS_PER_TICK	3

void run_fd_provider_replenish(unsigned int per_provider_budget)
{
	struct list_head *node;
	unsigned int providers_touched = 0;

	if (fd_providers == NULL)
		return;

	/*
	 * Coarse rate-limit gate.  run_fd_provider_child_ops() itself is
	 * only entered every 128 child-loop iterations from periodic_work,
	 * so this halves the effective replenish cadence again to ~1 tick
	 * in 512 child ops.  Replenish issues create syscalls (epoll_create1,
	 * eventfd, fanotify_init, ...) that compete with the fuzz budget --
	 * without the gate, the child-tick add-rate would dominate small
	 * -N runs and skew per-syscall coverage share.  Mask 3 fires ~1
	 * call in 4.
	 */
	if ((rnd_u32() & 3U) != 0U)
		return;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (!provider->initialized || provider->try_replenish == NULL)
			continue;

		provider->try_replenish(per_provider_budget);

		if (++providers_touched >= REPLENISH_MAX_PROVIDERS_PER_TICK)
			break;
	}
}

