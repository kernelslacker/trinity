#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "fd.h"
#include "fd-event.h"
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

static unsigned int num_fd_providers;			// num in list.
static unsigned int num_fd_providers_to_enable = 0;	// num of --fd-enable= params
static unsigned int num_fd_providers_enabled = 0;	// final num we enabled.
static unsigned int num_fd_providers_initialized = 0;	// num we called ->init on
static bool enable_fd_initialized = false;		// initialized (disabled all) fd providers
static bool disable_fd_used = false;			// --disable-fds was passed

static struct fd_provider *fd_providers = NULL;

/* Array of enabled+initialized providers for O(1) random selection. */
static struct fd_provider **active_providers = NULL;
static unsigned int num_active_providers = 0;

/*
 * Per-init failure-reason slot.  __open_fds() resets these immediately
 * before calling provider->init(); on a false return it logs whichever
 * reason the provider stamped via fd_provider_init_fail().  A provider
 * that returns false without calling the helper leaves the slot at
 * FD_INIT_REASON_NONE and the dispatcher falls back to the bare
 * "Error during initialization of <name>" line.
 */
static enum fd_init_reason last_init_reason;
static int last_init_errno;
static char last_init_detail[128];

void fd_provider_init_fail(enum fd_init_reason reason, int captured_errno,
			   const char *detail)
{
	last_init_reason = reason;
	last_init_errno = captured_errno;
	if (detail != NULL) {
		strncpy(last_init_detail, detail, sizeof(last_init_detail) - 1);
		last_init_detail[sizeof(last_init_detail) - 1] = '\0';
	} else {
		last_init_detail[0] = '\0';
	}
}

const char *fd_init_reason_name(enum fd_init_reason r)
{
	switch (r) {
	case FD_INIT_REASON_NONE:		return "none";
	case FD_INIT_REASON_ERRNO:		return "errno";
	case FD_INIT_REASON_CONFIG_ABSENT:	return "config-absent";
	case FD_INIT_REASON_CAP_MISSING:	return "cap-missing";
	case FD_INIT_REASON_RESOURCE:		return "resource";
	}
	return "unknown";
}

/*
 * This is called by the REG_FD_PROV constructors on startup.
 * Because of this, this function shouldn't rely on anything
 * already existing/being initialized.
 */
void register_fd_provider(const struct fd_provider *prov)
{
	struct fd_provider *newnode;

	if (fd_providers == NULL) {
		fd_providers = zmalloc(sizeof(struct fd_provider));
		INIT_LIST_HEAD(&fd_providers->list);
	}
	newnode = zmalloc(sizeof(struct fd_provider));
	newnode->name = strdup(prov->name);
	if (!newnode->name) {
		free(newnode);
		return;
	}
	newnode->objtype = prov->objtype;
	newnode->enabled = prov->enabled;
	newnode->init = prov->init;
	newnode->get = prov->get;
	newnode->child_init = prov->child_init;
	newnode->child_ops = prov->child_ops;
	newnode->try_replenish = prov->try_replenish;
	newnode->poll_can_block = prov->poll_can_block;
	num_fd_providers++;

	list_add_tail(&newnode->list, &fd_providers->list);
}

/*
 * Return the registered fd_provider name whose objtype matches @type,
 * or NULL if no provider was registered with that objtype.  Surfaces
 * the provider→name mapping to dump_stats() so the per-provider
 * outstanding-fd gauge in shm->stats can be labelled without
 * exposing the provider list itself.
 */
const char *fd_provider_name(enum objecttype type)
{
	struct list_head *node;

	if (fd_providers == NULL)
		return NULL;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (provider->objtype == type)
			return provider->name;
	}
	return NULL;
}

/*
 * Print the names of all registered fd providers as a comma-separated
 * list, for use in --enable-fds/--disable-fds help output.
 */
void dump_fd_provider_names(void)
{
	struct list_head *node;
	bool first = true;

	if (fd_providers == NULL)
		return;

	outputerr(" --enable-fds/--disable-fds= {");
	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (!first)
			outputerr(",");
		outputerr("%s", provider->name);
		first = false;
	}
	outputerr("}\n");
}

static void __open_fds(bool do_rand)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;

		/* disabled on cmdline */
		if (provider->enabled == false)
			continue;

		/* already done */
		if (provider->initialized == true)
			continue;

		if (do_rand == true) {
			/* to mix up init order */
			if (RAND_BOOL())
				continue;
		}

		/* Print before calling so a stall inside provider->init() is
		 * pinned to the last-printed name.  Mirrors the existing
		 * "Initializing %s objects." line that init_global_objects()
		 * emits for REG_GLOBAL_OBJ entries. */
		output(1, "Initializing %s fds.\n", provider->name);
		last_init_reason = FD_INIT_REASON_NONE;
		last_init_errno = 0;
		last_init_detail[0] = '\0';
		provider->enabled = provider->init();
		if (provider->enabled == true) {
			provider->initialized = true;
			num_fd_providers_initialized++;
			num_fd_providers_enabled++;
		} else {
			if (last_init_reason != FD_INIT_REASON_NONE)
				outputstd("Error during initialization of %s: reason=%s errno=%d (%s) detail=%s\n",
					provider->name,
					fd_init_reason_name(last_init_reason),
					last_init_errno,
					last_init_errno != 0 ? strerror(last_init_errno) : "-",
					last_init_detail[0] != '\0' ? last_init_detail : "-");
			else
				outputstd("Error during initialization of %s\n", provider->name);
			if (num_fd_providers_to_enable > 0)
				num_fd_providers_to_enable--;
		}
	}
}

bool open_fds(void)
{
	struct list_head *node;

	/* Open half the providers randomly */
	while (num_fd_providers_initialized < (num_fd_providers_to_enable / 2))
		__open_fds(true);

	/* Now open any leftovers */
	__open_fds(false);

	/* Build array of active providers for O(1) random selection. */
	active_providers = zmalloc((num_fd_providers_enabled > 0 ? num_fd_providers_enabled : 1) *
				   sizeof(struct fd_provider *));
	num_active_providers = 0;
	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider = (struct fd_provider *) node;

		if (provider->enabled && provider->initialized)
			active_providers[num_active_providers++] = provider;
	}

	output(0, "Enabled %d/%d fd providers. initialized:%d.\n",
		num_fd_providers_enabled, num_fd_providers, num_fd_providers_initialized);

	/*
	 * Per-provider initial pool size.  Pools populate once here at
	 * init and only drain afterwards -- no provider has a runtime
	 * replenish hook -- so this is the entire lifetime budget for
	 * each pool.  Logging it once at startup makes runtime depletion
	 * (sustained -1 returns from get_new_random_fd, fd_random_exhausted
	 * bumps) interpretable: a provider that started with 8 entries
	 * was always going to bottom out fast under fd-stress / close /
	 * dup2-replace churn, where a provider that started with 50+
	 * survives much longer.
	 */
	{
		unsigned int j;

		for (j = 0; j < num_active_providers; j++) {
			struct fd_provider *prov = active_providers[j];
			struct objhead *head;

			if (prov == NULL)
				continue;
			head = get_objhead(OBJ_GLOBAL, prov->objtype);
			output(0, "fd_provider init pool size: %s = %u\n",
			       prov->name,
			       head != NULL ? head->num_entries : 0);
		}
	}

	return num_fd_providers_enabled > 0;
}

int get_new_random_fd(void)
{
	struct fd_provider *provider;
	struct fd_provider *populated[MAX_OBJECT_TYPES];
	unsigned int npop = 0;
	unsigned int retries = 0;
	unsigned int i;
	int fd;

	if (num_active_providers == 0)
		return -1;

	/*
	 * Pre-filter to providers whose OBJ_GLOBAL pool is currently
	 * non-empty.  Without this, uniform random selection across all
	 * active providers wastes draws on syscall-populated pools that
	 * are momentarily empty (sockets, eventfd, timerfd, memfd, pipes,
	 * ...): each empty draw returns -1, which used to bail this
	 * function immediately (the historic `fd >= 0 && fd <= 2` check
	 * silently fell through for fd == -1) and burned a full outer
	 * regen in get_random_fd().  With ~30+ providers and many often
	 * empty under load, the outer 64-retry budget was hitting
	 * exhaustion hundreds of times per child -- each exhaustion
	 * surfaces to the kernel as EBADF, wasting fd-arg syscalls that
	 * should have hit real kernel fd paths and produced coverage.
	 *
	 * The NULL/->get-NULL slot guard is preserved by skipping such
	 * slots here; the canary stat still fires once per scan-detected
	 * invalid entry instead of once per random draw.
	 *
	 * objects_empty() is an O(1) read of head->num_entries -- racy
	 * vs. concurrent updates but only transiently so; worst case we
	 * skip a provider that just got populated, or include one that
	 * just emptied (the inner retry covers the latter).
	 */
	for (i = 0; i < num_active_providers; i++) {
		provider = active_providers[i];
		if (provider == NULL || provider->get == NULL) {
			__atomic_add_fetch(&shm->stats.fd.provider_invalid, 1,
					   __ATOMIC_RELAXED);
			continue;
		}
		if (objects_empty(provider->objtype))
			continue;
		populated[npop++] = provider;
	}

	if (npop == 0)
		return -1;

retry:
	provider = populated[rnd_modulo_u32(npop)];
	fd = provider->get();
	/*
	 * fd <= 2 covers both stdin/stdout/stderr draws and the
	 * transient -1 a provider can hand back when its internal slot
	 * pick loses a race (e.g. fds/eventfd.c's 1000-iter objpool_check
	 * loop bottoms out, OBJ_GLOBAL slot recycle, ...).  Reroll within
	 * the inner budget instead of letting -1 escape to the outer
	 * regen and burn a budgeted retry.
	 */
	if (fd <= 2) {
		if (++retries < 10)
			goto retry;
		return -1;
	}
	return fd;
}

/*
 * Outer-loop retry budget for get_random_fd().  Each iteration of
 * `regen:` re-runs get_new_random_fd() (itself bounded to 10 inner
 * sub-retries) plus the fd_hash_lookup recovery path.  If we still
 * cannot produce a usable fd (>2, tracked-or-over-budget) after this
 * many outer iterations, bail and return -1.  Callers cast the result
 * to unsigned long and pass it as a syscall arg, so an outer-budget
 * bail surfaces to the kernel as EBADF — same handling already in
 * place for the existing -1/<=2 returns.
 *
 * get_new_random_fd() itself has two distinct paths that can return
 * -1, both of which feed back into this outer regen loop:
 *   (1) the populated-provider list is empty — no providers are
 *       active, or every active provider's OBJ_GLOBAL pool is
 *       currently empty/broken; and
 *   (2) the inner per-attempt retry budget (10 rerolls) is exhausted
 *       because every draw from the chosen provider came back <=2
 *       (stdin/stdout/stderr or a transient provider-side -1).
 * The bound below has to guard against either source, not just (1).
 *
 * Without this bound, either of those -1 sources — or a persistently
 * untracked return from get_new_random_fd() — can tight-loop in
 * argument generation.  Because the syscall record is still in PREP
 * at that point, the parent's progress check (which only acts from
 * BEFORE onward) does not consider the child stuck and will not kill
 * it, so a single child can burn a CPU indefinitely.
 */
#define GET_RANDOM_FD_BUDGET 64

int get_random_fd(void)
{
	struct childdata *child = this_child();
	unsigned int retries = 0;
	unsigned int outer_retries = 0;

	/* During init (no child context), skip fd_lifetime caching. */
	if (child == NULL)
		return get_new_random_fd();

	/*
	 * If our cached fd's slot has been mutated since we cached it
	 * (close, reopen, or simply emptied) the slot's generation will
	 * differ from what we recorded.  A NULL lookup also counts as
	 * stale — the fd was removed from tracking.
	 */
	if (child->fd_lifetime > 0) {
		struct fd_hash_entry *e = fd_hash_lookup(child->current_fd);

		if (e == NULL ||
		    __atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) !=
		    child->cached_fd_generation) {
			__atomic_add_fetch(&shm->stats.fd.stale_by_generation, 1,
					   __ATOMIC_RELAXED);
			child->fd_lifetime = 0;
		}
	}

	/* return the same fd as last time if we haven't over-used it yet. */
regen:
	{
		/*
		 * Once the outer has already churned through several passes
		 * without producing a usable fd, additional iterations at the
		 * full budget are unlikely to find new candidates — decay the
		 * effective bound so we bail out of the exhaustion cascade
		 * sooner instead of burning the full 64 sweeps.
		 */
		unsigned int effective_budget = GET_RANDOM_FD_BUDGET;

		if (outer_retries >= 4)
			effective_budget = GET_RANDOM_FD_BUDGET / 2;
		if (outer_retries >= 5)
			effective_budget = GET_RANDOM_FD_BUDGET / 4;

		if (outer_retries++ >= effective_budget) {
			__atomic_add_fetch(&shm->stats.fd.random_exhausted, 1,
					   __ATOMIC_RELAXED);
			outputerr("get_random_fd: outer retry budget (%u) exhausted, "
				  "returning -1\n", GET_RANDOM_FD_BUDGET);
			return -1;
		}
	}

	if (child->fd_lifetime == 0) {
		struct fd_hash_entry *e;

		child->current_fd = get_new_random_fd();

		/*
		 * get_new_random_fd() returns -1 only when every active
		 * provider's OBJ_GLOBAL pool is currently empty (or no
		 * providers are active).  Provider pools populate once at
		 * init via .init and only ever drain after that — no
		 * provider exposes a runtime .open replenish hook — so
		 * further outer iterations in this child will see the same
		 * state and burn the budget for no benefit.  Without this
		 * early-exit, every fd-arg syscall in a depleted-pool child
		 * spins the outer regen loop up to the decayed cap (16
		 * iterations under the existing decay), calls
		 * get_new_random_fd() each time only to get -1 again, and
		 * emits the post-budget "outer retry budget exhausted"
		 * outputerr — hundreds per child under sustained churn.
		 *
		 * Bail with the same exhaustion accounting the post-budget
		 * bail uses (same -1 contract to the caller, same EBADF
		 * surface in the kernel) but without the per-call log
		 * spam: when the pool is genuinely empty the message rate
		 * makes a healthy child indistinguishable from a stuck one
		 * and floods the bug log.  Persistent fd_random_exhausted
		 * remains the observable signal; the new pool-size dump in
		 * open_fds() makes the depletion timeline reproducible
		 * from a single run's log.
		 */
		if (child->current_fd < 0) {
			__atomic_add_fetch(&shm->stats.fd.random_exhausted, 1,
					   __ATOMIC_RELAXED);
			child->fd_lifetime = 0;
			return -1;
		}

		/*
		 * Cache the slot's generation so the next iteration can
		 * detect close-then-reopen-to-same-fd recycling without a
		 * syscall.  An untracked fd (e.g. a child-private fd not in
		 * the global pool) gets cached_fd_generation = 0; that won't
		 * match any real entry's gen, so the next iteration will
		 * always re-fetch.
		 */
		e = fd_hash_lookup(child->current_fd);
		if (e == NULL && child->current_fd >= 0 && retries++ < 10) {
			__atomic_add_fetch(&shm->stats.fd.stale_detected, 1,
					   __ATOMIC_RELAXED);
			goto regen;
		}
		child->cached_fd_generation = e ?
			__atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) : 0;

		if (max_children >= 5)
			child->fd_lifetime = RAND_RANGE(5U, max_children);
		else
			child->fd_lifetime = RAND_RANGE(1, 5);
	} else
		child->fd_lifetime--;

	if (child->current_fd <= 2) {
		child->fd_lifetime = 0;
		goto regen;
	}

	return child->current_fd;
}

/*
 * Return an fd of a specific type for syscalls that expect a particular
 * kind of fd (epoll, timerfd, socket, etc.).  Falls back to get_random_fd()
 * if no objects of that type exist.
 *
 * Validates the fd is still tracked by the parent via the fd_hash
 * lookup — a missing entry means the fd was closed (in another child or
 * by a cleanup path) and the object snapshot we got is stale.
 */
int get_typed_fd(enum argtype type)
{
	struct object *obj;
	enum objecttype objtype;
	int fd;
	unsigned int retries = 0;

	switch (type) {
	case ARG_FD_BPF_BTF:	objtype = OBJ_FD_BPF_BTF; break;
	case ARG_FD_BPF_LINK:	objtype = OBJ_FD_BPF_LINK; break;
	case ARG_FD_BPF_MAP:	objtype = OBJ_FD_BPF_MAP; break;
	case ARG_FD_BPF_PROG:	objtype = OBJ_FD_BPF_PROG; break;
	case ARG_FD_EPOLL:	objtype = OBJ_FD_EPOLL; break;
	case ARG_FD_EVENTFD:	objtype = OBJ_FD_EVENTFD; break;
	case ARG_FD_FANOTIFY:	objtype = OBJ_FD_FANOTIFY; break;
	case ARG_FD_FS_CTX:	objtype = OBJ_FD_FS_CTX; break;
	case ARG_FD_INOTIFY:	objtype = OBJ_FD_INOTIFY; break;
	case ARG_FD_IO_URING:	objtype = OBJ_FD_IO_URING; break;
	case ARG_FD_LANDLOCK:	objtype = OBJ_FD_LANDLOCK; break;
	case ARG_FD_MEMFD:	objtype = OBJ_FD_MEMFD; break;
	case ARG_FD_MOUNT:	objtype = OBJ_FD_MOUNT; break;
	case ARG_FD_MQ:		objtype = OBJ_FD_MQ; break;
	case ARG_FD_PERF:	objtype = OBJ_FD_PERF; break;
	case ARG_FD_PIDFD:	objtype = OBJ_FD_PIDFD; break;
	case ARG_FD_PIPE:	objtype = OBJ_FD_PIPE; break;
	case ARG_FD_SIGNALFD:	objtype = OBJ_FD_SIGNALFD; break;
	case ARG_FD_SOCKET:	objtype = OBJ_FD_SOCKET; break;
	case ARG_FD_TIMERFD:	objtype = OBJ_FD_TIMERFD; break;
	default:
		return get_random_fd();
	}

retry:
	if (retries >= 10)
		return get_random_fd();

	obj = get_random_object(objtype, OBJ_GLOBAL);
	if (obj == NULL)
		return get_random_fd();

	if (!objpool_check(obj, objtype)) {
		retries++;
		goto retry;
	}

	/*
	 * Lazy-arm epoll fds in child context.  arm_epoll() invokes
	 * epoll_ctl(EPOLL_CTL_ADD) on a fuzzer-controlled target_fd
	 * whose ->poll handler can block indefinitely (e.g. /dev/fuse
	 * waiting on its userspace daemon).  Doing this from the
	 * parent's main loop wedges the whole session because the
	 * watchdog cannot kill the parent; doing it from a child is
	 * recoverable via is_child_making_progress().  See the block
	 * comment above arm_epoll() in fds/epoll.c.
	 */
	if (objtype == OBJ_FD_EPOLL)
		arm_epoll_if_needed(&obj->epollobj);

	fd = fd_from_object(obj, objtype);
	if (fd < 0)
		return get_random_fd();

	/* Don't hand out stdin/stdout/stderr to syscalls. */
	if (fd <= 2)
		return get_random_fd();

	/*
	 * Validate fd is still tracked in this child's snapshot of the
	 * fd_hash.  A miss means the fd was closed (in this child) and
	 * the snapshot is stale; fall through to another pick.
	 */
	if (fd_hash_lookup(fd) == NULL) {
		__atomic_add_fetch(&shm->stats.fd.stale_detected, 1, __ATOMIC_RELAXED);
		retries++;
		goto retry;
	}

	return fd;
}

/*
 * Pick a random fd from the subset of fd_types whose backing kernel
 * file ops actually park the caller on a real wait queue: pipes,
 * eventfd, timerfd, signalfd, inotify, fanotify, and sockets.  These
 * are the fd shapes whose ->poll handlers feed poll(2)/select(2)
 * properly, as opposed to regular-file fds (which short-circuit to
 * POLLIN | POLLOUT) or random untracked fds (which are predominantly
 * non-pollable or closed).
 *
 * Each candidate fd_type is filtered through get_typed_fd(), which
 * already skips empty provider pools and falls back to get_random_fd()
 * if no object of the requested fd_type is available — so even on a
 * minimal startup configuration this never wedges.  Providers tagged
 * poll_can_block are excluded by construction: none of the listed
 * fd_types opt into that tag (FUSE/uffd/kvm/io_uring/pidfd/seccomp_notif
 * are kept out so the wait/wake codepath in do_sys_poll / do_select
 * actually gets to block).
 */
int get_pollable_random_fd(void)
{
	static const enum argtype pollable[] = {
		ARG_FD_PIPE,
		ARG_FD_EVENTFD,
		ARG_FD_TIMERFD,
		ARG_FD_SIGNALFD,
		ARG_FD_INOTIFY,
		ARG_FD_FANOTIFY,
		ARG_FD_SOCKET,
	};

	return get_typed_fd(pollable[rnd_modulo_u32(ARRAY_SIZE(pollable))]);
}

/*
 * Return a live fd from this child's recent-returns ring, or -1 if none
 * are available.  Validates each candidate with fcntl(F_GETFD) and
 * evicts stale entries (EBADF) inline to keep the ring clean.
 */
int get_child_live_fd(struct childdata *child)
{
	struct child_fd_ring *ring = &child->live_fds;
	unsigned int i, retries;

	for (retries = 0; retries < CHILD_FD_RING_SIZE; retries++) {
		i = rnd_modulo_u32(CHILD_FD_RING_SIZE);
		int fd = ring->fds[i];

		if (fd <= 2)
			continue;

		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
			ring->fds[i] = -1;
			continue;
		}

		return fd;
	}

	return -1;
}

/*
 * Protected-fd registry.  Argument generators for the close family
 * (close, dup2, dup3, close_range), the size-changing fd-arg sanitisers
 * (ftruncate / ftruncate64, fallocate, lseek / llseek, write / writev /
 * pwrite64 / pwritev / pwritev2 -- see reroll_protected_fd_arg()), and
 * the random-syscall chain-substitution path consult these predicates
 * to keep diagnostic and coverage fds out of the fuzz picker pool.
 * See the contract in include/fd.h.
 *
 * Two classes of fd live in this registry:
 *
 *   - the calling child's kcov PC fd and cmp fd, opened in
 *     kcov_init_child and re-located above KCOV_FD_HIGH_BASE so the
 *     low-slot ARG_FD pool never naturally hands them out -- but
 *     dup2's RAND_RANGE(rl.rlim_cur+1) and close_range's range walks
 *     can still reach them.  A successful close / dup2 over either
 *     slot silently disables coverage for the rest of the child's
 *     life (next ioctl(KCOV_ENABLE, ...) returns -ENOTTY).
 *
 *   - STDERR_FILENO and the in-memory stderr capture memfd installed
 *     by init_stderr_memfd.  The SIGABRT handler drains the memfd
 *     into the per-pid bug log via read(memfd, ...) + write(fd 2, ...);
 *     if either fd is clobbered by a fuzz close-family syscall before
 *     the handler runs, the buffered glibc malloc_printerr /
 *     __fortify_fail / __stack_chk_fail text is lost and the bug log
 *     bottoms out at the in-handler backtrace + siginfo with no
 *     pre-crash explanation.  The same memfd must also be kept out of
 *     size-changing syscall slots: a fuzz-induced ftruncate / fallocate /
 *     pwrite64 / lseek+write that extends the memfd to a multi-GB
 *     sparse size makes the bug-log drain materialise that range into
 *     the on-disk log on the next abort, swamping the host.
 *
 * Parent context (this_child() == NULL): STDERR_FILENO still matches
 * the constant check, but the parent never opens a kcov_child or a
 * stderr memfd, so those branches naturally fall through.  Parent-side
 * arg generation is rare and the conservative answer (treat fd 2 as
 * protected) is the right one regardless.
 *
 * The fd < 0 / hi < lo guards mirror the kernel-side validation order
 * the close-family syscalls themselves apply, so a sanitiser that
 * skipped its own bounds checks before consulting this registry would
 * still get a safe answer.
 */
bool fd_is_protected(int fd)
{
	struct childdata *child;
	int memfd;

	if (fd < 0)
		return false;
	if (fd == STDERR_FILENO)
		return true;
	memfd = trinity_stderr_memfd();
	if (memfd >= 0 && fd == memfd)
		return true;
	child = this_child();
	if (child == NULL)
		return false;
	if (child->kcov.fd >= 0 && fd == child->kcov.fd)
		return true;
	if (child->kcov.cmp_fd >= 0 && fd == child->kcov.cmp_fd)
		return true;
	return false;
}

/*
 * Bounds typed as unsigned int to mirror the kernel's close_range ABI:
 * the syscall takes (unsigned int first, unsigned int last) and walks
 * the fd table when first <= last as unsigned.  A signed int
 * comparison here treats rec->a2 == (unsigned long)-1 (the gen_arg_fd
 * exhaustion fallback, which surfaces to the kernel as 0xFFFFFFFF) as
 * a negative "hi", makes hi < lo true, and returns -1 -- skipping the
 * truncation that should have stopped the kernel-side walk before it
 * reached the kcov fd at KCOV_FD_HIGH_BASE.  All real protected fds
 * fit in int (STDERR_FILENO is 2; KCOV_FD_HIGH_BASE is 60000; the
 * stderr memfd is well below INT_MAX), so widening the comparison
 * operand to unsigned int doesn't shrink the range we cover.
 */
int lowest_protected_fd_in_range(unsigned int lo, unsigned int hi)
{
	struct childdata *child;
	int memfd;
	int lowest = -1;

	if (hi < lo)
		return -1;

	if ((unsigned int) STDERR_FILENO >= lo &&
	    (unsigned int) STDERR_FILENO <= hi)
		lowest = STDERR_FILENO;

	memfd = trinity_stderr_memfd();
	if (memfd >= 0 &&
	    (unsigned int) memfd >= lo && (unsigned int) memfd <= hi)
		if (lowest < 0 || memfd < lowest)
			lowest = memfd;

	child = this_child();
	if (child != NULL) {
		if (child->kcov.fd >= 0 &&
		    (unsigned int) child->kcov.fd >= lo &&
		    (unsigned int) child->kcov.fd <= hi)
			if (lowest < 0 || child->kcov.fd < lowest)
				lowest = child->kcov.fd;
		if (child->kcov.cmp_fd >= 0 &&
		    (unsigned int) child->kcov.cmp_fd >= lo &&
		    (unsigned int) child->kcov.cmp_fd <= hi)
			if (lowest < 0 || child->kcov.cmp_fd < lowest)
				lowest = child->kcov.cmp_fd;
	}

	return lowest;
}

/*
 * Belt-and-suspenders gate for size-changing fd-arg syscalls
 * (ftruncate / ftruncate64, fallocate, lseek / llseek, write / writev /
 * pwrite64 / pwritev / pwritev2).  gen_arg_fd() already filters
 * fd_is_protected() picks out of the ARG_FD pool, but its bounded
 * reroll falls back to the last (possibly protected) draw on pool
 * exhaustion, and the per-syscall RAND_RANGE / typed-fd-pool buckets in
 * the size-changing sanitisers can independently land on a protected
 * slot.  Per-syscall sanitisers feed rec->a1 through this gate after
 * their own rewrites and before any snap->fd capture: if the slot
 * names a protected fd, reroll up to FAILED_FD_REROLL_LIMIT times via
 * get_random_fd(); on exhaustion stamp the slot with (unsigned long)-1
 * so the kernel returns EBADF and the call cannot extend the stderr
 * capture memfd (or any other trinity-internal fd) into a multi-GB
 * sparse file that the SIGABRT-handler bug-log drain would then
 * materialise into the on-disk log.  Refusing is correct -- these fds
 * are never legitimate fuzz targets.
 */
void reroll_protected_fd_arg(unsigned long *slot)
{
	int fd;
	unsigned int tries;

	if (slot == NULL)
		return;
	if (!fd_is_protected((int) *slot))
		return;

	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = get_random_fd();
		if (!fd_is_protected(fd)) {
			*slot = (unsigned long) fd;
			return;
		}
	}
	*slot = (unsigned long) -1;
}

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

static void toggle_fds_param(char *str, bool enable)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (strcmp(provider->name, str) == 0) {
			if (enable == true) {
				provider->enabled = true;
				outputstd("Enabled fd provider %s\n", str);
				num_fd_providers_to_enable++;
			} else {
				provider->enabled = false;
				outputstd("Disabled fd provider %s\n", str);
			}
			return;
		}
	}

	outputstd("Unknown parameter \"%s\"\n", str);
	enable_disable_fd_usage();
	exit(EXIT_FAILURE);
}

void process_fds_param(char *param, bool enable)
{
	unsigned int len, i;
	char *str_orig = strdup(param);
	char *str = str_orig;

	if (!str_orig) {
		outputerr("strdup failed\n");
		return;
	}

	len = strlen(param);

	if (enable == true && disable_fd_used == true) {
		outputerr("Cannot use both --enable-fds and --disable-fds\n");
		free(str_orig);
		exit(EXIT_FAILURE);
	}
	if (enable == false && enable_fd_initialized == true) {
		outputerr("Cannot use both --enable-fds and --disable-fds\n");
		free(str_orig);
		exit(EXIT_FAILURE);
	}

	if (enable == false)
		disable_fd_used = true;

	if (enable_fd_initialized == false && enable == true) {
		struct list_head *node;

		/* First, pass through and mark everything disabled. */
		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			provider = (struct fd_provider *) node;
			provider->enabled = false;
		}
		enable_fd_initialized = true;
	}

	/* Check if there are any commas. If so, split them into multiple params,
	 * validating them as we go.
	 */
	for (i = 0; i < len; i++) {
		if (str_orig[i] == ',') {
			str_orig[i] = 0;
			toggle_fds_param(str, enable);
			str = str_orig + i + 1;
		}
	}
	if (str < str_orig + len)
		toggle_fds_param(str, enable);

	free(str_orig);
}
