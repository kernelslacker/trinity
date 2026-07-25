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

static bool enable_fd_initialized = false;		// initialized (disabled all) fd providers
static bool disable_fd_used = false;			// --disable-fds was passed

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
