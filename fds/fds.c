#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "fd-event.h"
#include "list.h"
#include "net.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
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
	newnode->open = prov->open;
	newnode->child_ops = prov->child_ops;
	num_fd_providers++;

	list_add_tail(&newnode->list, &fd_providers->list);
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

		provider->enabled = provider->init();
		if (provider->enabled == true) {
			provider->initialized = true;
			num_fd_providers_initialized++;
			num_fd_providers_enabled++;
		} else {
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

	return num_fd_providers_enabled > 0;
}

int get_new_random_fd(void)
{
	struct fd_provider *provider;
	unsigned int retries = 0;
	int fd;

	if (num_active_providers == 0)
		return -1;

retry:
	provider = active_providers[rand() % num_active_providers];
	fd = provider->get();
	if (fd >= 0 && fd <= 2) {
		if (++retries < 10)
			goto retry;
		return -1;
	}
	return fd;
}

int get_random_fd(void)
{
	struct childdata *child = this_child();
	unsigned int retries = 0;

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
			__atomic_add_fetch(&shm->stats.fd_stale_by_generation, 1,
					   __ATOMIC_RELAXED);
			child->fd_lifetime = 0;
		}
	}

	/* return the same fd as last time if we haven't over-used it yet. */
regen:
	if (child->fd_lifetime == 0) {
		struct fd_hash_entry *e;

		child->current_fd = get_new_random_fd();

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
			__atomic_add_fetch(&shm->stats.fd_stale_detected, 1,
					   __ATOMIC_RELAXED);
			goto regen;
		}
		child->cached_fd_generation = e ?
			__atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) : 0;

		if (max_children >= 5)
			child->fd_lifetime = RAND_RANGE(5, max_children);
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
 * Ask the parent to top up the global pool for objtype.  Safe from
 * either parent or child context: in the parent we just call
 * try_regenerate_fd() directly (the only path the global pool can be
 * mutated from), while in a child we hand the request to the parent
 * via the per-child fd_event ring.
 *
 * The shm-wide fd_regen_pending[type] flag dedups concurrent requests:
 * if the parent has already been notified for this type and hasn't
 * drained the request yet, additional notifications are skipped to
 * avoid filling the ring with duplicates while a single regen would
 * satisfy them all.
 */
static void request_fd_regen(enum objecttype type)
{
	struct childdata *child;
	uint8_t prev;

	if (getpid() == mainpid) {
		try_regenerate_fd(type);
		return;
	}

	child = this_child();
	if (child == NULL || child->fd_event_ring == NULL)
		return;

	prev = atomic_exchange_explicit(&shm->fd_regen_pending[type], 1,
					memory_order_relaxed);
	if (prev != 0)
		return;

	if (!fd_event_enqueue(child->fd_event_ring, FD_EVENT_REGEN_REQUEST,
			      -1, -1, type)) {
		/* Ring overflow — drop the rate-limit so the next caller
		 * gets to retry instead of permanently muting this type. */
		atomic_store_explicit(&shm->fd_regen_pending[type], 0,
				      memory_order_relaxed);
	}
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
	case ARG_FD_EPOLL:	objtype = OBJ_FD_EPOLL; break;
	case ARG_FD_EVENTFD:	objtype = OBJ_FD_EVENTFD; break;
	case ARG_FD_FANOTIFY:	objtype = OBJ_FD_FANOTIFY; break;
	case ARG_FD_FS_CTX:	objtype = OBJ_FD_FS_CTX; break;
	case ARG_FD_INOTIFY:	objtype = OBJ_FD_INOTIFY; break;
	case ARG_FD_IO_URING:	objtype = OBJ_FD_IO_URING; break;
	case ARG_FD_LANDLOCK:	objtype = OBJ_FD_LANDLOCK; break;
	case ARG_FD_MEMFD:	objtype = OBJ_FD_MEMFD; break;
	case ARG_FD_MQ:		objtype = OBJ_FD_MQ; break;
	case ARG_FD_PERF:	objtype = OBJ_FD_PERF; break;
	case ARG_FD_PIDFD:	objtype = OBJ_FD_PIDFD; break;
	case ARG_FD_PIPE:	objtype = OBJ_FD_PIPE; break;
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

	fd = fd_from_object(obj, objtype);
	if (fd < 0)
		return get_random_fd();

	/* Don't hand out stdin/stdout/stderr to syscalls. */
	if (fd <= 2)
		return get_random_fd();

	/* Validate fd is still tracked. */
	if (fd_hash_lookup(fd) == NULL) {
		__atomic_add_fetch(&shm->stats.fd_stale_detected, 1, __ATOMIC_RELAXED);
		destroy_object(obj, OBJ_GLOBAL, objtype);
		request_fd_regen(objtype);
		retries++;
		goto retry;
	}

	return fd;
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
		i = rand() % CHILD_FD_RING_SIZE;
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
 * Try to create a replacement fd after one was destroyed.
 * Finds the provider for the given object type and calls its
 * .open hook if available.
 */
void try_regenerate_fd(enum objecttype type)
{
	struct list_head *node;

	if (fd_providers == NULL)
		return;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (provider->objtype == type && provider->open != NULL &&
		    provider->initialized == true) {
			if (provider->open() == true)
				__atomic_add_fetch(&shm->stats.fd_regenerated, 1, __ATOMIC_RELAXED);
			return;
		}
	}
}

/*
 * Call child_ops for all initialized fd providers that have one.
 * Invoked periodically from the child process to exercise fd-level
 * operations (bind/listen/accept etc.) as fuzzing actions.
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
