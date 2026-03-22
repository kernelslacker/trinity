#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
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
static bool enable_fd_initialized = FALSE;		// initialized (disabled all) fd providers

static struct fd_provider *fd_providers = NULL;

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
	newnode->objtype = prov->objtype;
	newnode->enabled = prov->enabled;
	newnode->open = prov->open;
	newnode->get = prov->get;
	newnode->reopen = prov->reopen;
	num_fd_providers++;

	list_add_tail(&newnode->list, &fd_providers->list);
}

static void __open_fds(bool do_rand)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;

		/* disabled on cmdline */
		if (provider->enabled == FALSE)
			continue;

		/* already done */
		if (provider->initialized == TRUE)
			continue;

		if (do_rand == TRUE) {
			/* to mix up init order */
			if (RAND_BOOL())
				continue;
		}

		provider->enabled = provider->open();
		if (provider->enabled == TRUE) {
			provider->initialized = TRUE;
			num_fd_providers_initialized++;
			num_fd_providers_enabled++;
		} else {
			outputstd("Error during initialization of %s\n", provider->name);
			num_fd_providers_to_enable--;
		}
	}
}

unsigned int open_fds(void)
{
	/* Open half the providers randomly */
	while (num_fd_providers_initialized < (num_fd_providers_to_enable / 2))
		__open_fds(TRUE);

	/* Now open any leftovers */
	__open_fds(FALSE);

	output(0, "Enabled %d/%d fd providers. initialized:%d.\n",
		num_fd_providers_enabled, num_fd_providers, num_fd_providers_initialized);

	return TRUE;
}

int get_new_random_fd(void)
{
	struct list_head *node;
	int fd = -1;

	/* short-cut if we've disabled everything. */
	if (num_fd_providers_enabled == 0)
		return -1;

	/* if nothing has initialized yet, bail */
	if (num_fd_providers_initialized == 0)
		return -1;

	while (fd < 0) {
		unsigned int i, j;
		unsigned int attempts = 0;
retry:
		if (++attempts > num_fd_providers * 10)
			return -1;

		i = rand() % num_fd_providers;			// FIXME: after below fixme, this should be num_fd_providers_initialized
		j = 0;

		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			if (i == j) {
				provider = (struct fd_provider *) node;

				if (provider->enabled == FALSE)	// FIXME: Better would be to just remove disabled providers from the list.
					goto retry;

				// Hasn't been run yet.
				if (provider->initialized == FALSE)
					goto retry;

				fd = provider->get();
				break;
			}
			j++;
		}
	}

	return fd;
}

int get_random_fd(void)
{
	struct childdata *child = this_child();
	unsigned int retries = 0;

	/* return the same fd as last time if we haven't over-used it yet. */
regen:
	if (child->fd_lifetime == 0) {
		child->current_fd = get_new_random_fd();

		/* Validate the fd is still alive */
		if (child->current_fd > 0 &&
		    fcntl(child->current_fd, F_GETFD) == -1 && errno == EBADF) {
			__atomic_add_fetch(&shm->stats.fd_stale_detected, 1, __ATOMIC_RELAXED);
			if (++retries < 10)
				goto regen;
		}

		if (max_children > 5)
			child->fd_lifetime = RAND_RANGE(5, max_children);
		else
			child->fd_lifetime = RAND_RANGE(max_children, 5);
	} else
		child->fd_lifetime--;

	if (child->current_fd == 0) {
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
 * Validates that the fd is still alive via fcntl(F_GETFD).  If stale
 * (EBADF), destroys the object and retries up to 10 times before
 * falling back to get_random_fd().
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
	case ARG_FD_INOTIFY:	objtype = OBJ_FD_INOTIFY; break;
	case ARG_FD_IO_URING:	objtype = OBJ_FD_IO_URING; break;
	case ARG_FD_LANDLOCK:	objtype = OBJ_FD_LANDLOCK; break;
	case ARG_FD_MEMFD:	objtype = OBJ_FD_MEMFD; break;
	case ARG_FD_PERF:	objtype = OBJ_FD_PERF; break;
	case ARG_FD_PIDFD:	objtype = OBJ_FD_PIDFD; break;
	case ARG_FD_PIPE:	objtype = OBJ_FD_PIPE; break;
	case ARG_FD_SOCKET:	objtype = OBJ_FD_SOCKET; break;
	case ARG_FD_TIMERFD:	objtype = OBJ_FD_TIMERFD; break;
	default:
		return get_random_fd();
	}

retry:
	if (objects_empty(objtype) || retries >= 10)
		return get_random_fd();

	obj = get_random_object(objtype, OBJ_GLOBAL);
	if (obj == NULL)
		return get_random_fd();

	fd = fd_from_object(obj, objtype);
	if (fd < 0)
		return get_random_fd();

	/* Validate fd is still alive */
	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
		__atomic_add_fetch(&shm->stats.fd_stale_detected, 1, __ATOMIC_RELAXED);
		destroy_object(obj, OBJ_GLOBAL, objtype);
		try_regenerate_fd(objtype);
		retries++;
		goto retry;
	}

	return fd;
}

/*
 * Try to create a replacement fd after one was destroyed.
 * Finds the provider for the given object type and calls its
 * .reopen hook if available.
 */
void try_regenerate_fd(enum objecttype type)
{
	struct list_head *node;

	if (fd_providers == NULL)
		return;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (provider->objtype == type && provider->reopen != NULL &&
		    provider->initialized == TRUE) {
			if (provider->reopen() == TRUE)
				__atomic_add_fetch(&shm->stats.fd_regenerated, 1, __ATOMIC_RELAXED);
			return;
		}
	}
}

static void toggle_fds_param(char *str, bool enable)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (strcmp(provider->name, str) == 0) {
			if (enable == TRUE) {
				provider->enabled = TRUE;
				outputstd("Enabled fd provider %s\n", str);
				num_fd_providers_to_enable++;
			} else {
				provider->enabled = FALSE;
				outputstd("Disabled fd provider %s\n", str);
			}
			return;
		}
	}

	outputstd("Unknown parameter \"%s\"\n", str);
	enable_disable_fd_usage();
	exit(EXIT_FAILURE);
}

//TODO: prevent --enable and --disable being passed at the same time.
void process_fds_param(char *param, bool enable)
{
	unsigned int len, i;
	char *str_orig = strdup(param);
	char *str = str_orig;

	len = strlen(param);

	if (enable_fd_initialized == FALSE && enable == TRUE) {
		struct list_head *node;

		/* First, pass through and mark everything disabled. */
		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			provider = (struct fd_provider *) node;
			provider->enabled = FALSE;
		}
		enable_fd_initialized = TRUE;
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
