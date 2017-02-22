#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "list.h"
#include "net.h"
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
	newnode->enabled = prov->enabled;
	newnode->open = prov->open;
	newnode->get = prov->get;
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
retry:
		i = rnd() % num_fd_providers;			// FIXME: after below fixme, this should be num_fd_providers_initialized
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
	/* return the same fd as last time if we haven't over-used it yet. */
regen:
	if (shm->fd_lifetime == 0) {
		shm->current_fd = get_new_random_fd();
		if (max_children > 5)
			shm->fd_lifetime = RAND_RANGE(5, max_children);
		else
			shm->fd_lifetime = RAND_RANGE(max_children, 5);
	} else
		shm->fd_lifetime--;

	if (shm->current_fd == 0) {
		shm->fd_lifetime = 0;
		goto regen;
	}

	return shm->current_fd;
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
