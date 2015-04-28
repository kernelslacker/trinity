#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "epoll.h"
#include "eventfd.h"
#include "fd.h"
#include "files.h"
#include "log.h"
#include "list.h"
#include "memfd.h"
#include "net.h"
#include "params.h"
#include "perf.h"
#include "pids.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "testfile.h"
#include "utils.h"

static unsigned int num_fd_providers;
static unsigned int num_fd_providers_enabled = 0;

static struct fd_provider *fd_providers = NULL;

static void add_to_prov_list(const struct fd_provider *prov)
{
	struct fd_provider *newnode;

	newnode = zmalloc(sizeof(struct fd_provider));
	newnode->name = strdup(prov->name);
	newnode->enabled = prov->enabled;
	newnode->open = prov->open;
	newnode->get = prov->get;
	num_fd_providers++;

	list_add_tail(&newnode->list, &fd_providers->list);
}

void setup_fd_providers(void)
{
	fd_providers = zmalloc(sizeof(struct fd_provider));
	INIT_LIST_HEAD(&fd_providers->list);

	add_to_prov_list(&socket_fd_provider);
	add_to_prov_list(&pipes_fd_provider);
	add_to_prov_list(&perf_fd_provider);
	add_to_prov_list(&epoll_fd_provider);
	add_to_prov_list(&eventfd_fd_provider);
	add_to_prov_list(&file_fd_provider);
	add_to_prov_list(&timerfd_fd_provider);
	add_to_prov_list(&testfile_fd_provider);
	add_to_prov_list(&memfd_fd_provider);
	add_to_prov_list(&drm_fd_provider);

	output(0, "Registered %d fd providers.\n", num_fd_providers);
}

unsigned int open_fds(void)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;
		int ret;

		provider = (struct fd_provider *) node;

		if (provider->enabled == FALSE)
			continue;

		ret = provider->open();
		if (ret == FALSE)
			return FALSE;

		num_fd_providers_enabled++;
	}

	output(0, "Enabled %d fd providers.\n", num_fd_providers_enabled);

	return TRUE;
}

static int get_new_random_fd(void)
{
	struct list_head *node;
	int fd = -1;

	/* short-cut if we've disabled everything. */
	if (num_fd_providers_enabled == 0)
		return -1;

	while (fd < 0) {
		unsigned int i, j;
retry:
		i = rand() % num_fd_providers;
		j = 0;

		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			if (i == j) {
				provider = (struct fd_provider *) node;

				if (provider->enabled == FALSE)	// FIXME: Better would be to just remove disabled providers from the list.
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

static void enable_fds_param(char *str)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (strcmp(provider->name, str) == 0) {
			provider->enabled = TRUE;
			outputstd("Enabled fd provider %s\n", str);
			return;
		}
	}

	outputstd("Unknown --enable-fds parameter \"%s\"\n", str);
	enable_disable_fd_usage();
	exit(EXIT_FAILURE);
}

static void disable_fds_param(char *str)
{
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;

		provider = (struct fd_provider *) node;
		if (strcmp(provider->name, str) == 0) {
			provider->enabled = FALSE;
			outputstd("Disabled fd provider %s\n", str);
			return;
		}
	}

	outputstd("Unknown --disable-fds parameter \"%s\"\n", str);
	enable_disable_fd_usage();
	exit(EXIT_FAILURE);
}

void process_fds_param(char *param, bool enable)
{
	unsigned int len, i;
	char *str = param;

	len = strlen(param);

	if (enable == TRUE) {
		struct list_head *node;

		/* First, pass through and mark everything disabled. */
		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			provider = (struct fd_provider *) node;
			provider->enabled = FALSE;
		}
	}

	/* Check if there are any commas. If so, split them into multiple params,
	 * validating them as we go.
	 */
	for (i = 0; i < len; i++) {
		if (param[i] == ',') {
			param[i] = 0;
			if (enable == TRUE)
				enable_fds_param(str);
			else
				disable_fds_param(str);
			str = param + i + 1;
		}
	}
	if (str < param + len) {
		if (enable == TRUE)
			enable_fds_param(str);
		else
			disable_fds_param(str);
	}
}
