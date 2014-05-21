#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "epoll.h"
#include "eventfd.h"
#include "fd.h"
#include "files.h"
#include "log.h"
#include "list.h"
#include "net.h"
#include "params.h"
#include "perf.h"
#include "pids.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static int num_fd_providers;

static struct fd_provider *fd_providers = NULL;

static void add_to_prov_list(struct fd_provider *prov)
{
	struct fd_provider *newnode;

	newnode = zmalloc(sizeof(struct fd_provider));
	newnode->open = prov->open;
	newnode->get = prov->get;
	num_fd_providers++;

	if (fd_providers == NULL) {
		fd_providers = newnode;
		INIT_LIST_HEAD(&fd_providers->list);
	} else {
		list_add_tail(&newnode->list, &fd_providers->list);
	}
}

static void setup_fd_providers(void)
{
	add_to_prov_list(&socket_fd_provider);
	add_to_prov_list(&pipes_fd_provider);
	add_to_prov_list(&perf_fd_provider);
	add_to_prov_list(&epoll_fd_provider);
	add_to_prov_list(&eventfd_fd_provider);
	add_to_prov_list(&file_fd_provider);
}

unsigned int setup_fds(void)
{
	struct list_head *node;

	setup_fd_providers();

	output(0, "Registered %d fd providers.\n", num_fd_providers);

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *provider;
		int ret;

		provider = (struct fd_provider *) node;

		ret = provider->open();
		if (ret == FALSE)
			return FALSE;
	}

	return TRUE;
}

static int get_new_random_fd(void)
{
	struct list_head *node;
	int fd = -1;

	while (fd < 0) {
		unsigned int i, j = 0;
		i = rand() % num_fd_providers;

		list_for_each(node, &fd_providers->list) {
			struct fd_provider *provider;

			if (i == j) {
				provider = (struct fd_provider *) node;
				fd = provider->get();
			}
			j++;
		}
	}

	return fd;
}

int get_random_fd(void)
{
	/* 25% chance of returning something new. */
	if ((rand() % 4) == 0)
		return get_new_random_fd();

	/* the rest of the time, return the same fd as last time. */
regen:
	if (shm->fd_lifetime == 0) {
		shm->current_fd = get_new_random_fd();
		shm->fd_lifetime = rand_range(5, max_children);
	} else
		shm->fd_lifetime--;

	if (shm->current_fd == 0) {
		shm->fd_lifetime = 0;
		goto regen;
	}

	return shm->current_fd;
}
