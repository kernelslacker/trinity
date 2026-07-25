#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "fd.h"
#include "fds-internal.h"
#include "list.h"
#include "object-types.h"
#include "trinity.h"
#include "utils.h"

unsigned int num_fd_providers;			// num in list.

struct fd_provider *fd_providers = NULL;

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
