#include <stddef.h>
#include <string.h>

#include "fd.h"
#include "fds-internal.h"
#include "list.h"
#include "object-types.h"
#include "objects.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

unsigned int num_fd_providers_to_enable = 0;	// num of --fd-enable= params
unsigned int num_fd_providers_enabled = 0;	// final num we enabled.
unsigned int num_fd_providers_initialized = 0;	// num we called ->init on

/* Array of enabled+initialized providers for O(1) random selection. */
struct fd_provider **active_providers = NULL;
unsigned int num_active_providers = 0;

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
