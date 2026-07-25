#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "fd.h"
#include "fds-internal.h"
#include "list.h"
#include "params.h"
#include "trinity.h"
#include "utils.h"

static bool enable_fd_initialized = false;		// initialized (disabled all) fd providers
static bool disable_fd_used = false;			// --disable-fds was passed

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
