#include <unistd.h>
#include "files.h"
#include "log.h"
#include "maps.h"
#include "net.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#if 0
static void do_sso_sockets(void)
{
	struct sockopt so = { 0, 0, 0, 0 };
	unsigned int i;

	for (i = 0; i < nr_sockets; i++) {
		int fd;

		fd = shm->sockets[i].fd;
		sso_socket(&shm->sockets[i].triplet, &so, fd);
	}
}
#endif

void regenerate(void)
{
	if (no_files == TRUE)	/* We don't regenerate sockets */
		return;

	/* we're about to exit. */
	if (shm->spawn_no_more)
		return;

	shm->regenerating = TRUE;

	sleep(1);	/* give children time to finish with fds. */

	shm->regenerate = 0;

	output(0, "Regenerating random pages, fd's etc.\n");

	regenerate_fds();

	/* Do random setsockopts on all network sockets. */
	/* FIXME: Disabled for now.
	 *
	 * There's a problem if we have a child doing a read on a socket that blocks
	 * (like some weirdo ax25 socket for eg). The setsockopt will block on it.
	 *
	 * I'm not sure what to do about this problem yet.
	 * Maybe try waiting for nr_children to drop to zero when need_regenerate == 1 ?
	 */
	//do_sso_sockets();

	destroy_shared_mappings();
	setup_shared_mappings();

	generate_random_page(page_rand);

	shm->regenerating = FALSE;
}
