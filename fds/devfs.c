/* /dev fd provider (pool 0). */

#include "fd.h"
#include "files.h"
#include "objects.h"

static int init_devfiles(void)		{ return open_pool_files(0, OBJ_FD_DEVFILE); }
static int get_rand_devfile_fd(void)	{ return get_rand_pool_fd(OBJ_FD_DEVFILE); }
static int open_devfile_fd(void)	{ return open_pool_fd(0, OBJ_FD_DEVFILE); }

static const struct fd_provider devfile_provider = {
	.name = "dev",
	.objtype = OBJ_FD_DEVFILE,
	.enabled = true,
	.init = &init_devfiles,
	.get = &get_rand_devfile_fd,
	.open = &open_devfile_fd,
	/*
	 * The /dev pool is the only entry point through which trinity acquires
	 * /dev/fuse and /dev/userfaultfd handles, both of which back ->poll
	 * implementations that block for an external userspace actor
	 * (fuse_dev_poll waits on its connected daemon; uffd_poll waits for
	 * the next pending fault).  Tagging the whole pool is broader than
	 * strictly necessary — most /dev nodes have non-blocking poll
	 * handlers — but per-fd path tracking is not currently plumbed
	 * through the fileobj path, and barring the entire pool from epoll/
	 * select/poll watch sets only loses fuzz coverage that was already
	 * unreachable in practice (the moment a single fuse fd entered an
	 * epfd's interest list, every consumer of that epfd cascaded into
	 * uninterruptible-sleep on ep_item_poll).
	 */
	.poll_can_block = true,
};

REG_FD_PROV(devfile_provider);
