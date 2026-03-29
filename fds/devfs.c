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
};

REG_FD_PROV(devfile_provider);
