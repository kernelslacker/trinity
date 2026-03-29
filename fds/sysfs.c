/* /sys fd provider (pool 2). */

#include "fd.h"
#include "files.h"
#include "objects.h"

static int init_sysfiles(void)		{ return open_pool_files(2, OBJ_FD_SYSFILE); }
static int get_rand_sysfile_fd(void)	{ return get_rand_pool_fd(OBJ_FD_SYSFILE); }
static int open_sysfile_fd(void)	{ return open_pool_fd(2, OBJ_FD_SYSFILE); }

static const struct fd_provider sysfile_provider = {
	.name = "sys",
	.objtype = OBJ_FD_SYSFILE,
	.enabled = true,
	.init = &init_sysfiles,
	.get = &get_rand_sysfile_fd,
	.open = &open_sysfile_fd,
};

REG_FD_PROV(sysfile_provider);
