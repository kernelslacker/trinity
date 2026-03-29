/* /proc fd provider (pool 1). */

#include "fd.h"
#include "files.h"
#include "objects.h"

static int init_procfiles(void)		{ return open_pool_files(1, OBJ_FD_PROCFILE); }
static int get_rand_procfile_fd(void)	{ return get_rand_pool_fd(OBJ_FD_PROCFILE); }
static int open_procfile_fd(void)	{ return open_pool_fd(1, OBJ_FD_PROCFILE); }

static const struct fd_provider procfile_provider = {
	.name = "proc",
	.objtype = OBJ_FD_PROCFILE,
	.enabled = true,
	.init = &init_procfiles,
	.get = &get_rand_procfile_fd,
	.open = &open_procfile_fd,
};

REG_FD_PROV(procfile_provider);
