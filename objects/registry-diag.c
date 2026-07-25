#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "compiler.h"
#include "debug.h"
#include "deferred-free.h"
#include "maps.h"
#include "objects.h"
#include "objects-internal.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "registry-internal.h"
#include "shm.h"
#include "stats_ring.h"
#include "utils.h"

/*
 * Generic objhead->destroy handler shared by every fd-bearing pool whose
 * teardown is just close() on the per-pool fd.  Reads the fd via
 * fd_from_object(obj, obj->obj_type) so providers that need anything
 * extra (mq_unlink, munmap of mapped rings, peer fixups, releasing a
 * shared name buffer, ...) must keep their own destructor.
 */
void close_fd_destructor(struct object *obj)
{
	int fd = fd_from_object(obj, obj->obj_type);

	if (fd >= 0)
		close(fd);
}

/*
 * Generic objhead->dump shared by every fd-bearing pool whose dump
 * carries no fields beyond the per-pool label, fd, and scope.  The
 * label is dispatched off obj->obj_type so the generic dumper's
 * output matches each pool's expected label and format.
 */
void generic_fd_dump(struct object *obj, enum obj_scope scope)
{
	const char *name;

	switch (obj->obj_type) {
	case OBJ_FD_CGROUP:		name = "cgroup"; break;
	case OBJ_FD_IOMMUFD:		name = "iommufd"; break;
	case OBJ_FD_SECCOMP_NOTIF:	name = "seccomp_notif"; break;
	case OBJ_FD_FS_CTX:		name = "fs_ctx"; break;
	case OBJ_FD_LANDLOCK:		name = "landlock"; break;
	case OBJ_FD_MOUNT:		name = "mount"; break;
	case OBJ_FD_SIGNALFD:		name = "signalfd"; break;
	default:			name = "?"; break;
	}

	output(2, "%s fd:%d scope:%d\n",
		name, fd_from_object(obj, obj->obj_type), scope);
}
