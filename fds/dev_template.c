/*
 * dev_template fd provider — probes a small static table of
 * high-value character devices at startup and publishes successful
 * opens into OBJ_FD_DEV_TEMPLATE.
 *
 * The probe runs once in the parent during open_fds() (pre-fork), so
 * children inherit the fds via the normal fork-copies-fd path.  Per-
 * child re-opens would be wasted work for these devices: their open
 * has no per-fd state that disappears across fork (KVM's per-fd VM
 * state is created later via KVM_CREATE_VM ioctl, which the ioctl
 * fuzzer hits on its own; /dev/userfaultfd and /dev/fuse similarly
 * defer per-fd state to subsequent ioctls).
 *
 * Entries that fail to open log their gate label at output level 1
 * so the startup banner names what was missing rather than just
 * "open: ENOENT".
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dev_template.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

static const struct dev_template dev_templates[DEV_TEMPLATE_MAX] = {
	[DEV_TEMPLATE_NULL]          = { "/dev/null",           O_RDWR,   "baseline (always present)" },
	[DEV_TEMPLATE_ZERO]          = { "/dev/zero",           O_RDWR,   "baseline (always present)" },
	[DEV_TEMPLATE_FULL]          = { "/dev/full",           O_RDWR,   "baseline" },
	[DEV_TEMPLATE_URANDOM]       = { "/dev/urandom",        O_RDONLY, "baseline" },
	[DEV_TEMPLATE_LOOP_CONTROL]  = { "/dev/loop-control",   O_RDWR,   "CONFIG_BLK_DEV_LOOP" },
	[DEV_TEMPLATE_KVM]           = { "/dev/kvm",            O_RDWR,   "CONFIG_KVM + virt-capable hw" },
	[DEV_TEMPLATE_VFIO]          = { "/dev/vfio/vfio",      O_RDWR,   "CONFIG_VFIO" },
	[DEV_TEMPLATE_TUN]           = { "/dev/net/tun",        O_RDWR,   "CONFIG_TUN" },
	[DEV_TEMPLATE_USERFAULTFD]   = { "/dev/userfaultfd",    O_RDWR,   "CONFIG_USERFAULTFD (>=6.1)" },
	[DEV_TEMPLATE_DRI_RENDER]    = { "/dev/dri/renderD128", O_RDWR,   "CONFIG_DRM + render node" },
	[DEV_TEMPLATE_FUSE]          = { "/dev/fuse",           O_RDWR,   "CONFIG_FUSE_FS" },
	[DEV_TEMPLATE_BTRFS_CONTROL] = { "/dev/btrfs-control",  O_RDWR,   "CONFIG_BTRFS_FS" },
	[DEV_TEMPLATE_SND_SEQ]       = { "/dev/snd/seq",        O_RDWR,   "CONFIG_SND_SEQUENCER" },
	[DEV_TEMPLATE_BINDER]        = { "/dev/binder",         O_RDWR,   "CONFIG_ANDROID_BINDER_IPC" },
};

static void dev_template_destructor(struct object *obj)
{
	close(obj->fileobj.fd);
}

static void dev_template_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "dev_template fd:%d filename:%s flags:%x scope:%d\n",
		fo->fd, fo->filename, fo->flags, scope);
}

static int init_dev_templates(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int opened = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_DEV_TEMPLATE);
	head->destroy = &dev_template_destructor;
	head->dump = &dev_template_dump;

	for (i = 0; i < DEV_TEMPLATE_MAX; i++) {
		const struct dev_template *t = &dev_templates[i];
		struct object *obj;
		int fd;

		fd = open(t->path, t->flags | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) {
			output(1, "dev_template: skipped %s (gate: %s) — %s\n",
				t->path, t->gate, strerror(errno));
			continue;
		}

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->fileobj.filename = t->path;
		obj->fileobj.flags = t->flags;
		obj->fileobj.fd = fd;
		obj->fileobj.fopened = false;
		obj->fileobj.pagecache_backed = false;
		obj->fileobj.is_setuid = false;
		obj->fileobj.fcntl_flags = 0;
		obj->fileobj.obj_flags = 0;

		add_object(obj, OBJ_GLOBAL, OBJ_FD_DEV_TEMPLATE);

		opened++;
	}

	output(0, "dev_template: opened %u/%u entries\n",
		opened, (unsigned int)DEV_TEMPLATE_MAX);

	return opened > 0;
}

static int get_rand_dev_template_fd(void)
{
	if (objects_empty(OBJ_FD_DEV_TEMPLATE) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->fileobj.fd deref, mirroring fds/canary.c::
	 * get_rand_canary_fd().
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_DEV_TEMPLATE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_DEV_TEMPLATE))
			continue;
		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;
		/* skip stale dev fds: F_GETFD bounces EBADF when the underlying file got closed */
		if (fcntl(fd, F_GETFD) == -1)
			continue;
		return fd;
	}

	return -1;
}

static const struct fd_provider dev_template_provider = {
	.name = "dev_template",
	.objtype = OBJ_FD_DEV_TEMPLATE,
	.enabled = true,
	.init = &init_dev_templates,
	.get = &get_rand_dev_template_fd,
};

REG_FD_PROV(dev_template_provider);
