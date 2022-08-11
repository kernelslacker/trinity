/* DRM FDs */

#include "fd.h"
#include "memfd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

#ifdef USE_DRM

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <drm/drm.h>

static void drmfd_destructor(struct object *obj)
{
	close(obj->drmfd);
}

static void drmfd_dump(struct object *obj, bool global)
{
	output(2, "drmfd:%d global:%d\n", obj->drmfd, global);
}

static int create_dumb(__unused__ int fd)
{
#if defined(DRM_IOCTL_MODE_CREATE_DUMB) && defined(DRM_IOCTL_PRIME_HANDLE_TO_FD)
	struct drm_mode_create_dumb create;
	struct drm_prime_handle handle_to_fd;

	memset(&create, 0, sizeof(create));
	create.height = 1 << RAND_RANGE(0, 10);
	create.width = 1 << RAND_RANGE(0, 10);
	create.bpp = 32;

	if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &create) < 0) {
		return -1;
	}

	memset(&handle_to_fd, 0, sizeof(handle_to_fd));
	handle_to_fd.handle = create.handle;
	if (RAND_BOOL())
		handle_to_fd.flags = DRM_CLOEXEC;

	if (ioctl(fd, DRM_IOCTL_PRIME_HANDLE_TO_FD, &handle_to_fd) < 0) {
		return -1;
	}

	return handle_to_fd.fd;
#else
	return -1;
#endif
}

static void add_drm_obj(int fd)
{
	struct object *obj;

	obj = alloc_object();
	obj->drmfd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_DRM);

	output(2, "fd[%d] = drm\n", fd);
}

static struct fd_provider drm_fd_provider;

static int open_drm_fds(void)
{
	struct objhead *head;
	int fd, dfd;
	DIR *dir;
	struct dirent *entry;
	char buf[256 + 10];

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_DRM);
	head->destroy = &drmfd_destructor;
	head->dump = &drmfd_dump;

	dir = opendir("/dev/dri/");
	if (!dir)
		goto done;

	// Open all /dev/dri/*, and try to make FDs from each of them.
	while (1) {
		entry = readdir(dir);
		if (!entry)
			break;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(buf, sizeof(buf), "/dev/dri/%s", entry->d_name);
		buf[sizeof(buf)-1] = '\0';

		fd = open(buf, O_RDWR);
		if (fd < 0)
			continue;

		add_drm_obj(fd);

		dfd = create_dumb(fd);
		if (dfd < 0)
			continue;

		add_drm_obj(dfd);
	}

	if (dir)
		closedir(dir);

done:
	if (objects_empty(OBJ_FD_DRM) == TRUE)
		drm_fd_provider.enabled = FALSE;

	return TRUE;
}

#else

static int open_drm_fds(void) { return TRUE; }

#endif /* USE_DRM */

static int get_rand_drm_fd(void)
{
	struct object *obj;

	/* check if drm unavailable/disabled. */
	if (objects_empty(OBJ_FD_DRM) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_DRM, OBJ_GLOBAL);
	return obj->drmfd;
}

static struct fd_provider drm_fd_provider = {
	.name = "drm",
	.enabled = TRUE,
	.open = &open_drm_fds,
	.get = &get_rand_drm_fd,
};

REG_FD_PROV(drm_fd_provider);
