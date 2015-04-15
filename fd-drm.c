/* DRM FDs */

#include "config.h"
#include "fd.h"
#include "log.h"
#include "memfd.h"
#include "net.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static unsigned fd_count;

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

static int open_drm_fds(void)
{
	unsigned int i;
	int fd, dfd;
	DIR *dir;
	struct dirent *entry;
	char buf[128];

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
		if (fd < 0) {
			continue;
		}
		shm->drm_fds[fd_count++] = fd;

		if (fd_count >= MAX_DRM_FDS)
			break;

		dfd = create_dumb(fd);
		if (dfd < 0) {
			continue;
		}
		shm->drm_fds[fd_count++] = dfd;

		if (fd_count >= MAX_DRM_FDS)
			break;
	}

	if (dir)
		closedir(dir);

	for (i = 0; i < MAX_DRM_FDS; i++) {
		if (shm->drm_fds[i] > 0) {
			output(2, "fd[%d] = drm\n", shm->drm_fds[i]);
		}
	}

done:
	if (fd_count == 0)
		drm_fd_provider.enabled = FALSE;

	return TRUE;
}

#else

static int open_drm_fds(void) { return TRUE; }

#endif /* USE_DRM */

static int get_rand_drm_fd(void)
{
	// We should not be called when fd_count is zero, but avoid div-by-zero
	// just in case.
	if (fd_count > 0)
		return shm->drm_fds[rand() % fd_count];
	else
		return -1;
}

struct fd_provider drm_fd_provider = {
	.name = "drm",
	.enabled = TRUE,
	.open = &open_drm_fds,
	.get = &get_rand_drm_fd,
};
