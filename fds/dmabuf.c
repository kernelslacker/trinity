/*
 * dma-buf provider: a few dma-bufs made at init, so the dma-buf ioctls,
 * mmap and io_uring's DMABUF buffers meet a real one rather than one a
 * fuzzed call happened to make.  /dev/udmabuf exports a memfd's pages and
 * /dev/dma_heap/system allocates its own; both nodes are root-only on a
 * stock system, so a run as anyone else makes none.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/dma-heap.h>
#include <linux/udmabuf.h>

#include "arch.h"		/* page_size */
#include "dmabuf.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/memfd.h"

#define NR_DMABUF_FDS_PER_SOURCE	2
#define DMABUF_MAX_PAGES		16U

/*
 * udmabuf_create() pins the memfd's pages: it takes a shmem file sealed
 * against shrinking and refuses one sealed against writes.  The dma-buf
 * holds the pages, not the file, so the memfd goes once it is made.
 */
static int make_udmabuf(int dev, unsigned int size)
{
	struct udmabuf_create create;
	int memfd, fd = -1;

	memfd = memfd_create("trinity-udmabuf", MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (memfd < 0)
		return -1;
	if (ftruncate(memfd, size) == 0 &&
	    fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK) == 0) {
		memset(&create, 0, sizeof(create));
		create.memfd = memfd;
		create.flags = RAND_BOOL() ? UDMABUF_FLAGS_CLOEXEC : 0;
		create.size = size;
		fd = ioctl(dev, UDMABUF_CREATE, &create);
	}
	close(memfd);
	return fd;
}

static int make_heap_dmabuf(int dev, unsigned int size)
{
	struct dma_heap_allocation_data alloc;

	memset(&alloc, 0, sizeof(alloc));
	alloc.len = size;
	alloc.fd_flags = O_RDWR | (RAND_BOOL() ? O_CLOEXEC : 0);
	if (ioctl(dev, DMA_HEAP_IOCTL_ALLOC, &alloc) < 0)
		return -1;
	return alloc.fd;
}

static void dmabuf_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "dmabuf fd:%d size:%u scope:%d\n",
		obj->dmabufobj.fd, obj->dmabufobj.size, scope);
}

/*
 * Each source whose node opens makes a few dma-bufs of up to
 * DMABUF_MAX_PAGES pages; the first it fails to make ends its turn.  A run
 * that makes none reports why the last source failed.
 */
static int init_dmabuf_fds(void)
{
	static const struct {
		const char *path;
		int (*make)(int dev, unsigned int size);
	} sources[] = {
		{ "/dev/udmabuf", make_udmabuf },
		{ "/dev/dma_heap/system", make_heap_dmabuf },
	};
	struct objhead *head;
	unsigned int i, made = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_DMABUF);
	head->destroy = &close_fd_destructor;
	head->dump = &dmabuf_dump;

	for (i = 0; i < ARRAY_SIZE(sources); i++) {
		int dev = open(sources[i].path, O_RDWR | O_CLOEXEC);
		unsigned int k;

		if (dev < 0) {
			int err = errno;
			enum fd_init_reason reason =
				(err == ENOENT || err == ENXIO || err == ENODEV) ?
					FD_INIT_REASON_CONFIG_ABSENT :
				(err == EACCES || err == EPERM) ?
					FD_INIT_REASON_CAP_MISSING :
					FD_INIT_REASON_ERRNO;

			fd_provider_init_fail(reason, err, sources[i].path);
			continue;
		}
		for (k = 0; k < NR_DMABUF_FDS_PER_SOURCE; k++) {
			unsigned int size = page_size * RAND_RANGE(1U, DMABUF_MAX_PAGES);
			struct object *obj;
			int fd;

			fd = sources[i].make(dev, size);
			if (fd < 0) {
				fd_provider_init_fail(FD_INIT_REASON_ERRNO, errno,
						      sources[i].path);
				break;
			}
			obj = alloc_object();
			if (obj == NULL) {
				close(fd);
				break;
			}
			obj->dmabufobj.fd = fd;
			obj->dmabufobj.size = size;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_DMABUF);
			made++;
		}
		close(dev);
	}

	return made > 0;
}

/* Picks as get_rand_cgroup_fd() does, for the same lockless reader of
 * the global pool. */
int get_rand_dmabuf_fd(void)
{
	if (objects_empty(OBJ_FD_DMABUF) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;

		obj = get_random_object(OBJ_FD_DMABUF, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_DMABUF))
			continue;
		if (obj->dmabufobj.fd >= 0)
			return obj->dmabufobj.fd;
	}

	return -1;
}

static const struct fd_provider dmabuf_fd_provider = {
	.name = "dmabuf",
	.objtype = OBJ_FD_DMABUF,
	.enabled = true,
	.init = &init_dmabuf_fds,
	.get = &get_rand_dmabuf_fd,
};

REG_FD_PROV(dmabuf_fd_provider);
