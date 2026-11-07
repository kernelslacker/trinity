/*
 * pagemap_wp_scan -- reach PAGEMAP_SCAN's WP_MATCHING path, which the
 * random-syscall path almost never arranges: pagemap_scan_test_walk()
 * skips every VMA that is not registered for userfaultfd write
 * protection in async mode, and nothing registers one.  The sequence
 * is a userfaultfd made in this child, an anonymous mapping
 * registered on it for write protection with WP_ASYNC, a PAGEMAP_SCAN
 * with PM_SCAN_WP_MATCHING over the mapping, and a write to a scanned
 * page, whose fault the kernel resolves in async mode with no message
 * to a monitor and no signal.  The uffd is the child's own: the
 * kernel binds one to its creator's mm, so a pooled parent-made uffd
 * would act on the parent's address space.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "fd.h"
#include "kernel/fs.h"
#include "kernel/userfaultfd.h"
#include "shm.h"
#include "userfaultfd.h"

#define SCAN_PAGES	8
#define SCAN_VEC_LEN	16

bool pagemap_wp_scan(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned long direct_calls = 0;
	unsigned char *map;
	size_t len = SCAN_PAGES * page_size;
	int uffd = -1;
	int pmfd = -1;
	bool registered = false;
	size_t i;

	map = mmap(NULL, len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	direct_calls++;
	if (map == MAP_FAILED)
		goto out;

	/* Fault the pages in so the scan walks present PTEs. */
	memset(map, 0, len);

	uffd = create_userfaultfd(O_CLOEXEC);
	direct_calls++;
	if (uffd < 0)
		goto out;

	{
		struct uffdio_api api;

		memset(&api, 0, sizeof(api));
		api.api = UFFD_API;
		api.features = UFFD_FEATURE_WP_ASYNC |
			       UFFD_FEATURE_WP_UNPOPULATED;
		direct_calls++;
		if (ioctl(uffd, UFFDIO_API, &api) != 0 ||
		    !(api.features & UFFD_FEATURE_WP_ASYNC))
			goto out;
	}

	{
		struct uffdio_register reg;

		memset(&reg, 0, sizeof(reg));
		reg.range.start = (unsigned long)map;
		reg.range.len = len;
		reg.mode = UFFDIO_REGISTER_MODE_WP;
		direct_calls++;
		if (ioctl(uffd, UFFDIO_REGISTER, &reg) != 0)
			goto out;
		registered = true;
	}

	pmfd = open_owner_only("/proc/self/pagemap");
	direct_calls++;
	if (pmfd < 0)
		goto out;

	{
		struct pm_scan_arg arg;
		struct page_region vec[SCAN_VEC_LEN];

		memset(&arg, 0, sizeof(arg));
		memset(vec, 0, sizeof(vec));
		arg.size = sizeof(arg);
		arg.flags = PM_SCAN_WP_MATCHING;
		arg.start = (unsigned long)map;
		arg.end = (unsigned long)map + len;
		arg.return_mask = PAGE_IS_WPALLOWED | PAGE_IS_WRITTEN |
				  PAGE_IS_PRESENT;
		arg.vec = (unsigned long)vec;
		arg.vec_len = SCAN_VEC_LEN;
		arg.max_pages = SCAN_PAGES;
		direct_calls++;
		(void)ioctl(pmfd, PAGEMAP_SCAN, &arg);

		/*
		 * The write fault on a write-protected page: in async
		 * mode the kernel resolves it without a uffd message
		 * and clears the protection, so this must succeed
		 * rather than SIGBUS or block.
		 */
		for (i = 0; i < SCAN_PAGES; i++)
			map[i * page_size] = 0x55;
	}

out:
	if (registered) {
		struct uffdio_range range;

		memset(&range, 0, sizeof(range));
		range.start = (unsigned long)map;
		range.len = len;
		direct_calls++;
		(void)ioctl(uffd, UFFDIO_UNREGISTER, &range);
	}
	if (pmfd >= 0) {
		direct_calls++;
		close(pmfd);
	}
	if (uffd >= 0) {
		direct_calls++;
		close(uffd);
	}
	if (map != MAP_FAILED) {
		direct_calls++;
		munmap(map, len);
	}
	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
