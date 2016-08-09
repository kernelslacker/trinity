#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "kcov.h"

static int kcovfd;

static unsigned long *cover;

//TODO: Make sure get_random_fd can't touch the kcovfd

void init_kcov(void)
{
	/* A single fd descriptor allows coverage collection on a single
	 * thread.
	 */
	kcovfd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcovfd == -1)
		return;

	/* Setup trace mode and trace size. */
	if (ioctl(kcovfd, KCOV_INIT_TRACE, COVER_SIZE)) {
		printf("Failed to init kcov: %s\n", strerror(errno));
		goto fail;
	}
	/* Mmap buffer shared between kernel- and user-space. */
	cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
				     PROT_READ | PROT_WRITE, MAP_SHARED, kcovfd, 0);
	if ((void*)cover == MAP_FAILED) {
		printf("Failed to mmap kcov buffer: %s\n", strerror(errno));
		goto fail;
	}
	return;

fail:
	close(kcovfd);
	kcovfd = -1;
	return;
}

void enable_kcov(void)
{
	/* Enable coverage collection on the current thread. */
	if (ioctl(kcovfd, KCOV_ENABLE, 0))
		printf("Error enabling kcov: %s\n", strerror(errno));

	/* Reset coverage from the tail of the ioctl() call. */
	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
}

void dump_kcov_buffer(void)
{
	unsigned long n, i;

	/* Read number of PCs collected. */
	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	for (i = 0; i < n; i++)
		printf("0x%lx\n", cover[i + 1]);
}

void disable_kcov(void)
{
	/* Disable coverage collection for the current thread. After this call
	 * coverage can be enabled for a different thread.
	 */
	if (ioctl(kcovfd, KCOV_DISABLE, 0))
		printf("Failed to disable kcov: %s\n", strerror(errno));
}

void shutdown_kcov(void)
{
	if (kcovfd == -1)
		return;

	if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
		printf("Couldn't munmap kcov buffer : %s\n", strerror(errno));

	if (close(kcovfd))
		printf("Couldn't close kcov fd (%d) : %s\n", kcovfd, strerror(errno));
}
